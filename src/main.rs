use std::time::Duration;

use anyhow::Context;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use factory::api;
use factory::cloud::aws::{AwsCloud, AwsCloudConfig};
use factory::reconciler::{Reconciler, ReconcilerConfig};

fn required(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} must be set"))
}

fn optional_u64(name: &str, default: u64) -> anyhow::Result<u64> {
    match std::env::var(name) {
        Ok(v) => v
            .parse()
            .with_context(|| format!("{name} must be a non-negative integer, got {v:?}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(e).with_context(|| format!("reading {name}")),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let database_url = required("DATABASE_URL")?;
    let listen_addr =
        std::env::var("FACTORY_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let agent_base_url = api::parse_agent_base_url(&required("FACTORY_PUBLIC_URL")?)
        .context("FACTORY_PUBLIC_URL")?;
    if agent_base_url.starts_with("http://") {
        warn!("FACTORY_PUBLIC_URL is plain http; agent tokens will cross the network unencrypted");
    }
    let cloud_config = AwsCloudConfig {
        deployment: required("FACTORY_DEPLOYMENT_ID")?,
        ami_id: required("FACTORY_AMI_ID")?,
        instance_type: std::env::var("FACTORY_INSTANCE_TYPE").unwrap_or_else(|_| "t3.micro".into()),
        subnet_id: required("FACTORY_SUBNET_ID")?,
        security_group_id: required("FACTORY_SECURITY_GROUP_ID")?,
        instance_profile_name: required("FACTORY_INSTANCE_PROFILE")?,
    };
    let reconciler_config = ReconcilerConfig {
        interval: Duration::from_secs(optional_u64("FACTORY_RECONCILE_INTERVAL_SECS", 5)?),
        heartbeat_timeout: Duration::from_secs(optional_u64(
            "FACTORY_HEARTBEAT_TIMEOUT_SECS",
            300,
        )?),
        max_launches_per_tick: i64::try_from(optional_u64("FACTORY_MAX_LAUNCHES_PER_TICK", 5)?)
            .context("FACTORY_MAX_LAUNCHES_PER_TICK is too large")?,
        max_active_per_tenant: i64::try_from(optional_u64(
            "FACTORY_MAX_ACTIVE_TASKS_PER_TENANT",
            5,
        )?)
        .context("FACTORY_MAX_ACTIVE_TASKS_PER_TENANT is too large")?,
        tick_timeout: Duration::from_secs(optional_u64("FACTORY_TICK_TIMEOUT_SECS", 120)?),
        agent_base_url,
    };
    anyhow::ensure!(
        !reconciler_config.interval.is_zero() && !reconciler_config.tick_timeout.is_zero(),
        "FACTORY_RECONCILE_INTERVAL_SECS and FACTORY_TICK_TIMEOUT_SECS must be greater than 0"
    );
    anyhow::ensure!(
        reconciler_config.max_active_per_tenant > 0 && reconciler_config.max_launches_per_tick > 0,
        "FACTORY_MAX_ACTIVE_TASKS_PER_TENANT and FACTORY_MAX_LAUNCHES_PER_TICK must be greater than 0"
    );
    anyhow::ensure!(
        reconciler_config.heartbeat_timeout > reconciler_config.interval,
        "FACTORY_HEARTBEAT_TIMEOUT_SECS must be longer than FACTORY_RECONCILE_INTERVAL_SECS"
    );

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .context("connecting to Postgres")?;
    factory::db::migrate(&pool).await?;
    // The agent API is reachable from outside, so it gets its own small pool: a flood of
    // reports can't take the connections the reconciler needs.
    // Short timeouts so reports stuck behind a row lock (held while an agent is being
    // started) fail fast; curl retries them.
    let api_db_options = database_url
        .parse::<PgConnectOptions>()
        .context("parsing DATABASE_URL")?
        .options([("lock_timeout", "5s"), ("statement_timeout", "10s")]);
    let api_pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(api_db_options)
        .await
        .context("connecting to Postgres for the agent API")?;

    let cloud = AwsCloud::new(cloud_config).await?;
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("binding FACTORY_LISTEN_ADDR {listen_addr}"))?;
    let reconciler = Reconciler::new(pool.clone(), cloud, reconciler_config);

    // Dropping the sender tells every receiver to stop.
    let (stop_tx, stop_rx) = watch::channel(());
    let signal = shutdown_signal()?;
    tokio::spawn(async move {
        signal.await;
        drop(stop_tx);
    });
    let stopped = |mut rx: watch::Receiver<()>| async move {
        let _ = rx.changed().await;
    };

    info!(%listen_addr, "agent API and reconciler starting");
    let server_stop = stopped(stop_rx.clone());
    let server = async {
        axum::serve(listener, api::router(api_pool))
            .with_graceful_shutdown(server_stop)
            .await
            .context("agent API server")
    };
    let reconcile = async {
        reconciler.run(stopped(stop_rx)).await;
        Ok(())
    };
    // An API server failure ends the process rather than leaving the reconciler running
    // with no way for agents to report.
    tokio::try_join!(server, reconcile)?;
    Ok(())
}

/// Resolves on Ctrl-C or SIGTERM.
fn shutdown_signal() -> anyhow::Result<impl std::future::Future<Output = ()>> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;
    Ok(async move {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "listening for ctrl-c failed; shutting down");
                }
            }
            _ = sigterm.recv() => {}
        }
    })
}
