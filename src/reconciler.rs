//! Converges EC2 toward what Postgres says should exist. Holds no state between ticks:
//! every tick re-reads Postgres and re-lists EC2, so a restart at any point is safe.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use anyhow::Context;
use sqlx::PgPool;
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::agent::{self, AgentMode};
use crate::api;
use crate::cloud::{Cloud, Instance, InstanceState, LaunchRequest, ScriptRequest, ScriptStart};
use crate::credentials::{self, RepositoryTokenIssuer, TaskCredentials};
use crate::db::{self, Task, TaskState};
use crate::github::{GitHubApp, InstallationToken};

#[derive(Debug, Clone)]
pub struct ReconcilerConfig {
    pub deployment: String,
    pub agent_mode: AgentMode,
    pub interval: Duration,
    /// A launching/running/verifying task with no heartbeat for this long is failed.
    pub heartbeat_timeout: Duration,
    /// Cap on queued tasks claimed per tick, to bound how fast VMs are created.
    pub max_launches_per_tick: i64,
    /// Cap on a tenant's launching/running/verifying tasks. Queued tasks beyond it wait.
    pub max_active_per_tenant: i64,
    /// A tick that takes longer than this (e.g. a hung AWS call) is abandoned and retried.
    pub tick_timeout: Duration,
    /// How VMs reach the agent API, e.g. `https://factory.example.com`.
    pub agent_base_url: String,
}

struct RepositoryAccess {
    github: InstallationToken,
    model_key: String,
}

pub struct Reconciler<C, G = GitHubApp> {
    github: Option<G>,
    pool: PgPool,
    cloud: C,
    config: ReconcilerConfig,
}

impl<C: Cloud> Reconciler<C, GitHubApp> {
    pub fn new(pool: PgPool, cloud: C, config: ReconcilerConfig) -> Self {
        Reconciler {
            github: None,
            pool,
            cloud,
            config,
        }
    }

    pub fn with_github<G: RepositoryTokenIssuer>(self, github: G) -> Reconciler<C, G> {
        Reconciler {
            pool: self.pool,
            cloud: self.cloud,
            config: self.config,
            github: Some(github),
        }
    }
}

impl<C: Cloud, G: RepositoryTokenIssuer> Reconciler<C, G> {
    /// Ticks until `shutdown` resolves. A failed tick is logged and retried next interval.
    pub async fn run(&self, shutdown: impl Future<Output = ()>) {
        let mut interval = tokio::time::interval(self.config.interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("reconciler shutting down");
                    return;
                }
                _ = interval.tick() => {
                    // Abandoning a tick midway is safe: nothing is held in memory, and the
                    // next tick re-derives everything from Postgres and EC2.
                    match tokio::time::timeout(self.config.tick_timeout, self.tick()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => error!(error = ?e, "reconcile tick failed"),
                        Err(_) => error!(timeout = ?self.config.tick_timeout, "reconcile tick timed out"),
                    }
                }
            }
        }
    }

    pub async fn tick(&self) -> anyhow::Result<()> {
        // List EC2 before reading Postgres. Any instance launched after this snapshot belongs
        // to a task that was already claimed, so it can't be mistaken for an orphan below.
        let instances = self
            .cloud
            .list_tagged()
            .await
            .context("listing tagged instances")?;

        for task in db::fail_expired(&self.pool).await? {
            warn!(task_id = %task.id, tenant_id = %task.tenant_id, "task expired; marked failed");
        }
        for task in db::fail_stale_heartbeats(&self.pool, self.config.heartbeat_timeout).await? {
            warn!(task_id = %task.id, tenant_id = %task.tenant_id, "heartbeat stale; marked failed");
        }
        for task in db::claim_queued(
            &self.pool,
            self.config.max_launches_per_tick,
            self.config.max_active_per_tenant,
        )
        .await?
        {
            info!(task_id = %task.id, tenant_id = %task.tenant_id, "claimed queued task");
        }

        // One task's failure here must not block the rest; the heartbeat timeout eventually
        // fails a task that never launches or never starts its agent.
        for task in db::list_live_tasks(&self.pool).await? {
            match task.state {
                TaskState::Launching => {
                    if let Err(e) = self.advance_launching(&task, &instances).await {
                        warn!(task_id = %task.id, error = ?e, "could not advance launching task");
                    }
                }
                TaskState::Running if task.agent_command_id.is_none() => {
                    if let Err(e) = self.start_agent(&task).await {
                        warn!(task_id = %task.id, error = ?e, "could not start agent");
                    }
                }
                _ => {}
            }
        }

        // VM termination must not wait for slow Parameter Store pagination.
        let live = db::list_live_tasks(&self.pool).await?;
        let vm_result = self.terminate_unowned(&instances, &live).await;
        // Snapshot Parameter Store BEFORE reading live tasks: a concurrent start after
        // this snapshot cannot be mistaken for an orphan by an older database view.
        let secrets = self.cloud.list_task_secrets().await;
        let live = db::list_live_tasks(&self.pool).await?;
        match secrets {
            Ok(secrets) => {
                for secret in secrets {
                    if !live
                        .iter()
                        .any(|task| task.id == secret.task_id && task.tenant_id == secret.tenant_id)
                        && let Err(error) = self.cloud.delete_task_secret(&secret.name).await
                    {
                        warn!(task_id = %secret.task_id, error = %error, "could not delete task secrets; will retry");
                    }
                }
            }
            Err(error) => warn!(error = %error, "could not list task secrets; will retry"),
        }
        vm_result
    }

    /// Sends the agent script to a running task's VM with a fresh token.
    ///
    /// Token, send and record share one transaction whose row lock makes other reconcilers
    /// skip the task meanwhile. If anything fails after the send (or the tick is abandoned),
    /// the token never commits, so that run can't report, and the next tick sends a new one.
    async fn start_agent(&self, task: &Task) -> anyhow::Result<()> {
        let Some(instance_id) = &task.vm_instance_id else {
            return Ok(());
        };
        let token = api::new_agent_token();
        let mut tx = self
            .pool
            .begin()
            .await
            .context("starting agent transaction")?;
        if !db::set_agent_token(&mut *tx, task.id, &token).await? {
            return Ok(()); // Finished, started, or being started by another reconciler.
        }
        if task.expires_at <= chrono::Utc::now() {
            return Ok(());
        }
        if !self.cloud.script_ready(instance_id).await? {
            return Ok(());
        }
        let access = match self.repository_access(task, &mut tx).await {
            Ok(access) => access,
            Err(error)
                if error.is::<credentials::RepositoryConfigurationError>()
                    || error.is::<crate::cloud::SecretConfigurationError>()
                    || error.is::<crate::github::GitHubConfigurationError>() =>
            {
                db::fail_agent_start(&mut *tx, task.id, &error.to_string()).await?;
                tx.commit()
                    .await
                    .context("committing credential configuration failure")?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if task.expires_at <= chrono::Utc::now() {
            return Ok(());
        }
        let credentials = TaskCredentials {
            callback_token: &token,
            expires_at: task.expires_at,
            github_token: access.as_ref().map(|a| a.github.token.as_str()),
            github_expires_at: access.as_ref().map(|a| a.github.expires_at),
            model_api_key: access.as_ref().map(|a| a.model_key.as_str()),
        };
        let value = serde_json::to_string(&credentials).context("encoding task credentials")?;
        if value.len() > 4096 {
            db::fail_agent_start(
                &mut *tx,
                task.id,
                "task credentials exceed the 4096-byte limit",
            )
            .await?;
            tx.commit()
                .await
                .context("committing credential size failure")?;
            return Ok(());
        }
        let parameter = self
            .cloud
            .put_task_secret(task.tenant_id, task.id, instance_id, &value)
            .await?;
        let script = match &self.config.agent_mode {
            AgentMode::Hello => {
                api::hello_agent_script(&self.config.agent_base_url, task.id, &parameter)
            }
            AgentMode::Codex { model } => {
                agent::codex_script(&self.config.agent_base_url, task.id, &parameter, model)
            }
        };
        let timeout = (task.expires_at - chrono::Utc::now())
            .to_std()
            .unwrap_or(Duration::ZERO);
        if timeout.is_zero() {
            self.cloud.delete_task_secret(&parameter.name).await?;
            return Ok(());
        }
        let request = ScriptRequest {
            task_id: task.id,
            instance_id,
            script: &script,
            timeout,
        };
        match self.cloud.run_script(&request).await? {
            ScriptStart::NotReady => {
                // A definite rejection started no script; remove this unused attempt now.
                self.cloud.delete_task_secret(&parameter.name).await?;
                info!(task_id = %task.id, %instance_id, "SSM can't reach instance yet (agent registering, or missing SSM permissions); will retry");
            }
            ScriptStart::Sent { command_id } => {
                // Can't be false: this transaction has held the row since the token was set.
                if !db::record_agent_command(&mut *tx, task.id, &command_id).await? {
                    anyhow::bail!("agent command {command_id} could not be recorded");
                }
                tx.commit().await.context("committing agent start")?;
                info!(task_id = %task.id, %instance_id, %command_id, "started agent");
            }
        }
        Ok(())
    }

    async fn repository_access(
        &self,
        task: &Task,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> anyhow::Result<Option<RepositoryAccess>> {
        if matches!(self.config.agent_mode, AgentMode::Codex { .. })
            && (task.instructions.trim().is_empty()
                || task.instructions.len() > 65536
                || task.instructions.contains('\0'))
        {
            return Err(credentials::RepositoryConfigurationError(
                "invalid coding task instructions",
            )
            .into());
        }
        let Some(github) = &self.github else {
            if matches!(self.config.agent_mode, AgentMode::Codex { .. }) {
                return Err(credentials::RepositoryConfigurationError(
                    "codex mode requires GitHub App credentials",
                )
                .into());
            }
            return Ok(None);
        };
        let binding = credentials::for_task(&mut **tx, task.tenant_id, &task.repo_url).await?;
        if matches!(self.config.agent_mode, AgentMode::Codex { .. }) {
            credentials::validate_checks(binding.check_command.as_deref())?;
        }
        let prefix = format!(
            "/factory/{}/tenants/{}/",
            self.config.deployment, task.tenant_id
        );
        if !binding.model_key_parameter.starts_with(&prefix) {
            return Err(credentials::RepositoryConfigurationError(
                "model key parameter does not belong to tenant",
            )
            .into());
        }
        let model_key = self.cloud.read_secure(&binding.model_key_parameter).await?;
        if model_key.is_empty() || model_key.len() > 2048 || model_key.chars().any(char::is_control)
        {
            return Err(credentials::RepositoryConfigurationError(
                "model key must be a nonempty single-line secret of at most 2048 bytes",
            )
            .into());
        }
        if task.expires_at <= chrono::Utc::now() {
            anyhow::bail!("task expired while preparing credentials");
        }
        let github = github
            .mint_repository_token(
                u64::try_from(binding.installation_id)?,
                u64::try_from(binding.repository_id)?,
            )
            .await?;
        Ok(Some(RepositoryAccess { github, model_key }))
    }

    async fn advance_launching(&self, task: &Task, instances: &[Instance]) -> anyhow::Result<()> {
        match &task.vm_instance_id {
            None => {
                // A VM already tagged for this task means a previous run launched it and
                // died before recording it. Adopt it instead of launching another.
                let existing = instances
                    .iter()
                    .filter(|i| i.belongs_to(task.id, task.tenant_id))
                    .min_by_key(|i| adoption_preference(i.state));
                let instance_id = match existing {
                    Some(instance) => {
                        info!(task_id = %task.id, instance_id = %instance.id, "adopting existing instance");
                        instance.id.clone()
                    }
                    None => {
                        let request = LaunchRequest {
                            task_id: task.id,
                            tenant_id: task.tenant_id,
                            expires_at: task.expires_at,
                        };
                        let id = self.cloud.launch(&request).await?;
                        info!(task_id = %task.id, instance_id = %id, "launched instance");
                        id
                    }
                };
                if !db::record_vm_instance(&self.pool, task.id, &instance_id).await? {
                    // Another reconciler got there first, or the task left `launching`.
                    // If this instance ends up unowned, the orphan sweep removes it.
                    warn!(task_id = %task.id, instance_id = %instance_id, "task no longer awaiting a VM; not recorded");
                }
            }
            Some(vm_id) => {
                let up = instances.iter().any(|i| {
                    &i.id == vm_id
                        && i.belongs_to(task.id, task.tenant_id)
                        && i.state == InstanceState::Running
                });
                if up && db::mark_running(&self.pool, task.id).await? {
                    info!(task_id = %task.id, instance_id = %vm_id, "task running");
                }
            }
        }
        Ok(())
    }

    /// Terminates every tagged instance that isn't the recorded VM of a live task with the
    /// same task and tenant ids: orphans, duplicates, VMs of finished or failed tasks, and
    /// VMs past `expires_at` regardless of task state.
    ///
    /// Exception: an instance tagged for a live `launching` task that has no VM recorded yet
    /// is spared. It is that task's adoption candidate (e.g. recording it failed this tick),
    /// and the next tick will adopt it.
    async fn terminate_unowned(&self, instances: &[Instance], live: &[Task]) -> anyhow::Result<()> {
        let owners: HashMap<&str, (Uuid, Uuid)> = live
            .iter()
            .filter_map(|t| Some((t.vm_instance_id.as_deref()?, (t.id, t.tenant_id))))
            .collect();
        let awaiting_vm: Vec<(Uuid, Uuid)> = live
            .iter()
            .filter(|t| t.state == TaskState::Launching && t.vm_instance_id.is_none())
            .map(|t| (t.id, t.tenant_id))
            .collect();

        let doomed: Vec<String> = instances
            .iter()
            .filter(|i| {
                let owned = owners
                    .get(i.id.as_str())
                    .is_some_and(|&(task_id, tenant_id)| i.belongs_to(task_id, tenant_id));
                let adoptable = awaiting_vm
                    .iter()
                    .any(|&(task_id, tenant_id)| i.belongs_to(task_id, tenant_id));
                !owned && !adoptable
            })
            .map(|i| i.id.clone())
            .collect();

        if doomed.is_empty() {
            return Ok(());
        }
        warn!(instance_ids = ?doomed, "terminating instances with no live owning task");
        if let Err(batch_err) = self.cloud.terminate(&doomed).await {
            // EC2 rejects the whole batch if any one instance can't be terminated. Retry
            // individually so one bad instance can't block cleanup of the rest.
            warn!(error = ?batch_err, "batch terminate failed; retrying individually");
            let mut failed = Vec::new();
            for id in &doomed {
                if let Err(e) = self.cloud.terminate(std::slice::from_ref(id)).await {
                    error!(instance_id = %id, error = ?e, "could not terminate instance");
                    failed.push(id.as_str());
                }
            }
            if !failed.is_empty() {
                anyhow::bail!("could not terminate instances: {failed:?}");
            }
        }
        Ok(())
    }
}

fn adoption_preference(state: InstanceState) -> u8 {
    match state {
        InstanceState::Running => 0,
        InstanceState::Pending => 1,
        InstanceState::Other => 2,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{Duration as ChronoDuration, Utc};

    use super::*;
    use crate::cloud::fake::{DEPLOYMENT, FakeCloud, FakeState};
    use crate::cloud::{DEPLOYMENT_TAG, TASK_ID_TAG, TENANT_ID_TAG};

    const HEARTBEAT_TIMEOUT_SECS: i64 = 60;
    const MAX_LAUNCHES: i64 = 3;
    const MAX_ACTIVE_PER_TENANT: i64 = 10;
    const AGENT_BASE_URL: &str = "https://factory.test";

    fn token_in(cloud: &FakeCloud, script: &str) -> String {
        cloud.secret_for_script(script)["callback_token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// Ticks a fresh task to `running` with a booted VM, before its agent is started.
    async fn running_without_agent(
        pool: &PgPool,
        r: &Reconciler<Arc<FakeCloud>>,
        cloud: &FakeCloud,
    ) -> Task {
        let t = queued_task(pool).await;
        r.tick().await.unwrap(); // claim + launch
        cloud.boot_all();
        let vm = task(pool, t.id).await.vm_instance_id.unwrap();
        cloud.ssm_unreachable(&vm);
        r.tick().await.unwrap(); // mark running
        cloud.ssm_reachable(&vm);
        let t = task(pool, t.id).await;
        assert_eq!(
            (t.state, t.agent_command_id.as_deref()),
            (TaskState::Running, None)
        );
        t
    }

    fn reconciler(pool: &PgPool, cloud: &Arc<FakeCloud>) -> Reconciler<Arc<FakeCloud>> {
        Reconciler::new(
            pool.clone(),
            Arc::clone(cloud),
            ReconcilerConfig {
                deployment: DEPLOYMENT.into(),
                agent_mode: AgentMode::Hello,
                interval: Duration::from_secs(5),
                heartbeat_timeout: Duration::from_secs(HEARTBEAT_TIMEOUT_SECS as u64),
                max_launches_per_tick: MAX_LAUNCHES,
                max_active_per_tenant: MAX_ACTIVE_PER_TENANT,
                tick_timeout: Duration::from_secs(30),
                agent_base_url: AGENT_BASE_URL.to_string(),
            },
        )
    }

    async fn queued_task(pool: &PgPool) -> Task {
        db::create_test_task(pool, Uuid::new_v4(), Utc::now() + ChronoDuration::hours(1))
            .await
            .unwrap()
    }

    async fn task(pool: &PgPool, id: Uuid) -> Task {
        let tenant: Uuid = sqlx::query_scalar("SELECT tenant_id FROM tasks WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
        db::get_task(pool, tenant, id).await.unwrap().unwrap()
    }

    /// Puts a task directly into a given state, as a previous orchestrator run might have left it.
    async fn force(pool: &PgPool, id: Uuid, state: TaskState, vm: Option<&str>) {
        sqlx::query(
            "UPDATE tasks SET state = $2, vm_instance_id = $3, heartbeat_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(state)
        .bind(vm)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn set_heartbeat_age(pool: &PgPool, id: Uuid, age_secs: i64) {
        sqlx::query(
            "UPDATE tasks SET heartbeat_at = now() - make_interval(secs => $2) WHERE id = $1",
        )
        .bind(id)
        .bind(age_secs as f64)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn expire(pool: &PgPool, id: Uuid) {
        sqlx::query(
            "UPDATE tasks SET created_at = now() - interval '2 hours', \
             expires_at = now() - interval '1 second' WHERE id = $1",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn queued_task_launches_tagged_vm_then_runs(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = queued_task(&pool).await;

        r.tick().await.unwrap();

        let launching = task(&pool, t.id).await;
        assert_eq!(launching.state, TaskState::Launching);
        assert!(
            launching.heartbeat_at.is_some(),
            "claim starts the heartbeat grace period"
        );
        let vm = launching.vm_instance_id.clone().unwrap();
        let instance = cloud.instance(&vm).unwrap();
        assert_eq!(instance.tags[DEPLOYMENT_TAG], DEPLOYMENT);
        assert_eq!(instance.tags[TASK_ID_TAG], t.id.to_string());
        assert_eq!(instance.tags[TENANT_ID_TAG], t.tenant_id.to_string());
        assert_eq!(instance.self_terminates_at, Some(t.expires_at));

        // Instance still pending: stays launching.
        r.tick().await.unwrap();
        assert_eq!(task(&pool, t.id).await.state, TaskState::Launching);

        cloud.boot_all();
        r.tick().await.unwrap();

        let running = task(&pool, t.id).await;
        assert_eq!(running.state, TaskState::Running);
        assert_eq!(running.vm_instance_id, Some(vm.clone()));
        assert_eq!(cloud.launch_calls(), 1);
        assert_eq!(cloud.alive(), vec![vm]);
    }

    #[sqlx::test]
    async fn orphans_are_terminated(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let no_task = cloud.insert_for_task(FakeState::Running, Uuid::new_v4(), Uuid::new_v4());
        let garbage_tag = cloud.insert(
            FakeState::Running,
            &[(DEPLOYMENT_TAG, DEPLOYMENT), (TASK_ID_TAG, "not-a-uuid")],
        );
        let deployment_only = cloud.insert(FakeState::Running, &[(DEPLOYMENT_TAG, DEPLOYMENT)]);
        let untagged = cloud.insert(FakeState::Running, &[("Name", "someone-elses-box")]);

        let finished = queued_task(&pool).await;
        let finished_vm =
            cloud.insert_for_task(FakeState::Running, finished.id, finished.tenant_id);
        force(&pool, finished.id, TaskState::Succeeded, Some(&finished_vm)).await;

        let wrong_tenant = queued_task(&pool).await;
        let wrong_tenant_vm =
            cloud.insert_for_task(FakeState::Running, wrong_tenant.id, Uuid::new_v4());
        force(
            &pool,
            wrong_tenant.id,
            TaskState::Running,
            Some(&wrong_tenant_vm),
        )
        .await;

        reconciler(&pool, &cloud).tick().await.unwrap();

        for id in [
            &no_task,
            &garbage_tag,
            &deployment_only,
            &finished_vm,
            &wrong_tenant_vm,
        ] {
            assert_eq!(
                cloud.state(id),
                Some(FakeState::Terminated),
                "{id} should be terminated"
            );
        }
        assert_eq!(
            cloud.state(&untagged),
            Some(FakeState::Running),
            "untagged instances are not ours"
        );
    }

    #[sqlx::test]
    async fn other_deployments_instances_are_left_alone(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let (task_id, tenant_id) = (Uuid::new_v4().to_string(), Uuid::new_v4().to_string());
        let task_tags = [
            (TASK_ID_TAG, task_id.as_str()),
            (TENANT_ID_TAG, tenant_id.as_str()),
        ];
        let other_deployment = cloud.insert(
            FakeState::Running,
            &[&[(DEPLOYMENT_TAG, "someone-else")][..], &task_tags].concat(),
        );
        let no_deployment = cloud.insert(FakeState::Running, &task_tags);

        reconciler(&pool, &cloud).tick().await.unwrap();

        assert_eq!(cloud.state(&other_deployment), Some(FakeState::Running));
        assert_eq!(cloud.state(&no_deployment), Some(FakeState::Running));
    }

    #[sqlx::test]
    async fn duplicate_vm_for_a_task_is_terminated(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let t = queued_task(&pool).await;
        let recorded = cloud.insert_for_task(FakeState::Running, t.id, t.tenant_id);
        let duplicate = cloud.insert_for_task(FakeState::Running, t.id, t.tenant_id);
        force(&pool, t.id, TaskState::Running, Some(&recorded)).await;

        reconciler(&pool, &cloud).tick().await.unwrap();

        assert_eq!(cloud.alive(), vec![recorded]);
        assert_eq!(cloud.state(&duplicate), Some(FakeState::Terminated));
    }

    #[sqlx::test]
    async fn expired_running_task_fails_and_vm_is_terminated(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let t = queued_task(&pool).await;
        let vm = cloud.insert_for_task(FakeState::Running, t.id, t.tenant_id);
        force(&pool, t.id, TaskState::Running, Some(&vm)).await;
        expire(&pool, t.id).await;

        reconciler(&pool, &cloud).tick().await.unwrap();

        assert_eq!(task(&pool, t.id).await.state, TaskState::Failed);
        assert_eq!(cloud.state(&vm), Some(FakeState::Terminated));
    }

    #[sqlx::test]
    async fn expired_vm_is_terminated_even_if_task_already_succeeded(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let t = queued_task(&pool).await;
        let vm = cloud.insert_for_task(FakeState::Running, t.id, t.tenant_id);
        force(&pool, t.id, TaskState::Succeeded, Some(&vm)).await;
        expire(&pool, t.id).await;

        reconciler(&pool, &cloud).tick().await.unwrap();

        assert_eq!(
            task(&pool, t.id).await.state,
            TaskState::Succeeded,
            "terminal state is kept"
        );
        assert_eq!(cloud.state(&vm), Some(FakeState::Terminated));
    }

    #[sqlx::test]
    async fn expired_queued_task_fails_without_launching(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let t = queued_task(&pool).await;
        expire(&pool, t.id).await;

        reconciler(&pool, &cloud).tick().await.unwrap();

        assert_eq!(task(&pool, t.id).await.state, TaskState::Failed);
        assert_eq!(cloud.launch_calls(), 0);
    }

    #[sqlx::test]
    async fn stale_heartbeat_fails_task_and_terminates_vm(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let stale = queued_task(&pool).await;
        let stale_vm = cloud.insert_for_task(FakeState::Running, stale.id, stale.tenant_id);
        force(&pool, stale.id, TaskState::Running, Some(&stale_vm)).await;
        set_heartbeat_age(&pool, stale.id, HEARTBEAT_TIMEOUT_SECS + 1).await;

        let fresh = queued_task(&pool).await;
        let fresh_vm = cloud.insert_for_task(FakeState::Running, fresh.id, fresh.tenant_id);
        force(&pool, fresh.id, TaskState::Running, Some(&fresh_vm)).await;
        set_heartbeat_age(&pool, fresh.id, HEARTBEAT_TIMEOUT_SECS - 10).await;

        reconciler(&pool, &cloud).tick().await.unwrap();

        assert_eq!(task(&pool, stale.id).await.state, TaskState::Failed);
        assert_eq!(cloud.state(&stale_vm), Some(FakeState::Terminated));
        assert_eq!(task(&pool, fresh.id).await.state, TaskState::Running);
        assert_eq!(cloud.state(&fresh_vm), Some(FakeState::Running));
    }

    #[sqlx::test]
    async fn launch_that_never_gets_a_vm_fails_after_heartbeat_timeout(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = queued_task(&pool).await;
        cloud.fail_next_launches(usize::MAX);

        r.tick().await.unwrap();
        assert_eq!(task(&pool, t.id).await.state, TaskState::Launching);

        set_heartbeat_age(&pool, t.id, HEARTBEAT_TIMEOUT_SECS + 1).await;
        r.tick().await.unwrap();

        assert_eq!(task(&pool, t.id).await.state, TaskState::Failed);
        assert!(cloud.alive().is_empty());
    }

    #[sqlx::test]
    async fn failed_launch_is_retried_without_duplicating(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = queued_task(&pool).await;
        cloud.fail_next_launches(1);

        r.tick().await.unwrap();
        assert_eq!(task(&pool, t.id).await.vm_instance_id, None);

        r.tick().await.unwrap();

        let vm = task(&pool, t.id).await.vm_instance_id.unwrap();
        assert_eq!(cloud.alive(), vec![vm]);
    }

    #[sqlx::test]
    async fn listing_failure_changes_nothing(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let t = queued_task(&pool).await;
        let orphan = cloud.insert_for_task(FakeState::Running, Uuid::new_v4(), Uuid::new_v4());
        cloud.fail_list(true);

        assert!(reconciler(&pool, &cloud).tick().await.is_err());

        assert_eq!(task(&pool, t.id).await.state, TaskState::Queued);
        assert_eq!(cloud.state(&orphan), Some(FakeState::Running));
        assert_eq!(cloud.launch_calls(), 0);
    }

    #[sqlx::test]
    async fn one_unterminatable_instance_does_not_block_the_rest(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let stuck = cloud.insert_for_task(FakeState::Running, Uuid::new_v4(), Uuid::new_v4());
        let other = cloud.insert_for_task(FakeState::Running, Uuid::new_v4(), Uuid::new_v4());
        cloud.refuse_termination(&stuck);

        let result = reconciler(&pool, &cloud).tick().await;

        assert!(result.is_err(), "the stuck instance is reported");
        assert_eq!(cloud.state(&other), Some(FakeState::Terminated));
        assert_eq!(cloud.state(&stuck), Some(FakeState::Running));
    }

    #[sqlx::test]
    async fn launches_per_tick_are_capped(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        for _ in 0..MAX_LAUNCHES + 2 {
            queued_task(&pool).await;
        }

        r.tick().await.unwrap();
        assert_eq!(cloud.launch_calls(), MAX_LAUNCHES as usize);

        r.tick().await.unwrap();
        assert_eq!(cloud.launch_calls(), MAX_LAUNCHES as usize + 2);
    }

    #[sqlx::test]
    async fn unrecorded_vm_of_launching_task_is_spared_for_adoption(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let t = queued_task(&pool).await;
        force(&pool, t.id, TaskState::Launching, None).await;
        let vm = cloud.insert_for_task(FakeState::Running, t.id, t.tenant_id);
        let r = reconciler(&pool, &cloud);
        let instances = cloud.list_tagged().await.unwrap();
        let live = db::list_live_tasks(&pool).await.unwrap();

        // As if recording the adoption failed this tick: the task still has no VM.
        r.terminate_unowned(&instances, &live).await.unwrap();

        assert_eq!(cloud.state(&vm), Some(FakeState::Running));
    }

    #[sqlx::test]
    async fn two_reconcilers_on_one_database_launch_once(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let a = reconciler(&pool, &cloud);
        let b = reconciler(&pool, &cloud);
        let t = queued_task(&pool).await;

        for _ in 0..3 {
            let (ra, rb) = tokio::join!(a.tick(), b.tick());
            ra.unwrap();
            rb.unwrap();
        }
        cloud.boot_all();
        a.tick().await.unwrap();

        let vm = task(&pool, t.id).await.vm_instance_id.unwrap();
        assert_eq!(cloud.alive(), vec![vm]);
        assert_eq!(task(&pool, t.id).await.state, TaskState::Running);
    }

    // --- Orchestrator restarts mid-task. Each test builds a brand-new Reconciler over the
    // --- same database and cloud, which is all a process restart leaves behind.

    #[sqlx::test]
    async fn restart_after_launch_before_recording_adopts_the_vm(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let t = queued_task(&pool).await;
        // Previous process claimed the task and launched, then died before record_vm_instance.
        force(&pool, t.id, TaskState::Launching, None).await;
        let vm = cloud.insert_for_task(FakeState::Running, t.id, t.tenant_id);

        let restarted = reconciler(&pool, &cloud);
        restarted.tick().await.unwrap();

        assert_eq!(cloud.launch_calls(), 0, "must not launch a second VM");
        assert_eq!(task(&pool, t.id).await.vm_instance_id, Some(vm.clone()));
        assert_eq!(
            cloud.state(&vm),
            Some(FakeState::Running),
            "adopted VM is not an orphan"
        );

        restarted.tick().await.unwrap();
        assert_eq!(task(&pool, t.id).await.state, TaskState::Running);
    }

    #[sqlx::test]
    async fn restart_after_claim_before_launch_launches_once(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let t = queued_task(&pool).await;
        force(&pool, t.id, TaskState::Launching, None).await;

        reconciler(&pool, &cloud).tick().await.unwrap();
        reconciler(&pool, &cloud).tick().await.unwrap();

        assert_eq!(cloud.launch_calls(), 1);
        let vm = task(&pool, t.id).await.vm_instance_id.unwrap();
        assert_eq!(cloud.alive(), vec![vm]);
    }

    #[sqlx::test]
    async fn restart_after_launch_while_ec2_listing_lags_launches_once(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let t = queued_task(&pool).await;
        // Previous process claimed and called RunInstances, then died before recording.
        force(&pool, t.id, TaskState::Launching, None).await;
        let first = cloud
            .launch(&LaunchRequest {
                task_id: t.id,
                tenant_id: t.tenant_id,
                expires_at: t.expires_at,
            })
            .await
            .unwrap();
        // DescribeInstances is eventually consistent: the new VM isn't listed yet.
        cloud.hide_from_next_lists(&first, 1);

        reconciler(&pool, &cloud).tick().await.unwrap();

        // Adoption couldn't see it, so the retry relies on the client token.
        assert_eq!(task(&pool, t.id).await.vm_instance_id, Some(first.clone()));
        assert_eq!(cloud.alive(), vec![first]);
    }

    #[sqlx::test]
    async fn restart_with_running_task_leaves_it_alone(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let first = reconciler(&pool, &cloud);
        let t = queued_task(&pool).await;
        first.tick().await.unwrap();
        cloud.boot_all();
        first.tick().await.unwrap();
        drop(first);
        let before = task(&pool, t.id).await;
        assert_eq!(before.state, TaskState::Running);

        reconciler(&pool, &cloud).tick().await.unwrap();

        let after = task(&pool, t.id).await;
        assert_eq!(after.state, TaskState::Running);
        assert_eq!(after.vm_instance_id, before.vm_instance_id);
        assert_eq!(cloud.launch_calls(), 1);
        assert_eq!(cloud.alive().len(), 1);
    }

    #[sqlx::test]
    async fn running_task_gets_its_agent_started_once(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;

        r.tick().await.unwrap();
        r.tick().await.unwrap();

        let scripts = cloud.scripts();
        assert_eq!(scripts.len(), 1, "sent once");
        assert_eq!(scripts[0].task_id, t.id);
        assert_eq!(Some(&scripts[0].instance_id), t.vm_instance_id.as_ref());
        assert!(
            scripts[0]
                .script
                .contains(&format!("{AGENT_BASE_URL}/v1/tasks/{}", t.id))
        );
        let t = task(&pool, t.id).await;
        assert_eq!(t.agent_command_id, Some(scripts[0].command_id.clone()));
        assert_eq!(t.state, TaskState::Running);
    }

    #[sqlx::test]
    async fn hello_result_succeeds_the_task_and_its_vm_is_terminated(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        r.tick().await.unwrap();
        let token = token_in(&cloud, &cloud.scripts()[0].script).to_string();

        // What the script does on the VM, minus HTTP (covered in api tests).
        assert!(db::record_heartbeat(&pool, t.id, &token).await.unwrap());
        assert!(
            db::record_result(&pool, t.id, &token, "hello")
                .await
                .unwrap()
        );
        r.tick().await.unwrap();

        let done = task(&pool, t.id).await;
        assert_eq!(done.state, TaskState::Succeeded);
        assert_eq!(done.result.as_deref(), Some("hello"));
        assert!(
            cloud.alive().is_empty(),
            "VM terminated once the task finished"
        );
    }

    #[sqlx::test]
    async fn agent_start_waits_for_ssm_then_sends(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        let vm = t.vm_instance_id.clone().unwrap();
        cloud.ssm_unreachable(&vm);

        r.tick().await.unwrap();
        r.tick().await.unwrap();
        assert!(cloud.scripts().is_empty());
        assert_eq!(task(&pool, t.id).await.agent_command_id, None);

        cloud.ssm_reachable(&vm);
        r.tick().await.unwrap();
        assert_eq!(cloud.scripts().len(), 1);
    }

    #[sqlx::test]
    async fn agent_that_never_starts_fails_on_heartbeat_timeout(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        cloud.ssm_unreachable(t.vm_instance_id.as_ref().unwrap());
        set_heartbeat_age(&pool, t.id, HEARTBEAT_TIMEOUT_SECS + 1).await;

        r.tick().await.unwrap();

        let failed = task(&pool, t.id).await;
        assert_eq!(failed.state, TaskState::Failed);
        assert_eq!(
            failed.failure_reason.as_deref(),
            Some("no heartbeat while running")
        );
        assert!(cloud.alive().is_empty());
    }

    #[sqlx::test]
    async fn failed_send_is_retried_and_does_not_block_other_tasks(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let a = running_without_agent(&pool, &r, &cloud).await;
        let b = running_without_agent(&pool, &r, &cloud).await;
        cloud.fail_next_scripts(1);

        r.tick().await.unwrap();
        let started = [a.id, b.id].map(|id| cloud.scripts().iter().any(|s| s.task_id == id));
        assert_eq!(started.iter().filter(|s| **s).count(), 1);

        r.tick().await.unwrap();
        assert_eq!(cloud.scripts().len(), 2);
    }

    #[sqlx::test]
    async fn restart_after_send_before_record_resends_and_locks_out_the_first_run(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        // Previous process set a token and sent the script, then died before recording it.
        assert!(
            db::set_agent_token(&pool, t.id, "first-token")
                .await
                .unwrap()
        );
        let ScriptStart::Sent { .. } = cloud
            .run_script(&ScriptRequest {
                task_id: t.id,
                instance_id: t.vm_instance_id.as_deref().unwrap(),
                script: "first run",
                timeout: Duration::from_secs(60),
            })
            .await
            .unwrap()
        else {
            panic!("fake should accept");
        };

        reconciler(&pool, &cloud).tick().await.unwrap();

        let scripts = cloud.scripts();
        assert_eq!(scripts.len(), 2);
        assert_eq!(
            task(&pool, t.id).await.agent_command_id,
            Some(scripts[1].command_id.clone())
        );
        assert!(
            !db::record_heartbeat(&pool, t.id, "first-token")
                .await
                .unwrap()
        );
        assert!(
            db::record_heartbeat(&pool, t.id, &token_in(&cloud, &scripts[1].script))
                .await
                .unwrap()
        );
    }

    #[sqlx::test]
    async fn agent_start_in_progress_elsewhere_is_skipped_not_duplicated(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        // Another reconciler is between rotating the token and recording its command.
        let mut other = pool.begin().await.unwrap();
        sqlx::query("SELECT 1 FROM tasks WHERE id = $1 FOR UPDATE")
            .bind(t.id)
            .execute(&mut *other)
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), r.tick())
            .await
            .expect("tick must not wait for the other reconciler")
            .unwrap();
        assert!(cloud.scripts().is_empty());

        other.rollback().await.unwrap();
        r.tick().await.unwrap();
        assert_eq!(cloud.scripts().len(), 1);
    }

    #[sqlx::test]
    async fn tick_abandoned_after_send_commits_nothing_and_next_tick_resends(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        let sent = cloud.hang_after_next_send();
        {
            let tick = r.tick();
            tokio::pin!(tick);
            tokio::select! {
                result = &mut tick => panic!("tick should hang after sending: {result:?}"),
                observed = tokio::time::timeout(Duration::from_secs(10), sent.notified()) => {
                    observed.expect("script must be accepted before abandoning the tick");
                }
            }
        } // Cancel only after the fake has accepted the script.

        // SQLx queues rollback when the cancelled transaction is dropped. Acquire the
        // same row lock to wait for that rollback instead of racing SKIP LOCKED next tick.
        let mut rollback_finished = pool.begin().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(10),
            sqlx::query("SELECT 1 FROM tasks WHERE id = $1 FOR UPDATE")
                .bind(t.id)
                .execute(&mut *rollback_finished),
        )
        .await
        .expect("cancelled transaction must release its row lock")
        .unwrap();
        rollback_finished.rollback().await.unwrap();
        let first = cloud.scripts()[0].clone();
        let row = task(&pool, t.id).await;
        assert_eq!(row.agent_command_id, None);
        assert!(
            !db::record_heartbeat(&pool, t.id, &token_in(&cloud, &first.script))
                .await
                .unwrap()
        );

        r.tick().await.unwrap();
        let scripts = cloud.scripts();
        assert_eq!(scripts.len(), 2);
        assert_eq!(
            task(&pool, t.id).await.agent_command_id,
            Some(scripts[1].command_id.clone())
        );
        assert!(
            !db::record_heartbeat(&pool, t.id, &token_in(&cloud, &first.script))
                .await
                .unwrap()
        );
        assert!(
            db::record_heartbeat(&pool, t.id, &token_in(&cloud, &scripts[1].script))
                .await
                .unwrap()
        );
    }
    struct FakeGithub;
    impl RepositoryTokenIssuer for FakeGithub {
        async fn mint_repository_token(
            &self,
            installation_id: u64,
            repository_id: u64,
        ) -> anyhow::Result<crate::github::InstallationToken> {
            assert_eq!((installation_id, repository_id), (11, 22));
            Ok(crate::github::InstallationToken {
                token: "synthetic-github-token".into(),
                expires_at: Utc::now() + ChronoDuration::hours(1),
            })
        }
    }

    #[sqlx::test]
    async fn credentials_are_scoped_to_the_tenant_and_never_sent_in_script(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        sqlx::query("UPDATE tasks SET repo_url = 'https://github.com/owner/repo' WHERE id = $1")
            .bind(t.id)
            .execute(&pool)
            .await
            .unwrap();
        let name = format!("/factory/{DEPLOYMENT}/tenants/{}/model-key", t.tenant_id);
        sqlx::query("INSERT INTO repository_credentials (tenant_id, repository, installation_id, repository_id, model_key_parameter) VALUES ($1, 'owner/repo', 11, 22, $2)")
            .bind(t.tenant_id).bind(&name).execute(&pool).await.unwrap();
        cloud.set_source_secret(&name, "synthetic-model-key");
        let r = r.with_github(FakeGithub);
        r.tick().await.unwrap();
        let script = &cloud.scripts()[0].script;
        let credentials = cloud.secret_for_script(script);
        assert_eq!(credentials["github_token"], "synthetic-github-token");
        assert_eq!(credentials["model_api_key"], "synthetic-model-key");
        for key in ["github_token", "model_api_key", "callback_token"] {
            assert!(!script.contains(credentials[key].as_str().unwrap()));
        }
        assert!(
            db::record_result(
                &pool,
                t.id,
                credentials["callback_token"].as_str().unwrap(),
                "hello"
            )
            .await
            .unwrap()
        );
        r.tick().await.unwrap();
        assert!(cloud.list_task_secrets().await.unwrap().is_empty());
    }

    #[sqlx::test]
    async fn codex_rejects_invalid_instructions_before_credentials(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let mut r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        r.config.agent_mode = AgentMode::Codex {
            model: "configured-model".into(),
        };
        sqlx::query("UPDATE tasks SET instructions = $2 WHERE id = $1")
            .bind(t.id)
            .bind("x".repeat(65537))
            .execute(&pool)
            .await
            .unwrap();
        r.with_github(FakeGithub).tick().await.unwrap();
        assert!(cloud.scripts().is_empty());
        assert!(cloud.list_task_secrets().await.unwrap().is_empty());
        assert_eq!(
            task(&pool, t.id).await.failure_reason.as_deref(),
            Some("invalid coding task instructions")
        );
    }

    #[sqlx::test]
    async fn codex_dispatch_requires_checks_and_keeps_input_out_of_ssm(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        for configured in [false, true] {
            let mut r = reconciler(&pool, &cloud);
            let t = running_without_agent(&pool, &r, &cloud).await;
            r.config.agent_mode = AgentMode::Codex {
                model: "configured-model".into(),
            };
            sqlx::query("UPDATE tasks SET repo_url = 'https://github.com/owner/repo', instructions = 'UNTRUSTED_TASK_INPUT' WHERE id = $1")
                .bind(t.id).execute(&pool).await.unwrap();
            let name = format!("/factory/{DEPLOYMENT}/tenants/{}/model-key", t.tenant_id);
            sqlx::query("INSERT INTO repository_credentials (tenant_id, repository, installation_id, repository_id, model_key_parameter, check_command) VALUES ($1, 'owner/repo', 11, 22, $2, $3)")
                .bind(t.tenant_id).bind(&name)
                .bind(configured.then(|| vec!["cargo".to_string(), "test".to_string(), "--locked".to_string()]))
                .execute(&pool).await.unwrap();
            cloud.set_source_secret(&name, "synthetic-model-key");
            r.with_github(FakeGithub).tick().await.unwrap();
            if configured {
                let script = &cloud.scripts()[0].script;
                assert!(script.contains("--model 'configured-model'"));
                assert!(script.contains("class Runner:"));
                assert!(!script.contains("UNTRUSTED_TASK_INPUT"));
                let stored = cloud.list_task_secrets().await.unwrap();
                let credentials: serde_json::Value =
                    serde_json::from_str(&cloud.secret_value(&stored[0].name)).unwrap();
                for key in ["github_token", "model_api_key", "callback_token"] {
                    assert!(!script.contains(credentials[key].as_str().unwrap()));
                }
                assert!(
                    db::record_heartbeat(
                        &pool,
                        t.id,
                        credentials["callback_token"].as_str().unwrap()
                    )
                    .await
                    .unwrap()
                );
            } else {
                assert!(cloud.scripts().is_empty());
                assert!(cloud.list_task_secrets().await.unwrap().is_empty());
                assert_eq!(
                    task(&pool, t.id).await.failure_reason.as_deref(),
                    Some("repository checks are not configured")
                );
            }
            // Finish this iteration before testing the next configuration.
            sqlx::query("UPDATE tasks SET state = 'failed' WHERE id = $1")
                .bind(t.id)
                .execute(&pool)
                .await
                .unwrap();
        }
    }

    #[sqlx::test]
    async fn unapproved_repository_gets_no_credentials_or_script(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        let r = r.with_github(FakeGithub);
        r.tick().await.unwrap();
        assert!(cloud.scripts().is_empty());
        assert!(cloud.list_task_secrets().await.unwrap().is_empty());
        let failed = task(&pool, t.id).await;
        assert!(failed.agent_command_id.is_none());
        assert_eq!(failed.state, TaskState::Failed);
        assert_eq!(
            failed.failure_reason.as_deref(),
            Some("repository not configured for tenant")
        );
    }

    #[sqlx::test]
    async fn failed_secret_write_does_not_send_or_commit_token(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        cloud.fail_secret_write(true);
        r.tick().await.unwrap();
        assert!(cloud.scripts().is_empty());
        assert!(task(&pool, t.id).await.agent_command_id.is_none());
        cloud.fail_secret_write(false);
        r.tick().await.unwrap();
        let script = &cloud.scripts()[0].script;
        assert!(
            db::record_heartbeat(&pool, t.id, &token_in(&cloud, script))
                .await
                .unwrap()
        );
    }

    #[sqlx::test]
    async fn restart_sweeps_unrecorded_and_finished_secrets_and_retries_deletes(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        // A put accepted before a process crash, without a saved SSM command.
        cloud
            .put_task_secret(
                t.tenant_id,
                t.id,
                t.vm_instance_id.as_deref().unwrap(),
                "old attempt",
            )
            .await
            .unwrap();
        cloud
            .put_task_secret(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "i-1234567890abcdef0",
                "orphan",
            )
            .await
            .unwrap();
        reconciler(&pool, &cloud).tick().await.unwrap();
        assert_eq!(
            cloud.list_task_secrets().await.unwrap().len(),
            2,
            "live task attempts retained, orphan deleted"
        );
        expire(&pool, t.id).await;
        cloud.fail_secret_delete(true);
        reconciler(&pool, &cloud).tick().await.unwrap();
        assert!(
            cloud.alive().is_empty(),
            "cleanup failure must not block VM termination"
        );
        assert_eq!(cloud.list_task_secrets().await.unwrap().len(), 2);
        cloud.fail_secret_delete(false);
        reconciler(&pool, &cloud).tick().await.unwrap();
        assert!(cloud.list_task_secrets().await.unwrap().is_empty());
    }

    #[sqlx::test]
    async fn foreign_tenant_key_and_missing_source_secret_fail_with_clear_reasons(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        for foreign in [true, false] {
            let r = reconciler(&pool, &cloud);
            let t = running_without_agent(&pool, &r, &cloud).await;
            sqlx::query(
                "UPDATE tasks SET repo_url = 'https://github.com/owner/repo' WHERE id = $1",
            )
            .bind(t.id)
            .execute(&pool)
            .await
            .unwrap();
            let owner = if foreign { Uuid::new_v4() } else { t.tenant_id };
            sqlx::query("INSERT INTO repository_credentials (tenant_id, repository, installation_id, repository_id, model_key_parameter) VALUES ($1, 'owner/repo', 11, 22, $2)")
                .bind(t.tenant_id).bind(format!("/factory/{DEPLOYMENT}/tenants/{owner}/model-key")).execute(&pool).await.unwrap();
            r.with_github(FakeGithub).tick().await.unwrap();
            assert!(cloud.scripts().is_empty());
            assert!(cloud.list_task_secrets().await.unwrap().is_empty());
            let failed = task(&pool, t.id).await;
            assert_eq!(failed.state, TaskState::Failed);
            assert_eq!(
                failed.failure_reason.as_deref(),
                Some(if foreign {
                    "model key parameter does not belong to tenant"
                } else {
                    "configured secret does not exist"
                })
            );
        }
    }

    #[sqlx::test]
    async fn ssm_warmup_creates_no_bundles_and_definite_rejection_deletes_attempt(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        let vm = t.vm_instance_id.as_deref().unwrap();
        cloud.ssm_unreachable(vm);
        for _ in 0..3 {
            r.tick().await.unwrap();
        }
        assert!(cloud.list_task_secrets().await.unwrap().is_empty());
        cloud.ssm_reachable(vm);
        cloud.disconnect_on_send();
        r.tick().await.unwrap();
        assert!(cloud.list_task_secrets().await.unwrap().is_empty());
        assert!(cloud.scripts().is_empty());
        r.tick().await.unwrap();
        assert_eq!(cloud.list_task_secrets().await.unwrap().len(), 1);
    }

    #[sqlx::test]
    async fn slow_secret_listing_cannot_block_expired_vm_termination(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        expire(&pool, t.id).await;
        cloud.hang_secret_list();
        assert!(
            tokio::time::timeout(Duration::from_millis(500), r.tick())
                .await
                .is_err()
        );
        assert!(cloud.alive().is_empty());
    }

    #[sqlx::test]
    async fn oversized_serialized_credentials_never_reach_send_command(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        sqlx::query("UPDATE tasks SET repo_url = 'https://github.com/owner/repo' WHERE id = $1")
            .bind(t.id)
            .execute(&pool)
            .await
            .unwrap();
        let name = format!("/factory/{DEPLOYMENT}/tenants/{}/model-key", t.tenant_id);
        sqlx::query("INSERT INTO repository_credentials (tenant_id, repository, installation_id, repository_id, model_key_parameter) VALUES ($1, 'owner/repo', 11, 22, $2)")
            .bind(t.tenant_id).bind(&name).execute(&pool).await.unwrap();
        cloud.set_source_secret(&name, &"\"".repeat(2048));
        r.with_github(FakeGithub).tick().await.unwrap();
        assert!(cloud.scripts().is_empty());
        assert!(cloud.list_task_secrets().await.unwrap().is_empty());
        let failed = task(&pool, t.id).await;
        assert!(failed.agent_command_id.is_none());
        assert_eq!(failed.state, TaskState::Failed);
        assert_eq!(
            failed.failure_reason.as_deref(),
            Some("task credentials exceed the 4096-byte limit")
        );
        // A second tick does not try to mint or dispatch for a terminal task.
        reconciler(&pool, &cloud).tick().await.unwrap();
        assert!(cloud.scripts().is_empty());
    }
    #[sqlx::test]
    async fn secret_sweep_reads_live_tasks_after_a_concurrent_put(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let (entered, resume) = cloud.pause_next_secret_list();
        let tick = tokio::spawn(async move { r.tick().await });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        let t = queued_task(&pool).await;
        let secret = cloud
            .put_task_secret(
                t.tenant_id,
                t.id,
                "i-1234567890abcdef0",
                "concurrent bundle",
            )
            .await
            .unwrap();
        resume.notify_one();
        tokio::time::timeout(Duration::from_secs(5), tick)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            cloud
                .list_task_secrets()
                .await
                .unwrap()
                .iter()
                .any(|s| s.name == secret.name)
        );
    }
    struct UninstalledGithub;
    impl RepositoryTokenIssuer for UninstalledGithub {
        async fn mint_repository_token(&self, _: u64, _: u64) -> anyhow::Result<InstallationToken> {
            Err(crate::github::GitHubConfigurationError { status: 404 }.into())
        }
    }

    #[sqlx::test]
    async fn permanent_github_scope_errors_fail_task_and_terminate_vm(pool: PgPool) {
        let cloud = Arc::new(FakeCloud::default());
        let r = reconciler(&pool, &cloud);
        let t = running_without_agent(&pool, &r, &cloud).await;
        sqlx::query("UPDATE tasks SET repo_url = 'https://github.com/owner/repo' WHERE id = $1")
            .bind(t.id)
            .execute(&pool)
            .await
            .unwrap();
        let name = format!("/factory/{DEPLOYMENT}/tenants/{}/model-key", t.tenant_id);
        sqlx::query("INSERT INTO repository_credentials (tenant_id, repository, installation_id, repository_id, model_key_parameter) VALUES ($1, 'owner/repo', 11, 22, $2)")
            .bind(t.tenant_id).bind(&name).execute(&pool).await.unwrap();
        cloud.set_source_secret(&name, "synthetic-model-key");
        r.with_github(UninstalledGithub).tick().await.unwrap();
        let failed = task(&pool, t.id).await;
        assert_eq!(failed.state, TaskState::Failed);
        assert_eq!(
            failed.failure_reason.as_deref(),
            Some("GitHub repository installation is not configured (HTTP 404)")
        );
        assert!(cloud.scripts().is_empty());
        assert!(cloud.list_task_secrets().await.unwrap().is_empty());
        assert!(cloud.alive().is_empty());
    }
}
