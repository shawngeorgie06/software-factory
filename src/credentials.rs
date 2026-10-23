//! Trusted tenant/repository bindings, separate from untrusted task instructions.
use std::future::Future;

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::Serialize;
#[cfg(test)]
use sqlx::PgPool;
use uuid::Uuid;

use crate::github::{GitHubApp, InstallationToken};

pub trait RepositoryTokenIssuer: Send + Sync {
    fn mint_repository_token(
        &self,
        installation_id: u64,
        repository_id: u64,
    ) -> impl Future<Output = anyhow::Result<InstallationToken>> + Send;
}

impl RepositoryTokenIssuer for GitHubApp {
    async fn mint_repository_token(
        &self,
        installation_id: u64,
        repository_id: u64,
    ) -> anyhow::Result<InstallationToken> {
        GitHubApp::mint_repository_token(self, installation_id, repository_id).await
    }
}

#[derive(sqlx::FromRow)]
pub struct RepositoryCredentials {
    pub installation_id: i64,
    pub repository_id: i64,
    pub model_key_parameter: String,
}

/// Only explicit HTTPS github.com owner/repo URLs are credential eligible.
/// Canonicalization prevents credentialed requests being redirected to another host.
pub fn repository_name(url: &str) -> anyhow::Result<String> {
    let path = url
        .strip_prefix("https://github.com/")
        .context("credentialed repository must use https://github.com/owner/repo")?;
    let path = path.strip_suffix(".git").unwrap_or(path);
    let parts: Vec<_> = path.split('/').collect();
    anyhow::ensure!(
        parts.len() == 2
            && parts.iter().all(|part| {
                !part.is_empty()
                    && *part != "."
                    && *part != ".."
                    && part.len() <= 100
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            }),
        "repository must identify one GitHub owner/repo without a query or fragment"
    );
    Ok(path.to_ascii_lowercase())
}

#[derive(Debug)]
pub struct RepositoryConfigurationError(pub &'static str);
impl std::fmt::Display for RepositoryConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for RepositoryConfigurationError {}

pub async fn for_task<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    tenant_id: Uuid,
    repo_url: &str,
) -> anyhow::Result<RepositoryCredentials> {
    let repository = repository_name(repo_url)
        .map_err(|_| RepositoryConfigurationError("invalid repository URL"))?;
    sqlx::query_as!(RepositoryCredentials,
        "SELECT installation_id, repository_id, model_key_parameter FROM repository_credentials WHERE tenant_id = $1 AND repository = $2",
        tenant_id, repository
    ).fetch_optional(executor).await
        .context("reading tenant repository credential binding")?
        .ok_or_else(|| RepositoryConfigurationError("repository not configured for tenant").into())
}

/// Values exist only in memory and encrypted Parameter Store, never task rows or scripts.
#[derive(Serialize)]
pub struct TaskCredentials<'a> {
    pub callback_token: &'a str,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_api_key: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repository_credentials_only_match_an_exact_github_repository() {
        assert_eq!(
            repository_name("https://github.com/Owner/Repo.git").unwrap(),
            "owner/repo"
        );
        for bad in [
            "http://github.com/a/b",
            "https://github.com.evil/a/b",
            "https://github.com/a/b?x",
            "https://github.com/a/b/",
            "https://github.com/a/..",
            "https://github.com/a/%62",
            "git@github.com:a/b",
            "https://github.com/a/b#x",
        ] {
            assert!(repository_name(bad).is_err(), "{bad}");
        }
    }

    #[sqlx::test]
    async fn repository_bindings_are_tenant_scoped(pool: PgPool) {
        let tenant = Uuid::new_v4();
        sqlx::query("INSERT INTO repository_credentials (tenant_id, repository, installation_id, repository_id, model_key_parameter) VALUES ($1, 'owner/repo', 11, 22, $2)")
            .bind(tenant).bind(format!("/factory/dev/tenants/{tenant}/model-key")).execute(&pool).await.unwrap();
        assert_eq!(
            for_task(&pool, tenant, "https://github.com/owner/repo.git")
                .await
                .unwrap()
                .repository_id,
            22
        );
        assert!(
            for_task(&pool, Uuid::new_v4(), "https://github.com/owner/repo")
                .await
                .is_err()
        );
        assert!(
            for_task(&pool, tenant, "https://github.com/owner/other")
                .await
                .is_err()
        );
    }
}
