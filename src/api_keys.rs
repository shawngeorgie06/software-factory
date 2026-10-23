//! Bearer keys tenants use to call the task API. A key is shown once when created; only its
//! sha256 is stored, so a database leak doesn't reveal working keys.

use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Prefix that makes leaked keys easy to recognise and scan for.
pub const KEY_PREFIX: &str = "sf_";

pub struct CreatedKey {
    pub id: Uuid,
    /// The only copy of the secret. Never logged or stored.
    pub key: String,
}

#[derive(Debug)]
pub struct KeyInfo {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Whether `key` has the shape of a key we issue, checked before touching the database.
pub fn well_formed(key: &str) -> bool {
    key.strip_prefix(KEY_PREFIX).is_some_and(|rest| {
        rest.len() == 64 && rest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

pub async fn create(pool: &PgPool, tenant_id: Uuid, name: &str) -> anyhow::Result<CreatedKey> {
    let name = name.trim();
    anyhow::ensure!(
        (1..=100).contains(&name.chars().count()) && !name.chars().any(char::is_control),
        "key name must be 1-100 printable characters"
    );
    let key = format!("{KEY_PREFIX}{}", crate::api::new_agent_token());
    let id = sqlx::query_scalar!(
        "INSERT INTO api_keys (tenant_id, name, key_hash)
         VALUES ($1, $2, sha256(convert_to($3, 'UTF8'))) RETURNING id",
        tenant_id,
        name,
        key,
    )
    .fetch_one(pool)
    .await
    .context("creating API key")?;
    Ok(CreatedKey { id, key })
}

pub async fn list(pool: &PgPool, tenant_id: Uuid) -> anyhow::Result<Vec<KeyInfo>> {
    sqlx::query_as!(
        KeyInfo,
        "SELECT id, tenant_id, name, created_at, last_used_at, revoked_at
         FROM api_keys WHERE tenant_id = $1 ORDER BY created_at, id",
        tenant_id,
    )
    .fetch_all(pool)
    .await
    .context("listing API keys")
}

/// Revokes a key immediately. Returns false if it doesn't exist or was already revoked.
pub async fn revoke(pool: &PgPool, id: Uuid) -> anyhow::Result<bool> {
    let result = sqlx::query!(
        "UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
        id
    )
    .execute(pool)
    .await
    .context("revoking API key")?;
    Ok(result.rows_affected() == 1)
}

/// The tenant an unrevoked key belongs to. Records use at most once a minute, so busy
/// clients don't turn every read into a write.
pub async fn authenticate(pool: &PgPool, key: &str) -> anyhow::Result<Option<Uuid>> {
    if !well_formed(key) {
        return Ok(None);
    }
    let Some(row) = sqlx::query!(
        "SELECT id, tenant_id, last_used_at FROM api_keys
         WHERE key_hash = sha256(convert_to($1, 'UTF8')) AND revoked_at IS NULL",
        key,
    )
    .fetch_optional(pool)
    .await
    .context("looking up API key")?
    else {
        return Ok(None);
    };
    if row
        .last_used_at
        .is_none_or(|used| used < Utc::now() - chrono::Duration::minutes(1))
    {
        sqlx::query!(
            "UPDATE api_keys SET last_used_at = now() WHERE id = $1",
            row.id
        )
        .execute(pool)
        .await
        .context("recording API key use")?;
    }
    Ok(Some(row.tenant_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_issued_shapes_are_well_formed() {
        let key = format!("{KEY_PREFIX}{}", "a1".repeat(32));
        assert!(well_formed(&key));
        assert!(!well_formed(&key[..key.len() - 1]));
        assert!(!well_formed(&key.to_uppercase()));
        assert!(!well_formed(&"a1".repeat(32)));
        assert!(!well_formed(""));
    }

    #[sqlx::test]
    async fn keys_authenticate_their_tenant_until_revoked(pool: PgPool) {
        let tenant = Uuid::new_v4();
        let created = create(&pool, tenant, " ci ").await.unwrap();
        assert!(well_formed(&created.key));
        assert_eq!(
            authenticate(&pool, &created.key).await.unwrap(),
            Some(tenant)
        );

        let keys = list(&pool, tenant).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "ci");
        assert!(keys[0].last_used_at.is_some(), "use is recorded");
        assert!(list(&pool, Uuid::new_v4()).await.unwrap().is_empty());

        let stored: Vec<u8> = sqlx::query_scalar("SELECT key_hash FROM api_keys")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_ne!(stored, created.key.as_bytes(), "only the hash is stored");

        assert!(revoke(&pool, created.id).await.unwrap());
        assert!(!revoke(&pool, created.id).await.unwrap());
        assert_eq!(authenticate(&pool, &created.key).await.unwrap(), None);
    }

    #[sqlx::test]
    async fn unknown_and_malformed_keys_are_rejected(pool: PgPool) {
        create(&pool, Uuid::new_v4(), "real").await.unwrap();
        let unknown = format!("{KEY_PREFIX}{}", "0".repeat(64));
        assert_eq!(authenticate(&pool, &unknown).await.unwrap(), None);
        assert_eq!(authenticate(&pool, "not-a-key").await.unwrap(), None);
    }

    #[sqlx::test]
    async fn names_must_be_printable(pool: PgPool) {
        let tenant = Uuid::new_v4();
        assert!(create(&pool, tenant, "  ").await.is_err());
        assert!(create(&pool, tenant, "bad\nname").await.is_err());
        assert!(create(&pool, tenant, &"x".repeat(101)).await.is_err());
    }
}
