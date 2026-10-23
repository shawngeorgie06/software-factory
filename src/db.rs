use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Advisory lock serialising [`claim_queued`] across processes. Arbitrary but fixed.
const CLAIM_LOCK_KEY: i64 = 0x6661_6374_6f72_7931; // "factory1"

/// Mirrors the Postgres `task_state` enum. Variant names map to the lowercase labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(type_name = "task_state", rename_all = "lowercase")]
pub enum TaskState {
    Queued,
    Launching,
    Running,
    /// Reserved for checking an agent's result before accepting it. Nothing enters it yet:
    /// a reported result currently goes straight to `Succeeded`.
    Verifying,
    Succeeded,
    Failed,
}

impl TaskState {
    pub const ALL: [TaskState; 6] = [
        TaskState::Queued,
        TaskState::Launching,
        TaskState::Running,
        TaskState::Verifying,
        TaskState::Succeeded,
        TaskState::Failed,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub state: TaskState,
    pub vm_instance_id: Option<String>,
    pub heartbeat_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub repo_url: String,
    pub instructions: String,
    /// What the agent reported on success.
    pub result: Option<String>,
    /// Why the orchestrator failed the task.
    pub failure_reason: Option<String>,
    /// SSM command that started the agent; `None` until sent.
    pub agent_command_id: Option<String>,
}

pub struct NewTask<'a> {
    pub tenant_id: Uuid,
    pub repo_url: &'a str,
    pub instructions: &'a str,
    pub expires_at: DateTime<Utc>,
}

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!()
        .run(pool)
        .await
        .context("running database migrations")
}

/// Inserts a new task in the `queued` state.
pub async fn create_task(pool: &PgPool, new: &NewTask<'_>) -> anyhow::Result<Task> {
    sqlx::query_as!(
        Task,
        r#"
        INSERT INTO tasks (tenant_id, repo_url, instructions, expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id, tenant_id, state AS "state: TaskState", vm_instance_id,
                  heartbeat_at, expires_at, created_at, updated_at,
                  repo_url, instructions, result, failure_reason, agent_command_id
        "#,
        new.tenant_id,
        new.repo_url,
        new.instructions,
        new.expires_at,
    )
    .fetch_one(pool)
    .await
    .context("inserting task")
}

/// Fetches a task, scoped to its tenant. A task belonging to another tenant is `None`.
pub async fn get_task(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> anyhow::Result<Option<Task>> {
    sqlx::query_as!(
        Task,
        r#"
        SELECT id, tenant_id, state AS "state: TaskState", vm_instance_id,
               heartbeat_at, expires_at, created_at, updated_at,
               repo_url, instructions, result, failure_reason, agent_command_id
        FROM tasks
        WHERE tenant_id = $1 AND id = $2
        "#,
        tenant_id,
        id,
    )
    .fetch_optional(pool)
    .await
    .context("fetching task")
}

/// Marks every non-terminal task whose `expires_at` has passed as failed.
pub async fn fail_expired(pool: &PgPool) -> anyhow::Result<Vec<Task>> {
    sqlx::query_as!(
        Task,
        r#"
        UPDATE tasks
        SET state = 'failed', failure_reason = 'expired while ' || state::text
        WHERE state NOT IN ('succeeded', 'failed') AND expires_at <= now()
        RETURNING id, tenant_id, state AS "state: TaskState", vm_instance_id,
                  heartbeat_at, expires_at, created_at, updated_at,
                  repo_url, instructions, result, failure_reason, agent_command_id
        "#,
    )
    .fetch_all(pool)
    .await
    .context("failing expired tasks")
}

/// Marks tasks that own (or are acquiring) a VM as failed when their last heartbeat is older
/// than `timeout`. `heartbeat_at` is set when a task is claimed, so launch gets the same grace.
pub async fn fail_stale_heartbeats(
    pool: &PgPool,
    timeout: std::time::Duration,
) -> anyhow::Result<Vec<Task>> {
    sqlx::query_as!(
        Task,
        r#"
        UPDATE tasks
        SET state = 'failed', failure_reason = 'no heartbeat while ' || state::text
        WHERE state IN ('launching', 'running', 'verifying')
          AND COALESCE(heartbeat_at, created_at) < now() - make_interval(secs => $1)
        RETURNING id, tenant_id, state AS "state: TaskState", vm_instance_id,
                  heartbeat_at, expires_at, created_at, updated_at,
                  repo_url, instructions, result, failure_reason, agent_command_id
        "#,
        timeout.as_secs_f64(),
    )
    .fetch_all(pool)
    .await
    .context("failing tasks with stale heartbeats")
}

/// Moves up to `limit` queued tasks (oldest first) to `launching`, starting the heartbeat
/// clock, without taking any tenant past `max_active_per_tenant` launching/running/verifying
/// tasks. The rest stay queued for a later tick.
pub async fn claim_queued(
    pool: &PgPool,
    limit: i64,
    max_active_per_tenant: i64,
) -> anyhow::Result<Vec<Task>> {
    let mut tx = pool.begin().await.context("starting claim transaction")?;
    // Counting a tenant's active tasks and claiming more is check-then-act, so claimers
    // (e.g. two reconcilers) take turns. Released at commit; claims are a single quick UPDATE.
    sqlx::query!("SELECT pg_advisory_xact_lock($1)", CLAIM_LOCK_KEY)
        .execute(&mut *tx)
        .await
        .context("taking claim lock")?;
    let claimed = sqlx::query_as!(
        Task,
        r#"
        WITH active AS (
            SELECT tenant_id, count(*) AS n
            FROM tasks
            WHERE state IN ('launching', 'running', 'verifying')
            GROUP BY tenant_id
        ),
        queued AS (
            SELECT id, tenant_id, created_at,
                   row_number() OVER (PARTITION BY tenant_id ORDER BY created_at, id) AS position
            FROM tasks
            WHERE state = 'queued' AND expires_at > now()
        ),
        picked AS (
            SELECT q.id
            FROM queued q LEFT JOIN active a USING (tenant_id)
            WHERE q.position + COALESCE(a.n, 0) <= $2
            ORDER BY q.created_at, q.id
            LIMIT $1
        )
        UPDATE tasks
        SET state = 'launching', heartbeat_at = now()
        FROM picked
        WHERE tasks.id = picked.id AND tasks.state = 'queued'
        RETURNING tasks.id, tasks.tenant_id, tasks.state AS "state: TaskState",
                  tasks.vm_instance_id, tasks.heartbeat_at, tasks.expires_at,
                  tasks.created_at, tasks.updated_at, tasks.repo_url, tasks.instructions,
                  tasks.result, tasks.failure_reason, tasks.agent_command_id
        "#,
        limit,
        max_active_per_tenant,
    )
    .fetch_all(&mut *tx)
    .await
    .context("claiming queued tasks")?;
    tx.commit().await.context("committing claims")?;
    Ok(claimed)
}

/// Non-terminal, unexpired tasks across all tenants. These are the only tasks allowed a VM.
pub async fn list_live_tasks(pool: &PgPool) -> anyhow::Result<Vec<Task>> {
    sqlx::query_as!(
        Task,
        r#"
        SELECT id, tenant_id, state AS "state: TaskState", vm_instance_id,
               heartbeat_at, expires_at, created_at, updated_at,
               repo_url, instructions, result, failure_reason, agent_command_id
        FROM tasks
        WHERE state NOT IN ('succeeded', 'failed') AND expires_at > now()
        ORDER BY created_at
        "#,
    )
    .fetch_all(pool)
    .await
    .context("listing live tasks")
}

/// Records the VM for a launching task. Returns false if the task was no longer eligible.
pub async fn record_vm_instance(
    pool: &PgPool,
    id: Uuid,
    instance_id: &str,
) -> anyhow::Result<bool> {
    let result = sqlx::query!(
        r#"
        UPDATE tasks
        SET vm_instance_id = $2
        WHERE id = $1 AND state = 'launching' AND vm_instance_id IS NULL
        "#,
        id,
        instance_id,
    )
    .execute(pool)
    .await
    .context("recording VM instance")?;
    Ok(result.rows_affected() == 1)
}

/// `launching` -> `running` once the task's VM is up, restarting the heartbeat clock so the
/// VM gets a full timeout to register with SSM and start the agent. Returns false if the task
/// was no longer eligible.
pub async fn mark_running(pool: &PgPool, id: Uuid) -> anyhow::Result<bool> {
    let result = sqlx::query!(
        r#"
        UPDATE tasks
        SET state = 'running', heartbeat_at = now()
        WHERE id = $1 AND state = 'launching' AND vm_instance_id IS NOT NULL
        "#,
        id,
    )
    .execute(pool)
    .await
    .context("marking task running")?;
    Ok(result.rows_affected() == 1)
}

/// Records a permanent credential configuration failure while the caller holds the task lock.
pub async fn fail_agent_start<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    id: Uuid,
    reason: &str,
) -> anyhow::Result<()> {
    sqlx::query!("UPDATE tasks SET state = 'failed', failure_reason = $2, heartbeat_token_hash = NULL WHERE id = $1 AND state = 'running' AND agent_command_id IS NULL", id, reason)
        .execute(executor).await.context("recording agent configuration failure")?;
    Ok(())
}

/// Sets the token the agent will authenticate with, replacing any earlier one, before the
/// agent command is sent. Only its sha256 is stored. Returns false if the task is no longer
/// running, its agent has already been started, or another transaction holds the task
/// (someone else is starting its agent).
///
/// Run it, the send, and [`record_agent_command`] in one transaction: the row lock taken
/// here then keeps other reconcilers out until the command is recorded or abandoned.
pub async fn set_agent_token<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    id: Uuid,
    token: &str,
) -> anyhow::Result<bool> {
    let result = sqlx::query!(
        r#"
        UPDATE tasks
        SET heartbeat_token_hash = sha256(convert_to($2, 'UTF8'))
        WHERE id = (
            SELECT id FROM tasks
            WHERE id = $1 AND state = 'running' AND agent_command_id IS NULL
            FOR UPDATE SKIP LOCKED
        )
        "#,
        id,
        token,
    )
    .execute(executor)
    .await
    .context("setting agent token")?;
    Ok(result.rows_affected() == 1)
}

/// Records the SSM command that started the task's agent. Returns false if the task is no
/// longer running or another reconciler already recorded one.
pub async fn record_agent_command<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    id: Uuid,
    command_id: &str,
) -> anyhow::Result<bool> {
    let result = sqlx::query!(
        r#"
        UPDATE tasks
        SET agent_command_id = $2
        WHERE id = $1 AND state = 'running' AND agent_command_id IS NULL
        "#,
        id,
        command_id,
    )
    .execute(executor)
    .await
    .context("recording agent command")?;
    Ok(result.rows_affected() == 1)
}

/// Records a heartbeat from the task's agent. Returns false unless `token` is the task's
/// current token and the task is still running and unexpired.
pub async fn record_heartbeat(pool: &PgPool, id: Uuid, token: &str) -> anyhow::Result<bool> {
    let result = sqlx::query!(
        r#"
        UPDATE tasks
        SET heartbeat_at = now()
        WHERE id = $1
          AND heartbeat_token_hash = sha256(convert_to($2, 'UTF8'))
          AND state IN ('running', 'verifying')
          AND expires_at > now()
        "#,
        id,
        token,
    )
    .execute(pool)
    .await
    .context("recording heartbeat")?;
    Ok(result.rows_affected() == 1)
}

/// Marks the task succeeded with the agent's result, under the same conditions as
/// [`record_heartbeat`]. The reconciler then terminates its VM.
pub async fn record_result(
    pool: &PgPool,
    id: Uuid,
    token: &str,
    result: &str,
) -> anyhow::Result<bool> {
    let outcome = sqlx::query!(
        r#"
        UPDATE tasks
        SET state = 'succeeded', result = $3, heartbeat_at = now()
        WHERE id = $1
          AND heartbeat_token_hash = sha256(convert_to($2, 'UTF8'))
          AND state IN ('running', 'verifying')
          AND expires_at > now()
        "#,
        id,
        token,
        result,
    )
    .execute(pool)
    .await
    .context("recording result")?;
    Ok(outcome.rows_affected() == 1)
}

/// Creates a task with placeholder input, for tests that only care about scheduling.
#[cfg(test)]
pub async fn create_test_task(
    pool: &PgPool,
    tenant_id: Uuid,
    expires_at: DateTime<Utc>,
) -> anyhow::Result<Task> {
    create_task(
        pool,
        &NewTask {
            tenant_id,
            repo_url: "https://github.com/example/repo",
            instructions: "say hello",
            expires_at,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn in_one_hour() -> DateTime<Utc> {
        Utc::now() + Duration::hours(1)
    }

    #[sqlx::test]
    async fn new_task_is_queued_with_no_vm(pool: PgPool) {
        let tenant = Uuid::new_v4();
        let expires_at = in_one_hour();

        let task = create_test_task(&pool, tenant, expires_at).await.unwrap();

        assert_eq!(task.tenant_id, tenant);
        assert_eq!(task.state, TaskState::Queued);
        assert_eq!(task.vm_instance_id, None);
        assert_eq!(task.heartbeat_at, None);
        // Postgres stores microseconds; compare at that precision.
        assert_eq!(
            task.expires_at.timestamp_micros(),
            expires_at.timestamp_micros()
        );
        assert_eq!(get_task(&pool, tenant, task.id).await.unwrap(), Some(task));
    }

    async fn states(pool: &PgPool, tenant: Uuid) -> Vec<TaskState> {
        sqlx::query_scalar!(
            r#"SELECT state AS "state: TaskState" FROM tasks WHERE tenant_id = $1 ORDER BY created_at"#,
            tenant
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    async fn claim_respects_per_tenant_active_cap(pool: PgPool) {
        let (busy, idle) = (Uuid::new_v4(), Uuid::new_v4());
        let running = create_test_task(&pool, busy, in_one_hour()).await.unwrap();
        sqlx::query!(
            "UPDATE tasks SET state = 'running' WHERE id = $1",
            running.id
        )
        .execute(&pool)
        .await
        .unwrap();
        for tenant in [busy, busy, busy, idle, idle] {
            create_test_task(&pool, tenant, in_one_hour())
                .await
                .unwrap();
        }

        let claimed = claim_queued(&pool, 10, 2).await.unwrap();

        assert_eq!(
            claimed.len(),
            3,
            "one more for the busy tenant, two for the idle one"
        );
        use TaskState::*;
        assert_eq!(
            states(&pool, busy).await,
            [Running, Launching, Queued, Queued]
        );
        assert_eq!(states(&pool, idle).await, [Launching, Launching]);

        assert!(
            claim_queued(&pool, 10, 2).await.unwrap().is_empty(),
            "both tenants at the cap"
        );
    }

    #[sqlx::test]
    async fn claim_fills_cap_oldest_first_and_honours_limit(pool: PgPool) {
        let tenant = Uuid::new_v4();
        let mut ids = Vec::new();
        for _ in 0..4 {
            ids.push(
                create_test_task(&pool, tenant, in_one_hour())
                    .await
                    .unwrap()
                    .id,
            );
        }

        let first = claim_queued(&pool, 1, 3).await.unwrap();
        let second = claim_queued(&pool, 10, 3).await.unwrap();

        assert_eq!(first.iter().map(|t| t.id).collect::<Vec<_>>(), ids[..1]);
        assert_eq!(second.iter().map(|t| t.id).collect::<Vec<_>>(), ids[1..3]);
    }

    /// Regression check only: racing claimers read the same queue and pick the same rows, so
    /// this passes even without the advisory lock. The lock covers rarer interleavings (e.g. a
    /// task expiring between two claimers' snapshots) that can't be staged deterministically.
    #[sqlx::test]
    async fn concurrent_claims_do_not_exceed_the_cap(pool: PgPool) {
        let tenant = Uuid::new_v4();
        for _ in 0..6 {
            create_test_task(&pool, tenant, in_one_hour())
                .await
                .unwrap();
        }

        let (a, b, c) = tokio::join!(
            claim_queued(&pool, 10, 1),
            claim_queued(&pool, 10, 1),
            claim_queued(&pool, 10, 1),
        );

        let total = a.unwrap().len() + b.unwrap().len() + c.unwrap().len();
        assert_eq!(total, 1);
    }

    #[sqlx::test]
    async fn new_task_stores_its_input(pool: PgPool) {
        let new = NewTask {
            tenant_id: Uuid::new_v4(),
            repo_url: "https://github.com/acme/app",
            instructions: "add a /health route",
            expires_at: in_one_hour(),
        };

        let task = create_task(&pool, &new).await.unwrap();

        assert_eq!(task.repo_url, new.repo_url);
        assert_eq!(task.instructions, new.instructions);
        assert_eq!(
            (task.result, task.failure_reason, task.agent_command_id),
            (None, None, None)
        );
    }

    /// A task with a VM that has just been marked running, as the reconciler leaves it.
    async fn running_task(pool: &PgPool) -> Task {
        let task = create_test_task(pool, Uuid::new_v4(), in_one_hour())
            .await
            .unwrap();
        sqlx::query!(
            "UPDATE tasks SET state = 'launching', vm_instance_id = $2 WHERE id = $1",
            task.id,
            format!("i-{}", task.id.simple())
        )
        .execute(pool)
        .await
        .unwrap();
        assert!(mark_running(pool, task.id).await.unwrap());
        get_task(pool, task.tenant_id, task.id)
            .await
            .unwrap()
            .unwrap()
    }

    #[sqlx::test]
    async fn mark_running_restarts_the_heartbeat_clock(pool: PgPool) {
        let task = create_test_task(&pool, Uuid::new_v4(), in_one_hour())
            .await
            .unwrap();
        sqlx::query!(
            "UPDATE tasks SET state = 'launching', vm_instance_id = 'i-1', \
             heartbeat_at = now() - interval '1 hour' WHERE id = $1",
            task.id
        )
        .execute(&pool)
        .await
        .unwrap();

        assert!(mark_running(&pool, task.id).await.unwrap());

        let task = get_task(&pool, task.tenant_id, task.id)
            .await
            .unwrap()
            .unwrap();
        assert!(task.heartbeat_at.unwrap() > Utc::now() - Duration::minutes(1));
    }

    #[sqlx::test]
    async fn agent_reports_need_the_current_token_of_that_task(pool: PgPool) {
        let task = running_task(&pool).await;
        let other = running_task(&pool).await;
        assert!(set_agent_token(&pool, task.id, "old").await.unwrap());
        assert!(
            set_agent_token(&pool, task.id, "tok").await.unwrap(),
            "re-sending rotates it"
        );
        assert!(set_agent_token(&pool, other.id, "other-tok").await.unwrap());

        assert!(!record_heartbeat(&pool, task.id, "old").await.unwrap());
        assert!(!record_heartbeat(&pool, task.id, "other-tok").await.unwrap());
        assert!(!record_heartbeat(&pool, task.id, "").await.unwrap());
        assert!(
            !record_heartbeat(&pool, Uuid::new_v4(), "tok")
                .await
                .unwrap()
        );
        assert!(
            !record_result(&pool, task.id, "other-tok", "x")
                .await
                .unwrap()
        );
        assert!(record_heartbeat(&pool, task.id, "tok").await.unwrap());

        assert!(record_result(&pool, task.id, "tok", "hello").await.unwrap());
        let done = get_task(&pool, task.tenant_id, task.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(done.state, TaskState::Succeeded);
        assert_eq!(done.result.as_deref(), Some("hello"));

        assert!(
            !record_heartbeat(&pool, task.id, "tok").await.unwrap(),
            "task is finished"
        );
        assert!(!record_result(&pool, task.id, "tok", "again").await.unwrap());
    }

    #[sqlx::test]
    async fn token_without_a_hash_set_matches_nothing(pool: PgPool) {
        let task = running_task(&pool).await;
        assert!(!record_heartbeat(&pool, task.id, "anything").await.unwrap());
    }

    #[sqlx::test]
    async fn expired_task_rejects_reports(pool: PgPool) {
        let task = running_task(&pool).await;
        assert!(set_agent_token(&pool, task.id, "tok").await.unwrap());
        sqlx::query!(
            "UPDATE tasks SET created_at = now() - interval '2 hours', \
             expires_at = now() - interval '1 second' WHERE id = $1",
            task.id
        )
        .execute(&pool)
        .await
        .unwrap();

        assert!(!record_heartbeat(&pool, task.id, "tok").await.unwrap());
        assert!(!record_result(&pool, task.id, "tok", "late").await.unwrap());
    }

    #[sqlx::test]
    async fn agent_command_is_recorded_once_and_freezes_the_token(pool: PgPool) {
        let task = running_task(&pool).await;
        assert!(set_agent_token(&pool, task.id, "tok").await.unwrap());

        assert!(record_agent_command(&pool, task.id, "cmd-1").await.unwrap());
        assert!(!record_agent_command(&pool, task.id, "cmd-2").await.unwrap());
        assert!(!set_agent_token(&pool, task.id, "new").await.unwrap());

        let task = get_task(&pool, task.tenant_id, task.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(task.agent_command_id.as_deref(), Some("cmd-1"));
        assert!(record_heartbeat(&pool, task.id, "tok").await.unwrap());
    }

    #[sqlx::test]
    async fn agent_token_is_only_set_on_running_tasks(pool: PgPool) {
        let queued = create_test_task(&pool, Uuid::new_v4(), in_one_hour())
            .await
            .unwrap();
        assert!(!set_agent_token(&pool, queued.id, "tok").await.unwrap());
        assert!(!record_agent_command(&pool, queued.id, "cmd").await.unwrap());
    }

    #[sqlx::test]
    async fn oversized_result_is_rejected(pool: PgPool) {
        let task = running_task(&pool).await;
        assert!(set_agent_token(&pool, task.id, "tok").await.unwrap());

        let err = record_result(&pool, task.id, "tok", &"x".repeat(65537))
            .await
            .unwrap_err();

        let db_err = err
            .downcast_ref::<sqlx::Error>()
            .unwrap()
            .as_database_error();
        assert_eq!(db_err.and_then(|e| e.code()).as_deref(), Some("23514"));
    }

    #[sqlx::test]
    async fn failures_record_a_reason(pool: PgPool) {
        let expired = running_task(&pool).await;
        sqlx::query!(
            "UPDATE tasks SET created_at = now() - interval '2 hours', \
             expires_at = now() - interval '1 second' WHERE id = $1",
            expired.id
        )
        .execute(&pool)
        .await
        .unwrap();
        let stale = running_task(&pool).await;
        sqlx::query!(
            "UPDATE tasks SET heartbeat_at = now() - interval '1 hour' WHERE id = $1",
            stale.id
        )
        .execute(&pool)
        .await
        .unwrap();

        let expired = &fail_expired(&pool).await.unwrap()[0];
        let stale = &fail_stale_heartbeats(&pool, std::time::Duration::from_secs(60))
            .await
            .unwrap()[0];

        assert_eq!(
            expired.failure_reason.as_deref(),
            Some("expired while running")
        );
        assert_eq!(
            stale.failure_reason.as_deref(),
            Some("no heartbeat while running")
        );
    }

    #[sqlx::test]
    async fn get_task_is_tenant_scoped(pool: PgPool) {
        let task = create_test_task(&pool, Uuid::new_v4(), in_one_hour())
            .await
            .unwrap();

        let other_tenant = get_task(&pool, Uuid::new_v4(), task.id).await.unwrap();

        assert_eq!(other_tenant, None);
    }

    #[sqlx::test]
    async fn rust_enum_matches_postgres_enum_labels(pool: PgPool) {
        let pg_labels: Vec<String> =
            sqlx::query_scalar("SELECT unnest(enum_range(NULL::task_state))::text")
                .fetch_all(&pool)
                .await
                .unwrap();

        let mut rust_labels = Vec::new();
        for state in TaskState::ALL {
            let label: String = sqlx::query_scalar("SELECT $1::task_state::text")
                .bind(state)
                .fetch_one(&pool)
                .await
                .unwrap();
            rust_labels.push(label);
        }

        assert_eq!(rust_labels, pg_labels);
    }

    #[sqlx::test]
    async fn every_state_round_trips_through_postgres(pool: PgPool) {
        let tenant = Uuid::new_v4();
        let task = create_test_task(&pool, tenant, in_one_hour())
            .await
            .unwrap();

        for state in TaskState::ALL {
            sqlx::query("UPDATE tasks SET state = $1 WHERE id = $2")
                .bind(state)
                .bind(task.id)
                .execute(&pool)
                .await
                .unwrap();

            let stored = get_task(&pool, tenant, task.id).await.unwrap().unwrap();
            assert_eq!(stored.state, state);
        }
    }

    #[sqlx::test]
    async fn update_bumps_updated_at(pool: PgPool) {
        let tenant = Uuid::new_v4();
        let task = create_test_task(&pool, tenant, in_one_hour())
            .await
            .unwrap();

        sqlx::query("UPDATE tasks SET heartbeat_at = now() WHERE id = $1")
            .bind(task.id)
            .execute(&pool)
            .await
            .unwrap();

        let updated = get_task(&pool, tenant, task.id).await.unwrap().unwrap();
        assert!(updated.updated_at > task.updated_at);
        assert_eq!(updated.created_at, task.created_at);
    }

    #[sqlx::test]
    async fn vm_instance_id_cannot_be_shared(pool: PgPool) {
        let a = create_test_task(&pool, Uuid::new_v4(), in_one_hour())
            .await
            .unwrap();
        let b = create_test_task(&pool, Uuid::new_v4(), in_one_hour())
            .await
            .unwrap();
        let set_vm = "UPDATE tasks SET vm_instance_id = 'i-0123456789abcdef0' WHERE id = $1";

        sqlx::query(set_vm).bind(a.id).execute(&pool).await.unwrap();
        let err = sqlx::query(set_vm)
            .bind(b.id)
            .execute(&pool)
            .await
            .unwrap_err();

        assert_eq!(pg_error_code(&err).as_deref(), Some(UNIQUE_VIOLATION));
    }

    #[sqlx::test]
    async fn task_cannot_be_created_already_expired(pool: PgPool) {
        let err = create_test_task(&pool, Uuid::new_v4(), Utc::now() - Duration::seconds(1))
            .await
            .unwrap_err();

        let sqlx_err = err.downcast_ref::<sqlx::Error>().unwrap();
        assert_eq!(pg_error_code(sqlx_err).as_deref(), Some(CHECK_VIOLATION));
    }

    const UNIQUE_VIOLATION: &str = "23505";
    const CHECK_VIOLATION: &str = "23514";

    fn pg_error_code(err: &sqlx::Error) -> Option<String> {
        err.as_database_error()
            .and_then(|e| e.code())
            .map(|c| c.into_owned())
    }
}
