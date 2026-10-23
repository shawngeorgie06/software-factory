-- no-transaction
-- Backstop for the advisory lock in submit_task. Built concurrently so task traffic keeps
-- flowing; Postgres runs a multi-statement file as one transaction, which CONCURRENTLY
-- refuses, so each index gets its own migration. If a build fails it leaves an INVALID
-- index: drop it and rerun.
CREATE UNIQUE INDEX CONCURRENTLY tasks_tenant_idempotency_key_idx ON tasks (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
