DROP INDEX tasks_tenant_created_idx;
DROP INDEX tasks_tenant_idempotency_key_idx;
ALTER TABLE tasks DROP COLUMN idempotency_key;
DROP TABLE api_keys;
