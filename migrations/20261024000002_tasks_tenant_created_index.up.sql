-- no-transaction
-- Newest-first listing per tenant. Built concurrently; see the previous migration.
CREATE INDEX CONCURRENTLY tasks_tenant_created_idx ON tasks (tenant_id, created_at DESC, id DESC);
