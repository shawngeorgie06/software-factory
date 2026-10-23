-- Bearer keys for the tenant task API. Only the sha256 of each key is stored.
CREATE TABLE api_keys (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL,
    name         text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    key_hash     bytea       NOT NULL UNIQUE CHECK (octet_length(key_hash) = 32),
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);

CREATE INDEX api_keys_tenant_id_idx ON api_keys (tenant_id);

-- A client-chosen key makes task submission safe to retry.
ALTER TABLE tasks
    ADD COLUMN idempotency_key text
        CONSTRAINT tasks_idempotency_key_size CHECK (char_length(idempotency_key) BETWEEN 1 AND 255);

CREATE UNIQUE INDEX tasks_tenant_idempotency_key_idx ON tasks (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Newest-first listing per tenant.
CREATE INDEX tasks_tenant_created_idx ON tasks (tenant_id, created_at DESC, id DESC);
