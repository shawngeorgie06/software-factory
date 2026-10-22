CREATE TYPE task_state AS ENUM (
    'queued',
    'launching',
    'running',
    'verifying',
    'succeeded',
    'failed'
);

CREATE TABLE tasks (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid        NOT NULL,
    state          task_state  NOT NULL DEFAULT 'queued',
    -- One VM per task; a given EC2 instance can never belong to two tasks.
    vm_instance_id text        UNIQUE,
    heartbeat_at   timestamptz,
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tasks_expires_after_created CHECK (expires_at > created_at)
);

CREATE INDEX tasks_tenant_id_idx ON tasks (tenant_id);

-- The reconciler scans non-terminal tasks every tick.
CREATE INDEX tasks_live_state_idx ON tasks (state)
    WHERE state NOT IN ('succeeded', 'failed');

CREATE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tasks_set_updated_at
    BEFORE UPDATE ON tasks
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
