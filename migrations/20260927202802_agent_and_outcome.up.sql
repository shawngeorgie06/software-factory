-- Task input. The temporary defaults only backfill rows created before this migration.
ALTER TABLE tasks
    ADD COLUMN repo_url     text NOT NULL DEFAULT '',
    ADD COLUMN instructions text NOT NULL DEFAULT '';
ALTER TABLE tasks
    ALTER COLUMN repo_url DROP DEFAULT,
    ALTER COLUMN instructions DROP DEFAULT;

ALTER TABLE tasks
    -- What the agent reported, and why the orchestrator gave up on a task.
    ADD COLUMN result               text,
    ADD COLUMN failure_reason       text,
    -- sha256 of the bearer token the VM uses to report on this task. The token itself is
    -- never stored; it's rotated each time the agent command is (re)sent.
    ADD COLUMN heartbeat_token_hash bytea,
    -- SSM command that started the agent. NULL means it hasn't been sent yet.
    ADD COLUMN agent_command_id     text,
    ADD CONSTRAINT tasks_result_size CHECK (octet_length(result) <= 65536);
