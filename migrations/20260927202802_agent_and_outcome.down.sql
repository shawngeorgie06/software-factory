ALTER TABLE tasks
    DROP CONSTRAINT tasks_result_size,
    DROP COLUMN agent_command_id,
    DROP COLUMN heartbeat_token_hash,
    DROP COLUMN failure_reason,
    DROP COLUMN result,
    DROP COLUMN instructions,
    DROP COLUMN repo_url;
