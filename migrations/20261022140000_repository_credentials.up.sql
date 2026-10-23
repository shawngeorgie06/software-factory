-- Administrator-managed allowlist. Task inputs cannot choose installation IDs or key paths.
CREATE TABLE repository_credentials (
    tenant_id uuid NOT NULL,
    repository text NOT NULL CHECK (repository = lower(repository) AND repository ~ '^[a-z0-9_.-]+/[a-z0-9_.-]+$'),
    installation_id bigint NOT NULL CHECK (installation_id > 0),
    repository_id bigint NOT NULL CHECK (repository_id > 0),
    model_key_parameter text NOT NULL,
    PRIMARY KEY (tenant_id, repository)
);
