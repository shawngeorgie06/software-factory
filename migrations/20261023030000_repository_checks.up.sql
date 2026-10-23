-- Existing bindings stay unconfigured for real coding tasks until an operator supplies checks.
ALTER TABLE repository_credentials ADD COLUMN check_command text[];
