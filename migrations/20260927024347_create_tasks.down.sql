DROP TRIGGER IF EXISTS tasks_set_updated_at ON tasks;
DROP FUNCTION IF EXISTS set_updated_at();
DROP TABLE IF EXISTS tasks;
DROP TYPE IF EXISTS task_state;
