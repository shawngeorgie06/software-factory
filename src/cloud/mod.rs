//! Every AWS call lives behind [`Cloud`]. Nothing outside this module touches the AWS SDK.

pub mod aws;
#[cfg(test)]
pub mod fake;
pub mod secrets;

use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

pub const TASK_ID_TAG: &str = "factory:task-id";
pub const TENANT_ID_TAG: &str = "factory:tenant-id";
/// Scopes everything a [`Cloud`] lists or cleans up to one orchestrator deployment, so two
/// deployments sharing an AWS account and region never terminate each other's instances.
pub const DEPLOYMENT_TAG: &str = "factory:deployment";

pub struct LaunchRequest {
    pub task_id: Uuid,
    pub tenant_id: Uuid,
    /// The instance powers itself off at this time even if the orchestrator is down.
    pub expires_at: DateTime<Utc>,
}

/// A shell script to run on one instance through SSM Run Command.
pub struct ScriptRequest<'a> {
    pub task_id: Uuid,
    pub instance_id: &'a str,
    /// POSIX sh.
    pub script: &'a str,
    /// The script is killed after this long.
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptStart {
    /// SSM accepted the command.
    Sent { command_id: String },
    /// SSM can't reach the instance yet (typically its agent hasn't registered). Try again later.
    NotReady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceState {
    Pending,
    Running,
    /// Stopping, stopped, or a state this code doesn't know. Still ours to terminate.
    Other,
}

/// A non-terminated instance carrying this deployment's tag. Tag values that are missing or
/// not UUIDs come back as `None`, which makes the instance an orphan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub id: String,
    pub state: InstanceState,
    pub task_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
}

impl Instance {
    pub fn from_tags<'a>(
        id: String,
        state: InstanceState,
        tags: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        let mut task_id = None;
        let mut tenant_id = None;
        for (key, value) in tags {
            match key {
                TASK_ID_TAG => task_id = Uuid::parse_str(value).ok(),
                TENANT_ID_TAG => tenant_id = Uuid::parse_str(value).ok(),
                _ => {}
            }
        }
        Instance {
            id,
            state,
            task_id,
            tenant_id,
        }
    }

    pub fn belongs_to(&self, task_id: Uuid, tenant_id: Uuid) -> bool {
        self.task_id == Some(task_id) && self.tenant_id == Some(tenant_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTaskSecret {
    pub name: String,
    pub tenant_id: Uuid,
    pub task_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct SecretReference {
    pub name: String,
    pub region: String,
}

#[derive(Debug)]
pub enum SecretConfigurationError {
    Missing,
    Invalid,
}
impl std::fmt::Display for SecretConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "configured secret does not exist",
            Self::Invalid => "configured secret is invalid",
        })
    }
}
impl std::error::Error for SecretConfigurationError {}

pub trait Cloud: Send + Sync {
    /// Read-only readiness check. A later send can still race with a VM going offline.
    fn script_ready(&self, instance_id: &str) -> impl Future<Output = anyhow::Result<bool>> + Send;
    fn read_secure(&self, name: &str) -> impl Future<Output = anyhow::Result<String>> + Send;
    fn put_task_secret(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
        instance_id: &str,
        value: &str,
    ) -> impl Future<Output = anyhow::Result<SecretReference>> + Send;
    fn list_task_secrets(
        &self,
    ) -> impl Future<Output = anyhow::Result<Vec<StoredTaskSecret>>> + Send;
    fn delete_task_secret(&self, name: &str) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Launches one instance tagged with this deployment and the task and tenant ids, and
    /// returns its id.
    /// Idempotent per task: repeating the call for the same task must not create a second VM.
    fn launch(
        &self,
        request: &LaunchRequest,
    ) -> impl Future<Output = anyhow::Result<String>> + Send;

    fn terminate(&self, instance_ids: &[String])
    -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Every non-terminated instance tagged with this deployment, including ones whose task
    /// tags are missing or malformed (orphans).
    fn list_tagged(&self) -> impl Future<Output = anyhow::Result<Vec<Instance>>> + Send;

    /// Starts a script on an instance via SSM Run Command, without waiting for it to finish.
    /// Not idempotent: each successful call starts another run.
    fn run_script(
        &self,
        request: &ScriptRequest<'_>,
    ) -> impl Future<Output = anyhow::Result<ScriptStart>> + Send;
}
