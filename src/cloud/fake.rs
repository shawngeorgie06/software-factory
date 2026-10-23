//! In-memory [`Cloud`] for tests. Mimics EC2's client-token idempotency.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use anyhow::bail;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{
    Cloud, DEPLOYMENT_TAG, Instance, InstanceState, LaunchRequest, ScriptRequest, ScriptStart,
    TASK_ID_TAG, TENANT_ID_TAG,
};

/// The deployment every `FakeCloud` belongs to.
pub const DEPLOYMENT: &str = "test-deployment";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeState {
    Pending,
    Running,
    Terminated,
}

#[derive(Debug, Clone)]
pub struct FakeInstance {
    pub state: FakeState,
    pub tags: BTreeMap<String, String>,
    /// When the instance's self-termination backstop fires; set only by `launch`.
    pub self_terminates_at: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct Inner {
    instances: BTreeMap<String, FakeInstance>,
    by_client_token: HashMap<String, String>,
    next_id: u64,
    launch_calls: usize,
    failing_launches: usize,
    fail_list: bool,
    refuse_termination: Vec<String>,
    hidden: HashMap<String, usize>,
    scripts: Vec<SentScript>,
    ssm_unreachable: Vec<String>,
    failing_scripts: usize,
    hang_after_next_send: Option<Arc<tokio::sync::Notify>>,
    secrets: BTreeMap<String, (super::StoredTaskSecret, String, String)>,
    source_secrets: BTreeMap<String, String>,
    fail_secret_write: bool,
    fail_secret_delete: bool,
    hang_secret_list: bool,
    disconnect_on_send: bool,
    secret_list_pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}

/// A script `run_script` accepted.
#[derive(Debug, Clone)]
pub struct SentScript {
    pub task_id: Uuid,
    pub instance_id: String,
    pub script: String,
    pub command_id: String,
}

#[derive(Default)]
pub struct FakeCloud {
    inner: Mutex<Inner>,
}

impl FakeCloud {
    pub fn pause_next_secret_list(&self) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let pair = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        self.with(|i| i.secret_list_pause = Some(pair.clone()));
        pair
    }
    pub fn hang_secret_list(&self) {
        self.with(|i| i.hang_secret_list = true);
    }
    pub fn disconnect_on_send(&self) {
        self.with(|i| i.disconnect_on_send = true);
    }

    pub fn set_source_secret(&self, name: &str, value: &str) {
        self.with(|inner| {
            inner.source_secrets.insert(name.into(), value.into());
        });
    }
    pub fn secret_value(&self, name: &str) -> String {
        self.with(|inner| inner.secrets.get(name).unwrap().1.clone())
    }
    pub fn secret_for_script(&self, script: &str) -> serde_json::Value {
        let line = script
            .lines()
            .find(|s| s.starts_with("parameter="))
            .unwrap();
        let name = line
            .strip_prefix("parameter='")
            .unwrap()
            .strip_suffix('\'')
            .unwrap();
        serde_json::from_str(&self.secret_value(name)).unwrap()
    }
    pub fn fail_secret_write(&self, fail: bool) {
        self.with(|i| i.fail_secret_write = fail);
    }
    pub fn fail_secret_delete(&self, fail: bool) {
        self.with(|i| i.fail_secret_delete = fail);
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        f(&mut self.inner.lock().unwrap())
    }

    /// Adds an instance with exactly these tags, bypassing `launch`. Without a
    /// [`DEPLOYMENT_TAG`] of [`DEPLOYMENT`] it belongs to someone else and is never listed.
    pub fn insert(&self, state: FakeState, tags: &[(&str, &str)]) -> String {
        self.with(|inner| {
            inner.next_id += 1;
            let id = format!("i-{:017x}", inner.next_id);
            let tags = tags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            inner.instances.insert(
                id.clone(),
                FakeInstance {
                    state,
                    tags,
                    self_terminates_at: None,
                },
            );
            id
        })
    }

    pub fn insert_for_task(&self, state: FakeState, task_id: Uuid, tenant_id: Uuid) -> String {
        self.insert(
            state,
            &[
                (DEPLOYMENT_TAG, DEPLOYMENT),
                (TASK_ID_TAG, &task_id.to_string()),
                (TENANT_ID_TAG, &tenant_id.to_string()),
            ],
        )
    }

    pub fn boot_all(&self) {
        self.with(|inner| {
            for i in inner.instances.values_mut() {
                if i.state == FakeState::Pending {
                    i.state = FakeState::Running;
                }
            }
        })
    }

    pub fn state(&self, id: &str) -> Option<FakeState> {
        self.with(|inner| inner.instances.get(id).map(|i| i.state))
    }

    pub fn instance(&self, id: &str) -> Option<FakeInstance> {
        self.with(|inner| inner.instances.get(id).cloned())
    }

    /// Ids of instances that are not terminated.
    pub fn alive(&self) -> Vec<String> {
        self.with(|inner| {
            inner
                .instances
                .iter()
                .filter(|(_, i)| i.state != FakeState::Terminated)
                .map(|(id, _)| id.clone())
                .collect()
        })
    }

    pub fn launch_calls(&self) -> usize {
        self.with(|inner| inner.launch_calls)
    }

    pub fn fail_next_launches(&self, n: usize) {
        self.with(|inner| inner.failing_launches = n)
    }

    /// Terminating this instance fails, and like EC2 fails the whole batch it's in.
    pub fn refuse_termination(&self, id: &str) {
        self.with(|inner| inner.refuse_termination.push(id.to_string()))
    }

    /// Leaves the instance out of the next `lists` listings (EC2 eventual consistency).
    pub fn hide_from_next_lists(&self, id: &str, lists: usize) {
        self.with(|inner| inner.hidden.insert(id.to_string(), lists));
    }

    pub fn fail_list(&self, fail: bool) {
        self.with(|inner| inner.fail_list = fail)
    }

    pub fn scripts(&self) -> Vec<SentScript> {
        self.with(|inner| inner.scripts.clone())
    }

    /// SSM reports the instance as not reachable (agent not registered) until `ssm_reachable`.
    pub fn ssm_unreachable(&self, id: &str) {
        self.with(|inner| inner.ssm_unreachable.push(id.to_string()))
    }

    pub fn ssm_reachable(&self, id: &str) {
        self.with(|inner| inner.ssm_unreachable.retain(|i| i != id))
    }

    pub fn fail_next_scripts(&self, n: usize) {
        self.with(|inner| inner.failing_scripts = n)
    }

    /// The next accepted script is recorded as sent, but `run_script` never returns, like
    /// an SSM response that is lost.
    pub fn hang_after_next_send(&self) -> Arc<tokio::sync::Notify> {
        let sent = Arc::new(tokio::sync::Notify::new());
        self.with(|inner| inner.hang_after_next_send = Some(Arc::clone(&sent)));
        sent
    }
}

impl Cloud for FakeCloud {
    async fn script_ready(&self, instance_id: &str) -> anyhow::Result<bool> {
        Ok(self.with(|i| {
            i.instances
                .get(instance_id)
                .is_some_and(|vm| vm.state == FakeState::Running)
                && !i.ssm_unreachable.iter().any(|id| id == instance_id)
        }))
    }

    async fn read_secure(&self, name: &str) -> anyhow::Result<String> {
        self.with(|i| i.source_secrets.get(name).cloned())
            .ok_or_else(|| super::SecretConfigurationError::Missing.into())
    }
    async fn put_task_secret(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
        instance_id: &str,
        value: &str,
    ) -> anyhow::Result<super::SecretReference> {
        self.with(|i| {
            anyhow::ensure!(!i.fail_secret_write, "injected secret write failure");
            anyhow::ensure!(value.len() <= 4096, "task secret exceeds 4096 bytes");
            anyhow::ensure!(
                instance_id
                    .strip_prefix("i-")
                    .is_some_and(|id| matches!(id.len(), 8 | 17)
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
                "invalid EC2 instance id"
            );
            let name = format!(
                "/factory/{DEPLOYMENT}/tasks/{tenant_id}/{task_id}/{}",
                Uuid::new_v4()
            );
            let record = super::StoredTaskSecret {
                name: name.clone(),
                tenant_id,
                task_id,
            };
            i.secrets
                .insert(name.clone(), (record, value.into(), instance_id.into()));
            Ok(super::SecretReference {
                name,
                region: "us-east-1".into(),
            })
        })
    }
    async fn list_task_secrets(&self) -> anyhow::Result<Vec<super::StoredTaskSecret>> {
        if self.with(|i| i.hang_secret_list) {
            std::future::pending::<()>().await;
        }
        if let Some((entered, resume)) = self.with(|i| i.secret_list_pause.take()) {
            entered.notify_one();
            resume.notified().await;
        }
        Ok(self.with(|i| i.secrets.values().map(|(s, _, _)| s.clone()).collect()))
    }
    async fn delete_task_secret(&self, name: &str) -> anyhow::Result<()> {
        self.with(|i| {
            anyhow::ensure!(!i.fail_secret_delete, "injected delete failure");
            i.secrets.remove(name);
            Ok(())
        })
    }

    async fn launch(&self, request: &LaunchRequest) -> anyhow::Result<String> {
        let token = request.task_id.to_string();
        let existing = self.with(|inner| {
            inner.launch_calls += 1;
            if inner.failing_launches > 0 {
                inner.failing_launches -= 1;
                return Err(anyhow::anyhow!("injected launch failure"));
            }
            Ok(inner.by_client_token.get(&token).cloned())
        })?;
        if let Some(id) = existing {
            return Ok(id);
        }
        let id = self.insert_for_task(FakeState::Pending, request.task_id, request.tenant_id);
        self.with(|inner| {
            inner.by_client_token.insert(token, id.clone());
            if let Some(i) = inner.instances.get_mut(&id) {
                i.self_terminates_at = Some(request.expires_at);
            }
        });
        Ok(id)
    }

    async fn terminate(&self, instance_ids: &[String]) -> anyhow::Result<()> {
        self.with(|inner| {
            // All-or-nothing, like EC2.
            for id in instance_ids {
                if !inner.instances.contains_key(id) || inner.refuse_termination.contains(id) {
                    bail!("cannot terminate {id}");
                }
            }
            for id in instance_ids {
                if let Some(i) = inner.instances.get_mut(id) {
                    i.state = FakeState::Terminated;
                }
            }
            Ok(())
        })
    }

    async fn list_tagged(&self) -> anyhow::Result<Vec<Instance>> {
        self.with(|inner| {
            if inner.fail_list {
                bail!("injected list failure");
            }
            let mut hidden = Vec::new();
            inner.hidden.retain(|id, remaining| {
                hidden.push(id.clone());
                *remaining -= 1;
                *remaining > 0
            });
            Ok(inner
                .instances
                .iter()
                .filter(|(id, _)| !hidden.contains(id))
                .filter(|(_, i)| {
                    i.state != FakeState::Terminated
                        && i.tags.get(DEPLOYMENT_TAG).map(String::as_str) == Some(DEPLOYMENT)
                })
                .map(|(id, i)| {
                    let state = match i.state {
                        FakeState::Pending => InstanceState::Pending,
                        FakeState::Running => InstanceState::Running,
                        FakeState::Terminated => InstanceState::Other,
                    };
                    let tags = i.tags.iter().map(|(k, v)| (k.as_str(), v.as_str()));
                    Instance::from_tags(id.clone(), state, tags)
                })
                .collect())
        })
    }

    async fn run_script(&self, request: &ScriptRequest<'_>) -> anyhow::Result<ScriptStart> {
        let (start, hang) = self.with(|inner| {
            if inner.failing_scripts > 0 {
                inner.failing_scripts -= 1;
                bail!("injected SendCommand failure");
            }
            if std::mem::take(&mut inner.disconnect_on_send) {
                return Ok((ScriptStart::NotReady, None));
            }
            let running = inner
                .instances
                .get(request.instance_id)
                .is_some_and(|i| i.state == FakeState::Running);
            if !running
                || inner
                    .ssm_unreachable
                    .iter()
                    .any(|i| i == request.instance_id)
            {
                return Ok((ScriptStart::NotReady, None));
            }
            let command_id = format!("cmd-{}", inner.scripts.len() + 1);
            inner.scripts.push(SentScript {
                task_id: request.task_id,
                instance_id: request.instance_id.to_string(),
                script: request.script.to_string(),
                command_id: command_id.clone(),
            });
            let hang = std::mem::take(&mut inner.hang_after_next_send);
            Ok((ScriptStart::Sent { command_id }, hang))
        })?;
        if let Some(sent) = hang {
            sent.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(start)
    }
}

/// Lets a test keep a handle on the fake while a reconciler owns it.
impl<C: Cloud> Cloud for Arc<C> {
    async fn script_ready(&self, instance_id: &str) -> anyhow::Result<bool> {
        C::script_ready(self, instance_id).await
    }

    async fn read_secure(&self, name: &str) -> anyhow::Result<String> {
        C::read_secure(self, name).await
    }
    async fn put_task_secret(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
        instance_id: &str,
        value: &str,
    ) -> anyhow::Result<super::SecretReference> {
        C::put_task_secret(self, tenant_id, task_id, instance_id, value).await
    }
    async fn list_task_secrets(&self) -> anyhow::Result<Vec<super::StoredTaskSecret>> {
        C::list_task_secrets(self).await
    }
    async fn delete_task_secret(&self, name: &str) -> anyhow::Result<()> {
        C::delete_task_secret(self, name).await
    }

    async fn launch(&self, request: &LaunchRequest) -> anyhow::Result<String> {
        C::launch(self, request).await
    }

    async fn terminate(&self, instance_ids: &[String]) -> anyhow::Result<()> {
        C::terminate(self, instance_ids).await
    }

    async fn list_tagged(&self) -> anyhow::Result<Vec<Instance>> {
        C::list_tagged(self).await
    }

    async fn run_script(&self, request: &ScriptRequest<'_>) -> anyhow::Result<ScriptStart> {
        C::run_script(self, request).await
    }
}
