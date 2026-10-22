use anyhow::{Context, anyhow, bail, ensure};
use aws_sdk_ec2::Client;
use aws_sdk_ec2::error::DisplayErrorContext;
use aws_sdk_ec2::types::{
    Filter, HttpTokensState, IamInstanceProfileSpecification, InstanceMetadataOptionsRequest,
    InstanceStateName, InstanceType, ResourceType, ShutdownBehavior, Tag, TagSpecification,
};
use aws_sdk_ssm::operation::send_command::SendCommandError;

use chrono::{DateTime, Utc};

use super::{
    Cloud, DEPLOYMENT_TAG, Instance, InstanceState, LaunchRequest, ScriptRequest, ScriptStart,
    TASK_ID_TAG, TENANT_ID_TAG,
};

/// Conservative batch size for TerminateInstances.
const TERMINATE_BATCH: usize = 100;

#[derive(Debug, Clone)]
pub struct AwsCloudConfig {
    /// Value of the `factory:deployment` tag. Only instances carrying it are listed or
    /// terminated. Must be unique per orchestrator deployment within an account and region.
    pub deployment: String,
    pub ami_id: String,
    pub instance_type: String,
    pub subnet_id: String,
    /// Must have zero inbound rules; checked in [`AwsCloud::new`].
    pub security_group_id: String,
    /// Instance profile whose role allows SSM (e.g. AmazonSSMManagedInstanceCore).
    pub instance_profile_name: String,
    pub secrets_kms_key_arn: String,
}

pub struct AwsCloud {
    ec2: Client,
    ssm: aws_sdk_ssm::Client,
    config: AwsCloudConfig,
    parameters: super::secrets::ParameterStore,
    region: String,
}

impl AwsCloud {
    /// Loads credentials and region from the standard AWS environment and verifies the
    /// security group has no inbound rules. Refuses to start otherwise.
    pub async fn new(config: AwsCloudConfig) -> anyhow::Result<Self> {
        validate_deployment(&config.deployment)?;
        let sdk_config = aws_config::load_from_env().await;
        let ec2 = Client::new(&sdk_config);
        let ssm = aws_sdk_ssm::Client::new(&sdk_config);
        let region = sdk_config
            .region()
            .context("AWS region must be configured")?
            .as_ref()
            .to_owned();
        let parameters = super::secrets::ParameterStore::new(
            ssm.clone(),
            &config.deployment,
            &config.secrets_kms_key_arn,
            &region,
        )?;
        let cloud = AwsCloud {
            ec2,
            ssm,
            config,
            parameters,
            region,
        };
        cloud.verify_security_group().await?;
        Ok(cloud)
    }

    async fn verify_security_group(&self) -> anyhow::Result<()> {
        let group_id = &self.config.security_group_id;
        let output = self
            .ec2
            .describe_security_groups()
            .group_ids(group_id)
            .send()
            .await
            .map_err(|e| {
                anyhow!(
                    "describing security group {group_id}: {}",
                    DisplayErrorContext(e)
                )
            })?;
        let group = output
            .security_groups()
            .first()
            .with_context(|| format!("security group {group_id} not found"))?;
        if !group.ip_permissions().is_empty() {
            bail!(
                "security group {group_id} has {} inbound rule(s); it must have none",
                group.ip_permissions().len()
            );
        }
        Ok(())
    }
}

/// 1-64 characters from `[A-Za-z0-9._-]`: safe as a tag value and in a filter.
fn validate_deployment(deployment: &str) -> anyhow::Result<()> {
    ensure!(
        (1..=64).contains(&deployment.len())
            && deployment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "deployment id must be 1-64 characters of letters, digits, '.', '_' or '-', got {deployment:?}"
    );
    Ok(())
}

/// Where cloud-init looks for scripts to run on every boot.
const PER_BOOT_SCRIPT: &str = "/var/lib/cloud/scripts/per-boot/factory-ttl.sh";

/// Schedules a power-off at the task's `expires_at` (a Unix timestamp), rounded up to the
/// minute and immediately if it has passed. With shutdown behaviour set to terminate, that
/// terminates the instance. The time is absolute and computed on the VM, so the script is
/// the same on every retry of a task's launch, which the client token requires.
fn ttl_script(expires_at: DateTime<Utc>) -> String {
    format!(
        "#!/bin/bash\n\
         minutes=$(( ({epoch} - $(date +%s) + 59) / 60 ))\n\
         if [ \"$minutes\" -lt 0 ]; then minutes=0; fi\n\
         shutdown -P \"+$minutes\"\n",
        epoch = expires_at.timestamp()
    )
}

/// Base64 user data that makes the VM enforce its own TTL, so it can't outlive its task
/// even while the orchestrator is down. The reconciler remains the primary enforcer.
///
/// User data runs only on first boot and a scheduled shutdown doesn't survive a reboot, so
/// this installs [`ttl_script`] as a cloud-init per-boot script and runs it once now.
fn user_data(expires_at: DateTime<Utc>) -> String {
    let script = format!(
        "#!/bin/bash\n\
         # factory: TTL backstop, re-armed on every boot.\n\
         set -eu\n\
         mkdir -p \"$(dirname {PER_BOOT_SCRIPT})\"\n\
         cat > {PER_BOOT_SCRIPT} <<'FACTORY_TTL'\n\
         {ttl}\
         FACTORY_TTL\n\
         chmod 755 {PER_BOOT_SCRIPT}\n\
         exec {PER_BOOT_SCRIPT}\n",
        ttl = ttl_script(expires_at)
    );
    base64(script.as_bytes())
}

/// Standard base64 with padding (RFC 4648), which EC2 requires for user data. The SDK
/// sends user data as given and does not encode it.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn tag(key: &str, value: String) -> Tag {
    Tag::builder().key(key).value(value).build()
}

impl Cloud for AwsCloud {
    async fn script_ready(&self, instance_id: &str) -> anyhow::Result<bool> {
        let filter = aws_sdk_ssm::types::InstanceInformationStringFilter::builder()
            .key("InstanceIds")
            .values(instance_id)
            .build()
            .map_err(|_| anyhow!("building SSM readiness filter failed"))?;
        let output = self
            .ssm
            .describe_instance_information()
            .filters(filter)
            .customize()
            .config_override(
                aws_sdk_ssm::config::Builder::default().timeout_config(
                    aws_sdk_ssm::config::timeout::TimeoutConfig::builder()
                        .operation_timeout(std::time::Duration::from_secs(10))
                        .build(),
                ),
            )
            .send()
            .await
            .map_err(|_| anyhow!("checking SSM readiness failed"))?;
        Ok(output.instance_information_list().iter().any(|info| {
            info.instance_id() == Some(instance_id)
                && info.ping_status() == Some(&aws_sdk_ssm::types::PingStatus::Online)
        }))
    }

    async fn read_secure(&self, name: &str) -> anyhow::Result<String> {
        self.parameters.read_secure(name).await
    }
    async fn put_task_secret(
        &self,
        tenant_id: uuid::Uuid,
        task_id: uuid::Uuid,
        instance_id: &str,
        value: &str,
    ) -> anyhow::Result<super::SecretReference> {
        let name = self
            .parameters
            .put_task(tenant_id, task_id, instance_id, value)
            .await?;
        Ok(super::SecretReference {
            name,
            region: self.region.clone(),
        })
    }
    async fn list_task_secrets(&self) -> anyhow::Result<Vec<super::StoredTaskSecret>> {
        self.parameters.list_tasks().await
    }
    async fn delete_task_secret(&self, name: &str) -> anyhow::Result<()> {
        self.parameters.delete_task(name).await
    }

    async fn launch(&self, request: &LaunchRequest) -> anyhow::Result<String> {
        let tags = [
            tag(DEPLOYMENT_TAG, self.config.deployment.clone()),
            tag(TASK_ID_TAG, request.task_id.to_string()),
            tag(TENANT_ID_TAG, request.tenant_id.to_string()),
        ];
        let tag_spec = |resource| {
            TagSpecification::builder()
                .resource_type(resource)
                .set_tags(Some(tags.to_vec()))
                .build()
        };

        let output = self
            .ec2
            .run_instances()
            .image_id(&self.config.ami_id)
            .instance_type(InstanceType::from(self.config.instance_type.as_str()))
            .min_count(1)
            .max_count(1)
            .subnet_id(&self.config.subnet_id)
            .security_group_ids(&self.config.security_group_id)
            .iam_instance_profile(
                IamInstanceProfileSpecification::builder()
                    .name(&self.config.instance_profile_name)
                    .build(),
            )
            // Same task id => same RunInstances request, so a retry after a crash can't
            // create a second VM. EC2 rejects a reused token whose other parameters differ,
            // so changing AMI/type/subnet mid-launch fails that task (heartbeat timeout).
            // The user data depends only on the task's fixed expires_at, so it matches too.
            .client_token(request.task_id.to_string())
            .user_data(user_data(request.expires_at))
            .tag_specifications(tag_spec(ResourceType::Instance))
            .tag_specifications(tag_spec(ResourceType::Volume))
            .metadata_options(
                InstanceMetadataOptionsRequest::builder()
                    .http_tokens(HttpTokensState::Required)
                    .build(),
            )
            .instance_initiated_shutdown_behavior(ShutdownBehavior::Terminate)
            .send()
            .await
            .map_err(|e| {
                anyhow!(
                    "RunInstances for task {}: {}",
                    request.task_id,
                    DisplayErrorContext(e)
                )
            })?;

        output
            .instances()
            .first()
            .and_then(|i| i.instance_id())
            .map(str::to_owned)
            .with_context(|| {
                format!(
                    "RunInstances for task {} returned no instance id",
                    request.task_id
                )
            })
    }

    async fn terminate(&self, instance_ids: &[String]) -> anyhow::Result<()> {
        for batch in instance_ids.chunks(TERMINATE_BATCH) {
            self.ec2
                .terminate_instances()
                .set_instance_ids(Some(batch.to_vec()))
                .send()
                .await
                .map_err(|e| anyhow!("TerminateInstances {batch:?}: {}", DisplayErrorContext(e)))?;
        }
        Ok(())
    }

    async fn list_tagged(&self) -> anyhow::Result<Vec<Instance>> {
        let mut pages = self
            .ec2
            .describe_instances()
            .filters(
                Filter::builder()
                    .name(format!("tag:{DEPLOYMENT_TAG}"))
                    .values(&self.config.deployment)
                    .build(),
            )
            .filters(
                Filter::builder()
                    .name("instance-state-name")
                    .values("pending")
                    .values("running")
                    .values("stopping")
                    .values("stopped")
                    .build(),
            )
            .into_paginator()
            .send();

        let mut instances = Vec::new();
        while let Some(page) = pages.next().await {
            let page =
                page.map_err(|e| anyhow!("DescribeInstances: {}", DisplayErrorContext(e)))?;
            for reservation in page.reservations() {
                for instance in reservation.instances() {
                    let Some(id) = instance.instance_id() else {
                        continue;
                    };
                    let state = match instance.state().and_then(|s| s.name()) {
                        Some(InstanceStateName::Pending) => InstanceState::Pending,
                        Some(InstanceStateName::Running) => InstanceState::Running,
                        _ => InstanceState::Other,
                    };
                    let tags = instance
                        .tags()
                        .iter()
                        .filter_map(|t| Some((t.key()?, t.value()?)));
                    instances.push(Instance::from_tags(id.to_owned(), state, tags));
                }
            }
        }
        Ok(instances)
    }

    async fn run_script(&self, request: &ScriptRequest<'_>) -> anyhow::Result<ScriptStart> {
        // AWS-RunShellScript caps executionTimeout at 48 hours.
        let timeout = request.timeout.as_secs().clamp(1, 172_800);
        let result = self
            .ssm
            .send_command()
            .document_name("AWS-RunShellScript")
            .instance_ids(request.instance_id)
            .parameters("commands", vec![request.script.to_owned()])
            .parameters("executionTimeout", vec![timeout.to_string()])
            .comment(format!("factory task {}", request.task_id))
            .customize()
            // SendCommand isn't idempotent: a retry after a lost response would start a
            // second agent. The caller holds the task's row lock for this call, so bound it
            // too. On either failure the next tick sends again with a fresh token.
            .config_override(
                aws_sdk_ssm::config::Builder::default()
                    .retry_config(aws_sdk_ssm::config::retry::RetryConfig::disabled())
                    .timeout_config(
                        aws_sdk_ssm::config::timeout::TimeoutConfig::builder()
                            .operation_timeout(std::time::Duration::from_secs(20))
                            .build(),
                    ),
            )
            .send()
            .await;
        match result {
            Ok(output) => output
                .command()
                .and_then(|c| c.command_id())
                .map(|id| ScriptStart::Sent {
                    command_id: id.to_owned(),
                })
                .with_context(|| {
                    format!(
                        "SendCommand for task {} returned no command id",
                        request.task_id
                    )
                }),
            // Also returned when the instance profile doesn't grant SSM; the task then fails
            // on heartbeat timeout, and this is logged on every attempt.
            Err(e)
                if matches!(
                    e.as_service_error(),
                    Some(SendCommandError::InvalidInstanceId(_))
                ) =>
            {
                Ok(ScriptStart::NotReady)
            }
            Err(e) => Err(anyhow!(
                "SendCommand for task {} on {}: {}",
                request.task_id,
                request.instance_id,
                DisplayErrorContext(e)
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected, "{input:?}");
        }
        assert_eq!(base64(&[0xfb, 0xff, 0xfe]), "+//+");
    }

    /// Runs [`ttl_script`] under bash with `date` pinned to `now` and `shutdown` stubbed
    /// to echo its arguments.
    #[cfg(unix)]
    fn run_ttl_script(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> String {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("factory-ttl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        for (name, body) in [
            ("date", format!("#!/bin/sh\necho {}\n", now.timestamp())),
            ("shutdown", "#!/bin/sh\necho \"$@\"\n".to_string()),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = format!("{}:{}", dir.display(), std::env::var("PATH").unwrap());
        let output = std::process::Command::new("bash")
            .args(["-c", &ttl_script(expires_at)])
            .env("PATH", path)
            .output()
            .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn ttl_script_schedules_shutdown_at_expiry_rounded_up() {
        let expires_at = Utc.with_ymd_and_hms(2026, 9, 27, 12, 0, 0).unwrap();
        for (secs_left, expected) in [
            (-600, "-P +0\n"),
            (0, "-P +0\n"),
            (1, "-P +1\n"),
            (60, "-P +1\n"),
            (61, "-P +2\n"),
            (3600, "-P +60\n"),
        ] {
            let now = expires_at - chrono::Duration::seconds(secs_left);
            assert_eq!(
                run_ttl_script(expires_at, now),
                expected,
                "{secs_left}s left"
            );
        }
    }

    #[test]
    fn user_data_installs_ttl_script_per_boot_and_is_deterministic() {
        let expires_at = Utc.with_ymd_and_hms(2026, 9, 27, 12, 0, 0).unwrap();
        let expected = format!(
            "#!/bin/bash\n\
             # factory: TTL backstop, re-armed on every boot.\n\
             set -eu\n\
             mkdir -p \"$(dirname {PER_BOOT_SCRIPT})\"\n\
             cat > {PER_BOOT_SCRIPT} <<'FACTORY_TTL'\n\
             {}\
             FACTORY_TTL\n\
             chmod 755 {PER_BOOT_SCRIPT}\n\
             exec {PER_BOOT_SCRIPT}\n",
            ttl_script(expires_at)
        );
        assert_eq!(user_data(expires_at), base64(expected.as_bytes()));
        assert_eq!(user_data(expires_at), user_data(expires_at));
    }

    #[test]
    fn deployment_ids_are_validated() {
        for ok in ["prod", "staging-us-east-1", "a.b_c-1", &"x".repeat(64)] {
            assert!(validate_deployment(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            "has space",
            "comma,list",
            "star*",
            "ünïcode",
            &"x".repeat(65),
        ] {
            assert!(validate_deployment(bad).is_err(), "{bad:?}");
        }
    }
}
