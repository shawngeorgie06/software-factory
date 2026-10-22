//! Parameter Store access. Secret values and SDK errors must never enter diagnostics.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use aws_sdk_ssm::Client;
use aws_sdk_ssm::config::{retry::RetryConfig, timeout::TimeoutConfig};
use aws_sdk_ssm::types::{ParameterStringFilter, ParameterTier, ParameterType, Tag};
use uuid::Uuid;

use super::{SecretConfigurationError, StoredTaskSecret};

pub struct ParameterStore {
    client: Client,
    deployment: String,
    kms_key_arn: String,
    instance_arn_prefix: String,
}

impl ParameterStore {
    pub fn new(client: Client, deployment: &str, kms_key_arn: &str, region: &str) -> Result<Self> {
        validate_deployment(deployment)?;
        let (partition, account) = validate_key_arn(kms_key_arn, region)?;
        ensure!(
            client.config().region().map(|r| r.as_ref()) == Some(region),
            "Parameter Store client region does not match configured region"
        );
        // A failed put may already have committed remotely. Never retry with another name
        // here; the caller's orphan sweep recovers attempts not recorded in the database.
        let config = client
            .config()
            .to_builder()
            .retry_config(RetryConfig::standard())
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(3))
                    .read_timeout(Duration::from_secs(10))
                    .operation_attempt_timeout(Duration::from_secs(15))
                    .operation_timeout(Duration::from_secs(20))
                    .build(),
            )
            .build();
        Ok(Self {
            client: Client::from_conf(config),
            deployment: deployment.to_owned(),
            kms_key_arn: kms_key_arn.to_owned(),
            instance_arn_prefix: format!("arn:{partition}:ec2:{region}:{account}:instance/"),
        })
    }

    /// Administrative configuration may live anywhere beneath `/factory/`, including
    /// outside this deployment. ARNs, version selectors and unrelated paths are rejected.
    pub async fn read_secure(&self, name: &str) -> Result<String> {
        if !valid_read_name(name) {
            return Err(SecretConfigurationError::Invalid.into());
        }
        let output = self
            .client
            .get_parameter()
            .name(name)
            .with_decryption(true)
            .send()
            .await
            .map_err(|error| {
                if error
                    .as_service_error()
                    .is_some_and(|e| e.is_parameter_not_found())
                {
                    anyhow::Error::from(SecretConfigurationError::Missing)
                } else {
                    anyhow!("reading secure parameter failed")
                }
            })?;
        let parameter = output
            .parameter()
            .ok_or_else(|| anyhow!("secure parameter response is missing"))?;
        if parameter.r#type() != Some(&ParameterType::SecureString) {
            return Err(SecretConfigurationError::Invalid.into());
        }
        let value = parameter
            .value()
            .ok_or_else(|| anyhow!("secure parameter value is missing"))?;
        if value.is_empty() || value.len() > 8192 {
            return Err(SecretConfigurationError::Invalid.into());
        }
        Ok(value.to_owned())
    }

    /// Creates an immutable attempt with its access-control tags in the initial request.
    /// On error the result is uncertain; orphan cleanup must reconcile unrecorded puts.
    pub async fn put_task(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
        instance_id: &str,
        value: &str,
    ) -> Result<String> {
        ensure!(valid_instance_id(instance_id), "invalid EC2 instance id");
        ensure!(
            !value.is_empty() && value.len() <= 4096,
            "task secret must contain 1-4096 bytes"
        );
        let name = format!(
            "{}{tenant_id}/{task_id}/{}",
            self.task_prefix(),
            Uuid::new_v4()
        );
        let tags = [
            ("factory:tenant-id", tenant_id.to_string()),
            ("factory:task-id", task_id.to_string()),
            ("factory:deployment", self.deployment.clone()),
            (
                "factory:instance-arn",
                format!("{}{instance_id}", self.instance_arn_prefix),
            ),
        ]
        .into_iter()
        .map(|(key, value)| {
            Tag::builder()
                .key(key)
                .value(value)
                .build()
                .map_err(|_| anyhow!("building task secret tags failed"))
        })
        .collect::<Result<Vec<_>>>()?;
        self.client
            .put_parameter()
            .name(&name)
            .value(value)
            .r#type(ParameterType::SecureString)
            .tier(ParameterTier::Standard)
            .key_id(&self.kms_key_arn)
            .overwrite(false)
            .set_tags(Some(tags))
            .customize()
            .config_override(
                aws_sdk_ssm::config::Builder::default().retry_config(RetryConfig::disabled()),
            )
            .send()
            .await
            .map_err(|_| anyhow!("creating task secret failed; outcome may be uncertain"))?;
        Ok(name)
    }

    pub fn task_prefix(&self) -> String {
        format!("/factory/{}/tasks/", self.deployment)
    }

    pub async fn list_tasks(&self) -> Result<Vec<StoredTaskSecret>> {
        let prefix = self.task_prefix();
        let filter = ParameterStringFilter::builder()
            .key("Name")
            .option("BeginsWith")
            .values(&prefix)
            .build()
            .map_err(|_| anyhow!("building task secret filter failed"))?;
        let mut next_token = None;
        let mut seen_tokens = HashSet::new();
        let mut secrets = Vec::new();
        loop {
            let output = self
                .client
                .describe_parameters()
                .max_results(50)
                .parameter_filters(filter.clone())
                .set_next_token(next_token)
                .send()
                .await
                .map_err(|_| anyhow!("listing task secrets failed"))?;
            for parameter in output.parameters() {
                let Some(name) = parameter.name() else {
                    continue;
                };
                if let Some((tenant_id, task_id)) = parse_task_path(&prefix, name) {
                    secrets.push(StoredTaskSecret {
                        name: name.to_owned(),
                        tenant_id,
                        task_id,
                    });
                }
            }
            match output.next_token().filter(|token| !token.is_empty()) {
                None => return Ok(secrets),
                Some(token) => {
                    ensure!(
                        seen_tokens.insert(token.to_owned()),
                        "task secret pagination did not advance"
                    );
                    next_token = Some(token.to_owned());
                }
            }
        }
    }

    pub async fn delete_task(&self, name: &str) -> Result<()> {
        ensure!(
            parse_task_path(&self.task_prefix(), name).is_some(),
            "invalid task secret deletion path"
        );
        match self.client.delete_parameter().name(name).send().await {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|error| error.is_parameter_not_found()) =>
            {
                Ok(())
            }
            Err(_) => Err(anyhow!("deleting task secret failed")),
        }
    }
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn validate_deployment(deployment: &str) -> Result<()> {
    ensure!(
        deployment.len() <= 64 && safe_component(deployment),
        "deployment must contain 1-64 safe path characters"
    );
    Ok(())
}

fn validate_key_arn<'a>(arn: &'a str, region: &str) -> Result<(&'a str, &'a str)> {
    let parts: Vec<_> = arn.split(':').collect();
    ensure!(parts.len() == 6, "KMS customer key ARN is required");
    let [scheme, partition, service, key_region, account, resource] = parts[..] else {
        unreachable!()
    };
    ensure!(
        scheme == "arn"
            && matches!(
                partition,
                "aws"
                    | "aws-cn"
                    | "aws-us-gov"
                    | "aws-iso"
                    | "aws-iso-b"
                    | "aws-iso-e"
                    | "aws-iso-f"
            )
            && service == "kms"
            && !region.is_empty()
            && region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && key_region == region
            && account.len() == 12
            && account.bytes().all(|b| b.is_ascii_digit()),
        "invalid KMS customer key ARN or region mismatch"
    );
    let key_id = resource
        .strip_prefix("key/")
        .ok_or_else(|| anyhow!("KMS key ARN must reference a key, not an alias"))?;
    let valid_key_id = canonical_uuid(key_id).is_some()
        || key_id.strip_prefix("mrk-").is_some_and(|id| {
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
    ensure!(valid_key_id, "invalid KMS customer key id");
    Ok((partition, account))
}

fn valid_instance_id(value: &str) -> bool {
    value.strip_prefix("i-").is_some_and(|id| {
        matches!(id.len(), 8 | 17)
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn valid_read_name(name: &str) -> bool {
    name.len() <= 900
        && name.strip_prefix("/factory/").is_some_and(|suffix| {
            suffix.split('/').all(safe_component) && name.split('/').skip(1).count() <= 15
        })
}

fn canonical_uuid(value: &str) -> Option<Uuid> {
    let uuid = Uuid::parse_str(value).ok()?;
    (uuid.hyphenated().to_string() == value).then_some(uuid)
}

fn parse_task_path(prefix: &str, name: &str) -> Option<(Uuid, Uuid)> {
    let mut parts = name.strip_prefix(prefix)?.split('/');
    let tenant_id = canonical_uuid(parts.next()?)?;
    let task_id = canonical_uuid(parts.next()?)?;
    canonical_uuid(parts.next()?)?;
    parts.next().is_none().then_some((tenant_id, task_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread::{self, JoinHandle};

    const KEY: &str = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789abc";
    const TENANT: &str = "11111111-1111-4111-8111-111111111111";
    const TASK: &str = "22222222-2222-4222-8222-222222222222";
    const ATTEMPT: &str = "33333333-3333-4333-8333-333333333333";

    fn task_name() -> String {
        format!("/factory/test/tasks/{TENANT}/{TASK}/{ATTEMPT}")
    }

    // All SDK tests have explicit static credentials and a loopback-only endpoint.
    // Each response closes its connection, allowing sequential pagination requests.
    fn mock(responses: Vec<(u16, String)>) -> (ParameterStore, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "mock request timed out"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("mock accept failed: {error}"),
                    }
                };
                // Accepted sockets inherit O_NONBLOCK on macOS.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    let mut buffer = [0; 2048];
                    let count = stream.read(&mut buffer).unwrap();
                    assert_ne!(count, 0, "incomplete mock request");
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(index) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                while request.len() < header_end + length {
                    let mut buffer = [0; 2048];
                    let count = stream.read(&mut buffer).unwrap();
                    assert_ne!(count, 0, "incomplete mock body");
                    request.extend_from_slice(&buffer[..count]);
                }
                requests.push(String::from_utf8(request).unwrap());
                write!(stream, "HTTP/1.1 {status} Response\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        let config = aws_sdk_ssm::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_ssm::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_ssm::config::Credentials::new(
                "test",
                "test",
                None,
                None,
                "local-test",
            ))
            .endpoint_url(format!("http://{address}"))
            .build();
        let store =
            ParameterStore::new(Client::from_conf(config), "test", KEY, "us-east-1").unwrap();
        (store, server)
    }

    #[test]
    fn rejects_unsafe_configuration_and_references() {
        for deployment in ["", ".", "..", "a/b", "test*", "space here", &"a".repeat(65)] {
            assert!(validate_deployment(deployment).is_err());
        }
        for deployment in ["test", "prod.us-east-1_01", &"a".repeat(64)] {
            assert!(validate_deployment(deployment).is_ok());
        }
        assert!(validate_key_arn(KEY, "us-east-1").is_ok());
        assert!(validate_key_arn(KEY, "us-west-2").is_err());
        for key in [
            KEY.replace("key/", "alias/"),
            KEY.replace("123456789012", "12345678901x"),
            KEY.replace("12345678-1234-1234-1234-123456789abc", "*"),
            KEY.replace(":aws:", ":unknown:"),
            String::new(),
        ] {
            assert!(validate_key_arn(&key, "us-east-1").is_err());
        }
        let mrk = KEY.replace(
            "12345678-1234-1234-1234-123456789abc",
            "mrk-0123456789abcdef0123456789abcdef",
        );
        assert!(validate_key_arn(&mrk, "us-east-1").is_ok());
        for name in [
            "/other/key",
            "/factory/",
            "/factory/a//b",
            "/factory/../key",
            "/factory/key:1",
            "arn:aws:ssm:us-east-1:123456789012:parameter/factory/key",
        ] {
            assert!(!valid_read_name(name));
        }
        assert!(valid_read_name("/factory/admin/github-token"));
        assert!(valid_read_name("/factory/other-deployment/config/token"));
        assert!(valid_instance_id("i-0123456789abcdef0"));
        assert!(valid_instance_id("i-01234567"));
        for id in [
            "i-*",
            "i-0123456789abcdefg",
            "i-0123456789ABCDEF0",
            "i-0123456789abcdef0/other",
        ] {
            assert!(!valid_instance_id(id));
        }
    }

    #[test]
    fn task_paths_cannot_escape_deployment_or_accept_noncanonical_ids() {
        let name = task_name();
        let prefix = "/factory/test/tasks/";
        assert_eq!(
            parse_task_path(prefix, &name),
            Some((
                Uuid::parse_str(TENANT).unwrap(),
                Uuid::parse_str(TASK).unwrap()
            ))
        );
        for invalid in [
            name.replace("/test/", "/test-other/"),
            name.replace("/test/", "/other/"),
            format!("{name}/extra"),
            format!("{name}/"),
            name.replace(ATTEMPT, "bad"),
            name.replace(TENANT, &TENANT.replace('-', "")),
            name.replace(TASK, "../config"),
        ] {
            assert!(parse_task_path(prefix, &invalid).is_none());
        }
    }

    #[tokio::test]
    async fn put_is_immutable_encrypted_and_tagged_at_creation() {
        let (store, server) = mock(vec![
            (200, "{\"Version\":1}".into()),
            (200, "{\"Version\":1}".into()),
        ]);
        let tenant = Uuid::parse_str(TENANT).unwrap();
        let task = Uuid::parse_str(TASK).unwrap();
        let first = store
            .put_task(tenant, task, "i-0123456789abcdef0", "synthetic-token")
            .await
            .unwrap();
        let second = store
            .put_task(tenant, task, "i-0123456789abcdef0", "synthetic-token")
            .await
            .unwrap();
        assert_ne!(first, second);
        assert!(parse_task_path(&store.task_prefix(), &first).is_some());
        for request in server.join().unwrap() {
            for expected in [
                "AmazonSSM.PutParameter",
                "\"Type\":\"SecureString\"",
                "\"Tier\":\"Standard\"",
                "\"Overwrite\":false",
                KEY,
                "factory:tenant-id",
                TENANT,
                "factory:task-id",
                TASK,
                "factory:deployment",
                "factory:instance-arn",
                "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
            ] {
                assert!(
                    request.contains(expected),
                    "missing contract field {expected}"
                );
            }
        }
        assert_eq!(
            store.client.config().retry_config().unwrap().max_attempts(),
            3
        );
        assert_eq!(
            store
                .client
                .config()
                .timeout_config()
                .unwrap()
                .operation_timeout(),
            Some(Duration::from_secs(20))
        );
    }

    #[tokio::test]
    async fn put_accepts_exact_byte_limit_and_does_not_expose_uncertain_failure() {
        let (store, server) = mock(vec![(200, "{\"Version\":1}".into())]);
        let id = Uuid::new_v4();
        store
            .put_task(id, id, "i-0123456789abcdef0", &"é".repeat(2048))
            .await
            .unwrap();
        assert_eq!(server.join().unwrap().len(), 1);
        let (store, server) = mock(vec![(
            500,
            "{\"__type\":\"InternalServerError\",\"message\":\"synthetic-private-body\"}".into(),
        )]);
        let error = store
            .put_task(id, id, "i-0123456789abcdef0", "synthetic-private-value")
            .await
            .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "creating task secret failed; outcome may be uncertain"
        );
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn reads_require_decryption_secure_type_and_byte_bounds() {
        let cases = [
            ("SecureString", "synthetic", true),
            ("String", "synthetic", false),
            ("SecureString", "", false),
            ("SecureString", &"x".repeat(8192), true),
            ("SecureString", &"x".repeat(8193), false),
        ];
        for (kind, value, valid) in cases {
            let response =
                format!("{{\"Parameter\":{{\"Type\":\"{kind}\",\"Value\":\"{value}\"}}}}");
            let (store, server) = mock(vec![(200, response)]);
            assert_eq!(
                store.read_secure("/factory/admin/token").await.is_ok(),
                valid
            );
            let request = server.join().unwrap().pop().unwrap();
            assert!(request.contains("\"WithDecryption\":true"));
        }
    }

    #[tokio::test]
    async fn list_paginates_and_skips_unowned_or_malformed_paths() {
        let name = task_name();
        let first = format!(
            "{{\"Parameters\":[{{\"Name\":\"{name}\"}},{{\"Name\":\"/factory/other/tasks/{TENANT}/{TASK}/{ATTEMPT}\"}},{{\"Name\":\"{name}/extra\"}}],\"NextToken\":\"page-two\"}}"
        );
        let (store, server) = mock(vec![(200, first), (200, "{\"Parameters\":[]}".into())]);
        let secrets = store.list_tasks().await.unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, name);
        assert_eq!(secrets[0].tenant_id, Uuid::parse_str(TENANT).unwrap());
        assert_eq!(secrets[0].task_id, Uuid::parse_str(TASK).unwrap());
        let requests = server.join().unwrap();
        assert!(requests[0].contains("\"MaxResults\":50"));
        assert!(requests[0].contains("\"Key\":\"Name\""));
        assert!(requests[0].contains("\"Option\":\"BeginsWith\""));
        assert!(requests[0].contains("/factory/test/tasks/"));
        assert!(requests[1].contains("\"NextToken\":\"page-two\""));
    }

    #[tokio::test]
    async fn missing_delete_is_idempotent_and_sdk_errors_are_redacted() {
        let (store, server) = mock(vec![(
            400,
            "{\"__type\":\"ParameterNotFound\",\"message\":\"synthetic-private-body\"}".into(),
        )]);
        store.delete_task(&task_name()).await.unwrap();
        assert!(server.join().unwrap()[0].contains("AmazonSSM.DeleteParameter"));
        let (store, server) = mock(vec![(
            400,
            "{\"__type\":\"ValidationException\",\"message\":\"synthetic-private-body\"}".into(),
        )]);
        let error = store.read_secure("/factory/admin/token").await.unwrap_err();
        assert_eq!(format!("{error:#}"), "reading secure parameter failed");
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invalid_inputs_are_rejected_before_network_io() {
        let (store, server) = mock(vec![]);
        let id = Uuid::new_v4();
        for value in [String::new(), "é".repeat(2049)] {
            assert!(
                store
                    .put_task(id, id, "i-0123456789abcdef0", &value)
                    .await
                    .is_err()
            );
        }
        assert!(store.put_task(id, id, "i-*", "synthetic").await.is_err());
        assert!(store.read_secure("/unrelated/token").await.is_err());
        assert!(
            store
                .delete_task("/factory/test/config/token")
                .await
                .is_err()
        );
        assert!(
            store
                .delete_task(&task_name().replace("/test/", "/other/"))
                .await
                .is_err()
        );
        assert!(server.join().unwrap().is_empty());
    }
}
