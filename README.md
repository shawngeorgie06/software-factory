# Software Factory

Rust orchestrator for task-scoped EC2 VMs. Postgres owns task state; a reconciler launches and cleans up instances through the `Cloud` trait. VMs accept commands through SSM with no inbound network access.

Milestones 1–3 provide task storage, reconciliation, and a heartbeat/`hello` round trip. Milestone 4 adds encrypted credential delivery and repository-scoped GitHub App tokens. The coding agent, PR creation, verification stage, deployment, and monitoring are later milestones.

## Test locally

Use Rust stable, PostgreSQL 16, Python 3, and curl. Tests use FakeCloud and local HTTP servers; they do not call AWS or GitHub.

```sh
docker compose up -d postgres
cp .env.example .env
set -a
. ./.env
set +a
SQLX_OFFLINE=true cargo test --locked
SQLX_OFFLINE=true cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

For an existing local Postgres installation, set `DATABASE_URL` to its `factory` database instead. The test database user needs permission to create test databases. Do not point tests at production.

SQLx compiles from the checked-in `.sqlx` cache with `SQLX_OFFLINE=true`. To update the cache after query changes:

```sh
cargo sqlx migrate run
cargo sqlx prepare -- --all-targets
```

## Configure credential delivery

The following setup is for the operator. Running the orchestrator creates billable AWS resources. No setup or live cloud verification is performed by the test suite.

1. Choose a deployment ID unique within the AWS account and region. Set the existing EC2 and API settings in `.env.example`.
2. Create a symmetric customer-managed KMS key in the VM region. Set `FACTORY_SECRETS_KMS_KEY_ARN` to its full key ARN. The orchestrator needs `kms:Encrypt` and `kms:Decrypt` through SSM.
3. Grant the orchestrator `ssm:PutParameter`, `ssm:AddTagsToResource`, and `ssm:DeleteParameter` on `/factory/DEPLOYMENT/tasks/*`. Grant `ssm:GetParameter` on the control key and the configured tenant model keys. `ssm:DescribeParameters` requires `Resource: "*"`; it lists metadata, not secret values. Grant `ssm:DescribeInstanceInformation` for the readiness check. Keep the existing EC2, SSM Run Command, and `iam:PassRole` permissions.
4. Restrict the VM instance role with [the policy template](docs/vm-secret-policy.json). Replace `REGION`, `ACCOUNT_ID`, `DEPLOYMENT`, and `KMS_KEY_ID`. Keep `${ec2:SourceInstanceARN}` unchanged: IAM substitutes the calling VM's ARN. The template is for the standard `aws` partition. It must accompany the existing SSM agent permissions.
5. Ensure the AMI has AWS CLI v2, Python 3, curl, SSM Agent, and cloud-init. VMs need outbound HTTPS to SSM, KMS through SSM, and the callback API. GitHub access will also be needed by the later coding agent.

The explicit denies in the template are required: `AmazonSSMManagedInstanceCore` already grants broad `GetParameter` and `GetParameters` access. The denies prevent access to other VMs' bundles and control secrets, and block history/path reads. Do not grant VMs parameter writes, tag changes, permission changes, or the orchestrator role. A task bundle is tagged with the exact owning instance ARN.

Review both IAM role policies and the KMS key policy before running in AWS. Local tests verify request construction; AWS policy enforcement remains a live acceptance check for the operator.

## Configure a GitHub App

Create a GitHub App with repository **Contents: read and write** and **Pull requests: read and write**. Disable webhooks unless another service needs them. Install the App only on repositories the factory may change. Download the private key to a secure operator location; never commit it.

Store the PEM as a `SecureString` at `/factory/DEPLOYMENT/control/github-private-key`. Store each tenant's model API key as a `SecureString` beneath `/factory/DEPLOYMENT/tenants/TENANT_UUID/`. Use the customer-managed KMS key and a secret-management tool that does not place plaintext in shell history or logs.

Set both environment variables:

```sh
FACTORY_GITHUB_APP_ID=123456
FACTORY_GITHUB_PRIVATE_KEY_PARAMETER=/factory/dev/control/github-private-key
```

Apply migrations with `cargo sqlx migrate run`, then add an administrator-managed binding. Use the real tenant UUID, GitHub installation ID, repository ID, and model key path:

```sql
INSERT INTO repository_credentials
    (tenant_id, repository, installation_id, repository_id, model_key_parameter)
VALUES
    ('00000000-0000-0000-0000-000000000001', 'owner/repository', 123, 456,
     '/factory/dev/tenants/00000000-0000-0000-0000-000000000001/model-key');
```

Task `repo_url` must be `https://github.com/owner/repository` or the same URL ending in `.git`. The owner and repository name match case-insensitively. An unconfigured repository, another tenant's model key path, or a missing or invalid model secret fails the task immediately with a specific reason. Transient secret-service errors retry. Task instructions cannot select installation IDs or parameter paths. There is no public binding-management API.

When both GitHub settings are absent, the existing hello flow still runs with an encrypted callback token only. When configured, the reconciler mints an installation token for exactly the bound repository with the two permissions above. The App private key stays on the orchestrator. A task bundle contains the callback token, model key, GitHub token, and expiry timestamps. Standard Parameter Store bundles are limited to 4096 bytes; oversized credentials fail before any SSM send.

## Credential lifecycle and limits

The reconciler checks SSM readiness and task expiry before minting credentials. Every send attempt uses a unique immutable `SecureString`. SSM command history contains its name and region, not its values. The VM retrieves and decrypts the bundle, stores it in a private temporary directory, checks the task expiry, and sends the hello heartbeat/result with a header file. The script removes the temporary directory on exit.

A failed or timed-out send rolls back the callback-token hash, so an abandoned run cannot report successfully. The next attempt gets a new bundle. The reconciler lists bundle metadata and deletes bundles for finished, expired, or missing tasks, including puts accepted just before a crash. VM termination runs before the secret sweep. Delete failures retry on later ticks. A definite SSM rejection deletes its unused bundle immediately. Bundles from uncertain sends remain until the task finishes. GitHub tokens already minted during an uncertain send or a readiness race expire naturally; this milestone does not revoke them.

Parameter Store does not enforce the task's expiry as a revocation deadline. Cleanup requires a running orchestrator. Deleting a bundle cannot revoke a secret already read by the VM. GitHub installation tokens expire after roughly one hour; model keys remain tenant credentials and need provider-side limits and rotation. This milestone does not refresh or revoke GitHub tokens or run repository code. Use short tasks during initial testing. VM root can read its own credentials; do not grant that VM access to other tasks.

The API is still the milestone-3 callback API. Tasks are created through the database, and successful hello results go directly to `succeeded`; `verifying` remains reserved. Real AWS launch, SSM registration, IAM/KMS isolation, and self-shutdown must be tested by the operator before customer workloads.

## References

- [Supported GitHub REST API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions)
- [GitHub App JWT authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
- [Repository-scoped installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [Parameter Store SecureString encryption](https://docs.aws.amazon.com/systems-manager/latest/userguide/secure-string-parameter-kms-encryption.html)
- [SSM actions and resource-tag conditions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ssm.html)
- [IAM condition keys, including EC2 source instance ARN](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
