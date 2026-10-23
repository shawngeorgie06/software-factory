# Software Factory

Rust orchestrator for task-scoped EC2 VMs. Postgres owns task state; a reconciler launches and cleans up instances through the `Cloud` trait. VMs accept commands through SSM with no inbound network access.

Milestones 1–3 provide task storage, reconciliation, and a heartbeat/`hello` round trip. Milestone 4 adds encrypted credential delivery and repository-scoped GitHub App tokens. Milestone 5 adds a Codex CLI runner, administrator-configured verification, and task-branch PR creation. Milestone 6 adds an authenticated task API for submitting, listing, and cancelling tasks. Deployment and monitoring are later milestones.

## Test locally

Use Rust stable, PostgreSQL 16, Python 3.9 or newer, git, and curl. Tests use FakeCloud, local HTTP servers, and temporary Git repositories; they do not call AWS, GitHub, or a model API.

```sh
docker compose up -d postgres
cp .env.example .env
set -a
. ./.env
set +a
python3 -m unittest discover -s vm -p 'test_*.py'
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

## Submit tasks through the API

Tenants call the task API with an API key. An administrator creates keys with the same binary; it needs only `DATABASE_URL`:

```sh
factory api-key create <tenant-uuid> "ci"   # prints the key once, on stdout
factory api-key list <tenant-uuid>
factory api-key revoke <key-uuid>           # takes effect on the next request
```

Keys look like `sf_` followed by 64 hex characters. Only their SHA-256 is stored. Send them as `Authorization: Bearer <key>`. A key only ever sees its own tenant's tasks; another tenant's task returns 404.

| Request | Result |
| --- | --- |
| `POST /v1/tasks` with `{"repo_url", "instructions", "ttl_seconds"?}` | `201` with the queued task |
| `GET /v1/tasks?state=&limit=&cursor=` | Newest first, up to 100 per page, with `next_cursor` |
| `GET /v1/tasks/{id}` | The task, including `result` or `failure_reason` |
| `POST /v1/tasks/{id}/cancel` | `200` with the failed task; `409` if it already finished |

```sh
curl -sS https://factory.example.com/v1/tasks \
  -H "Authorization: Bearer $FACTORY_API_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H 'Content-Type: application/json' \
  -d '{"repo_url": "https://github.com/owner/repo", "instructions": "Fix the failing test"}'
```

`repo_url` must be `https://github.com/<owner>/<repo>`. Instructions are limited to 64 KiB. `ttl_seconds` runs from 300 to `FACTORY_TASK_MAX_TTL_SECS` and defaults to `FACTORY_TASK_DEFAULT_TTL_SECS`; the reconciler terminates the VM when it expires. In Codex mode, a task's repository must already have a `repository_credentials` binding with checks, or submission returns `422`.

Retrying with the same `Idempotency-Key` and input returns the original task with `200`. Reusing a key for different input returns `409`. Each tenant may have `FACTORY_MAX_PENDING_TASKS_PER_TENANT` queued or active tasks; more return `429`. A replay is matched on `repo_url` and `instructions` only; a different `ttl_seconds` is ignored. Replays are answered before the repository binding is checked, so a retry still succeeds after the binding changes. A tenant's submissions are handled one at a time; if the database is saturated or a submission waits more than 5 seconds behind the same tenant's earlier ones, the API returns `503` with `Retry-After`.

Cancelling marks the task failed with reason `cancelled through the task API`. The next reconciler tick terminates its VM and deletes its credential bundle, and the agent's token stops working at once. A runner that is already publishing can still push its branch or open a PR before the VM stops.

## Configure credential delivery

The following setup is for the operator. Running the orchestrator creates billable AWS resources. No setup or live cloud verification is performed by the test suite.

1. Choose a deployment ID unique within the AWS account and region. Set the existing EC2 and API settings in `.env.example`.
2. Create a symmetric customer-managed KMS key in the VM region. Set `FACTORY_SECRETS_KMS_KEY_ARN` to its full key ARN. The orchestrator needs `kms:Encrypt` and `kms:Decrypt` through SSM.
3. Grant the orchestrator `ssm:PutParameter`, `ssm:AddTagsToResource`, and `ssm:DeleteParameter` on `/factory/DEPLOYMENT/tasks/*`. Grant `ssm:GetParameter` on the control key and the configured tenant model keys. `ssm:DescribeParameters` requires `Resource: "*"`; it lists metadata, not secret values. Grant `ssm:DescribeInstanceInformation` for the readiness check. Keep the existing EC2, SSM Run Command, and `iam:PassRole` permissions.
4. Restrict the VM instance role with [the policy template](docs/vm-secret-policy.json). Replace `REGION`, `ACCOUNT_ID`, `DEPLOYMENT`, and `KMS_KEY_ID`. Keep `${ec2:SourceInstanceARN}` unchanged: IAM substitutes the calling VM's ARN. The template is for the standard `aws` partition. It must accompany the existing SSM agent permissions.
5. Ensure the AMI has AWS CLI v2, Python 3, curl, SSM Agent, and cloud-init. VMs need outbound HTTPS to SSM, KMS through SSM, and the callback API. Codex mode also requires outbound HTTPS to GitHub and the OpenAI API.

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

When both GitHub settings are absent, the existing hello flow still runs with an encrypted callback token only. When configured, the reconciler mints an installation token for exactly the bound repository with the two permissions above. The App private key stays on the orchestrator. A task bundle contains the callback token, model key, GitHub token, and expiry timestamps. Standard Parameter Store bundles are limited to 4096 bytes; oversized credentials fail the task before any SSM send. GitHub HTTP 404 and 422 scope errors also fail the task with a specific reason.

## Credential lifecycle and limits

The reconciler checks SSM readiness and task expiry before minting credentials. Every send attempt uses a unique immutable `SecureString`. SSM command history contains its name and region, not its values. The VM retrieves and decrypts the bundle, stores it in a private temporary directory, checks the task expiry, and sends the hello heartbeat/result with a header file. The script removes the temporary directory on exit.

A failed or timed-out send rolls back the callback-token hash, so an abandoned run cannot report successfully. The next attempt gets a new bundle. The reconciler lists bundle metadata and deletes bundles for finished, expired, or missing tasks, including puts accepted just before a crash. VM termination runs before the secret sweep. Delete failures retry on later ticks. A definite SSM rejection deletes its unused bundle immediately. Bundles from uncertain sends remain until the task finishes. GitHub tokens already minted during an uncertain send or a readiness race expire naturally; this milestone does not revoke them.

Parameter Store does not enforce the task's expiry as a revocation deadline. Cleanup requires a running orchestrator. Deleting a bundle cannot revoke a secret already read by the VM. GitHub installation tokens expire after roughly one hour; model keys remain tenant credentials and need provider-side limits and rotation. The runner does not refresh or revoke GitHub tokens; it stops before the installation token expires. Use short tasks during initial testing. VM root can read its own credentials; do not grant that VM access to other tasks.

Tasks are still created through the database. Real AWS launch, SSM registration, IAM/KMS isolation, and self-shutdown must be tested by the operator before customer workloads.

## Run coding tasks with Codex

The default `FACTORY_AGENT_MODE=hello` preserves the smoke test. To enable coding, set `FACTORY_AGENT_MODE=codex` and `FACTORY_CODEX_MODEL` to an explicit model ID enabled for your OpenAI API key. Both GitHub App settings and a dedicated HTTPS callback origin on port 443 (no path prefix) are required. Store the OpenAI API key in the bound tenant model-key SecureString.

Apply the new migration and configure a verification command on each repository binding. Existing bindings have no check command and fail closed in Codex mode. This is administrator-managed argv, not task-provided shell text:

```sql
UPDATE repository_credentials
SET check_command = ARRAY['env', 'CARGO_HOME=/opt/factory/cargo', 'cargo', 'test', '--locked', '--offline']
WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
  AND repository = 'owner/repository';
```

Prepare a Linux AMI with Python 3.9+, Git, a pinned Codex CLI supporting `exec --ephemeral --ignore-user-config --ignore-rules`, AWS CLI v2, `setpriv`, `unshare`, `mount`, `pkill`, `iptables`, and `ip6tables`. Install toolchains system-wide on `/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin` and prepopulate dependencies in an administrator-owned, agent-read-only cache. The Cargo example assumes a system Cargo/Rust installation and `/opt/factory/cargo` cache; per-user rustup installations are not on the runner's PATH. Verification receives a fresh HOME and no network access. Create a dedicated `factory-agent` account with a nonzero UID/GID, home `/home/factory-agent`, and no sudo or privileged groups. Root must be able to create mount/network namespaces and tmpfs mounts. Deny cron, at, and systemd user lingering for this account so it cannot schedule processes outside the runner. One task owns that UID and VM; the runner terminates its remaining processes after each code/check phase. SSM runs the trusted bootstrap as root. Do not enable this mode on a shared host.

Before runners start, provision root-owned storage and persist these metadata firewall rules. They must be the first rule in each OUTPUT chain; the runner checks the exact rules and verifies metadata connections fail under the agent UID. IMDSv2 alone does not isolate local processes.

```sh
install -d -o root -g root -m 0711 /var/lib/software-factory
factory_uid="$(id -u factory-agent)"
iptables -w 5 -I OUTPUT 1 -d 169.254.169.254/32 -m owner --uid-owner "$factory_uid" -j REJECT --reject-with icmp-port-unreachable
ip6tables -w 5 -I OUTPUT 1 -d fd00:ec2::254/128 -m owner --uid-owner "$factory_uid" -j REJECT --reject-with icmp6-port-unreachable
```

Use the AMI's firewall persistence mechanism and verify both rules survive reboot before accepting tasks. For an AMI with `netfilter-persistent`, run `netfilter-persistent save` and enable that service. The runner checks host isolation before loading credentials; a misconfigured host never reaches repository or model execution. The operator must verify actual firewall, namespace and sandbox enforcement on the prepared AMI.

The runner first authenticates a heartbeat, then fetches the task's repository, instructions, and configured checks. It clones the default branch, runs Codex as `factory-agent` with workspace-write sandboxing and tool network access disabled, freezes the resulting Git tree, and enters `verifying`. Checks run against a separate checkout of that frozen tree. Only a passing tree is pushed to `factory/task-TASK_UUID`, followed by a PR against the repository's default branch. Existing conflicting task branches are refused. A no-change task still runs checks and succeeds without a push or PR. The result records status, branch, commit, and PR URL, distinguishing newly created, existing open, and already closed PRs; failures expose only a fixed phase label.

GitHub and callback credentials stay in the root runner. Only the Codex invocation receives `CODEX_API_KEY`; verification receives no credentials. Each invocation gets private `/tmp`, `/var/tmp`, `/dev/shm`, and account-home mounts; checks also cannot read the model HOME. Publishing uses a separate root-owned Git directory, ignores repository hooks/configuration, and checks staged files for literal credentials. Symlinks, hardlinks, submodules, nested Git metadata, and oversized trees/files are rejected (16 MiB per file, 256 MiB per tree, and 100,000 entries). Repository or ancestor `.codex` configuration is also rejected before invoking Codex. Repositories requiring these features are not supported by this milestone. These controls do not make arbitrary repository code safe against kernel or sandbox vulnerabilities; use disposable, isolated task VMs.

Heartbeats continue during work. Any routine heartbeat failure, including a temporary network or server failure, aborts the run; this conservative policy favors stopping work when authorization cannot be confirmed. Task expiry or the GitHub token's expiry margin also stops work. Transient admission and final-result requests retry within the lease deadline; the 30-second freshness bound may shorten that retry budget. The authenticated callback API now includes `GET /v1/tasks/{id}/assignment` and `POST` endpoints for `heartbeat`, `verifying`, `result`, and `failure`. Successful coding tasks move through `running → verifying → succeeded`; failures become terminal `failed` tasks for reconciler cleanup.

Local tests exercise mocked credential/model/GitHub transport and real temporary Git repositories. Linux privilege dropping, network namespaces, the installed Codex sandbox, and real cloud/provider access remain operator acceptance checks on the prepared AMI; local tests do not claim those live checks passed. Exercise the exact offline check command on the AMI, including Cargo cache locking, and verify that SSM accepts the embedded command payload.

## References

- [Supported GitHub REST API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions)
- [GitHub App JWT authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
- [Repository-scoped installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [Parameter Store SecureString encryption](https://docs.aws.amazon.com/systems-manager/latest/userguide/secure-string-parameter-kms-encryption.html)
- [SSM actions and resource-tag conditions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ssm.html)
- [IAM condition keys, including EC2 source instance ARN](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
