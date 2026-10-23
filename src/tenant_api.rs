//! HTTP endpoints tenants use to submit, inspect, and cancel tasks.
//!
//! Every request carries an API key (see [`crate::api_keys`]) that fixes the tenant; no
//! request can name another tenant, and another tenant's task looks like a missing one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::db::{self, Cancelled, NewTask, Submission, Submitted, Task, TaskState};

/// Largest `instructions` accepted, matching what the agent will fetch.
pub const MAX_INSTRUCTIONS_BYTES: usize = 65536;
const MAX_REPO_URL_BYTES: usize = 2048;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;
/// Shortest lifetime a task may ask for; less can't fit a VM boot and an agent run.
pub const MIN_TTL: Duration = Duration::from_secs(300);
const DEFAULT_PAGE: i64 = 50;
const MAX_PAGE: i64 = 100;
/// How long a submission waits behind the same tenant's earlier ones before giving up.
const SUBMIT_QUEUE_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct TaskApiConfig {
    pub default_ttl: Duration,
    pub max_ttl: Duration,
    /// Most queued or active tasks one tenant may have at once.
    pub max_pending_per_tenant: i64,
    /// Coding agents need an administrator-configured repository binding with checks, so
    /// tasks for unconfigured repositories are rejected up front instead of failing later.
    pub require_repository_binding: bool,
}

#[derive(Clone)]
struct ApiState {
    pool: PgPool,
    config: TaskApiConfig,
    submit_gates: SubmitGates,
}

/// Lets one submission per tenant at a time reach the database from this process. The
/// advisory lock in [`db::submit_task`] already serialises them, but each waiter would hold a
/// pooled connection, so one tenant's burst could starve everyone else's requests.
#[derive(Clone, Default)]
struct SubmitGates(Arc<Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>>);

struct SubmitTurn {
    gates: SubmitGates,
    tenant_id: Uuid,
    _turn: tokio::sync::OwnedMutexGuard<()>,
}

impl SubmitGates {
    /// Waits for the tenant's turn; `None` if earlier submissions held it too long.
    async fn enter(&self, tenant_id: Uuid) -> Option<SubmitTurn> {
        let gate = {
            let mut gates = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(gates.entry(tenant_id).or_default())
        };
        let turn = tokio::time::timeout(SUBMIT_QUEUE_WAIT, gate.lock_owned())
            .await
            .ok()?;
        Some(SubmitTurn {
            gates: self.clone(),
            tenant_id,
            _turn: turn,
        })
    }
}

impl Drop for SubmitTurn {
    fn drop(&mut self) {
        let mut gates = self
            .gates
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Only the map and this turn's guard hold the gate: nobody is waiting, so forget it.
        if gates
            .get(&self.tenant_id)
            .is_some_and(|gate| Arc::strong_count(gate) <= 2)
        {
            gates.remove(&self.tenant_id);
        }
    }
}

pub fn router(pool: PgPool, config: TaskApiConfig) -> Router {
    Router::new()
        .route("/v1/tasks", post(create).get(list))
        .route("/v1/tasks/{id}", get(show))
        .route("/v1/tasks/{id}/cancel", post(cancel))
        // Room for the largest instructions once JSON-escaped (`\u00XX` is 6 bytes per byte).
        .layer(DefaultBodyLimit::max(7 * MAX_INSTRUCTIONS_BYTES))
        .with_state(ApiState {
            pool,
            config,
            submit_gates: SubmitGates::default(),
        })
}

/// What tenants see of a task. VM and SSM identifiers stay internal.
#[derive(Serialize)]
struct TaskView {
    id: Uuid,
    state: TaskState,
    repo_url: String,
    instructions: String,
    result: Option<String>,
    failure_reason: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    heartbeat_at: Option<DateTime<Utc>>,
}

impl From<Task> for TaskView {
    fn from(task: Task) -> Self {
        TaskView {
            id: task.id,
            state: task.state,
            repo_url: task.repo_url,
            instructions: task.instructions,
            result: task.result,
            failure_reason: task.failure_reason,
            created_at: task.created_at,
            updated_at: task.updated_at,
            expires_at: task.expires_at,
            heartbeat_at: task.heartbeat_at,
        }
    }
}

/// JSON response that intermediaries must not cache: bodies hold task instructions.
fn reply(status: StatusCode, body: impl Serialize) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(body),
    )
        .into_response()
}

fn problem(status: StatusCode, message: &str) -> Response {
    reply(status, json!({ "error": message }))
}

fn not_found() -> Response {
    problem(StatusCode::NOT_FOUND, "task not found")
}

fn internal_error(tenant_id: Uuid, error: anyhow::Error) -> Response {
    if saturated(&error) {
        warn!(%tenant_id, error = ?error, "task API database busy");
        return busy();
    }
    error!(%tenant_id, error = ?error, "task API request failed");
    problem(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

/// 503 with a hint to retry: the request was fine, the server is momentarily overloaded.
fn busy() -> Response {
    let mut response = problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "server is busy; retry shortly",
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

/// Whether a failure came from load rather than a fault: no free pooled connection, or a
/// lock or statement timeout.
fn saturated(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| match cause.downcast_ref::<sqlx::Error>() {
            Some(sqlx::Error::PoolTimedOut) => true,
            Some(sqlx::Error::Database(db)) => {
                matches!(db.code().as_deref(), Some("55P03" | "57014"))
            }
            _ => false,
        })
}

/// Resolves the caller's tenant from `Authorization: Bearer <key>`.
async fn tenant(state: &ApiState, headers: &HeaderMap) -> Result<Uuid, Response> {
    let unauthorized = || {
        let mut response = problem(StatusCode::UNAUTHORIZED, "a valid API key is required");
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        response
    };
    let key = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, key)| key.trim_start_matches(' '))
        .ok_or_else(unauthorized)?;
    match crate::api_keys::authenticate(&state.pool, key).await {
        Ok(Some(tenant_id)) => Ok(tenant_id),
        Ok(None) => Err(unauthorized()),
        Err(error) if saturated(&error) => {
            warn!(error = ?error, "API key lookup hit a busy database");
            Err(busy())
        }
        Err(error) => {
            error!(error = ?error, "API key lookup failed");
            Err(problem(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    repo_url: String,
    instructions: String,
    /// Seconds the task may live, VM included. Defaults to the configured default.
    ttl_seconds: Option<u64>,
}

async fn create(State(state): State<ApiState>, request: Request) -> Response {
    // Authenticate before reading the body, so unauthenticated callers can't make the
    // server buffer and parse it, and learn nothing from validation errors.
    let headers = request.headers().clone();
    let tenant_id = match tenant(&state, &headers).await {
        Ok(tenant_id) => tenant_id,
        Err(response) => return response,
    };
    let body = match axum::Json::<CreateBody>::from_request(request, &state).await {
        Ok(axum::Json(body)) => body,
        Err(rejection) => return problem(rejection.status(), &rejection.body_text()),
    };
    let idempotency_key = match headers.get("idempotency-key") {
        None => None,
        Some(value) => match value.to_str() {
            Ok(key)
                if !key.is_empty()
                    && key.len() <= MAX_IDEMPOTENCY_KEY_BYTES
                    && key.bytes().all(|b| b.is_ascii_graphic()) =>
            {
                Some(key)
            }
            _ => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "Idempotency-Key must be 1-255 visible ASCII characters",
                );
            }
        },
    };
    if let Err(message) = validate_input(&body) {
        return problem(StatusCode::UNPROCESSABLE_ENTITY, message);
    }
    let ttl = match body.ttl_seconds.map(Duration::from_secs) {
        None => state.config.default_ttl,
        Some(ttl) if (MIN_TTL..=state.config.max_ttl).contains(&ttl) => ttl,
        Some(_) => {
            return problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!(
                    "ttl_seconds must be between {} and {}",
                    MIN_TTL.as_secs(),
                    state.config.max_ttl.as_secs()
                ),
            );
        }
    };
    let Ok(ttl) = chrono::Duration::from_std(ttl) else {
        return internal_error(tenant_id, anyhow::anyhow!("ttl out of range"));
    };
    let new = NewTask {
        tenant_id,
        repo_url: &body.repo_url,
        instructions: &body.instructions,
        expires_at: Utc::now() + ttl,
    };
    // A retry of an accepted submission must succeed even if the repository's binding
    // changed since, so answer replays before checking it.
    if let Some(key) = idempotency_key {
        match db::replay(&state.pool, &new, key).await {
            Ok(Some(replay)) => return submitted(tenant_id, replay),
            Ok(None) => {}
            Err(error) => return internal_error(tenant_id, error),
        }
    }
    if state.config.require_repository_binding {
        match repository_ready(&state.pool, tenant_id, &body.repo_url).await {
            Ok(true) => {}
            Ok(false) => {
                return problem(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "repository is not configured for this tenant",
                );
            }
            Err(error) => return internal_error(tenant_id, error),
        }
    }

    let submission = Submission {
        task: new,
        idempotency_key,
        max_pending: state.config.max_pending_per_tenant,
    };
    let Some(_turn) = state.submit_gates.enter(tenant_id).await else {
        return busy();
    };
    match db::submit_task(&state.pool, &submission).await {
        Ok(outcome) => submitted(tenant_id, outcome),
        Err(error) => internal_error(tenant_id, error),
    }
}

fn submitted(tenant_id: Uuid, outcome: Submitted) -> Response {
    match outcome {
        Submitted::Created(task) => {
            info!(%tenant_id, task_id = %task.id, "task submitted");
            let location = format!("/v1/tasks/{}", task.id);
            let mut response = reply(StatusCode::CREATED, TaskView::from(task));
            if let Ok(location) = HeaderValue::from_str(&location) {
                response.headers_mut().insert(header::LOCATION, location);
            }
            response
        }
        Submitted::Existing(task) => reply(StatusCode::OK, TaskView::from(task)),
        Submitted::KeyReused => problem(
            StatusCode::CONFLICT,
            "Idempotency-Key was already used for a different task",
        ),
        Submitted::TooManyPending => problem(
            StatusCode::TOO_MANY_REQUESTS,
            "too many queued or active tasks; wait for some to finish",
        ),
    }
}

fn validate_input(body: &CreateBody) -> Result<(), &'static str> {
    if body.repo_url.len() > MAX_REPO_URL_BYTES
        || crate::credentials::repository_name(&body.repo_url).is_err()
    {
        return Err("repo_url must be https://github.com/<owner>/<repo>");
    }
    if body.instructions.trim().is_empty() {
        return Err("instructions must not be empty");
    }
    if body.instructions.len() > MAX_INSTRUCTIONS_BYTES {
        return Err("instructions must be at most 65536 bytes");
    }
    if body.instructions.contains('\0') {
        return Err("instructions must not contain NUL characters"); // Postgres text can't.
    }
    Ok(())
}

/// Whether the tenant's binding for this repository exists and has usable checks.
async fn repository_ready(pool: &PgPool, tenant_id: Uuid, repo_url: &str) -> anyhow::Result<bool> {
    match crate::credentials::for_task(pool, tenant_id, repo_url).await {
        Ok(binding) => {
            Ok(crate::credentials::validate_checks(binding.check_command.as_deref()).is_ok())
        }
        Err(error) if error.is::<crate::credentials::RepositoryConfigurationError>() => Ok(false),
        Err(error) => Err(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    state: Option<TaskState>,
    limit: Option<i64>,
    /// `next_cursor` from the previous page.
    cursor: Option<Uuid>,
}

#[derive(Serialize)]
struct Page {
    tasks: Vec<TaskView>,
    next_cursor: Option<Uuid>,
}

async fn list(
    State(state): State<ApiState>,
    headers: HeaderMap,
    params: Result<Query<ListParams>, QueryRejection>,
) -> Response {
    let tenant_id = match tenant(&state, &headers).await {
        Ok(tenant_id) => tenant_id,
        Err(response) => return response,
    };
    let Query(params) = match params {
        Ok(params) => params,
        Err(rejection) => return problem(StatusCode::BAD_REQUEST, &rejection.body_text()),
    };
    let limit = params.limit.unwrap_or(DEFAULT_PAGE);
    if !(1..=MAX_PAGE).contains(&limit) {
        return problem(StatusCode::BAD_REQUEST, "limit must be between 1 and 100");
    }
    // One extra row says whether another page exists.
    let mut tasks = match db::list_tasks(
        &state.pool,
        tenant_id,
        params.state,
        params.cursor,
        limit + 1,
    )
    .await
    {
        Ok(tasks) => tasks,
        Err(error) => return internal_error(tenant_id, error),
    };
    let next_cursor = if tasks.len() > limit as usize {
        tasks.truncate(limit as usize);
        tasks.last().map(|task| task.id)
    } else {
        None
    };
    reply(
        StatusCode::OK,
        Page {
            tasks: tasks.into_iter().map(TaskView::from).collect(),
            next_cursor,
        },
    )
}

async fn show(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant_id = match tenant(&state, &headers).await {
        Ok(tenant_id) => tenant_id,
        Err(response) => return response,
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return not_found();
    };
    match db::get_task(&state.pool, tenant_id, id).await {
        Ok(Some(task)) => reply(StatusCode::OK, TaskView::from(task)),
        Ok(None) => not_found(),
        Err(error) => internal_error(tenant_id, error),
    }
}

async fn cancel(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant_id = match tenant(&state, &headers).await {
        Ok(tenant_id) => tenant_id,
        Err(response) => return response,
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return not_found();
    };
    match db::cancel_task(&state.pool, tenant_id, id).await {
        Ok(Cancelled::Cancelled(task)) => {
            info!(%tenant_id, task_id = %task.id, "task cancelled");
            reply(StatusCode::OK, TaskView::from(task))
        }
        Ok(Cancelled::Finished(task)) => reply(
            StatusCode::CONFLICT,
            json!({ "error": "task already finished", "task": TaskView::from(task) }),
        ),
        Ok(Cancelled::NotFound) => not_found(),
        Err(error) => internal_error(tenant_id, error),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use tokio::net::TcpListener;

    use super::*;

    const REPO: &str = "https://github.com/owner/repo";

    fn config() -> TaskApiConfig {
        TaskApiConfig {
            default_ttl: Duration::from_secs(3600),
            max_ttl: Duration::from_secs(7200),
            max_pending_per_tenant: 3,
            require_repository_binding: false,
        }
    }

    struct Client {
        base: String,
        http: reqwest::Client,
    }

    impl Client {
        async fn start(pool: PgPool, config: TaskApiConfig) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let app = crate::api::router(pool.clone()).merge(router(pool, config));
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            Client {
                base,
                http: reqwest::Client::new(),
            }
        }

        async fn send(&self, request: reqwest::RequestBuilder) -> (u16, HeaderMap, Value) {
            let response = request.send().await.unwrap();
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response.json().await.unwrap_or(Value::Null);
            (status, headers, body)
        }

        async fn create(&self, key: &str, body: Value) -> (u16, HeaderMap, Value) {
            self.send(
                self.http
                    .post(format!("{}/v1/tasks", self.base))
                    .bearer_auth(key)
                    .json(&body),
            )
            .await
        }

        async fn get(&self, key: &str, path: &str) -> (u16, Value) {
            let (status, _, body) = self
                .send(
                    self.http
                        .get(format!("{}{path}", self.base))
                        .bearer_auth(key),
                )
                .await;
            (status, body)
        }

        async fn cancel(&self, key: &str, id: &str) -> (u16, Value) {
            let (status, _, body) = self
                .send(
                    self.http
                        .post(format!("{}/v1/tasks/{id}/cancel", self.base))
                        .bearer_auth(key),
                )
                .await;
            (status, body)
        }
    }

    async fn key(pool: &PgPool, tenant: Uuid) -> String {
        crate::api_keys::create(pool, tenant, "test")
            .await
            .unwrap()
            .key
    }

    fn task_body(instructions: &str) -> Value {
        json!({ "repo_url": REPO, "instructions": instructions })
    }

    #[sqlx::test]
    async fn requests_without_a_valid_key_are_rejected(pool: PgPool) {
        let client = Client::start(pool.clone(), config()).await;
        let revoked = crate::api_keys::create(&pool, Uuid::new_v4(), "old")
            .await
            .unwrap();
        crate::api_keys::revoke(&pool, revoked.id).await.unwrap();
        let unknown = format!("sf_{}", "0".repeat(64));

        for bad in [
            None,
            Some("garbage"),
            Some(unknown.as_str()),
            Some(&revoked.key),
        ] {
            let mut request = client.http.post(format!("{}/v1/tasks", client.base));
            if let Some(bad) = bad {
                request = request.bearer_auth(bad);
            }
            // Not even valid JSON: authentication must fail first.
            let (status, headers, _) = client.send(request.body("{")).await;
            assert_eq!(status, 401, "{bad:?}");
            assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
        }
        let (status, _) = client.get(&unknown, "/v1/tasks").await;
        assert_eq!(status, 401);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM tasks")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[sqlx::test]
    async fn submitted_tasks_are_queued_and_visible_only_to_their_tenant(pool: PgPool) {
        let client = Client::start(pool.clone(), config()).await;
        let tenant = Uuid::new_v4();
        let mine = key(&pool, tenant).await;
        let theirs = key(&pool, Uuid::new_v4()).await;

        let (status, headers, task) = client
            .create(
                &mine,
                json!({ "repo_url": REPO, "instructions": "fix it", "ttl_seconds": 600 }),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        let id = task["id"].as_str().unwrap().to_owned();
        assert_eq!(
            headers[header::LOCATION],
            format!("/v1/tasks/{id}").as_str()
        );
        assert_eq!(task["state"], "queued");
        assert_eq!(task["repo_url"], REPO);
        assert_eq!(task["instructions"], "fix it");
        assert!(
            task.get("vm_instance_id").is_none(),
            "internal ids stay hidden"
        );
        let stored = db::get_task(&pool, tenant, id.parse().unwrap())
            .await
            .unwrap()
            .unwrap();
        let ttl = stored.expires_at - stored.created_at;
        assert!((590..=610).contains(&ttl.num_seconds()), "{ttl}");

        assert_eq!(
            client.get(&mine, &format!("/v1/tasks/{id}")).await.1["id"],
            id
        );
        assert_eq!(client.get(&theirs, &format!("/v1/tasks/{id}")).await.0, 404);
        assert_eq!(client.get(&mine, "/v1/tasks/not-a-uuid").await.0, 404);
        assert_eq!(client.cancel(&theirs, &id).await.0, 404);
        let (_, page) = client.get(&theirs, "/v1/tasks").await;
        assert_eq!(page["tasks"], json!([]));
        assert_eq!(
            client.get(&mine, &format!("/v1/tasks/{id}")).await.1["state"],
            "queued",
            "the other tenant's cancel changed nothing"
        );
    }

    #[sqlx::test]
    async fn invalid_input_is_rejected_without_creating_tasks(pool: PgPool) {
        let client = Client::start(pool.clone(), config()).await;
        let key = key(&pool, Uuid::new_v4()).await;
        let long = "x".repeat(MAX_INSTRUCTIONS_BYTES + 1);
        let cases = [
            (
                json!({ "repo_url": "https://gitlab.com/o/r", "instructions": "x" }),
                422,
            ),
            (
                json!({ "repo_url": "https://github.com/o/r/extra", "instructions": "x" }),
                422,
            ),
            (json!({ "repo_url": REPO, "instructions": "  " }), 422),
            (json!({ "repo_url": REPO, "instructions": "a\u{0}b" }), 422),
            (json!({ "repo_url": REPO, "instructions": long }), 422),
            (
                json!({ "repo_url": REPO, "instructions": "x", "ttl_seconds": 299 }),
                422,
            ),
            (
                json!({ "repo_url": REPO, "instructions": "x", "ttl_seconds": 7201 }),
                422,
            ),
            (
                json!({ "repo_url": REPO, "instructions": "x", "tenant_id": Uuid::new_v4() }),
                422,
            ),
            (json!({ "repo_url": REPO }), 422),
        ];
        for (body, expected) in cases {
            let (status, _, response) = client.create(&key, body.clone()).await;
            assert_eq!(status, expected, "{body}");
            assert!(response["error"].is_string(), "{body}");
        }
        let (status, _, _) = client
            .send(
                client
                    .http
                    .post(format!("{}/v1/tasks", client.base))
                    .bearer_auth(&key)
                    .header("content-type", "application/json")
                    .body("{"),
            )
            .await;
        assert_eq!(status, 400);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM tasks")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[sqlx::test]
    async fn idempotency_keys_replay_or_conflict(pool: PgPool) {
        let client = Client::start(pool.clone(), config()).await;
        let key = key(&pool, Uuid::new_v4()).await;
        let other_tenant = self::key(&pool, Uuid::new_v4()).await;
        let submit = |key: String, instructions: &'static str, idem: &'static str| {
            let request = client
                .http
                .post(format!("{}/v1/tasks", client.base))
                .bearer_auth(key)
                .header("Idempotency-Key", idem)
                .json(&task_body(instructions));
            client.send(request)
        };

        let (status, _, first) = submit(key.clone(), "one", "abc").await;
        assert_eq!(status, 201);
        let (status, _, again) = submit(key.clone(), "one", "abc").await;
        assert_eq!((status, &again["id"]), (200, &first["id"]));
        let (status, _, _) = submit(key.clone(), "two", "abc").await;
        assert_eq!(status, 409);
        let (status, _, theirs) = submit(other_tenant, "one", "abc").await;
        assert_eq!(status, 201, "keys are scoped per tenant");
        assert_ne!(theirs["id"], first["id"]);
        let (status, _, _) = submit(key.clone(), "one", "has space").await;
        assert_eq!(status, 400);
    }

    #[sqlx::test]
    async fn pending_tasks_are_capped_per_tenant(pool: PgPool) {
        let client = Client::start(pool.clone(), config()).await;
        let key = key(&pool, Uuid::new_v4()).await;
        let other = self::key(&pool, Uuid::new_v4()).await;
        let mut ids = Vec::new();
        for _ in 0..3 {
            let (status, _, task) = client.create(&key, task_body("x")).await;
            assert_eq!(status, 201);
            ids.push(task["id"].as_str().unwrap().to_owned());
        }
        assert_eq!(client.create(&key, task_body("x")).await.0, 429);
        assert_eq!(client.create(&other, task_body("x")).await.0, 201);
        assert_eq!(client.cancel(&key, &ids[0]).await.0, 200);
        assert_eq!(client.create(&key, task_body("x")).await.0, 201);
    }

    #[sqlx::test]
    async fn concurrent_submissions_respect_the_cap(pool: PgPool) {
        let client = Client::start(pool.clone(), config()).await;
        let key = key(&pool, Uuid::new_v4()).await;
        let mut handles = Vec::new();
        for _ in 0..10 {
            let (http, base, key) = (client.http.clone(), client.base.clone(), key.clone());
            handles.push(tokio::spawn(async move {
                http.post(format!("{base}/v1/tasks"))
                    .bearer_auth(key)
                    .json(&task_body("x"))
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .as_u16()
            }));
        }
        let mut statuses = Vec::new();
        for handle in handles {
            statuses.push(handle.await.unwrap());
        }
        statuses.sort_unstable();
        assert_eq!(statuses, [201, 201, 201, 429, 429, 429, 429, 429, 429, 429]);
    }

    #[sqlx::test]
    async fn listing_pages_newest_first_and_filters_by_state(pool: PgPool) {
        let client = Client::start(
            pool.clone(),
            TaskApiConfig {
                max_pending_per_tenant: 10,
                ..config()
            },
        )
        .await;
        let key = key(&pool, Uuid::new_v4()).await;
        let mut ids = Vec::new();
        for n in 0..3 {
            let (_, _, task) = client.create(&key, task_body(&format!("task {n}"))).await;
            ids.push(task["id"].clone());
        }
        client.cancel(&key, ids[1].as_str().unwrap()).await;

        let (status, first) = client.get(&key, "/v1/tasks?limit=2").await;
        assert_eq!(status, 200);
        assert_eq!(first["tasks"][0]["id"], ids[2]);
        assert_eq!(first["tasks"][1]["id"], ids[1]);
        let cursor = first["next_cursor"].as_str().unwrap();
        assert_eq!(cursor, ids[1]);
        let (_, second) = client
            .get(&key, &format!("/v1/tasks?limit=2&cursor={cursor}"))
            .await;
        assert_eq!(second["tasks"].as_array().unwrap().len(), 1);
        assert_eq!(second["tasks"][0]["id"], ids[0]);
        assert_eq!(second["next_cursor"], Value::Null);

        let (_, failed) = client.get(&key, "/v1/tasks?state=failed").await;
        assert_eq!(failed["tasks"].as_array().unwrap().len(), 1);
        assert_eq!(failed["tasks"][0]["id"], ids[1]);
        assert_eq!(failed["tasks"][0]["failure_reason"], db::CANCELLED_REASON);

        for bad in ["limit=0", "limit=101", "state=done", "cursor=x", "tenant=1"] {
            assert_eq!(
                client.get(&key, &format!("/v1/tasks?{bad}")).await.0,
                400,
                "{bad}"
            );
        }
    }

    #[sqlx::test]
    async fn cancel_is_idempotent_and_refuses_finished_tasks(pool: PgPool) {
        let client = Client::start(pool.clone(), config()).await;
        let key = key(&pool, Uuid::new_v4()).await;
        let (_, _, task) = client.create(&key, task_body("x")).await;
        let id = task["id"].as_str().unwrap();

        let (status, cancelled) = client.cancel(&key, id).await;
        assert_eq!(status, 200);
        assert_eq!(cancelled["state"], "failed");
        assert_eq!(cancelled["failure_reason"], db::CANCELLED_REASON);
        assert_eq!(client.cancel(&key, id).await.0, 200);

        let (_, _, done) = client.create(&key, task_body("y")).await;
        let done_id = done["id"].as_str().unwrap();
        sqlx::query("UPDATE tasks SET state = 'succeeded', result = 'ok' WHERE id = $1")
            .bind(Uuid::parse_str(done_id).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        let (status, body) = client.cancel(&key, done_id).await;
        assert_eq!(status, 409);
        assert_eq!(body["task"]["state"], "succeeded");
        assert_eq!(
            client.cancel(&key, &Uuid::new_v4().to_string()).await.0,
            404
        );
    }

    #[sqlx::test]
    async fn coding_mode_requires_a_configured_repository(pool: PgPool) {
        let client = Client::start(
            pool.clone(),
            TaskApiConfig {
                require_repository_binding: true,
                ..config()
            },
        )
        .await;
        let tenant = Uuid::new_v4();
        let key = key(&pool, tenant).await;
        let insert = "INSERT INTO repository_credentials \
            (tenant_id, repository, installation_id, repository_id, model_key_parameter, check_command) \
            VALUES ($1, 'owner/repo', 1, 2, 'p', $2)";

        assert_eq!(client.create(&key, task_body("x")).await.0, 422);
        // Another tenant's binding doesn't count.
        sqlx::query(insert)
            .bind(Uuid::new_v4())
            .bind(vec!["make", "test"])
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(client.create(&key, task_body("x")).await.0, 422);
        // A binding without checks can't run a coding task.
        sqlx::query(insert)
            .bind(tenant)
            .bind(None::<Vec<String>>)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(client.create(&key, task_body("x")).await.0, 422);
        sqlx::query("UPDATE repository_credentials SET check_command = $2 WHERE tenant_id = $1")
            .bind(tenant)
            .bind(vec!["make", "test"])
            .execute(&pool)
            .await
            .unwrap();
        let (status, _, _) = client
            .create(
                &key,
                json!({ "repo_url": "https://github.com/Owner/Repo.git", "instructions": "x" }),
            )
            .await;
        assert_eq!(status, 201, "repository names match case-insensitively");

        // A retried submission still replays after its binding is removed.
        let retry = || {
            client
                .http
                .post(format!("{}/v1/tasks", client.base))
                .bearer_auth(&key)
                .header("Idempotency-Key", "retry-1")
                .json(&task_body("keyed"))
        };
        let (status, _, first) = client.send(retry()).await;
        assert_eq!(status, 201);
        sqlx::query("DELETE FROM repository_credentials WHERE tenant_id = $1")
            .bind(tenant)
            .execute(&pool)
            .await
            .unwrap();
        let (status, _, again) = client.send(retry()).await;
        assert_eq!(status, 200);
        assert_eq!(again["id"], first["id"]);
        assert_eq!(client.create(&key, task_body("new")).await.0, 422);
    }

    #[sqlx::test]
    async fn authentication_precedes_reading_the_body(pool: PgPool) {
        let client = Client::start(pool.clone(), config()).await;
        let key = key(&pool, Uuid::new_v4()).await;
        let oversized = "x".repeat(8 * MAX_INSTRUCTIONS_BYTES);
        let request = |auth: Option<&str>| {
            let mut request = client
                .http
                .post(format!("{}/v1/tasks", client.base))
                .header(header::CONTENT_TYPE, "application/json")
                .body(oversized.clone());
            if let Some(auth) = auth {
                request = request.header(header::AUTHORIZATION, auth);
            }
            request
        };
        assert_eq!(client.send(request(None)).await.0, 401);
        assert_eq!(
            client.send(request(Some(&format!("Bearer {key}")))).await.0,
            413
        );
        // The scheme is case-insensitive (RFC 9110).
        let (status, _, _) = client
            .send(
                client
                    .http
                    .post(format!("{}/v1/tasks", client.base))
                    .header(header::AUTHORIZATION, format!("bearer {key}"))
                    .json(&task_body("x")),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(
            client.send(request(Some(&format!("Basic {key}")))).await.0,
            401
        );
    }

    #[sqlx::test]
    async fn expired_tasks_do_not_count_against_the_cap(pool: PgPool) {
        let client = Client::start(pool.clone(), config()).await;
        let tenant = Uuid::new_v4();
        let key = key(&pool, tenant).await;
        for _ in 0..3 {
            assert_eq!(client.create(&key, task_body("x")).await.0, 201);
        }
        assert_eq!(client.create(&key, task_body("x")).await.0, 429);
        sqlx::query(
            "UPDATE tasks SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 second' WHERE tenant_id = $1",
        )
        .bind(tenant)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(client.create(&key, task_body("x")).await.0, 201);
    }

    #[tokio::test]
    async fn submit_gates_serialise_a_tenant_and_forget_idle_ones() {
        let gates = SubmitGates::default();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let first = gates.enter(a).await.unwrap();
        // Another tenant isn't held up.
        drop(gates.enter(b).await.unwrap());
        let waiter = tokio::spawn({
            let gates = gates.clone();
            async move { gates.enter(a).await.is_some() }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "same tenant waits its turn");
        drop(first);
        assert!(waiter.await.unwrap());
        assert!(gates.0.lock().unwrap().is_empty(), "idle gates are dropped");
    }

    #[test]
    fn load_failures_are_reported_as_busy() {
        assert!(saturated(
            &anyhow::Error::new(sqlx::Error::PoolTimedOut).context("x")
        ));
        assert!(!saturated(&anyhow::Error::new(sqlx::Error::RowNotFound)));
        assert!(!saturated(&anyhow::anyhow!("other")));
    }
}
