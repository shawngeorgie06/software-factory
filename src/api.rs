//! HTTP endpoints the agent on a task's VM reports to, and the script that calls them.
//!
//! Each task gets its own bearer token (see [`new_agent_token`]); only its sha256 is stored.
//! A token authorises reports for its one task and nothing else.

use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::post;
use serde::Deserialize;
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::db;

/// Largest `result` accepted, matching the `tasks_result_size` constraint.
pub const MAX_RESULT_BYTES: usize = 65536;

pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route("/v1/tasks/{id}/heartbeat", post(heartbeat))
        .route("/v1/tasks/{id}/result", post(result))
        // Room for the largest result once JSON-escaped (`\u00XX` is 6 bytes per byte).
        .layer(DefaultBodyLimit::max(7 * MAX_RESULT_BYTES))
        .with_state(pool)
}

/// 256 bits from the OS CSPRNG (via two v4 UUIDs, 122 random bits each), hex encoded.
pub fn new_agent_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// The script SSM runs on a task's VM: one heartbeat, then a "hello" result.
///
/// `base_url` is how the VM reaches this API, e.g. `https://factory.example.com`.
pub fn hello_agent_script(base_url: &str, task_id: Uuid, token: &str) -> String {
    let task_url = format!("{}/v1/tasks/{task_id}", base_url.trim_end_matches('/'));
    format!(
        "set -eu\n\
         task_url={task_url}\n\
         auth={auth}\n\
         post() {{ curl -fsS --retry 5 --retry-all-errors --max-time 30 -X POST -H \"$auth\" \"$@\"; }}\n\
         post \"$task_url/heartbeat\"\n\
         post -H 'Content-Type: application/json' --data '{{\"result\":\"hello\"}}' \"$task_url/result\"\n",
        task_url = shell_quote(&task_url),
        auth = shell_quote(&format!("Authorization: Bearer {token}")),
    )
}

/// Checks the URL VMs use to reach this API and drops any trailing slash. Plain `http` is
/// accepted for local testing but sends agent tokens in the clear.
pub fn parse_agent_base_url(url: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        url.starts_with("https://") || url.starts_with("http://"),
        "agent base URL must start with https:// or http://, got {url:?}"
    );
    anyhow::ensure!(
        !url.chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '?' || c == '#'),
        "agent base URL must not contain whitespace, a query or a fragment, got {url:?}"
    );
    Ok(url.trim_end_matches('/').to_string())
}

/// Single-quotes `s` for POSIX sh.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[derive(Deserialize)]
struct ResultBody {
    result: String,
}

async fn heartbeat(
    State(pool): State<PgPool>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> StatusCode {
    let (id, token) = match authenticate(&id, &headers) {
        Ok(auth) => auth,
        Err(status) => return status,
    };
    match db::record_heartbeat(&pool, id, token).await {
        Ok(true) => StatusCode::NO_CONTENT,
        Ok(false) => StatusCode::NOT_FOUND,
        Err(e) => internal_error(id, e),
    }
}

async fn result(
    State(pool): State<PgPool>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<axum::Json<ResultBody>, axum::extract::rejection::JsonRejection>,
) -> StatusCode {
    let (id, token) = match authenticate(&id, &headers) {
        Ok(auth) => auth,
        Err(status) => return status,
    };
    // Authenticate before looking at the body, so unauthenticated callers learn nothing.
    let Ok(axum::Json(body)) = body else {
        return StatusCode::BAD_REQUEST;
    };
    if body.result.len() > MAX_RESULT_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    if body.result.contains('\0') {
        return StatusCode::BAD_REQUEST; // Postgres text can't hold NUL.
    }
    match db::record_result(&pool, id, token, &body.result).await {
        Ok(true) => StatusCode::NO_CONTENT,
        Ok(false) => StatusCode::NOT_FOUND,
        Err(e) => internal_error(id, e),
    }
}

/// Parses the task id and bearer token. A malformed id is a 404, like an unknown task;
/// a missing or malformed token is a 401. Whether the token is right is checked in Postgres,
/// and a wrong one is also a 404, so callers can't tell which tasks exist.
fn authenticate<'h>(id: &str, headers: &'h HeaderMap) -> Result<(Uuid, &'h str), StatusCode> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| !t.is_empty())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let id = Uuid::parse_str(id).map_err(|_| StatusCode::NOT_FOUND)?;
    Ok((id, token))
}

fn internal_error(task_id: Uuid, e: anyhow::Error) -> StatusCode {
    error!(%task_id, error = ?e, "agent report failed");
    StatusCode::INTERNAL_SERVER_ERROR
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::db::{Task, TaskState};

    /// Serves the router on an ephemeral port and returns its address.
    async fn serve(pool: PgPool) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, router(pool)).await.unwrap() });
        addr
    }

    /// Minimal HTTP/1.1 POST; returns the status code.
    async fn post(addr: &str, path: &str, token: Option<&str>, body: &str) -> u16 {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let auth = token.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"));
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Content-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response.split(' ').nth(1).unwrap().parse().unwrap()
    }

    /// A running task whose agent token is `token`.
    async fn running_task(pool: &PgPool, token: &str) -> Task {
        let task = db::create_test_task(pool, Uuid::new_v4(), Utc::now() + Duration::hours(1))
            .await
            .unwrap();
        sqlx::query("UPDATE tasks SET state = 'launching', vm_instance_id = $2 WHERE id = $1")
            .bind(task.id)
            .bind(format!("i-{}", task.id.simple()))
            .execute(pool)
            .await
            .unwrap();
        assert!(db::mark_running(pool, task.id).await.unwrap());
        assert!(db::set_agent_token(pool, task.id, token).await.unwrap());
        task
    }

    async fn reload(pool: &PgPool, task: &Task) -> Task {
        db::get_task(pool, task.tenant_id, task.id)
            .await
            .unwrap()
            .unwrap()
    }

    #[sqlx::test]
    async fn heartbeat_then_result_succeeds_the_task(pool: PgPool) {
        let addr = serve(pool.clone()).await;
        let task = running_task(&pool, "tok").await;
        sqlx::query("UPDATE tasks SET heartbeat_at = now() - interval '1 minute' WHERE id = $1")
            .bind(task.id)
            .execute(&pool)
            .await
            .unwrap();
        let before = reload(&pool, &task).await.heartbeat_at.unwrap();

        let base = format!("/v1/tasks/{}", task.id);
        assert_eq!(
            post(&addr, &format!("{base}/heartbeat"), Some("tok"), "").await,
            204
        );
        assert!(reload(&pool, &task).await.heartbeat_at.unwrap() > before);

        let result = format!("{base}/result");
        assert_eq!(
            post(&addr, &result, Some("tok"), r#"{"result":"hello"}"#).await,
            204
        );
        let done = reload(&pool, &task).await;
        assert_eq!(done.state, TaskState::Succeeded);
        assert_eq!(done.result.as_deref(), Some("hello"));

        // Finished tasks accept nothing more.
        assert_eq!(
            post(&addr, &format!("{base}/heartbeat"), Some("tok"), "").await,
            404
        );
    }

    #[sqlx::test]
    async fn bad_credentials_are_rejected_without_revealing_the_task(pool: PgPool) {
        let addr = serve(pool.clone()).await;
        let task = running_task(&pool, "tok").await;
        let other = running_task(&pool, "other-tok").await;
        let hb = format!("/v1/tasks/{}/heartbeat", task.id);

        assert_eq!(post(&addr, &hb, None, "").await, 401);
        assert_eq!(post(&addr, &hb, Some(""), "").await, 401);
        assert_eq!(post(&addr, &hb, Some("wrong"), "").await, 404);
        assert_eq!(post(&addr, &hb, Some("other-tok"), "").await, 404);
        let unknown = format!("/v1/tasks/{}/heartbeat", Uuid::new_v4());
        assert_eq!(post(&addr, &unknown, Some("tok"), "").await, 404);
        assert_eq!(
            post(&addr, "/v1/tasks/not-a-uuid/heartbeat", Some("tok"), "").await,
            404
        );

        let result = format!("/v1/tasks/{}/result", other.id);
        assert_eq!(
            post(&addr, &result, Some("tok"), r#"{"result":"x"}"#).await,
            404
        );
        assert_eq!(reload(&pool, &other).await.state, TaskState::Running);
    }

    #[sqlx::test]
    async fn malformed_or_oversized_results_are_rejected(pool: PgPool) {
        let addr = serve(pool.clone()).await;
        let task = running_task(&pool, "tok").await;
        let path = format!("/v1/tasks/{}/result", task.id);

        assert_eq!(
            post(&addr, &path, None, "not json").await,
            401,
            "auth comes first"
        );
        assert_eq!(post(&addr, &path, Some("tok"), "not json").await, 400);
        assert_eq!(post(&addr, &path, Some("tok"), r#"{"other":1}"#).await, 400);
        let big = format!(r#"{{"result":"{}"}}"#, "x".repeat(MAX_RESULT_BYTES + 1));
        assert_eq!(post(&addr, &path, Some("tok"), &big).await, 413);
        assert_eq!(
            post(&addr, &path, Some("tok"), r#"{"result":"a\u0000b"}"#).await,
            400
        );
        // Worst-case escaping of a maximum-size result still fits the body limit.
        let limit = format!(r#"{{"result":"{}"}}"#, r"\u0001".repeat(MAX_RESULT_BYTES));
        assert_eq!(post(&addr, &path, Some("tok"), &limit).await, 204);
    }

    #[test]
    fn tokens_are_long_and_unique() {
        let (a, b) = (new_agent_token(), new_agent_token());
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn agent_base_url_is_validated() {
        assert_eq!(
            parse_agent_base_url("https://f.example.com/").unwrap(),
            "https://f.example.com"
        );
        assert!(parse_agent_base_url("http://127.0.0.1:8080").is_ok());
        for bad in [
            "f.example.com",
            "ftp://x",
            "https://x y",
            "https://x\n",
            "https://x/?a=1",
            "https://x/#f",
            "",
        ] {
            assert!(parse_agent_base_url(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn shell_quote_survives_single_quotes() {
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
    }

    /// Runs the real script under sh against the real router, with curl on PATH.
    #[sqlx::test]
    async fn hello_script_reports_to_the_api(pool: PgPool) {
        let addr = serve(pool.clone()).await;
        let token = new_agent_token();
        let task = running_task(&pool, &token).await;

        let script = hello_agent_script(&format!("http://{addr}/"), task.id, &token);
        // Blocking call off the runtime, which is also serving the API.
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new("sh")
                .args(["-c", &script])
                .output()
        })
        .await
        .unwrap()
        .unwrap();

        assert!(output.status.success(), "{output:?}");
        let done = reload(&pool, &task).await;
        assert_eq!(done.state, TaskState::Succeeded);
        assert_eq!(done.result.as_deref(), Some("hello"));
    }
}
