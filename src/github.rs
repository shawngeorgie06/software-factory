//! Repository-scoped GitHub App credentials. This module never loads secrets itself.

use std::{fmt, time::Duration};

use anyhow::{Result, anyhow, ensure};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::{Client, StatusCode, header, redirect::Policy};
use serde::{Deserialize, Serialize};

const API_BASE: &str = "https://api.github.com";
const API_VERSION: &str = "2026-03-10";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;

pub struct GitHubApp {
    app_id: String,
    signing_key: EncodingKey,
    client: Client,
    // Only unit tests can replace the fixed production endpoint.
    #[cfg(test)]
    test_endpoint: Option<String>,
}

#[derive(Debug)]
pub struct GitHubConfigurationError {
    pub status: u16,
}
impl fmt::Display for GitHubConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GitHub repository installation is not configured (HTTP {})",
            self.status
        )
    }
}
impl std::error::Error for GitHubConfigurationError {}

pub struct InstallationToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for InstallationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstallationToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    expires_at: String,
}

impl GitHubApp {
    pub fn new(app_id: String, private_key_pem: &[u8]) -> Result<Self> {
        ensure!(
            !app_id.is_empty()
                && app_id.bytes().all(|b| b.is_ascii_digit())
                && app_id.parse::<u64>().is_ok_and(|id| id > 0),
            "GitHub App ID must be a positive integer"
        );
        let signing_key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|_| anyhow!("invalid GitHub App RSA private key"))?;
        Ok(Self {
            app_id,
            signing_key,
            client: Self::build_client(true)?,
            #[cfg(test)]
            test_endpoint: None,
        })
    }

    fn build_client(https_only: bool) -> Result<Client> {
        Client::builder()
            .https_only(https_only)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .user_agent("software-factory-github-app")
            .build()
            .map_err(|_| anyhow!("could not initialize GitHub HTTP client"))
    }

    fn jwt(&self, now: DateTime<Utc>) -> Result<String> {
        // GitHub recommends backdating iat by 60s for clock drift; exp must be
        // at most ten minutes ahead. Use five minutes to leave ample margin.
        let claims = Claims {
            iss: &self.app_id,
            iat: now.timestamp() - 60,
            exp: now.timestamp() + 300,
        };
        encode(&Header::new(Algorithm::RS256), &claims, &self.signing_key)
            .map_err(|_| anyhow!("could not sign GitHub App JWT"))
    }

    pub async fn mint_repository_token(
        &self,
        installation_id: u64,
        repository_id: u64,
    ) -> Result<InstallationToken> {
        ensure!(
            installation_id > 0,
            "GitHub installation ID must be positive"
        );
        ensure!(repository_id > 0, "GitHub repository ID must be positive");
        let base = API_BASE;
        #[cfg(test)]
        let base = self.test_endpoint.as_deref().unwrap_or(base);
        let jwt = self.jwt(Utc::now())?;
        let mut authorization = header::HeaderValue::from_str(&format!("Bearer {jwt}"))
            .map_err(|_| anyhow!("could not construct GitHub authorization"))?;
        authorization.set_sensitive(true);
        let mut response = self
            .client
            .post(format!(
                "{base}/app/installations/{installation_id}/access_tokens"
            ))
            .header(header::AUTHORIZATION, authorization)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .json(&serde_json::json!({
                "repository_ids": [repository_id],
                "permissions": {"contents": "write", "pull_requests": "write"}
            }))
            .send()
            .await
            // Deliberately discard underlying errors: URLs, headers, and body
            // contents from third-party errors must not reach logs.
            .map_err(|_| anyhow!("GitHub installation token request failed"))?;
        if matches!(
            response.status(),
            StatusCode::NOT_FOUND | StatusCode::UNPROCESSABLE_ENTITY
        ) {
            return Err(GitHubConfigurationError {
                status: response.status().as_u16(),
            }
            .into());
        }
        ensure!(
            response.status() == StatusCode::CREATED,
            "GitHub installation token request returned HTTP {}",
            response.status().as_u16()
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= MAX_RESPONSE_BYTES as u64),
            "GitHub installation token response exceeds size limit"
        );
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow!("could not read GitHub installation token response"))?
        {
            ensure!(
                chunk.len() <= MAX_RESPONSE_BYTES - body.len(),
                "GitHub installation token response exceeds size limit"
            );
            body.extend_from_slice(&chunk);
        }
        let parsed: TokenResponse = serde_json::from_slice(&body)
            .map_err(|_| anyhow!("invalid GitHub installation token response"))?;
        validate_token_response(parsed, Utc::now())
    }
}

fn validate_token_response(
    response: TokenResponse,
    now: DateTime<Utc>,
) -> Result<InstallationToken> {
    // Accept both legacy opaque and stateless JWT-based GitHub tokens. Do not
    // depend on a fixed prefix or length; require safe bearer-token characters.
    ensure!(
        !response.token.is_empty()
            && response.token.len() <= MAX_TOKEN_BYTES
            && response
                .token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b)),
        "invalid GitHub installation token"
    );
    let expires_at = DateTime::parse_from_rfc3339(&response.expires_at)
        .map_err(|_| anyhow!("invalid GitHub installation token expiry"))?
        .with_timezone(&Utc);
    // Installation tokens last one hour. Allow five minutes of clock skew,
    // and reject credentials too close to expiry to hand off safely.
    ensure!(
        expires_at > now + chrono::Duration::seconds(60)
            && expires_at <= now + chrono::Duration::minutes(65),
        "GitHub installation token expiry is outside the permitted window"
    );
    Ok(InstallationToken {
        token: response.token,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation, decode};
    use serde_json::{Value, json};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    // Synthetic test key, generated solely for these fixtures; never registered
    // with GitHub and never used for any real credentials.
    const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/github/test-private.pem");
    const PUBLIC_KEY: &[u8] = include_bytes!("../tests/fixtures/github/test-public.pem");
    const SECRET: &str = "ghs_SYNTHETIC_SECRET_NEVER_LOG";

    fn app() -> GitHubApp {
        GitHubApp::new("123".into(), PRIVATE_KEY).unwrap()
    }

    fn success_body() -> String {
        json!({"token": SECRET, "expires_at": (Utc::now() + chrono::Duration::hours(1)).to_rfc3339()}).to_string()
    }

    fn mock_app(
        status: &str,
        headers: &str,
        body: String,
    ) -> (GitHubApp, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let response = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{headers}\r\n{body}");
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0u8; 4096];
                let n = socket.read(&mut buffer).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buffer[..n]);
                if let Some(split) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..split]);
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|n| n.trim().parse().unwrap())
                        })
                        .unwrap();
                    if request.len() >= split + 4 + length {
                        break;
                    }
                }
            }
            tx.send(String::from_utf8(request).unwrap()).unwrap();
            let _ = socket.write_all(response.as_bytes());
        });
        let mut app = app();
        app.client = Client::builder()
            .https_only(false)
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        app.test_endpoint = Some(endpoint);
        (app, rx, handle)
    }

    async fn exchange(status: &str, body: String) -> Result<InstallationToken> {
        let headers = format!("Content-Length: {}\r\n", body.len());
        let (app, request, server) = mock_app(status, &headers, body);
        let result = app.mint_repository_token(456, 789).await;
        let _ = request.recv_timeout(Duration::from_secs(3)).unwrap();
        server.join().unwrap();
        result
    }

    fn assert_redacted(error: anyhow::Error) {
        for rendered in [
            format!("{error}"),
            format!("{error:?}"),
            format!("{error:#}"),
        ] {
            assert!(!rendered.contains(SECRET));
            assert!(!rendered.contains("PRIVATE KEY"));
            assert!(!rendered.contains("Bearer"));
        }
    }

    #[test]
    fn validates_app_and_key_without_echoing_input() {
        for id in ["", "0", "-1", "+1", " 1", "abc", "18446744073709551616"] {
            assert!(GitHubApp::new(id.into(), PRIVATE_KEY).is_err());
        }
        assert_redacted(GitHubApp::new("1".into(), SECRET.as_bytes()).err().unwrap());
    }

    #[test]
    fn jwt_has_verified_rs256_signature_and_skew_safe_claims() {
        let now = Utc::now();
        let jwt = app().jwt(now).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["123"]);
        let decoded = decode::<Value>(
            &jwt,
            &DecodingKey::from_rsa_pem(PUBLIC_KEY).unwrap(),
            &validation,
        )
        .unwrap();
        assert_eq!(decoded.header.alg, Algorithm::RS256);
        assert_eq!(decoded.claims["iss"], "123");
        assert_eq!(decoded.claims["iat"], now.timestamp() - 60);
        assert_eq!(decoded.claims["exp"], now.timestamp() + 300);
    }

    #[tokio::test]
    async fn request_is_scoped_and_response_debug_is_redacted() {
        let body = success_body();
        let (app, requests, server) = mock_app(
            "201 Created",
            &format!("Content-Length: {}\r\n", body.len()),
            body,
        );
        let token = app.mint_repository_token(456, 789).await.unwrap();
        let request = requests.recv_timeout(Duration::from_secs(3)).unwrap();
        server.join().unwrap();
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("POST /app/installations/456/access_tokens HTTP/1.1\r\n"));
        let headers = headers.to_ascii_lowercase();
        assert!(headers.contains("accept: application/vnd.github+json"));
        assert!(headers.contains(&format!("x-github-api-version: {API_VERSION}")));
        assert!(headers.contains("authorization: bearer ey"));
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            json!({
                "repository_ids": [789], "permissions": {"contents": "write", "pull_requests": "write"}
            })
        );
        assert_eq!(token.token, SECRET);
        assert!(token.expires_at > Utc::now());
        assert!(!format!("{token:?}").contains(SECRET));
    }

    #[tokio::test]
    async fn zero_ids_fail_before_network() {
        for (installation, repository) in [(0, 1), (1, 0)] {
            assert!(
                app()
                    .mint_repository_token(installation, repository)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("positive")
            );
        }
    }

    #[tokio::test]
    async fn failures_discard_response_bodies() {
        for status in [
            "401 Unauthorized",
            "403 Forbidden",
            "429 Too Many Requests",
            "500 Internal Server Error",
            "200 OK",
        ] {
            let error = exchange(status, SECRET.into()).await.unwrap_err();
            assert!(error.to_string().contains(&status[..3]));
            assert_redacted(error);
        }
        for body in [
            SECRET.to_string(),
            json!({"token": SECRET}).to_string(),
            json!({"token": SECRET,"expires_at": SECRET}).to_string(),
        ] {
            assert_redacted(exchange("201 Created", body).await.unwrap_err());
        }
    }

    #[tokio::test]
    async fn permanent_repository_scope_failures_are_typed_without_exposing_bodies() {
        for status in ["404 Not Found", "422 Unprocessable Entity"] {
            let error = exchange(status, SECRET.into()).await.unwrap_err();
            assert!(error.is::<GitHubConfigurationError>());
            assert_redacted(error);
        }
    }

    #[tokio::test]
    async fn redirects_are_rejected_without_following_or_leaking() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        for status in [
            "301 Moved Permanently",
            "302 Found",
            "307 Temporary Redirect",
            "308 Permanent Redirect",
        ] {
            let headers = format!(
                "Location: http://{}/{}\r\nContent-Length: 0\r\n",
                target.local_addr().unwrap(),
                SECRET
            );
            let (app, request, server) = mock_app(status, &headers, String::new());
            assert_redacted(app.mint_repository_token(1, 1).await.unwrap_err());
            request.recv_timeout(Duration::from_secs(3)).unwrap();
            server.join().unwrap();
            assert_eq!(
                target.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }

    #[tokio::test]
    async fn bounded_reads_reject_content_length_and_chunked_overflow() {
        let huge = "x".repeat(MAX_RESPONSE_BYTES + 1);
        assert_redacted(exchange("201 Created", huge.clone()).await.unwrap_err());
        let chunked = format!("{:x}\r\n{}\r\n0\r\n\r\n", huge.len(), huge);
        let (app, request, server) =
            mock_app("201 Created", "Transfer-Encoding: chunked\r\n", chunked);
        assert_redacted(app.mint_repository_token(1, 1).await.unwrap_err());
        request.recv_timeout(Duration::from_secs(3)).unwrap();
        server.join().unwrap();
    }

    #[tokio::test]
    async fn invalid_expiries_and_tokens_are_rejected() {
        for seconds in [-3600, 0, 30, 66 * 60] {
            let body = json!({"token": SECRET, "expires_at": (Utc::now() + chrono::Duration::seconds(seconds)).to_rfc3339()}).to_string();
            assert_redacted(exchange("201 Created", body).await.unwrap_err());
        }
        for token in ["", " ", "bad\r\nheader", "bad token", "🔥"] {
            let body = json!({"token": token, "expires_at": (Utc::now() + chrono::Duration::hours(1)).to_rfc3339()}).to_string();
            assert_redacted(exchange("201 Created", body).await.unwrap_err());
        }
    }

    #[tokio::test]
    async fn stalled_response_times_out_and_truncated_body_is_redacted() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut app = app();
        app.test_endpoint = Some(format!("http://{}", listener.local_addr().unwrap()));
        app.client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut buffer = [0; 4096];
            assert!(socket.read(&mut buffer).unwrap() > 0);
            thread::sleep(Duration::from_millis(300));
        });
        let started = std::time::Instant::now();
        assert_redacted(app.mint_repository_token(1, 1).await.unwrap_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        server.join().unwrap();

        let (app, request, server) =
            mock_app("201 Created", "Content-Length: 1000\r\n", SECRET.into());
        assert_redacted(app.mint_repository_token(1, 1).await.unwrap_err());
        request.recv_timeout(Duration::from_secs(3)).unwrap();
        server.join().unwrap();
    }

    #[tokio::test]
    async fn transport_errors_do_not_echo_endpoint_secrets() {
        let mut app = app();
        app.test_endpoint = Some(format!("http://127.0.0.1:1/{SECRET}"));
        app.client = GitHubApp::build_client(true).unwrap();
        assert_redacted(app.mint_repository_token(1, 1).await.unwrap_err());
    }
}
