//! End-to-end verification against a local mock server. Proves the three
//! safety/correctness properties that matter most:
//!   1. cross-session IDOR detection (session B receives session A's data);
//!   2. session isolation (no shared cookie jar — B never carries A's cookie);
//!   3. redirects are captured, never followed (scope can't be escaped via 3xx).

use std::sync::Arc;

use idorra_core::config::Config;
use idorra_core::engine::Engine;
use idorra_core::logging::NullAuditLog;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Start a mock API on 127.0.0.1 and return its base URL.
async fn start_mock_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            if let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(handle_conn(sock));
            }
        }
    });
    format!("http://{addr}")
}

async fn handle_conn(mut sock: TcpStream) {
    let mut buf = [0u8; 8192];
    let mut data = Vec::new();
    // Read until the end of the request headers.
    loop {
        match sock.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let req = String::from_utf8_lossy(&data);
    let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("/");

    // Echo the credential the client actually sent (to prove isolation).
    let mut seen = String::from("none");
    for line in req.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("authorization:") || lower.starts_with("cookie:") {
            seen = line.split_once(':').map(|x| x.1).unwrap_or("").trim().replace('"', "'");
        }
    }

    let (status, extra, body) = route(path, &seen);
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
        body.len()
    );
    let _ = sock.write_all(resp.as_bytes()).await;
    let _ = sock.shutdown().await;
}

fn route(path: &str, seen: &str) -> (&'static str, String, String) {
    if path.starts_with("/api/orders/") {
        // IDOR simulation: the SAME owner data regardless of who asks.
        let id = path.rsplit('/').next().unwrap_or("0");
        ("200 OK", String::new(), format!("{{\"id\":\"{id}\",\"email\":\"victim@example.com\"}}"))
    } else if path.starts_with("/whoami/") {
        // Echoes the caller's own credential — bodies differ per session.
        ("200 OK", String::new(), format!("{{\"seen\":\"{seen}\"}}"))
    } else if path.starts_with("/redirect/") {
        ("302 Found", "Location: http://evil.invalid/stolen\r\n".to_string(), String::new())
    } else {
        ("404 Not Found", String::new(), "{}".to_string())
    }
}

fn config_toml(base_url: &str) -> String {
    format!(
        r#"
[general]
dry_run = false

[scope]
allow = ["127.0.0.1"]

[rate_limit]
requests_per_second = 1000.0
burst = 100
max_concurrency = 8

[[target]]
name = "mock"
base_url = "{base_url}"
baseline_session = "a"

  [[target.endpoint]]
  name = "orders"
  path_template = "/api/orders/{{id}}"
  method = "GET"
  id_param = "id"
  id_source = {{ kind = "range", start = 1, end = 2 }}
  sessions = ["a", "b"]

  [[target.endpoint]]
  name = "whoami"
  path_template = "/whoami/{{id}}"
  method = "GET"
  id_param = "id"
  id_source = {{ kind = "range", start = 1, end = 1 }}
  sessions = ["a", "b"]

  [[target.endpoint]]
  name = "redir"
  path_template = "/redirect/{{id}}"
  method = "GET"
  id_param = "id"
  id_source = {{ kind = "range", start = 1, end = 1 }}
  sessions = ["a", "b"]
"#
    )
}

const SECRETS: &str = r#"
[[session]]
name = "a"
cookie = "sid=AAA-cookie-secret"
[[session]]
name = "b"
bearer_token = "BBB-bearer-secret"
"#;

#[tokio::test]
async fn end_to_end_detects_idor_isolates_sessions_and_never_follows_redirects() {
    let base_url = start_mock_server().await;

    let mut config = Config::parse(&config_toml(&base_url)).unwrap();
    config.merge_secrets(SECRETS).unwrap();
    config.validate().unwrap();

    let engine = Engine::from_config(config, Arc::new(NullAuditLog), false, Some(false)).unwrap();
    assert!(!engine.is_dry_run());
    let summary = engine.run().await.unwrap();

    // Requests were actually sent, none blocked.
    assert!(summary.sent > 0, "expected live requests, got {}", summary.sent);
    assert_eq!(summary.blocked, 0);

    // (1) IDOR: a High cross-session finding with the exposed email.
    let idor = summary
        .findings
        .iter()
        .find(|f| f.summary.contains("identical") && f.detected_sensitive_fields.contains(&"email".to_string()));
    let idor = idor.expect("expected a cross-session IDOR finding on /api/orders");
    assert_eq!(idor.severity, idorra_core::Severity::High);

    // (2) Session isolation: each /whoami response echoes only that session's own
    // credential — B never carries A's cookie and vice-versa (no shared jar).
    let whoami: Vec<_> =
        summary.outcomes.iter().filter(|o| o.url.contains("/whoami/")).collect();
    assert_eq!(whoami.len(), 2);
    let a = whoami.iter().find(|o| o.session == "a").unwrap();
    let b = whoami.iter().find(|o| o.session == "b").unwrap();
    let a_body = a.response_body.as_deref().unwrap_or("");
    let b_body = b.response_body.as_deref().unwrap_or("");
    assert!(a_body.contains("AAA-cookie-secret"), "A should send its own cookie: {a_body}");
    assert!(!a_body.contains("BBB-bearer-secret"), "A must not carry B's token");
    assert!(b_body.contains("BBB-bearer-secret"), "B should send its own bearer: {b_body}");
    assert!(!b_body.contains("AAA-cookie-secret"), "B must not carry A's cookie (no shared jar)");

    // (3) Redirects captured but never followed; nothing sent to the out-of-scope host.
    let redirs: Vec<_> =
        summary.outcomes.iter().filter(|o| o.url.contains("/redirect/")).collect();
    assert!(!redirs.is_empty());
    for o in &redirs {
        assert_eq!(o.status, Some(302), "redirect must be returned as-is, not followed");
        assert!(o.redirect_location.as_deref() == Some("http://evil.invalid/stolen"));
    }
    assert!(
        !summary.outcomes.iter().any(|o| o.url.contains("evil.invalid")),
        "no request may target the out-of-scope redirect host"
    );
}
