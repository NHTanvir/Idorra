//! The gate: the **only** place in the crate that constructs a
//! [`reqwest::Client`] and the **only** place a request is executed.
//!
//! Every call to [`Gate::send`] runs the same unconditional sequence:
//! 1. scope check (host + port) — reject before building any request;
//! 2. dry-run short-circuit — nothing sent, no tokens/permits consumed;
//! 3. rate-limit token, then concurrency permit;
//! 4. audit-log the outgoing request;
//! 5. execute with redirects disabled, capping the captured body.
//!
//! `reqwest`'s cookie jar is never enabled, so sessions cannot cross-contaminate.

use crate::error::{Error, GateError, Result};
use crate::http::rate_limiter::Limiter;
use crate::http::request_builder::build_spec;
use crate::logging::{AuditEntry, AuditSink};
use crate::outcome::{RequestOutcome, RequestSpec};
use crate::session::Session;
use crate::testcase::TestCase;
use chrono::Utc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

/// Construction parameters for the gate that come from `[http]` + CLI flags.
#[derive(Debug, Clone)]
pub struct GateConfig {
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Total request timeout.
    pub request_timeout: Duration,
    /// Cap on response bytes captured into evidence.
    pub max_body_capture_bytes: usize,
    /// Optional upstream proxy URL.
    pub proxy: Option<String>,
    /// If true, nothing is ever sent.
    pub dry_run: bool,
    /// If true, secret header values appear unredacted in logs/reports.
    pub include_secrets_in_log: bool,
}

/// The outbound-HTTP choke point.
#[derive(Clone)]
pub struct Gate {
    client: reqwest::Client,
    scope: Arc<crate::scope::ScopeGuard>,
    limiter: Arc<Limiter>,
    audit: Arc<dyn AuditSink>,
    max_body_bytes: usize,
    dry_run: bool,
    include_secrets: bool,
}

impl Gate {
    /// Build a gate. This is the sole construction site of the HTTP client;
    /// the clippy `disallowed-methods` lint forbids it everywhere else.
    pub fn new(
        scope: Arc<crate::scope::ScopeGuard>,
        limiter: Arc<Limiter>,
        audit: Arc<dyn AuditSink>,
        cfg: GateConfig,
    ) -> Result<Self> {
        #[allow(clippy::disallowed_methods)]
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(cfg.connect_timeout)
            .timeout(cfg.request_timeout)
            .user_agent(concat!("idorra/", env!("CARGO_PKG_VERSION")));

        if let Some(proxy) = &cfg.proxy {
            let p = reqwest::Proxy::all(proxy)
                .map_err(|e| Error::Config(format!("invalid proxy {proxy:?}: {e}")))?;
            builder = builder.proxy(p);
        }

        let client =
            builder.build().map_err(|e| Error::Config(format!("building HTTP client: {e}")))?;

        Ok(Self {
            client,
            scope,
            limiter,
            audit,
            max_body_bytes: cfg.max_body_capture_bytes,
            dry_run: cfg.dry_run,
            include_secrets: cfg.include_secrets_in_log,
        })
    }

    /// Build the spec for a case+session and send it through the gate.
    pub async fn send_test_case(&self, tc: &TestCase, session: &Session) -> RequestOutcome {
        match build_spec(tc, session) {
            Ok(spec) => self.send(spec).await,
            Err(e) => {
                // A malformed spec never touches the network.
                let placeholder = RequestSpec {
                    method: tc.method,
                    url: tc.base_url.clone(),
                    headers: Vec::new(),
                    body: None,
                    content_type: None,
                    test_case_id: tc.id,
                    target_name: tc.target_name.clone(),
                    session: tc.session.clone(),
                    strategy: tc.strategy,
                    param_location: tc.param_location,
                    id_value: tc.id_value.clone(),
                    comparison_group_id: tc.comparison_group_id,
                    protocol: tc.protocol,
                    is_baseline: tc.is_baseline,
                };
                RequestOutcome::failed(&placeholder, self.include_secrets, e.to_string())
            }
        }
    }

    /// The single send path. Never panics; failures become [`RequestOutcome`]s
    /// with `error` set.
    pub async fn send(&self, spec: RequestSpec) -> RequestOutcome {
        // (1) Scope check — before constructing any reqwest request.
        let (host, port) = match host_and_port(&spec.url) {
            Ok(hp) => hp,
            Err(ge) => return self.blocked(&spec, ge),
        };
        if let Err(ge) = self.scope.check(&host, port) {
            return self.blocked(&spec, ge);
        }

        // (2) Dry-run — nothing sent, no tokens/permits consumed.
        if self.dry_run {
            self.audit(&spec, "dry_run", None, None);
            return RequestOutcome::dry_run(&spec, self.include_secrets);
        }

        // (3) Rate-limit token, then concurrency permit (held across the send).
        let _permit = self.limiter.acquire().await;

        // (4) Audit the outgoing request.
        self.audit(&spec, "send", None, None);

        // (5) Execute.
        let start = Instant::now();
        let mut outcome = RequestOutcome::failed(&spec, self.include_secrets, String::new());
        outcome.error = None;
        outcome.sent_at = Utc::now();

        match self.execute(&spec).await {
            Ok(resp) => {
                self.fill_from_response(&mut outcome, resp).await;
                outcome.elapsed_ms = start.elapsed().as_millis();
                self.audit(&spec, "recv", outcome.status, outcome.redirect_location.clone());
            }
            Err(e) => {
                outcome.elapsed_ms = start.elapsed().as_millis();
                outcome.error = Some(e.to_string());
                self.audit(&spec, "error", None, Some(e.to_string()));
            }
        }
        outcome
    }

    async fn execute(&self, spec: &RequestSpec) -> std::result::Result<reqwest::Response, GateError> {
        let method = reqwest::Method::from_bytes(spec.method.as_str().as_bytes())
            .map_err(|e| GateError::Send(format!("bad method: {e}")))?;
        let mut rb = self.client.request(method, &spec.url);
        for (k, v) in &spec.headers {
            rb = rb.header(k, v);
        }
        if let Some(ct) = &spec.content_type {
            rb = rb.header(reqwest::header::CONTENT_TYPE, ct);
        }
        if let Some(body) = &spec.body {
            rb = rb.body(body.clone());
        }
        rb.send().await.map_err(|e| GateError::Send(e.to_string()))
    }

    async fn fill_from_response(&self, outcome: &mut RequestOutcome, resp: reqwest::Response) {
        let status = resp.status();
        outcome.status = Some(status.as_u16());
        outcome.response_headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("<binary>").to_string()))
            .collect();
        if status.is_redirection() {
            outcome.redirect_location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(String::from);
        }
        let content_len =
            resp.content_length().map(|n| n as usize).filter(|_| true);

        // Stream chunks up to the cap; never buffer an unbounded body.
        let mut resp = resp;
        let mut buf: Vec<u8> = Vec::new();
        let mut truncated = false;
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    if buf.len() >= self.max_body_bytes {
                        truncated = true;
                        break;
                    }
                    let remaining = self.max_body_bytes - buf.len();
                    if chunk.len() > remaining {
                        buf.extend_from_slice(&chunk[..remaining]);
                        truncated = true;
                        break;
                    }
                    buf.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    outcome.error = Some(format!("reading body: {e}"));
                    break;
                }
            }
        }
        outcome.body_truncated = truncated;
        outcome.body_len = content_len.or(Some(buf.len()));
        outcome.response_body = Some(String::from_utf8_lossy(&buf).to_string());
    }

    fn blocked(&self, spec: &RequestSpec, ge: GateError) -> RequestOutcome {
        self.audit(spec, "blocked", None, Some(ge.to_string()));
        RequestOutcome::failed(spec, self.include_secrets, ge.to_string())
    }

    fn audit(&self, spec: &RequestSpec, event: &str, status: Option<u16>, note: Option<String>) {
        self.audit.record(&AuditEntry {
            ts: Utc::now().to_rfc3339(),
            event,
            test_case_id: spec.test_case_id.to_string(),
            session: &spec.session,
            method: spec.method.as_str(),
            url: &spec.url,
            status,
            note,
        });
    }
}

/// Extract the host and effective port from an absolute URL, for scope-checking.
fn host_and_port(url: &str) -> std::result::Result<(String, u16), GateError> {
    let parsed = Url::parse(url).map_err(|_| GateError::MissingHost { url: url.to_string() })?;
    let host = parsed
        .host_str()
        .ok_or_else(|| GateError::MissingHost { url: url.to_string() })?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| GateError::MissingHost { url: url.to_string() })?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::MemAuditLog;
    use crate::outcome::RequestSpec;
    use crate::scope::ScopeGuard;
    use crate::testcase::{ComparisonGroupId, HttpMethod, IdValue, ParamLocation, Protocol, TestStrategy};
    use uuid::Uuid;

    fn spec_to(url: &str) -> RequestSpec {
        RequestSpec {
            method: HttpMethod::Get,
            url: url.into(),
            headers: vec![("Cookie".into(), "sid=secret".into())],
            body: None,
            content_type: None,
            test_case_id: Uuid::nil(),
            target_name: "t".into(),
            session: "a".into(),
            strategy: TestStrategy::IdEnumeration,
            param_location: ParamLocation::Path,
            id_value: IdValue::Numeric(1),
            comparison_group_id: ComparisonGroupId(Uuid::nil()),
            protocol: Protocol::Rest,
            is_baseline: true,
        }
    }

    fn gate(scope_hosts: &[&str], dry_run: bool, audit: Arc<MemAuditLog>) -> Gate {
        let scope = Arc::new(
            ScopeGuard::new(&scope_hosts.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &[])
                .unwrap(),
        );
        let limiter = Arc::new(Limiter::new(1000.0, 1000, 4).unwrap());
        Gate::new(
            scope,
            limiter,
            audit,
            GateConfig {
                connect_timeout: Duration::from_secs(5),
                request_timeout: Duration::from_secs(5),
                max_body_capture_bytes: 65536,
                proxy: None,
                dry_run,
                include_secrets_in_log: false,
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn out_of_scope_request_is_blocked_and_never_sent() {
        let audit = Arc::new(MemAuditLog::default());
        let g = gate(&["api.example.com"], false, audit.clone());
        // Out-of-scope host that would fail closed even if a send were attempted.
        let outcome = g.send(spec_to("https://evil.invalid/api/orders/1")).await;
        assert!(outcome.error.as_deref().unwrap().contains("out of scope"));
        assert!(outcome.status.is_none());
        assert!(!outcome.dry_run);
        let lines = audit.lines.lock().unwrap();
        assert!(lines.iter().any(|l| l.contains("\"event\":\"blocked\"")));
    }

    #[tokio::test]
    async fn dry_run_sends_nothing_and_consumes_no_permit() {
        let audit = Arc::new(MemAuditLog::default());
        let g = gate(&["api.example.com"], true, audit.clone());
        let outcome = g.send(spec_to("https://api.example.com/api/orders/1")).await;
        assert!(outcome.dry_run);
        assert!(outcome.status.is_none());
        assert!(outcome.error.is_none());
        // Secret cookie value is redacted in captured evidence.
        assert!(outcome
            .request_evidence
            .headers
            .iter()
            .any(|(k, v)| k == "Cookie" && v.starts_with("<redacted:")));
        let lines = audit.lines.lock().unwrap();
        assert!(lines.iter().any(|l| l.contains("\"event\":\"dry_run\"")));
    }

    #[test]
    fn host_and_port_uses_scheme_default() {
        assert_eq!(host_and_port("https://h.com/x").unwrap(), ("h.com".to_string(), 443));
        assert_eq!(host_and_port("http://h.com/x").unwrap(), ("h.com".to_string(), 80));
        assert_eq!(host_and_port("https://h.com:8443/x").unwrap(), ("h.com".to_string(), 8443));
        assert!(host_and_port("not a url").is_err());
    }
}
