//! What the gate sends ([`RequestSpec`]) and what comes back ([`RequestOutcome`]),
//! plus the redactable [`RequestEvidence`] captured for reports.

use crate::session::is_secret_header;
use crate::testcase::{ComparisonGroupId, HttpMethod, IdValue, ParamLocation, Protocol, TestStrategy};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A fully-resolved request, ready to hand to the gate. Building one performs no
/// network I/O; it is pure data that the gate scope-checks before sending.
#[derive(Debug, Clone)]
pub struct RequestSpec {
    // --- wire ---
    /// HTTP method.
    pub method: HttpMethod,
    /// Absolute request URL (scheme://host[:port]/path[?query]).
    pub url: String,
    /// Headers to send (session credentials + extras), in order.
    pub headers: Vec<(String, String)>,
    /// Optional request body bytes.
    pub body: Option<Vec<u8>>,
    /// Optional explicit content-type for the body.
    pub content_type: Option<String>,

    // --- context (for correlation / evidence / logging) ---
    /// Originating test-case id.
    pub test_case_id: Uuid,
    /// Target name.
    pub target_name: String,
    /// Session name that owns these credentials.
    pub session: String,
    /// Strategy that produced the case.
    pub strategy: TestStrategy,
    /// Where the id was injected.
    pub param_location: ParamLocation,
    /// The id under test.
    pub id_value: IdValue,
    /// Comparison-group correlation id.
    pub comparison_group_id: ComparisonGroupId,
    /// REST vs GraphQL.
    pub protocol: Protocol,
    /// Whether this is the reference/baseline of its comparison group.
    pub is_baseline: bool,
}

/// A redacted, report-safe snapshot of what was (or would be) sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEvidence {
    /// Method token.
    pub method: String,
    /// URL.
    pub url: String,
    /// Headers, with secret values redacted unless opted in.
    pub headers: Vec<(String, String)>,
    /// Body as (possibly-truncated) text, if any.
    pub body: Option<String>,
}

impl RequestEvidence {
    /// Capture evidence from a spec, redacting secret headers unless
    /// `include_secrets` is set.
    pub fn capture(spec: &RequestSpec, include_secrets: bool) -> Self {
        let headers = redact_headers(&spec.headers, include_secrets);
        let body = spec.body.as_ref().map(|b| {
            let text = String::from_utf8_lossy(b);
            truncate(&text, 4096)
        });
        Self { method: spec.method.as_str().to_string(), url: spec.url.clone(), headers, body }
    }
}

/// Redact the values of secret headers (Authorization/Cookie) unless opted in.
pub fn redact_headers(headers: &[(String, String)], include_secrets: bool) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            if !include_secrets && is_secret_header(k) {
                (k.clone(), redacted_marker(v))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

fn redacted_marker(v: &str) -> String {
    format!("<redacted:{} chars>", v.chars().count())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…<+{} bytes>", &s[..end], s.len() - end)
    }
}

/// The result of (attempting to) send one request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestOutcome {
    /// Originating test-case id.
    pub test_case_id: Uuid,
    /// Target name.
    pub target_name: String,
    /// Session name.
    pub session: String,
    /// Strategy that produced the case.
    pub strategy: TestStrategy,
    /// Where the id was injected.
    pub param_location: ParamLocation,
    /// The id under test.
    pub id_value: IdValue,
    /// Comparison-group correlation id.
    pub comparison_group_id: ComparisonGroupId,
    /// REST vs GraphQL.
    pub protocol: Protocol,
    /// Whether this is the reference/baseline of its comparison group.
    pub is_baseline: bool,
    /// Method token.
    pub method: String,
    /// Request URL.
    pub url: String,
    /// When the request was sent.
    pub sent_at: DateTime<Utc>,
    /// Redacted request evidence.
    pub request_evidence: RequestEvidence,
    /// Response status code, if a response was received.
    pub status: Option<u16>,
    /// Response headers (empty if none).
    pub response_headers: Vec<(String, String)>,
    /// Captured (capped) response body text.
    pub response_body: Option<String>,
    /// Whether the captured body was truncated at the cap.
    pub body_truncated: bool,
    /// True total body length if known (from Content-Length or full read).
    pub body_len: Option<usize>,
    /// Round-trip time in milliseconds.
    pub elapsed_ms: u128,
    /// Error text if the send failed or was blocked.
    pub error: Option<String>,
    /// Whether this was a dry-run (nothing sent).
    pub dry_run: bool,
    /// `Location` header value if the response was a redirect (never followed).
    pub redirect_location: Option<String>,
}

impl RequestOutcome {
    fn base(spec: &RequestSpec, include_secrets: bool) -> Self {
        Self {
            test_case_id: spec.test_case_id,
            target_name: spec.target_name.clone(),
            session: spec.session.clone(),
            strategy: spec.strategy,
            param_location: spec.param_location,
            id_value: spec.id_value.clone(),
            comparison_group_id: spec.comparison_group_id,
            protocol: spec.protocol,
            is_baseline: spec.is_baseline,
            method: spec.method.as_str().to_string(),
            url: spec.url.clone(),
            sent_at: Utc::now(),
            request_evidence: RequestEvidence::capture(spec, include_secrets),
            status: None,
            response_headers: Vec::new(),
            response_body: None,
            body_truncated: false,
            body_len: None,
            elapsed_ms: 0,
            error: None,
            dry_run: false,
            redirect_location: None,
        }
    }

    /// A synthetic outcome for a dry-run (nothing sent).
    pub fn dry_run(spec: &RequestSpec, include_secrets: bool) -> Self {
        let mut o = Self::base(spec, include_secrets);
        o.dry_run = true;
        o
    }

    /// An outcome representing a blocked/failed request (scope, port, network).
    pub fn failed(spec: &RequestSpec, include_secrets: bool, error: String) -> Self {
        let mut o = Self::base(spec, include_secrets);
        o.error = Some(error);
        o
    }

    /// True if the response status is 2xx.
    pub fn is_success(&self) -> bool {
        matches!(self.status, Some(s) if (200..300).contains(&s))
    }

    /// Parse the captured body as JSON, if possible.
    pub fn json(&self) -> Option<serde_json::Value> {
        self.response_body.as_ref().and_then(|b| serde_json::from_str(b).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_headers_are_redacted_by_default() {
        let redacted = redact_headers(
            &[("Authorization".into(), "Bearer supersecret".into()), ("X-Trace".into(), "abc".into())],
            false,
        );
        assert!(redacted[0].1.starts_with("<redacted:"));
        assert_eq!(redacted[1].1, "abc");
    }

    #[test]
    fn secret_headers_shown_when_opted_in() {
        let shown = redact_headers(&[("Cookie".into(), "sid=1".into())], true);
        assert_eq!(shown[0].1, "sid=1");
    }
}
