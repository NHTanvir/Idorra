//! A flagged result: severity/confidence, why it fired, and the request/response
//! evidence that proves it — the artifact a human reviews and writes up.

use crate::analysis::diff::JsonDiffSummary;
use crate::outcome::RequestOutcome;
use crate::testcase::{IdValue, TestStrategy};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How serious the potential issue is, if real.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — surfaced for review, not asserted as a vuln.
    Info,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        };
        f.write_str(s)
    }
}

/// How confident the tool is that the signal is real (vs a false positive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Low confidence.
    Low,
    /// Medium confidence.
    Medium,
    /// High confidence.
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        };
        f.write_str(s)
    }
}

/// Machine-readable reason a finding fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// A non-baseline session received data matching the baseline's (core IDOR).
    CrossSessionDataMatch,
    /// Status codes diverged in a suspicious way.
    StatusAnomaly,
    /// Response body length differed beyond the configured threshold.
    BodyLengthAnomaly,
    /// A sensitive-looking field was present in a response.
    SensitiveFieldExposed,
    /// An HTTP method returned success where the canonical method was denied.
    MethodBypassedAuth,
    /// A parameter location returned success where the canonical one was denied.
    ParamLocationBypass,
    /// A GraphQL response carried an `errors[]` array (likely a stale template).
    GraphQlSchemaError,
}

/// A flagged result with its supporting evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique id.
    pub id: Uuid,
    /// Strategy that produced it.
    pub strategy: TestStrategy,
    /// Severity axis.
    pub severity: Severity,
    /// Confidence axis.
    pub confidence: Confidence,
    /// Human-readable one-liner.
    pub summary: String,
    /// Machine-readable reason codes.
    pub reason_codes: Vec<ReasonCode>,
    /// Sessions involved (derived from evidence).
    pub involved_sessions: Vec<String>,
    /// Ids involved (derived from evidence).
    pub involved_ids: Vec<IdValue>,
    /// The request/response pairs that prove the finding.
    pub evidence: Vec<RequestOutcome>,
    /// Structural diff summary, when applicable.
    pub diff_summary: Option<JsonDiffSummary>,
    /// Sensitive field paths detected in the response, if any.
    pub detected_sensitive_fields: Vec<String>,
    /// When the finding was created.
    pub created_at: DateTime<Utc>,
}

impl Finding {
    /// Build a finding, deriving `involved_sessions`/`involved_ids` from evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn from_evidence(
        strategy: TestStrategy,
        severity: Severity,
        confidence: Confidence,
        summary: impl Into<String>,
        reason_codes: Vec<ReasonCode>,
        diff_summary: Option<JsonDiffSummary>,
        detected_sensitive_fields: Vec<String>,
        evidence: Vec<RequestOutcome>,
    ) -> Self {
        let involved_sessions = dedup(evidence.iter().map(|o| o.session.clone()));
        let involved_ids = dedup_ids(evidence.iter().map(|o| o.id_value.clone()));
        Self {
            id: Uuid::new_v4(),
            strategy,
            severity,
            confidence,
            summary: summary.into(),
            reason_codes,
            involved_sessions,
            involved_ids,
            evidence,
            diff_summary,
            detected_sensitive_fields,
            created_at: Utc::now(),
        }
    }
}

fn dedup(iter: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in iter {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

fn dedup_ids(iter: impl Iterator<Item = IdValue>) -> Vec<IdValue> {
    let mut out: Vec<IdValue> = Vec::new();
    for s in iter {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_high_above_low() {
        assert!(Severity::High > Severity::Low);
        assert!(Severity::Medium > Severity::Info);
    }

    #[test]
    fn confidence_orders_and_displays() {
        assert!(Confidence::High > Confidence::Medium);
        assert_eq!(Confidence::High.to_string(), "high");
    }
}
