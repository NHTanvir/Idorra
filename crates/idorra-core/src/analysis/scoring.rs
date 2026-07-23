//! The scoring rule table — turns request outcomes into [`Finding`]s. Rules are
//! explicit and documented (no ML), and every rule attaches a [`ReasonCode`].
//!
//! Severity and confidence are separate axes: a cross-session data match with
//! sensitive fields is High/High; a verb that flips a 403 to a 200 is High but
//! only Medium confidence because a human must confirm the action really
//! mutated/exposed something.

use crate::analysis::{diff, sensitive_fields};
use crate::config::Analysis;
use crate::finding::{Confidence, Finding, ReasonCode, Severity};
use crate::outcome::RequestOutcome;
use crate::testcase::TestStrategy;

/// Core IDOR check: does a non-baseline session receive (near-)identical data to
/// the baseline for the same id? Only fires when both responses are 2xx.
pub fn cross_session_finding(
    baseline: &RequestOutcome,
    other: &RequestOutcome,
    analysis: &Analysis,
) -> Option<Finding> {
    if !baseline.is_success() || !other.is_success() {
        return None; // divergent status (e.g. 200 vs 403) is the expected, safe case
    }

    let (similarity, diff_summary, sensitive) = match (baseline.json(), other.json()) {
        (Some(a), Some(b)) => {
            let d = diff::diff(&a, &b);
            let sens = sensitive_fields::detect(&b, &analysis.sensitive_field_patterns);
            (d.similarity(), Some(d), sens)
        }
        _ => {
            // Non-JSON: only treat byte-identical bodies as a match.
            let equal = baseline.response_body.is_some()
                && baseline.response_body == other.response_body;
            (if equal { 1.0 } else { 0.0 }, None, Vec::new())
        }
    };

    if similarity < 0.9 {
        return None;
    }

    let has_sensitive = !sensitive.is_empty();
    let severity = if has_sensitive { Severity::High } else { Severity::Medium };
    let confidence = if similarity >= 0.99 { Confidence::High } else { Confidence::Medium };

    let mut reasons = vec![ReasonCode::CrossSessionDataMatch];
    if has_sensitive {
        reasons.push(ReasonCode::SensitiveFieldExposed);
    }

    let pct = (similarity * 100.0).round() as u32;
    let sens_note = if has_sensitive {
        format!("; sensitive fields: {}", sensitive.join(", "))
    } else {
        String::new()
    };
    let summary = format!(
        "Session '{}' received data {pct}% identical to baseline '{}' for id {}{sens_note}",
        other.session, baseline.session, other.id_value
    );

    Some(Finding::from_evidence(
        TestStrategy::TwoSessionCompare,
        severity,
        confidence,
        summary,
        reasons,
        diff_summary,
        sensitive,
        vec![baseline.clone(), other.clone()],
    ))
}

/// Auth-bypass check: a `variant` request succeeds (2xx) where a `reference`
/// request for the same id was denied (401/403). Used for both method and
/// parameter-location tampering.
pub fn bypass_finding(
    reference: &RequestOutcome,
    variant: &RequestOutcome,
    strategy: TestStrategy,
) -> Option<Finding> {
    let denied = matches!(reference.status, Some(401) | Some(403));
    if !denied || !variant.is_success() {
        return None;
    }

    let (reason, summary) = match strategy {
        TestStrategy::MethodTampering => (
            ReasonCode::MethodBypassedAuth,
            format!(
                "Method {} returned {} for id {} where {} was denied ({})",
                variant.method,
                variant.status.unwrap_or(0),
                variant.id_value,
                reference.method,
                reference.status.unwrap_or(0),
            ),
        ),
        _ => (
            ReasonCode::ParamLocationBypass,
            format!(
                "Id in '{}' returned {} for id {} where '{}' was denied ({})",
                variant.param_location,
                variant.status.unwrap_or(0),
                variant.id_value,
                reference.param_location,
                reference.status.unwrap_or(0),
            ),
        ),
    };

    Some(Finding::from_evidence(
        strategy,
        Severity::High,
        Confidence::Medium,
        summary,
        vec![reason],
        None,
        Vec::new(),
        vec![reference.clone(), variant.clone()],
    ))
}

/// Flags a GraphQL response that carries an `errors[]` array — usually a stale
/// query template or schema change, not a clean allow/deny signal. Info-level so
/// the operator notices false negatives rather than trusting a silent "no vuln".
pub fn graphql_schema_warning(outcome: &RequestOutcome) -> Option<Finding> {
    let json = outcome.json()?;
    let errors = json.get("errors")?.as_array()?;
    if errors.is_empty() {
        return None;
    }
    let summary = format!(
        "GraphQL query for id {} returned errors[] (likely a stale template or schema change); \
         treat allow/deny results for this query as unreliable",
        outcome.id_value
    );
    Some(Finding::from_evidence(
        TestStrategy::GraphQlVariation,
        Severity::Info,
        Confidence::High,
        summary,
        vec![ReasonCode::GraphQlSchemaError],
        None,
        Vec::new(),
        vec![outcome.clone()],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testcase::{ComparisonGroupId, IdValue, ParamLocation, Protocol};
    use crate::outcome::{RequestEvidence, RequestOutcome};
    use chrono::Utc;
    use uuid::Uuid;

    fn outcome(session: &str, status: u16, body: serde_json::Value) -> RequestOutcome {
        RequestOutcome {
            test_case_id: Uuid::nil(),
            target_name: "t".into(),
            session: session.into(),
            strategy: TestStrategy::TwoSessionCompare,
            param_location: ParamLocation::Path,
            id_value: IdValue::Numeric(7),
            comparison_group_id: ComparisonGroupId(Uuid::nil()),
            protocol: Protocol::Rest,
            is_baseline: false,
            method: "GET".into(),
            url: "https://api.example.com/api/orders/7".into(),
            sent_at: Utc::now(),
            request_evidence: RequestEvidence {
                method: "GET".into(),
                url: "https://api.example.com/api/orders/7".into(),
                headers: vec![],
                body: None,
            },
            status: Some(status),
            response_headers: vec![],
            response_body: Some(body.to_string()),
            body_truncated: false,
            body_len: None,
            elapsed_ms: 1,
            error: None,
            dry_run: false,
            redirect_location: None,
        }
    }

    fn analysis() -> Analysis {
        Analysis::default()
    }

    #[test]
    fn cross_session_flags_identical_data_with_sensitive_field() {
        let base = outcome("a", 200, serde_json::json!({"id": 7, "email": "a@b.com"}));
        let other = outcome("b", 200, serde_json::json!({"id": 7, "email": "a@b.com"}));
        let f = cross_session_finding(&base, &other, &analysis()).expect("should flag");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::High);
        assert!(f.reason_codes.contains(&ReasonCode::SensitiveFieldExposed));
        assert!(f.detected_sensitive_fields.contains(&"email".to_string()));
    }

    #[test]
    fn cross_session_ignores_divergent_data() {
        let base = outcome("a", 200, serde_json::json!({"id": 7, "owner": "alice"}));
        let other = outcome("b", 200, serde_json::json!({"id": 7, "owner": "bob"}));
        assert!(cross_session_finding(&base, &other, &analysis()).is_none());
    }

    #[test]
    fn cross_session_ignores_denied_other() {
        let base = outcome("a", 200, serde_json::json!({"id": 7, "email": "a@b.com"}));
        let other = outcome("b", 403, serde_json::json!({"error": "forbidden"}));
        assert!(cross_session_finding(&base, &other, &analysis()).is_none());
    }

    #[test]
    fn bypass_flags_denied_reference_but_allowed_variant() {
        let denied = outcome("a", 403, serde_json::json!({"error": "no"}));
        let mut allowed = outcome("a", 200, serde_json::json!({"id": 7}));
        allowed.method = "DELETE".into();
        let f = bypass_finding(&denied, &allowed, TestStrategy::MethodTampering).unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.reason_codes.contains(&ReasonCode::MethodBypassedAuth));
    }

    #[test]
    fn bypass_none_when_reference_not_denied() {
        let ok = outcome("a", 200, serde_json::json!({"id": 7}));
        let allowed = outcome("a", 200, serde_json::json!({"id": 7}));
        assert!(bypass_finding(&ok, &allowed, TestStrategy::MethodTampering).is_none());
    }

    #[test]
    fn graphql_warning_on_errors_array() {
        let o = outcome("a", 200, serde_json::json!({"errors": [{"message": "bad field"}]}));
        let f = graphql_schema_warning(&o).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.reason_codes.contains(&ReasonCode::GraphQlSchemaError));
    }
}
