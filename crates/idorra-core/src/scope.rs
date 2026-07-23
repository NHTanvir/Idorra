//! The scope allowlist — the safety-critical gate that decides whether a host
//! may be contacted at all.
//!
//! Matching semantics (v1, hostnames only — no CIDR/IP ranges):
//! - **Exact**: `api.example.com` matches only `api.example.com` (case-insensitive,
//!   trailing dot ignored).
//! - **Wildcard**: `*.example.com` matches any sub-domain of `example.com` at any
//!   depth (`a.example.com`, `a.b.example.com`) but **not** the bare apex
//!   `example.com`. List the apex explicitly if it is also in scope.
//! - **Ports**: an empty `allow_ports` permits any port; a non-empty list
//!   restricts to exactly those ports.
//!
//! The leading `.` in the wildcard suffix check (`host.ends_with(".example.com")`)
//! is what prevents suffix-confusion attacks like `notexample.com` or
//! `example.com.evil.com` from slipping through.

use crate::error::{Error, GateError, Result};

/// An immutable, validated allowlist. Built once at load time and shared
/// (read-only) for the whole run.
#[derive(Debug, Clone)]
pub struct ScopeGuard {
    /// Lowercased exact hostnames.
    exact: Vec<String>,
    /// Lowercased wildcard suffixes, stored *without* the leading `*.`
    /// (e.g. the pattern `*.example.com` is stored as `example.com`).
    wildcard_suffixes: Vec<String>,
    /// Allowed ports; empty means "any port".
    allow_ports: Vec<u16>,
}

impl ScopeGuard {
    /// Build a guard from raw allow patterns and an (optional) port allowlist.
    ///
    /// Fails if the pattern list is empty (a tool with no scope must never run)
    /// or a pattern is malformed.
    pub fn new(patterns: &[String], allow_ports: &[u16]) -> Result<Self> {
        if patterns.is_empty() {
            return Err(Error::Config(
                "scope.allow must list at least one host pattern; refusing to run with an empty allowlist"
                    .into(),
            ));
        }

        let mut exact = Vec::new();
        let mut wildcard_suffixes = Vec::new();

        for raw in patterns {
            let pat = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if pat.is_empty() {
                return Err(Error::Config(format!("scope.allow contains an empty pattern: {raw:?}")));
            }
            if let Some(suffix) = pat.strip_prefix("*.") {
                if suffix.is_empty() || suffix.contains('*') {
                    return Err(Error::Config(format!(
                        "invalid wildcard scope pattern {raw:?}: expected `*.domain.tld`"
                    )));
                }
                wildcard_suffixes.push(suffix.to_string());
            } else if pat.contains('*') {
                return Err(Error::Config(format!(
                    "invalid scope pattern {raw:?}: `*` is only allowed as a leading `*.` label"
                )));
            } else {
                exact.push(pat);
            }
        }

        Ok(Self { exact, wildcard_suffixes, allow_ports: allow_ports.to_vec() })
    }

    /// Normalize a host for comparison: lowercase, strip a trailing dot.
    fn normalize(host: &str) -> String {
        host.trim().trim_end_matches('.').to_ascii_lowercase()
    }

    /// Does this host match any allow pattern? (Ports are checked separately.)
    pub fn allows_host(&self, host: &str) -> bool {
        let host = Self::normalize(host);
        if host.is_empty() {
            return false;
        }
        if self.exact.contains(&host) {
            return true;
        }
        self.wildcard_suffixes
            .iter()
            .any(|suffix| host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")))
    }

    /// Is this port allowed? An empty port allowlist permits every port.
    pub fn allows_port(&self, port: u16) -> bool {
        self.allow_ports.is_empty() || self.allow_ports.contains(&port)
    }

    /// The single check every outbound request must pass. Returns a
    /// [`GateError`] (never a panic) so the caller logs and skips the request.
    pub fn check(&self, host: &str, port: u16) -> std::result::Result<(), GateError> {
        if !self.allows_host(host) {
            return Err(GateError::OutOfScope { host: host.to_string() });
        }
        if !self.allows_port(port) {
            return Err(GateError::PortNotAllowed { host: host.to_string(), port });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(patterns: &[&str], ports: &[u16]) -> ScopeGuard {
        let owned: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        ScopeGuard::new(&owned, ports).expect("valid guard")
    }

    #[test]
    fn empty_allowlist_is_rejected() {
        let err = ScopeGuard::new(&[], &[]).unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn exact_match_only() {
        let g = guard(&["api.example.com"], &[]);
        assert!(g.allows_host("api.example.com"));
        assert!(!g.allows_host("www.example.com"));
        assert!(!g.allows_host("example.com"));
    }

    #[test]
    fn matching_is_case_insensitive_and_ignores_trailing_dot() {
        let g = guard(&["API.Example.CoM"], &[]);
        assert!(g.allows_host("api.example.com"));
        assert!(g.allows_host("API.EXAMPLE.COM"));
        assert!(g.allows_host("api.example.com.")); // trailing dot (FQDN form)
    }

    #[test]
    fn wildcard_matches_subdomains_any_depth_but_not_apex() {
        let g = guard(&["*.example.com"], &[]);
        assert!(g.allows_host("foo.example.com"));
        assert!(g.allows_host("a.b.example.com"));
        assert!(!g.allows_host("example.com")); // apex excluded by design
    }

    #[test]
    fn wildcard_resists_suffix_confusion() {
        let g = guard(&["*.example.com"], &[]);
        // These look similar but must NOT match:
        assert!(!g.allows_host("notexample.com"));
        assert!(!g.allows_host("example.com.evil.com"));
        assert!(!g.allows_host("foo.example.com.evil.com"));
        assert!(!g.allows_host("evil-example.com"));
    }

    #[test]
    fn apex_and_wildcard_can_both_be_listed() {
        let g = guard(&["example.com", "*.example.com"], &[]);
        assert!(g.allows_host("example.com"));
        assert!(g.allows_host("api.example.com"));
    }

    #[test]
    fn empty_port_list_allows_any_port() {
        let g = guard(&["api.example.com"], &[]);
        assert!(g.allows_port(443));
        assert!(g.allows_port(8080));
    }

    #[test]
    fn non_empty_port_list_restricts() {
        let g = guard(&["api.example.com"], &[443, 8443]);
        assert!(g.allows_port(443));
        assert!(g.allows_port(8443));
        assert!(!g.allows_port(80));
    }

    #[test]
    fn check_reports_precise_gate_errors() {
        let g = guard(&["api.example.com"], &[443]);
        assert_eq!(g.check("api.example.com", 443), Ok(()));
        assert_eq!(
            g.check("evil.com", 443),
            Err(GateError::OutOfScope { host: "evil.com".into() })
        );
        assert_eq!(
            g.check("api.example.com", 80),
            Err(GateError::PortNotAllowed { host: "api.example.com".into(), port: 80 })
        );
    }

    #[test]
    fn malformed_wildcards_are_rejected() {
        assert!(ScopeGuard::new(&["*.".into()], &[]).is_err());
        assert!(ScopeGuard::new(&["*".into()], &[]).is_err());
        assert!(ScopeGuard::new(&["foo.*.com".into()], &[]).is_err());
    }
}
