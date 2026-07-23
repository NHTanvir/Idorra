//! Runtime sessions: turn parsed [`SessionConfig`] credentials into the concrete
//! headers attached to every request for that session.
//!
//! Sessions are applied as **explicit per-request headers**. The tool never
//! enables reqwest's automatic cookie jar — on a client shared across sessions
//! that jar would replay `Set-Cookie` responses across every session and
//! silently corrupt each IDOR comparison.

use crate::config::SessionConfig;
use crate::error::{Error, Result};
use std::collections::BTreeMap;

/// Header names whose *values* are secrets and must be redacted in logs/reports
/// unless the operator explicitly opts in. Compared case-insensitively.
pub const SECRET_HEADERS: &[&str] = &["authorization", "cookie"];

/// Returns true if a header's value should be redacted by default.
pub fn is_secret_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_HEADERS.contains(&lower.as_str())
}

/// A prepared session: a name plus the ordered headers to attach to its requests.
#[derive(Debug, Clone)]
pub struct Session {
    /// Session name.
    pub name: String,
    /// Optional description (for reports).
    pub description: Option<String>,
    /// Headers to attach, in insertion order (auth/cookie first, then extras).
    pub headers: Vec<(String, String)>,
}

impl Session {
    /// Build a runtime session from its config, enforcing exactly-one-credential.
    pub fn from_config(cfg: &SessionConfig) -> Result<Self> {
        let mut headers: Vec<(String, String)> = Vec::new();
        match (&cfg.cookie, &cfg.bearer_token) {
            (Some(cookie), None) => headers.push(("Cookie".into(), cookie.clone())),
            (None, Some(token)) => {
                headers.push(("Authorization".into(), format!("Bearer {token}")))
            }
            (Some(_), Some(_)) => {
                return Err(Error::Config(format!(
                    "session {:?} has both cookie and bearer_token; use exactly one",
                    cfg.name
                )))
            }
            (None, None) => {
                return Err(Error::Config(format!(
                    "session {:?} has neither cookie nor bearer_token",
                    cfg.name
                )))
            }
        }
        for (k, v) in &cfg.headers {
            headers.push((k.clone(), v.clone()));
        }
        Ok(Self { name: cfg.name.clone(), description: cfg.description.clone(), headers })
    }
}

/// An immutable set of named sessions for a run.
#[derive(Debug, Clone, Default)]
pub struct SessionStore {
    map: BTreeMap<String, Session>,
}

impl SessionStore {
    /// Build the store from parsed session configs.
    pub fn from_configs(cfgs: &[SessionConfig]) -> Result<Self> {
        let mut map = BTreeMap::new();
        for c in cfgs {
            if map.contains_key(&c.name) {
                return Err(Error::Config(format!("duplicate session name {:?}", c.name)));
            }
            map.insert(c.name.clone(), Session::from_config(c)?);
        }
        Ok(Self { map })
    }

    /// Look up a session by name.
    pub fn get(&self, name: &str) -> Option<&Session> {
        self.map.get(name)
    }

    /// Iterate over session names.
    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.map.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, cookie: Option<&str>, bearer: Option<&str>) -> SessionConfig {
        SessionConfig {
            name: name.into(),
            description: None,
            cookie: cookie.map(String::from),
            bearer_token: bearer.map(String::from),
            headers: BTreeMap::new(),
        }
    }

    #[test]
    fn cookie_session_sets_cookie_header() {
        let s = Session::from_config(&cfg("a", Some("sid=1"), None)).unwrap();
        assert_eq!(s.headers, vec![("Cookie".to_string(), "sid=1".to_string())]);
    }

    #[test]
    fn bearer_session_sets_authorization_header() {
        let s = Session::from_config(&cfg("a", None, Some("tok"))).unwrap();
        assert_eq!(s.headers, vec![("Authorization".to_string(), "Bearer tok".to_string())]);
    }

    #[test]
    fn missing_or_double_credentials_fail() {
        assert!(Session::from_config(&cfg("a", None, None)).is_err());
        assert!(Session::from_config(&cfg("a", Some("x"), Some("y"))).is_err());
    }

    #[test]
    fn secret_headers_detected_case_insensitively() {
        assert!(is_secret_header("Authorization"));
        assert!(is_secret_header("cookie"));
        assert!(!is_secret_header("X-Request-Id"));
    }

    #[test]
    fn store_rejects_duplicates_and_looks_up() {
        let store = SessionStore::from_configs(&[
            cfg("a", Some("1"), None),
            cfg("b", None, Some("t")),
        ])
        .unwrap();
        assert!(store.get("a").is_some());
        assert!(store.get("missing").is_none());

        let dup = SessionStore::from_configs(&[cfg("a", Some("1"), None), cfg("a", Some("2"), None)]);
        assert!(dup.is_err());
    }
}
