//! TOML configuration schema, loading, secret-merge, and validation.
//!
//! Two files are read: the tracked `idorra.toml` (structure — scope, targets,
//! rate limits) and a gitignored `secrets.toml` (session tokens/cookies). They
//! are combined at load time. Validation is fail-fast: a bad reference or an
//! out-of-scope target is rejected up front with a clear message rather than
//! surfacing as a confusing mid-run error.

use crate::error::{Error, Result};
use crate::scope::ScopeGuard;
use crate::testcase::{HttpMethod, IdValue, ParamLocation, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The fully-merged, validated configuration for a run.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// General run settings.
    #[serde(default)]
    pub general: General,
    /// The scope allowlist (required).
    pub scope: Scope,
    /// Rate-limit and concurrency caps.
    #[serde(default)]
    pub rate_limit: RateLimit,
    /// HTTP client tuning.
    #[serde(default)]
    pub http: Http,
    /// Response-analysis settings.
    #[serde(default)]
    pub analysis: Analysis,
    /// Targets to test.
    #[serde(default, rename = "target")]
    pub targets: Vec<Target>,
    /// Named sessions — populated only from `secrets.toml`, never the main file.
    #[serde(skip)]
    pub sessions: Vec<SessionConfig>,
    /// Directory the config was loaded from; relative paths resolve against it.
    #[serde(skip)]
    pub base_dir: PathBuf,
}

/// General run settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct General {
    /// Default dry-run state (CLI `--live` overrides).
    pub dry_run: bool,
    /// Directory for the request/response audit log.
    pub log_dir: PathBuf,
    /// Directory for findings reports.
    pub report_dir: PathBuf,
}

impl Default for General {
    fn default() -> Self {
        Self {
            dry_run: true,
            log_dir: PathBuf::from("./idorra-logs"),
            report_dir: PathBuf::from("./idorra-reports"),
        }
    }
}

/// The scope allowlist section.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Scope {
    /// Allowed host patterns (exact or `*.suffix`). Must be non-empty.
    pub allow: Vec<String>,
    /// Allowed ports; empty means any port.
    #[serde(default)]
    pub allow_ports: Vec<u16>,
}

/// Rate-limit and concurrency configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RateLimit {
    /// Requests per second (fractional allowed, e.g. `0.5` = 1 per 2s).
    pub requests_per_second: f64,
    /// Token-bucket burst allowance.
    pub burst: u32,
    /// Hard cap on in-flight requests.
    pub max_concurrency: usize,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self { requests_per_second: 2.0, burst: 2, max_concurrency: 4 }
    }
}

/// HTTP client tuning.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Http {
    /// Connection timeout (seconds).
    pub connect_timeout_secs: u64,
    /// Total request timeout (seconds) — bounds how long a permit is held.
    pub request_timeout_secs: u64,
    /// Cap on response bytes captured into evidence.
    pub max_body_capture_bytes: usize,
    /// Optional upstream proxy (e.g. Burp/mitmproxy). Still scope-checked.
    pub proxy: Option<String>,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 10,
            request_timeout_secs: 20,
            max_body_capture_bytes: 262_144,
            proxy: None,
        }
    }
}

/// Response-analysis settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Analysis {
    /// Extra sensitive field-name patterns, additive to the built-in list.
    pub sensitive_field_patterns: Vec<String>,
    /// Body-length delta (percent) above which a size anomaly is noted.
    pub body_length_anomaly_threshold_pct: f64,
}

impl Default for Analysis {
    fn default() -> Self {
        Self { sensitive_field_patterns: Vec::new(), body_length_anomaly_threshold_pct: 15.0 }
    }
}

/// A target API.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Target {
    /// Human-readable target name.
    pub name: String,
    /// Base URL (`scheme://host[:port]`).
    pub base_url: String,
    /// REST or GraphQL.
    #[serde(default)]
    pub protocol: Protocol,
    /// The session treated as the resource owner in comparisons.
    pub baseline_session: String,
    /// REST endpoints to exercise.
    #[serde(default, rename = "endpoint")]
    pub endpoints: Vec<Endpoint>,
    /// GraphQL queries to exercise.
    #[serde(default, rename = "graphql_query")]
    pub graphql_queries: Vec<GraphQlQuery>,
}

/// A REST endpoint definition.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Endpoint {
    /// Endpoint name.
    pub name: String,
    /// Path template containing the `{id_param}` placeholder.
    pub path_template: String,
    /// Baseline HTTP method.
    #[serde(default = "default_get")]
    pub method: HttpMethod,
    /// The id parameter name (placeholder key).
    pub id_param: String,
    /// How to generate id values.
    pub id_source: IdSource,
    /// Parameter locations to try.
    #[serde(default)]
    pub param_locations: Vec<ParamLocation>,
    /// Additional HTTP methods to try (verb tampering).
    #[serde(default)]
    pub test_methods: Vec<HttpMethod>,
    /// Sessions participating (baseline plus others).
    pub sessions: Vec<String>,
}

/// A GraphQL query definition.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GraphQlQuery {
    /// Query name.
    pub name: String,
    /// Path to the `.graphql` template file (relative to the config dir).
    pub query_file: PathBuf,
    /// Variable name to bind the id to (referenced as `$name` in the query).
    pub variable_name: String,
    /// How to generate id values.
    pub id_source: IdSource,
    /// Sessions participating.
    pub sessions: Vec<String>,
}

/// A session credential, sourced only from `secrets.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    /// Session name (referenced by targets).
    pub name: String,
    /// Optional human description.
    #[serde(default)]
    pub description: Option<String>,
    /// Raw `Cookie` header value.
    #[serde(default)]
    pub cookie: Option<String>,
    /// Bearer token (sent as `Authorization: Bearer …`).
    #[serde(default)]
    pub bearer_token: Option<String>,
    /// Extra static headers merged into every request for this session.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

/// How a set of id values is produced.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdSource {
    /// Inclusive numeric range `start..=end`.
    Range {
        /// First id (inclusive).
        start: i64,
        /// Last id (inclusive).
        end: i64,
    },
    /// An explicit list of ids.
    List {
        /// The id values.
        values: Vec<IdValue>,
    },
    /// Ids read one-per-line from a file (numeric lines parse to numbers).
    File {
        /// Path to the id file (relative to the config dir).
        path: PathBuf,
    },
}

impl IdSource {
    /// Materialize the id values. `base_dir` resolves relative file paths.
    pub fn expand(&self, base_dir: &Path) -> Result<Vec<IdValue>> {
        match self {
            IdSource::Range { start, end } => {
                if end < start {
                    return Err(Error::Config(format!(
                        "id_source range end ({end}) is before start ({start})"
                    )));
                }
                Ok((*start..=*end).map(IdValue::Numeric).collect())
            }
            IdSource::List { values } => Ok(values.clone()),
            IdSource::File { path } => {
                let resolved =
                    if path.is_absolute() { path.clone() } else { base_dir.join(path) };
                let text = std::fs::read_to_string(&resolved)
                    .map_err(|e| Error::Config(format!("id_source file {resolved:?}: {e}")))?;
                Ok(text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(|l| match l.parse::<i64>() {
                        Ok(n) => IdValue::Numeric(n),
                        Err(_) => IdValue::Str(l.to_string()),
                    })
                    .collect())
            }
        }
    }
}

fn default_get() -> HttpMethod {
    HttpMethod::Get
}

impl Config {
    /// Parse the main config from a TOML string (no secrets, no fs checks).
    pub fn parse(main_toml: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(main_toml)?;
        Ok(cfg)
    }

    /// Merge session credentials from a `secrets.toml` string.
    pub fn merge_secrets(&mut self, secrets_toml: &str) -> Result<()> {
        #[derive(Deserialize)]
        struct Secrets {
            #[serde(default, rename = "session")]
            sessions: Vec<SessionConfig>,
        }
        let secrets: Secrets = toml::from_str(secrets_toml)?;
        self.sessions = secrets.sessions;
        Ok(())
    }

    /// Load config + secrets from disk and fully validate (including files).
    pub fn load(config_path: &Path, secrets_path: Option<&Path>) -> Result<Config> {
        let text = std::fs::read_to_string(config_path)
            .map_err(|e| Error::Config(format!("reading {config_path:?}: {e}")))?;
        let mut cfg = Config::parse(&text)?;
        cfg.base_dir = config_path.parent().map(Path::to_path_buf).unwrap_or_default();

        if let Some(sp) = secrets_path {
            if sp.exists() {
                let stext = std::fs::read_to_string(sp)
                    .map_err(|e| Error::Config(format!("reading {sp:?}: {e}")))?;
                cfg.merge_secrets(&stext)?;
            }
        }

        cfg.validate()?;
        cfg.validate_files()?;
        Ok(cfg)
    }

    /// Build a [`ScopeGuard`] from the scope section.
    pub fn scope_guard(&self) -> Result<ScopeGuard> {
        ScopeGuard::new(&self.scope.allow, &self.scope.allow_ports)
    }

    /// Logical validation (no filesystem access) — safe to call in tests.
    pub fn validate(&self) -> Result<()> {
        let guard = self.scope_guard()?;

        let rps = self.rate_limit.requests_per_second;
        if rps <= 0.0 || !rps.is_finite() {
            return Err(Error::Config(
                "rate_limit.requests_per_second must be a positive, finite number".into(),
            ));
        }
        if self.rate_limit.max_concurrency < 1 {
            return Err(Error::Config("rate_limit.max_concurrency must be >= 1".into()));
        }

        // Session names must be unique and carry exactly one credential.
        let mut seen = std::collections::BTreeSet::new();
        for s in &self.sessions {
            if !seen.insert(&s.name) {
                return Err(Error::Config(format!("duplicate session name {:?}", s.name)));
            }
            match (&s.cookie, &s.bearer_token) {
                (Some(_), Some(_)) => {
                    return Err(Error::Config(format!(
                        "session {:?} has both cookie and bearer_token; use exactly one",
                        s.name
                    )))
                }
                (None, None) => {
                    return Err(Error::Config(format!(
                        "session {:?} has neither cookie nor bearer_token",
                        s.name
                    )))
                }
                _ => {}
            }
        }
        let session_exists = |name: &str| self.sessions.iter().any(|s| s.name == name);

        if self.targets.is_empty() {
            return Err(Error::Config("no [[target]] defined".into()));
        }

        for t in &self.targets {
            // Target host must itself be in scope.
            let url = url::Url::parse(&t.base_url)
                .map_err(|e| Error::Config(format!("target {:?} base_url: {e}", t.name)))?;
            let host = url
                .host_str()
                .ok_or_else(|| Error::Config(format!("target {:?} base_url has no host", t.name)))?;
            if !guard.allows_host(host) {
                return Err(Error::Config(format!(
                    "target {:?} host '{host}' is not covered by scope.allow",
                    t.name
                )));
            }
            if !session_exists(&t.baseline_session) {
                return Err(Error::Config(format!(
                    "target {:?} baseline_session {:?} is not defined",
                    t.name, t.baseline_session
                )));
            }

            match t.protocol {
                Protocol::Rest => {
                    if t.endpoints.is_empty() {
                        return Err(Error::Config(format!(
                            "REST target {:?} has no [[target.endpoint]]",
                            t.name
                        )));
                    }
                    for e in &t.endpoints {
                        let placeholder = format!("{{{}}}", e.id_param);
                        if !e.path_template.contains(&placeholder) {
                            return Err(Error::Config(format!(
                                "endpoint {:?}: path_template {:?} is missing the id placeholder {placeholder}",
                                e.name, e.path_template
                            )));
                        }
                        check_sessions(&e.sessions, &t.baseline_session, &e.name, session_exists)?;
                    }
                }
                Protocol::GraphQl => {
                    if t.graphql_queries.is_empty() {
                        return Err(Error::Config(format!(
                            "GraphQL target {:?} has no [[target.graphql_query]]",
                            t.name
                        )));
                    }
                    for q in &t.graphql_queries {
                        check_sessions(&q.sessions, &t.baseline_session, &q.name, session_exists)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Filesystem-dependent validation (graphql query files exist and mention
    /// the variable). Split out so [`Config::validate`] stays pure for tests.
    pub fn validate_files(&self) -> Result<()> {
        for t in &self.targets {
            for q in &t.graphql_queries {
                let resolved = if q.query_file.is_absolute() {
                    q.query_file.clone()
                } else {
                    self.base_dir.join(&q.query_file)
                };
                let text = std::fs::read_to_string(&resolved).map_err(|e| {
                    Error::Config(format!(
                        "graphql_query {:?} query_file {resolved:?}: {e}",
                        q.name
                    ))
                })?;
                let var = format!("${}", q.variable_name);
                if !text.contains(&var) {
                    return Err(Error::Config(format!(
                        "graphql_query {:?}: query file does not reference variable {var}",
                        q.name
                    )));
                }
            }
        }
        Ok(())
    }
}

fn check_sessions(
    sessions: &[String],
    baseline: &str,
    owner_name: &str,
    exists: impl Fn(&str) -> bool,
) -> Result<()> {
    if sessions.len() < 2 {
        return Err(Error::Config(format!(
            "{owner_name:?}: needs at least 2 sessions to compare (got {})",
            sessions.len()
        )));
    }
    if !sessions.iter().any(|s| s == baseline) {
        return Err(Error::Config(format!(
            "{owner_name:?}: sessions list must include the baseline_session {baseline:?}"
        )));
    }
    for s in sessions {
        if !exists(s) {
            return Err(Error::Config(format!("{owner_name:?}: session {s:?} is not defined")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN: &str = r#"
[scope]
allow = ["api.example.com"]

[[target]]
name = "orders"
base_url = "https://api.example.com"
baseline_session = "a"

  [[target.endpoint]]
  name = "get_order"
  path_template = "/api/orders/{id}"
  method = "GET"
  id_param = "id"
  id_source = { kind = "range", start = 1, end = 3 }
  sessions = ["a", "b"]
"#;

    const SECRETS: &str = r#"
[[session]]
name = "a"
cookie = "sid=1"

[[session]]
name = "b"
bearer_token = "tok"
"#;

    fn loaded() -> Config {
        let mut c = Config::parse(MAIN).unwrap();
        c.merge_secrets(SECRETS).unwrap();
        c
    }

    #[test]
    fn valid_config_passes() {
        loaded().validate().unwrap();
    }

    #[test]
    fn defaults_are_conservative() {
        let c = loaded();
        assert!(c.general.dry_run, "dry_run must default to true");
        assert_eq!(c.rate_limit.requests_per_second, 2.0);
        assert_eq!(c.rate_limit.max_concurrency, 4);
    }

    #[test]
    fn sessions_only_come_from_secrets() {
        // Even if the main file contains [[session]], it is ignored (serde skip).
        let sneaky = format!("{MAIN}\n[[session]]\nname = \"leaked\"\ncookie=\"x\"\n");
        let c = Config::parse(&sneaky).unwrap();
        assert!(c.sessions.is_empty());
    }

    #[test]
    fn unknown_session_reference_fails() {
        let mut c = Config::parse(MAIN).unwrap();
        c.merge_secrets("[[session]]\nname=\"a\"\ncookie=\"x\"\n").unwrap(); // missing "b"
        let err = c.validate().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn out_of_scope_target_fails() {
        let bad = MAIN.replace("api.example.com\"]", "other.example.com\"]");
        let mut c = Config::parse(&bad).unwrap();
        c.merge_secrets(SECRETS).unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn missing_path_placeholder_fails() {
        let bad = MAIN.replace("/api/orders/{id}", "/api/orders");
        let mut c = Config::parse(&bad).unwrap();
        c.merge_secrets(SECRETS).unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn session_with_two_credentials_fails() {
        let mut c = Config::parse(MAIN).unwrap();
        c.merge_secrets("[[session]]\nname=\"a\"\ncookie=\"x\"\nbearer_token=\"y\"\n[[session]]\nname=\"b\"\ncookie=\"z\"\n")
            .unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn range_expands_inclusive() {
        let ids = IdSource::Range { start: 1, end: 3 }.expand(Path::new(".")).unwrap();
        assert_eq!(ids, vec![IdValue::Numeric(1), IdValue::Numeric(2), IdValue::Numeric(3)]);
    }
}
