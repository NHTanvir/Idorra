//! The engine: generate a plan, run it through the gate with bounded
//! concurrency, group the outcomes by comparison id, and score them into
//! findings.

pub mod plan;

use crate::analysis::scoring;
use crate::config::Config;
use crate::error::Result;
use crate::finding::Finding;
use crate::http::{Gate, GateConfig, Limiter};
use crate::logging::AuditSink;
use crate::outcome::RequestOutcome;
use crate::scope::ScopeGuard;
use crate::session::SessionStore;
use crate::testcase::{TestCase, TestStrategy};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use uuid::Uuid;

/// The result of a run: request counts plus scored findings and raw outcomes.
#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    /// Total planned test cases.
    pub total: usize,
    /// Requests actually sent (a response or send-error was produced).
    pub sent: usize,
    /// Requests blocked by the scope gate (never sent).
    pub blocked: usize,
    /// Requests skipped as dry-run.
    pub dry_run: usize,
    /// Requests that errored at the network layer.
    pub errored: usize,
    /// Whether the run was a dry run.
    pub was_dry_run: bool,
    /// Scored findings, most severe first.
    pub findings: Vec<Finding>,
    /// All raw outcomes (evidence), for the JSON report.
    pub outcomes: Vec<RequestOutcome>,
}

impl RunSummary {
    fn build(total: usize, was_dry_run: bool, outcomes: Vec<RequestOutcome>, findings: Vec<Finding>) -> Self {
        let mut sent = 0;
        let mut blocked = 0;
        let mut dry = 0;
        let mut errored = 0;
        for o in &outcomes {
            if o.dry_run {
                dry += 1;
            } else if o.status.is_some() {
                sent += 1;
            } else if let Some(e) = &o.error {
                if e.contains("BLOCKED") {
                    blocked += 1;
                } else {
                    errored += 1;
                }
            }
        }
        Self { total, sent, blocked, dry_run: dry, errored, was_dry_run, findings, outcomes }
    }
}

/// Drives a full run from a validated [`Config`].
pub struct Engine {
    config: Config,
    gate: Arc<Gate>,
    sessions: Arc<SessionStore>,
    dry_run: bool,
}

impl Engine {
    /// Wire an engine from config: build the scope guard, rate limiter, gate, and
    /// session store. `dry_run_override` lets the CLI force `--live`/`--dry-run`
    /// over the config default.
    pub fn from_config(
        config: Config,
        audit: Arc<dyn AuditSink>,
        include_secrets_in_log: bool,
        dry_run_override: Option<bool>,
    ) -> Result<Self> {
        let scope = Arc::new(ScopeGuard::new(&config.scope.allow, &config.scope.allow_ports)?);
        let limiter = Arc::new(Limiter::new(
            config.rate_limit.requests_per_second,
            config.rate_limit.burst,
            config.rate_limit.max_concurrency,
        )?);
        let dry_run = dry_run_override.unwrap_or(config.general.dry_run);
        let gate = Gate::new(
            scope,
            limiter,
            audit,
            GateConfig {
                connect_timeout: Duration::from_secs(config.http.connect_timeout_secs),
                request_timeout: Duration::from_secs(config.http.request_timeout_secs),
                max_body_capture_bytes: config.http.max_body_capture_bytes,
                proxy: config.http.proxy.clone(),
                dry_run,
                include_secrets_in_log,
            },
        )?;
        let sessions = Arc::new(SessionStore::from_configs(&config.sessions)?);
        Ok(Self { config, gate: Arc::new(gate), sessions, dry_run })
    }

    /// The resolved config.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Whether this run will be a dry run.
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Generate the test plan (without running it).
    pub fn plan(&self) -> Result<Vec<TestCase>> {
        plan::generate(&self.config)
    }

    /// Generate, execute, and score a full run.
    pub async fn run(&self) -> Result<RunSummary> {
        let cases = self.plan()?;
        let total = cases.len();
        let outcomes = self.execute(cases).await;
        let findings = self.score(&outcomes);
        Ok(RunSummary::build(total, self.dry_run, outcomes, findings))
    }

    /// Execute all cases through the gate, capped at `max_concurrency` in-flight.
    async fn execute(&self, cases: Vec<TestCase>) -> Vec<RequestOutcome> {
        let cap = self.config.rate_limit.max_concurrency.max(1);
        let mut set: JoinSet<RequestOutcome> = JoinSet::new();
        let mut outcomes = Vec::with_capacity(cases.len());

        for tc in cases {
            let Some(session) = self.sessions.get(&tc.session).cloned() else {
                // Validation guarantees the session exists; skip defensively.
                continue;
            };
            let gate = self.gate.clone();
            set.spawn(async move { gate.send_test_case(&tc, &session).await });

            while set.len() >= cap {
                if let Some(res) = set.join_next().await {
                    outcomes.push(res.expect("gate task panicked"));
                }
            }
        }
        while let Some(res) = set.join_next().await {
            outcomes.push(res.expect("gate task panicked"));
        }
        outcomes
    }

    /// Group outcomes by comparison id and apply the scoring rules.
    fn score(&self, outcomes: &[RequestOutcome]) -> Vec<Finding> {
        let mut groups: BTreeMap<Uuid, Vec<&RequestOutcome>> = BTreeMap::new();
        for o in outcomes {
            groups.entry(o.comparison_group_id.0).or_default().push(o);
        }

        let mut findings = Vec::new();
        for group in groups.values() {
            let Some(first) = group.first() else { continue };
            let strategy = first.strategy;
            let baseline = group.iter().copied().find(|o| o.is_baseline);

            match strategy {
                TestStrategy::TwoSessionCompare => {
                    if let Some(base) = baseline {
                        for other in group.iter().filter(|o| !o.is_baseline) {
                            if let Some(f) =
                                scoring::cross_session_finding(base, other, &self.config.analysis)
                            {
                                findings.push(f);
                            }
                        }
                    }
                }
                TestStrategy::GraphQlVariation => {
                    for o in group {
                        if let Some(f) = scoring::graphql_schema_warning(o) {
                            findings.push(f);
                        }
                    }
                    if let Some(base) = baseline {
                        for other in group.iter().filter(|o| !o.is_baseline) {
                            if let Some(f) =
                                scoring::cross_session_finding(base, other, &self.config.analysis)
                            {
                                findings.push(f);
                            }
                        }
                    }
                }
                TestStrategy::MethodTampering | TestStrategy::ParamLocationTampering => {
                    if let Some(base) = baseline {
                        for variant in group.iter().filter(|o| !o.is_baseline) {
                            if let Some(f) = scoring::bypass_finding(base, variant, strategy) {
                                findings.push(f);
                            }
                        }
                    }
                }
                TestStrategy::IdEnumeration => {}
            }
        }

        // Most severe first, then highest confidence.
        findings.sort_by(|a, b| {
            b.severity.cmp(&a.severity).then(b.confidence.cmp(&a.confidence))
        });
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::NullAuditLog;

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
  id_source = { kind = "range", start = 1, end = 2 }
  sessions = ["a", "b"]
"#;

    const SECRETS: &str = r#"
[[session]]
name = "a"
cookie = "sid=1"
[[session]]
name = "b"
bearer_token = "t"
"#;

    fn config() -> Config {
        let mut c = Config::parse(MAIN).unwrap();
        c.merge_secrets(SECRETS).unwrap();
        c.validate().unwrap();
        c
    }

    #[tokio::test]
    async fn dry_run_sends_nothing_and_finds_nothing() {
        let engine =
            Engine::from_config(config(), Arc::new(NullAuditLog), false, Some(true)).unwrap();
        assert!(engine.is_dry_run());
        let summary = engine.run().await.unwrap();
        assert_eq!(summary.total, 4); // 2 ids x 2 sessions (two-session only)
        assert_eq!(summary.dry_run, 4);
        assert_eq!(summary.sent, 0);
        assert_eq!(summary.blocked, 0);
        assert!(summary.findings.is_empty());
    }
}
