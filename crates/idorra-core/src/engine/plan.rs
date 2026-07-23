//! Test-plan generation: expand config + id sources into concrete [`TestCase`]s,
//! assigning a shared [`ComparisonGroupId`] to every set of cases that must be
//! compared together (and marking the reference case with `is_baseline`).
//!
//! The strategies deliberately share one generator so a group's correlation id
//! is assigned exactly once, adjacently — never from separate per-session loops
//! that could lose the correlation.

use crate::config::{Config, Endpoint, GraphQlQuery, Target};
use crate::error::{Error, Result};
use crate::testcase::{
    ComparisonGroupId, GraphQlPayload, HttpMethod, IdValue, ParamLocation, Protocol, TestCase,
    TestStrategy,
};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Generate the full list of test cases for a validated config.
pub fn generate(config: &Config) -> Result<Vec<TestCase>> {
    let mut out = Vec::new();
    for target in &config.targets {
        match target.protocol {
            Protocol::Rest => {
                for endpoint in &target.endpoints {
                    gen_endpoint(config, target, endpoint, &mut out)?;
                }
            }
            Protocol::GraphQl => {
                for query in &target.graphql_queries {
                    gen_graphql(config, target, query, &mut out)?;
                }
            }
        }
    }
    Ok(out)
}

fn gen_endpoint(
    config: &Config,
    target: &Target,
    endpoint: &Endpoint,
    out: &mut Vec<TestCase>,
) -> Result<()> {
    let ids = endpoint.id_source.expand(&config.base_dir)?;

    for id in &ids {
        // --- Strategy: two-session comparison (core IDOR) ---
        let group = ComparisonGroupId::new();
        for session in &endpoint.sessions {
            let is_baseline = *session == target.baseline_session;
            out.push(rest_case(
                target,
                endpoint,
                id.clone(),
                endpoint.method,
                ParamLocation::Path,
                session,
                TestStrategy::TwoSessionCompare,
                is_baseline,
                group,
            ));
        }

        // --- Strategy: HTTP method tampering (baseline session) ---
        // Only when there's at least one method that differs from the baseline,
        // otherwise the group would be a lone baseline with nothing to compare.
        let extra_methods: Vec<HttpMethod> = endpoint
            .test_methods
            .iter()
            .copied()
            .filter(|m| *m != endpoint.method)
            .collect();
        if !extra_methods.is_empty() {
            let group = ComparisonGroupId::new();
            out.push(rest_case(
                target,
                endpoint,
                id.clone(),
                endpoint.method,
                ParamLocation::Path,
                &target.baseline_session,
                TestStrategy::MethodTampering,
                true,
                group,
            ));
            for method in extra_methods {
                out.push(rest_case(
                    target,
                    endpoint,
                    id.clone(),
                    method,
                    ParamLocation::Path,
                    &target.baseline_session,
                    TestStrategy::MethodTampering,
                    false,
                    group,
                ));
            }
        }

        // --- Strategy: parameter-location tampering (baseline session) ---
        let locations = location_set(&endpoint.param_locations);
        if locations.len() > 1 {
            let group = ComparisonGroupId::new();
            for loc in &locations {
                let is_baseline = *loc == ParamLocation::Path;
                out.push(rest_case(
                    target,
                    endpoint,
                    id.clone(),
                    endpoint.method,
                    *loc,
                    &target.baseline_session,
                    TestStrategy::ParamLocationTampering,
                    is_baseline,
                    group,
                ));
            }
        }
    }
    Ok(())
}

fn gen_graphql(
    config: &Config,
    target: &Target,
    query: &GraphQlQuery,
    out: &mut Vec<TestCase>,
) -> Result<()> {
    let path = if query.query_file.is_absolute() {
        query.query_file.clone()
    } else {
        config.base_dir.join(&query.query_file)
    };
    let query_text = std::fs::read_to_string(&path)
        .map_err(|e| Error::Config(format!("graphql_query {:?} file {path:?}: {e}", query.name)))?;
    let ids = query.id_source.expand(&config.base_dir)?;

    for id in &ids {
        let group = ComparisonGroupId::new();
        for session in &query.sessions {
            let is_baseline = *session == target.baseline_session;
            out.push(TestCase {
                id: Uuid::new_v4(),
                target_name: target.name.clone(),
                protocol: Protocol::GraphQl,
                method: HttpMethod::Post,
                base_url: target.base_url.clone(),
                path_template: String::new(),
                param_location: ParamLocation::JsonBody,
                id_param: query.variable_name.clone(),
                id_value: id.clone(),
                graphql: Some(GraphQlPayload {
                    query: query_text.clone(),
                    variable_name: query.variable_name.clone(),
                    id_value: id.clone(),
                }),
                session: session.clone(),
                strategy: TestStrategy::GraphQlVariation,
                is_baseline,
                comparison_group_id: group,
                extra_headers: BTreeMap::new(),
            });
        }
    }
    Ok(())
}

/// Ensure `Path` is present (as the baseline) and preserve the rest in order.
fn location_set(configured: &[ParamLocation]) -> Vec<ParamLocation> {
    let mut v = configured.to_vec();
    if !v.contains(&ParamLocation::Path) {
        v.insert(0, ParamLocation::Path);
    }
    v
}

#[allow(clippy::too_many_arguments)]
fn rest_case(
    target: &Target,
    endpoint: &Endpoint,
    id_value: IdValue,
    method: HttpMethod,
    param_location: ParamLocation,
    session: &str,
    strategy: TestStrategy,
    is_baseline: bool,
    comparison_group_id: ComparisonGroupId,
) -> TestCase {
    TestCase {
        id: Uuid::new_v4(),
        target_name: target.name.clone(),
        protocol: Protocol::Rest,
        method,
        base_url: target.base_url.clone(),
        path_template: endpoint.path_template.clone(),
        param_location,
        id_param: endpoint.id_param.clone(),
        id_value,
        graphql: None,
        session: session.to_string(),
        strategy,
        is_baseline,
        comparison_group_id,
        extra_headers: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

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
  param_locations = ["path", "query"]
  test_methods = ["DELETE"]
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

    #[test]
    fn generates_expected_case_count_and_baselines() {
        let cases = generate(&config()).unwrap();
        // per id: 2 (two-session) + 2 (method: GET baseline + DELETE) + 2 (param: path + query) = 6
        // 3 ids => 18 cases
        assert_eq!(cases.len(), 18);

        // Every comparison group has exactly one baseline case.
        let mut groups: BTreeMap<Uuid, (usize, usize)> = BTreeMap::new();
        for c in &cases {
            let e = groups.entry(c.comparison_group_id.0).or_default();
            e.0 += 1;
            if c.is_baseline {
                e.1 += 1;
            }
        }
        assert_eq!(groups.len(), 9, "3 ids x 3 strategies");
        for (total, baselines) in groups.values() {
            assert!(*total >= 2);
            assert_eq!(*baselines, 1, "each group has exactly one baseline");
        }
    }

    #[test]
    fn two_session_group_uses_configured_baseline() {
        let cases = generate(&config()).unwrap();
        let baseline = cases
            .iter()
            .find(|c| c.strategy == TestStrategy::TwoSessionCompare && c.is_baseline)
            .unwrap();
        assert_eq!(baseline.session, "a");
    }
}
