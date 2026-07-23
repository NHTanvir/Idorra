//! Turn a [`TestCase`] + [`Session`] into a concrete [`RequestSpec`] — pure, no
//! network. This is where the id lands in the chosen location (path / query /
//! header / JSON body) and where GraphQL payloads are shaped.
//!
//! Path semantics: `base_url` is treated as `scheme://host[:port]` and
//! `path_template` as the full path. For non-`Path` locations the `/{id_param}`
//! segment is stripped from the path and the id is injected elsewhere, e.g.
//! `/api/orders/{id}` becomes `/api/orders?id=123` for the `Query` location.

use crate::error::{Error, Result};
use crate::outcome::RequestSpec;
use crate::session::Session;
use crate::testcase::{HttpMethod, ParamLocation, Protocol, TestCase};
use url::Url;

/// Build the wire request for a test case under a given session.
pub fn build_spec(tc: &TestCase, session: &Session) -> Result<RequestSpec> {
    let mut headers: Vec<(String, String)> = session.headers.clone();
    for (k, v) in &tc.extra_headers {
        headers.push((k.clone(), v.clone()));
    }

    let mut body: Option<Vec<u8>> = None;
    let mut content_type: Option<String> = None;
    let method;
    let url;

    match tc.protocol {
        Protocol::GraphQl => {
            method = HttpMethod::Post;
            let gp = tc.graphql.as_ref().ok_or_else(|| {
                Error::Config(format!("GraphQL test case {} has no payload", tc.id))
            })?;
            let payload = serde_json::json!({
                "query": gp.query,
                "variables": { gp.variable_name.clone(): gp.id_value.to_json() },
            });
            body = Some(serde_json::to_vec(&payload)?);
            content_type = Some("application/json".to_string());
            url = join_url(&tc.base_url, "")?;
        }
        Protocol::Rest => {
            method = tc.method;
            let placeholder = format!("{{{}}}", tc.id_param);
            let id_str = tc.id_value.to_string();

            match tc.param_location {
                ParamLocation::Path => {
                    let path = tc.path_template.replace(&placeholder, &id_str);
                    url = join_url(&tc.base_url, &path)?;
                }
                ParamLocation::Query => {
                    let path = strip_placeholder(&tc.path_template, &placeholder);
                    let mut u = Url::parse(&join_url(&tc.base_url, &path)?)?;
                    u.query_pairs_mut().append_pair(&tc.id_param, &id_str);
                    url = u.to_string();
                }
                ParamLocation::Header => {
                    let path = strip_placeholder(&tc.path_template, &placeholder);
                    url = join_url(&tc.base_url, &path)?;
                    headers.push((tc.id_param.clone(), id_str));
                }
                ParamLocation::JsonBody => {
                    let path = strip_placeholder(&tc.path_template, &placeholder);
                    url = join_url(&tc.base_url, &path)?;
                    let payload =
                        serde_json::json!({ tc.id_param.clone(): tc.id_value.to_json() });
                    body = Some(serde_json::to_vec(&payload)?);
                    content_type = Some("application/json".to_string());
                }
            }
        }
    }

    Ok(RequestSpec {
        method,
        url,
        headers,
        body,
        content_type,
        test_case_id: tc.id,
        target_name: tc.target_name.clone(),
        session: tc.session.clone(),
        strategy: tc.strategy,
        param_location: tc.param_location,
        id_value: tc.id_value.clone(),
        comparison_group_id: tc.comparison_group_id,
        protocol: tc.protocol,
    })
}

/// Join a `scheme://host[:port]` base with a full path (leading `/` optional).
fn join_url(base_url: &str, path: &str) -> Result<String> {
    let base = base_url.trim_end_matches('/');
    let full = if path.is_empty() {
        base.to_string()
    } else if let Some(stripped) = path.strip_prefix('/') {
        format!("{base}/{stripped}")
    } else {
        format!("{base}/{path}")
    };
    // Validate it parses as an absolute URL.
    let _ = Url::parse(&full)?;
    Ok(full)
}

/// Remove the `/{id_param}` segment (or a bare `{id_param}`) from a path.
fn strip_placeholder(path: &str, placeholder: &str) -> String {
    let with_slash = format!("/{placeholder}");
    if let Some(idx) = path.find(&with_slash) {
        let mut s = path.to_string();
        s.replace_range(idx..idx + with_slash.len(), "");
        s
    } else {
        path.replace(placeholder, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testcase::{ComparisonGroupId, GraphQlPayload, IdValue, TestStrategy};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn session() -> Session {
        Session {
            name: "a".into(),
            description: None,
            headers: vec![("Cookie".into(), "sid=1".into())],
        }
    }

    fn rest_case(location: ParamLocation) -> TestCase {
        TestCase {
            id: Uuid::nil(),
            target_name: "t".into(),
            protocol: Protocol::Rest,
            method: HttpMethod::Get,
            base_url: "https://api.example.com".into(),
            path_template: "/api/orders/{id}".into(),
            param_location: location,
            id_param: "id".into(),
            id_value: IdValue::Numeric(123),
            graphql: None,
            session: "a".into(),
            strategy: TestStrategy::IdEnumeration,
            comparison_group_id: ComparisonGroupId(Uuid::nil()),
            extra_headers: BTreeMap::new(),
        }
    }

    #[test]
    fn path_location_substitutes_id() {
        let spec = build_spec(&rest_case(ParamLocation::Path), &session()).unwrap();
        assert_eq!(spec.url, "https://api.example.com/api/orders/123");
        assert!(spec.body.is_none());
        // Session cookie is attached.
        assert!(spec.headers.iter().any(|(k, v)| k == "Cookie" && v == "sid=1"));
    }

    #[test]
    fn query_location_moves_id_to_querystring() {
        let spec = build_spec(&rest_case(ParamLocation::Query), &session()).unwrap();
        assert_eq!(spec.url, "https://api.example.com/api/orders?id=123");
    }

    #[test]
    fn header_location_moves_id_to_header() {
        let spec = build_spec(&rest_case(ParamLocation::Header), &session()).unwrap();
        assert_eq!(spec.url, "https://api.example.com/api/orders");
        assert!(spec.headers.iter().any(|(k, v)| k == "id" && v == "123"));
    }

    #[test]
    fn json_body_location_moves_id_to_body() {
        let spec = build_spec(&rest_case(ParamLocation::JsonBody), &session()).unwrap();
        assert_eq!(spec.url, "https://api.example.com/api/orders");
        let body: serde_json::Value =
            serde_json::from_slice(spec.body.as_ref().unwrap()).unwrap();
        assert_eq!(body["id"], serde_json::json!(123));
        assert_eq!(spec.content_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn graphql_builds_post_with_variables() {
        let mut tc = rest_case(ParamLocation::JsonBody);
        tc.protocol = Protocol::GraphQl;
        tc.graphql = Some(GraphQlPayload {
            query: "query($id: ID!){ order(id:$id){ id } }".into(),
            variable_name: "id".into(),
            id_value: IdValue::Str("abc".into()),
        });
        let spec = build_spec(&tc, &session()).unwrap();
        assert_eq!(spec.method, HttpMethod::Post);
        assert_eq!(spec.url, "https://api.example.com");
        let body: serde_json::Value =
            serde_json::from_slice(spec.body.as_ref().unwrap()).unwrap();
        assert_eq!(body["variables"]["id"], serde_json::json!("abc"));
    }
}
