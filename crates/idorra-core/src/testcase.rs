//! The unit of work — a single planned request — plus the small shared enums
//! (protocol, method, parameter location, id value) used across the crate.
//!
//! A [`TestCase`] describes *what to send*; it says nothing about whether the
//! send is allowed. Scope enforcement, rate limiting, and dry-run all happen
//! later, at the [`crate::http::client::Gate`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use uuid::Uuid;

/// REST vs GraphQL. Governs how the request body/id are shaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Plain REST/JSON endpoint.
    #[default]
    Rest,
    /// GraphQL endpoint (always POST, id carried as a query variable).
    #[serde(rename = "graphql")]
    GraphQl,
}

/// HTTP verbs the tool can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// DELETE.
    Delete,
    /// PATCH.
    Patch,
}

impl HttpMethod {
    /// The canonical uppercase token (`"GET"`, `"POST"`, …).
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where the identifier is injected for a given test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamLocation {
    /// Substituted into the URL path (`/api/orders/{id}`).
    Path,
    /// Appended as a query parameter (`?id=…`).
    Query,
    /// Sent as an HTTP header.
    Header,
    /// Placed in a JSON request body (`{"id": …}`).
    JsonBody,
}

impl fmt::Display for ParamLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ParamLocation::Path => "path",
            ParamLocation::Query => "query",
            ParamLocation::Header => "header",
            ParamLocation::JsonBody => "json_body",
        };
        f.write_str(s)
    }
}

/// An identifier value — numeric or opaque string (UUID, slug, …).
///
/// `untagged` so TOML/JSON `123` deserializes to `Numeric` and `"a1b2"` to `Str`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IdValue {
    /// A numeric id.
    Numeric(i64),
    /// A string id.
    Str(String),
}

impl fmt::Display for IdValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdValue::Numeric(n) => write!(f, "{n}"),
            IdValue::Str(s) => f.write_str(s),
        }
    }
}

impl IdValue {
    /// Render as a JSON value, preserving numeric vs string type (important for
    /// GraphQL variable typing and JSON request bodies).
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            IdValue::Numeric(n) => serde_json::Value::from(*n),
            IdValue::Str(s) => serde_json::Value::from(s.clone()),
        }
    }
}

/// Which testing strategy produced a test case (drives scoring).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestStrategy {
    /// Enumerate an id range/list against one endpoint.
    IdEnumeration,
    /// Same request under different sessions (the core IDOR check).
    TwoSessionCompare,
    /// Same endpoint under different HTTP verbs.
    MethodTampering,
    /// Same id in path vs query vs header vs body.
    ParamLocationTampering,
    /// GraphQL query with varied id variable.
    GraphQlVariation,
}

/// A GraphQL request payload: the query template text plus the id variable to
/// bind. The variable's JSON type is preserved from [`IdValue`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphQlPayload {
    /// The raw GraphQL query/mutation text (from a user-supplied template).
    pub query: String,
    /// The variable name to bind the id to (e.g. `id`, referenced as `$id`).
    pub variable_name: String,
    /// The id value bound this run.
    pub id_value: IdValue,
}

/// A named-session reference (key into the [`crate::session::SessionStore`]).
pub type SessionRef = String;

/// Correlates the set of test cases that form one logical comparison (same
/// endpoint/id/method/location, differing only by session). Assigned once at
/// plan-generation time and threaded, untouched, into every outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ComparisonGroupId(pub Uuid);

impl ComparisonGroupId {
    /// A fresh random group id.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ComparisonGroupId {
    fn default() -> Self {
        Self::new()
    }
}

/// A single planned request. Pure data — building one touches no network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Unique id, for correlating logs/outcomes/findings.
    pub id: Uuid,
    /// The target this case belongs to.
    pub target_name: String,
    /// REST vs GraphQL.
    pub protocol: Protocol,
    /// The HTTP method to send.
    pub method: HttpMethod,
    /// The target base URL (scheme://host[:port]).
    pub base_url: String,
    /// Path template, may contain the `{id_param}` placeholder.
    pub path_template: String,
    /// Where the id is injected for this case.
    pub param_location: ParamLocation,
    /// The name of the id parameter (e.g. `id`).
    pub id_param: String,
    /// The id value under test.
    pub id_value: IdValue,
    /// GraphQL payload, present iff `protocol == GraphQl`.
    pub graphql: Option<GraphQlPayload>,
    /// The session that sends this request.
    pub session: SessionRef,
    /// The strategy that generated this case.
    pub strategy: TestStrategy,
    /// The comparison group this case participates in.
    pub comparison_group_id: ComparisonGroupId,
    /// Static extra headers merged in (from target/endpoint config).
    pub extra_headers: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_value_untagged_roundtrip() {
        let n: IdValue = serde_json::from_str("123").unwrap();
        assert_eq!(n, IdValue::Numeric(123));
        let s: IdValue = serde_json::from_str("\"a1b2\"").unwrap();
        assert_eq!(s, IdValue::Str("a1b2".into()));
    }

    #[test]
    fn id_value_json_preserves_type() {
        assert!(IdValue::Numeric(5).to_json().is_number());
        assert!(IdValue::Str("5".into()).to_json().is_string());
    }

    #[test]
    fn method_tokens() {
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
        assert_eq!(HttpMethod::Get.to_string(), "GET");
    }
}
