//! Path- and kind-aware structural JSON diff.
//!
//! Compares two JSON documents by flattening each to a map of leaf-path → scalar
//! value, then classifying every leaf as identical / changed / added / removed.
//! This catches the core IDOR signal — "same shape *and* same values" — while
//! being insensitive to object key ordering.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Summary of a structural diff between a baseline (A) and a variant (B).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonDiffSummary {
    /// Leaf paths present in B but not A.
    pub added_paths: Vec<String>,
    /// Leaf paths present in A but not B.
    pub removed_paths: Vec<String>,
    /// Leaf paths present in both but with a different value/kind.
    pub changed_paths: Vec<String>,
    /// Count of leaves identical in both.
    pub identical_leaves: usize,
    /// Total distinct leaf paths across both (the union).
    pub total_leaves: usize,
}

impl JsonDiffSummary {
    /// Fraction of union leaves that are identical (1.0 when both are empty).
    pub fn similarity(&self) -> f64 {
        if self.total_leaves == 0 {
            1.0
        } else {
            self.identical_leaves as f64 / self.total_leaves as f64
        }
    }

    /// True when the two documents are near-identical (default threshold 0.9).
    pub fn is_near_identical(&self) -> bool {
        self.similarity() >= 0.9
    }
}

/// Compute a structural diff of two JSON values.
pub fn diff(a: &Value, b: &Value) -> JsonDiffSummary {
    let mut fa = BTreeMap::new();
    flatten(a, String::new(), &mut fa);
    let mut fb = BTreeMap::new();
    flatten(b, String::new(), &mut fb);

    let mut added_paths = Vec::new();
    let mut removed_paths = Vec::new();
    let mut changed_paths = Vec::new();
    let mut identical_leaves = 0usize;

    for (path, va) in &fa {
        match fb.get(path) {
            Some(vb) if vb == va => identical_leaves += 1,
            Some(_) => changed_paths.push(path.clone()),
            None => removed_paths.push(path.clone()),
        }
    }
    for path in fb.keys() {
        if !fa.contains_key(path) {
            added_paths.push(path.clone());
        }
    }

    let total_leaves = fa.len() + added_paths.len();
    JsonDiffSummary { added_paths, removed_paths, changed_paths, identical_leaves, total_leaves }
}

/// Flatten a JSON value into leaf-path → scalar entries. Empty objects/arrays
/// are recorded as leaves so their presence is counted.
fn flatten(v: &Value, prefix: String, out: &mut BTreeMap<String, Value>) {
    match v {
        Value::Object(map) => {
            if map.is_empty() {
                out.insert(prefix, Value::Object(Default::default()));
            } else {
                for (k, val) in map {
                    let path =
                        if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                    flatten(val, path, out);
                }
            }
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                out.insert(prefix, Value::Array(Vec::new()));
            } else {
                for (i, val) in arr.iter().enumerate() {
                    flatten(val, format!("{prefix}[{i}]"), out);
                }
            }
        }
        scalar => {
            out.insert(prefix, scalar.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identical_documents_have_similarity_one() {
        let a = json!({"id": 1, "name": "x", "nested": {"a": true}});
        let b = json!({"nested": {"a": true}, "name": "x", "id": 1}); // key order differs
        let d = diff(&a, &b);
        assert_eq!(d.similarity(), 1.0);
        assert!(d.is_near_identical());
        assert!(d.changed_paths.is_empty());
    }

    #[test]
    fn changed_value_is_detected() {
        let a = json!({"id": 1, "owner": "alice"});
        let b = json!({"id": 1, "owner": "bob"});
        let d = diff(&a, &b);
        assert_eq!(d.changed_paths, vec!["owner".to_string()]);
        assert_eq!(d.identical_leaves, 1);
        assert_eq!(d.total_leaves, 2);
        assert!(d.similarity() < 0.9);
    }

    #[test]
    fn added_and_removed_paths_tracked() {
        let a = json!({"id": 1, "only_a": 9});
        let b = json!({"id": 1, "only_b": 8});
        let d = diff(&a, &b);
        assert_eq!(d.removed_paths, vec!["only_a".to_string()]);
        assert_eq!(d.added_paths, vec!["only_b".to_string()]);
        assert_eq!(d.total_leaves, 3);
    }
}
