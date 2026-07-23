//! Heuristic sensitive-field detection: walk a JSON response and flag object keys
//! whose names look sensitive (email, phone, token, …) and that carry a real
//! (non-null, non-empty) value.
//!
//! The built-in list is additively extended by `[analysis].sensitive_field_patterns`
//! from config — config adds to, never replaces, the defaults.

use serde_json::Value;

/// Built-in sensitive field-name substrings, matched case-insensitively.
pub const BUILTIN_PATTERNS: &[&str] = &[
    "email",
    "phone",
    "mobile",
    "ssn",
    "social_security",
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "credit",
    "card_number",
    "cardnumber",
    "cvv",
    "iban",
    "address",
    "dob",
    "date_of_birth",
    "birth",
    "first_name",
    "last_name",
    "full_name",
    "national_id",
    "passport",
    "auth",
];

/// Detect sensitive fields in a JSON value. Returns the sorted, de-duplicated
/// leaf paths of matching keys. `extra` patterns are added to the built-ins.
pub fn detect(value: &Value, extra: &[String]) -> Vec<String> {
    let mut patterns: Vec<String> = BUILTIN_PATTERNS.iter().map(|s| s.to_string()).collect();
    for e in extra {
        patterns.push(e.to_ascii_lowercase());
    }
    let mut hits: Vec<String> = Vec::new();
    walk(value, String::new(), None, &patterns, &mut hits);
    hits.sort();
    hits.dedup();
    hits
}

fn key_is_sensitive(key: &str, patterns: &[String]) -> bool {
    let lower = key.to_ascii_lowercase();
    patterns.iter().any(|p| lower.contains(p.as_str()))
}

fn value_is_meaningful(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => true,
    }
}

fn walk(v: &Value, path: String, key: Option<&str>, patterns: &[String], hits: &mut Vec<String>) {
    if let Some(k) = key {
        if key_is_sensitive(k, patterns) && value_is_meaningful(v) {
            hits.push(path.clone());
        }
    }
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                walk(val, p, Some(k), patterns, hits);
            }
        }
        Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                walk(val, format!("{path}[{i}]"), None, patterns, hits);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_builtin_sensitive_keys_with_values() {
        let v = json!({"user": {"email": "a@b.com", "id": 5, "phone": "123"}});
        let hits = detect(&v, &[]);
        assert!(hits.contains(&"user.email".to_string()));
        assert!(hits.contains(&"user.phone".to_string()));
        assert!(!hits.contains(&"user.id".to_string()));
    }

    #[test]
    fn ignores_empty_or_null_sensitive_values() {
        let v = json!({"email": "", "token": null});
        assert!(detect(&v, &[]).is_empty());
    }

    #[test]
    fn config_patterns_extend_builtins() {
        let v = json!({"salary": 100000, "name": "x"});
        assert!(detect(&v, &[]).is_empty());
        let hits = detect(&v, &["salary".to_string()]);
        assert_eq!(hits, vec!["salary".to_string()]);
    }

    #[test]
    fn detects_inside_arrays() {
        let v = json!({"users": [{"email": "a@b.com"}, {"email": "c@d.com"}]});
        let hits = detect(&v, &[]);
        assert!(hits.contains(&"users[0].email".to_string()));
        assert!(hits.contains(&"users[1].email".to_string()));
    }
}
