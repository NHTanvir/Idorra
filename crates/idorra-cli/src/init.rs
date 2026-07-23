//! `idorra init` — scaffold a starter config, a gitignored secrets file, and a
//! sample GraphQL query, without overwriting anything that already exists.

use std::path::Path;

use anyhow::{Context, Result};

const CONFIG_TEMPLATE: &str = r#"# idorra.toml — tracked config (NO secrets here; put tokens in secrets.toml)

[general]
dry_run = true                     # send nothing until you pass --live
log_dir = "./idorra-logs"
report_dir = "./idorra-reports"

[scope]
# Every request's host MUST match one of these or it is refused before sending.
allow = ["api.example-target.com", "*.staging.example-target.com"]
allow_ports = [443]

[rate_limit]
requests_per_second = 2.0          # conservative; fractional allowed (0.5 = 1 / 2s)
burst = 2
max_concurrency = 4

[http]
connect_timeout_secs = 10
request_timeout_secs = 20
max_body_capture_bytes = 262144
# proxy = "http://127.0.0.1:8080"  # optional: route through Burp/mitmproxy

[analysis]
sensitive_field_patterns = ["email", "phone", "ssn", "token", "address"]
body_length_anomaly_threshold_pct = 15.0

[[target]]
name = "orders_api"
base_url = "https://api.example-target.com"
protocol = "rest"
baseline_session = "session_a"

  [[target.endpoint]]
  name = "get_order_by_id"
  path_template = "/api/orders/{id}"
  method = "GET"
  id_param = "id"
  id_source = { kind = "range", start = 1, end = 50 }
  param_locations = ["path", "query"]
  test_methods = ["GET", "PUT"]     # PUT/POST/DELETE can MUTATE data — only sent with --live
  sessions = ["session_a", "session_b"]

# GraphQL example (uncomment and provide queries/order_by_id.graphql):
# [[target]]
# name = "graphql_api"
# base_url = "https://api.example-target.com"
# protocol = "graphql"
# baseline_session = "session_a"
#
#   [[target.graphql_query]]
#   name = "order_by_id"
#   query_file = "queries/order_by_id.graphql"
#   variable_name = "id"
#   id_source = { kind = "range", start = 1, end = 50 }
#   sessions = ["session_a", "session_b"]
"#;

const SECRETS_TEMPLATE: &str = r#"# secrets.toml — GITIGNORED. Paste session tokens/cookies captured from your
# own authenticated browser sessions for accounts you are authorized to test.
# Each session must have exactly one of `cookie` or `bearer_token`.

[[session]]
name = "session_a"
description = "Low-privilege user A (resource owner / baseline)"
cookie = "REPLACE_ME=..."

[[session]]
name = "session_b"
description = "Low-privilege user B (the attacker perspective)"
bearer_token = "REPLACE_ME"
"#;

const GRAPHQL_TEMPLATE: &str = r#"query GetOrder($id: ID!) {
  order(id: $id) {
    id
    total
    customerEmail
  }
}
"#;

const GITIGNORE_LINES: &str = "secrets.toml\n*.local.toml\nidorra-logs/\nidorra-reports/\n";

/// Scaffold starter files into `dir`. Existing files are left untouched.
pub fn scaffold(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {dir:?}"))?;

    write_if_absent(&dir.join("idorra.toml"), CONFIG_TEMPLATE)?;
    write_if_absent(&dir.join("secrets.toml"), SECRETS_TEMPLATE)?;
    std::fs::create_dir_all(dir.join("queries")).ok();
    write_if_absent(&dir.join("queries").join("order_by_id.graphql"), GRAPHQL_TEMPLATE)?;
    ensure_gitignore(&dir.join(".gitignore"))?;

    println!("\nScaffolded idorra config in {}", dir.display());
    println!("Next steps:");
    println!("  1. Edit idorra.toml — set your authorized scope + target endpoints.");
    println!("  2. Put session tokens in secrets.toml (already gitignored).");
    println!("  3. `idorra plan` to preview, then `idorra run --live` to test.");
    Ok(())
}

fn write_if_absent(path: &Path, contents: &str) -> Result<()> {
    if path.exists() {
        println!("  skip  {} (already exists)", path.display());
        return Ok(());
    }
    std::fs::write(path, contents).with_context(|| format!("writing {path:?}"))?;
    println!("  write {}", path.display());
    Ok(())
}

fn ensure_gitignore(path: &Path) -> Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut additions = String::new();
    for line in GITIGNORE_LINES.lines() {
        if !existing.lines().any(|l| l.trim() == line) {
            additions.push_str(line);
            additions.push('\n');
        }
    }
    if additions.is_empty() {
        return Ok(());
    }
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str("# idorra secrets/output\n");
    updated.push_str(&additions);
    std::fs::write(path, updated).with_context(|| format!("updating {path:?}"))?;
    println!("  update {} (ensured secrets.toml is ignored)", path.display());
    Ok(())
}
