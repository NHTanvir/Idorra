# Architecture Plan: `idorra` — Rust IDOR / Access-Control Testing CLI

## Context

You're an authorized bug bounty hunter (HackerOne-enrolled programs) who wants a desktop tool to systematically test REST and GraphQL APIs for IDOR and broken access control, using session tokens/cookies you capture manually from your own authenticated browser sessions. The tool runs structured test strategies (ID enumeration, cross-session comparison, HTTP method tampering, parameter-location tampering, GraphQL variation) and flags likely issues with evidence for you to manually review and write up.

This is a real tool that will send requests to real (authorized) targets, so the design bakes in hard safety rails — a structurally unbypassable scope allowlist, mandatory rate limiting/concurrency caps, dry-run mode, and full audit logging — as first-class architecture, not bolted-on features.

Repo: `C:\Users\SARK\Desktop\Idorra` (currently just `git init` + `.gitignore`, pushed to a private GitHub repo — nothing else exists yet). Confirmed local environment: Rust 1.95.0 / cargo 1.95.0 / rustup 1.29.0 installed, `x86_64-pc-windows-msvc` target already installed and active, Visual Studio Build Tools 2022 present — `cargo build --release` will work with no additional installs.

## Decisions locked in

- **N-session model** with a per-comparison designated `baseline_session` (not hardcoded to exactly 2) — supports the common case (session_a vs session_b) without a refactor when a 3rd account (e.g. admin, anonymous) is needed later.
- **Scope matching: hostnames only** — exact match or single-level `*.subdomain` wildcard, plus an optional port allowlist. No CIDR/IP-range matching in v1.
- **Secrets split out of the tracked config**: `idorra.toml` (structure: targets, scope, rate limits) + a gitignored `secrets.toml` (tokens/cookies), merged at load time. `idorra init` scaffolds both and ensures `secrets.toml` is gitignored.
- **Logs/reports redact secrets by default**: `Authorization`/`Cookie` header values are masked in the audit log and saved report unless `--include-secrets-in-log` is passed.
- **Lib + CLI crate split from day one** (not single-binary) — makes the scope gate structurally unbypassable and lets a future GUI (egui/tauri) crate reuse `idorra-core` unchanged.
- **GraphQL: user-supplied query templates**, not introspection-driven, for v1 — introspection is often disabled on hardened production APIs, and templates match how you'd already work (query captured from browser devtools).
- **Sensitive-field detection: built-in heuristic list, additively extended by config** (not replaced).
- **Findings persisted as JSON + human-readable Markdown per run** — no SQLite in v1 (add later only if cross-run querying becomes a real need).
- **HTTP client hardened for safety + correctness** (added in max-effort review): redirects **disabled** (`redirect::Policy::none()`) so an in-scope host can't bounce the client to an out-of-scope host behind the gate; automatic cookie **jar disabled** (session isolation — see below); `rustls-tls` instead of the default native-tls (portable, and makes the later Linux→Windows cross-compile trivial — no cross OpenSSL); explicit connect + total request timeouts so a hung target can't hold a concurrency permit forever.
- **Sessions are applied as explicit per-request `Authorization` / `Cookie` headers, never via a shared cookie store.** This directly implements the requested "cookies" support while avoiding a subtle but fatal bug: one reqwest `Client` with the auto-jar enabled would capture `Set-Cookie` from responses and replay them across *all* sessions, cross-contaminating Session A and B and silently invalidating every IDOR comparison. (If cookie *persistence across a login flow* is ever needed, the correct shape is one jar/Client per named session, still behind the single gate — deferred, not needed for token/cookie-paste testing.)
- **Optional upstream proxy** (`[http] proxy = "http://127.0.0.1:8080"`, off by default) so requests can be routed through Burp/mitmproxy for manual inspection — a near-universal bug-bounty workflow. Proxied requests are still scope-checked on their target Host, so the proxy doesn't weaken the allowlist.

## Workspace / module structure

```
idorra/
├── Cargo.toml                  # workspace root
├── crates/
│   ├── idorra-core/            # lib crate — all testing logic, NO terminal I/O
│   │   └── src/
│   │       ├── lib.rs                  # narrow public API: Config, Engine, TestPlan, Finding, RunSummary, errors
│   │       ├── config.rs               # TOML schema (idorra.toml + secrets.toml) + serde structs + validation
│   │       ├── scope.rs                # ScopeGuard — hostname/wildcard/port matching
│   │       ├── session.rs              # Session/SessionStore: named sessions, tokens/cookies
│   │       ├── http/
│   │       │   ├── client.rs           # Gate — the ONLY place reqwest::Client::execute is called
│   │       │   ├── request_builder.rs  # builds RequestSpec from a TestCase (pure, no network)
│   │       │   └── rate_limiter.rs     # governor token bucket + tokio::sync::Semaphore concurrency cap
│   │       ├── testcase.rs             # TestCase, TestPlan (lazily generates TestCases)
│   │       ├── engine/
│   │       │   ├── mod.rs              # orchestration: plan -> Gate -> analyze
│   │       │   ├── id_enum.rs          # ID enumeration strategy
│   │       │   ├── two_session.rs      # N-session comparison strategy (baseline vs others)
│   │       │   ├── method_test.rs      # HTTP verb tampering strategy
│   │       │   ├── param_location.rs   # path/query/header/body placement strategy
│   │       │   └── graphql.rs          # GraphQL query-template variation strategy
│   │       ├── analysis/
│   │       │   ├── diff.rs             # path+kind-aware structural JSON diff
│   │       │   ├── sensitive_fields.rs # built-in + config-extended field-name heuristics
│   │       │   └── scoring.rs          # rule table: anomalies -> Finding severity/confidence
│   │       ├── finding.rs              # Finding model + evidence capture
│   │       ├── report.rs               # JSON + Markdown report writers (secret-redacting)
│   │       ├── logging.rs              # structured, timestamped, secret-redacting request/response log
│   │       └── error.rs                # thiserror error types
│   └── idorra-cli/             # bin crate — argument parsing, terminal output only
│       └── src/
│           ├── main.rs                 # wires Config -> Engine, prints/saves results
│           ├── cli.rs                  # clap definitions (run, init, --live, --dry-run, --include-secrets-in-log)
│           ├── ui/                     # indicatif progress + colored terminal summary
│           └── init.rs                 # `idorra init` scaffolds idorra.toml + gitignored secrets.toml
└── examples/
    └── config.example.toml     # annotated sample, no real targets/tokens
```

**Why lib+cli**: `idorra-core`'s public API never exposes `reqwest::Client` or any way to send a request outside `Engine`/`Gate`. `idorra-cli` (and a future GUI crate) can only drive test runs through that curated surface — so the scope/rate-limit/dry-run rails apply no matter what front-end calls into the core.

## Config schema (TOML)

`idorra.toml` (tracked):
```toml
[general]
dry_run = true
log_dir = "./idorra-logs"
report_dir = "./idorra-reports"

[scope]
allow = ["api.example-target.com", "*.staging.example-target.com"]
allow_ports = [443, 8443]

[rate_limit]
requests_per_second = 2.0    # fractional OK, e.g. 0.5 = 1 req / 2s (built via Quota::with_period)
burst = 2
max_concurrency = 4

[http]
connect_timeout_secs = 10
request_timeout_secs = 20     # a hung target must not hold a concurrency permit forever
max_body_capture_bytes = 262144   # cap response bytes read into evidence (256 KiB); mark truncation
# proxy = "http://127.0.0.1:8080"  # optional: route through Burp/mitmproxy; still scope-checked

[[target]]
name = "orders_api"
base_url = "https://api.example-target.com"
protocol = "rest"                       # "rest" | "graphql"
baseline_session = "session_a"

  [[target.endpoint]]
  name = "get_order_by_id"
  path_template = "/api/orders/{id}"
  method = "GET"
  id_param = "id"
  id_source = { kind = "range", start = 1, end = 500 }   # end inclusive
  # alt: { kind = "list", values = [101, 102, 103] }  |  { kind = "file", path = "ids.txt" }
  param_locations = ["path", "query", "header", "json_body"]
  test_methods = ["GET", "PUT", "DELETE"]
  sessions = ["session_a", "session_b"]

[[target]]
name = "graphql_api"
base_url = "https://api.example-target.com"
protocol = "graphql"
baseline_session = "session_a"

  [[target.graphql_query]]
  name = "order_by_id"
  query_file = "queries/order_by_id.graphql"
  variable_name = "id"
  id_source = { kind = "range", start = 1, end = 200 }
  sessions = ["session_a", "session_b"]

[analysis]
sensitive_field_patterns = ["email", "phone", "ssn", "token", "address"]  # additive to built-ins
body_length_anomaly_threshold_pct = 15.0
```

`secrets.toml` (gitignored, scaffolded by `idorra init`, merged into `idorra.toml` at load):
```toml
[[session]]
name = "session_a"
description = "Low-privilege user (victim account)"
cookie = "sessionid=abc123..."

[[session]]
name = "session_b"
description = "Attacker / second low-priv account"
bearer_token = "eyJhbGciOi..."
```

**Merge + validation semantics** (`config.rs`, on load — fail fast with a clear message rather than a confusing mid-run error): sessions live *only* in `secrets.toml`, everything else *only* in `idorra.toml` (simple struct composition, no deep field merge). Validate that: every `baseline_session` and every name in a target's `sessions = [...]` exists in the merged session set; every session has exactly one credential (`cookie` xor `bearer_token`, plus optional `headers`); every `graphql_query.query_file` exists and every `variable_name` appears in it; every target `base_url` host is itself in `[scope].allow` (you can't have an in-config target you're not allowed to hit); `requests_per_second > 0` and `max_concurrency >= 1`.

**reqwest features**: enable `json`; use `rustls-tls` instead of the default `native-tls` (`default-features = false`, then re-enable what you need — `json`, `rustls-tls`, and typically `http2`, `charset`). Do **not** enable the `cookies` feature's auto-jar — sessions are explicit headers (see "Decisions locked in"). Pin the reqwest version in `Cargo.toml`.

## Data model

- **`TestCase`**: `id (uuid)`, `target_name`, `protocol (Rest|GraphQl)`, `method`, `base_url`, `path_template`, `param_location (Path|Query|Header|JsonBody)`, `id_value (Numeric|Str)`, `graphql: Option<GraphQlPayload>`, `session: SessionRef`, `strategy`, `comparison_group_id` (correlates same logical test across sessions), `extra_headers`.
- **`RequestOutcome`**: `test_case_id`, `sent_at`, `request_evidence` (redacted per config), `status`, `response_headers`, `response_body`, `body_len`, `elapsed`, `error`, `dry_run`.
- **`Finding`**: `id`, `strategy`, `severity (Info|Low|Medium|High)`, `confidence (Low|Medium|High)`, `summary`, `reason_codes` (e.g. `CrossSessionDataMatch`, `StatusAnomaly`, `SensitiveFieldExposed`, `MethodBypassedAuth`), `involved_sessions`, `involved_ids`, `evidence: Vec<RequestOutcome>`, `diff_summary`, `detected_sensitive_fields`, `created_at`.

`TestPlan` generates `TestCase`s lazily (iterator/stream, not a materialized `Vec` — ID ranges can be large). Two/N-session comparison isn't a separate wire format: it's `TestCase`s sharing everything except `session`, correlated by `comparison_group_id`, compared against the target's `baseline_session`.

## The scope-enforcement choke point (safety-critical)

- `idorra-core::http::client::Gate` is the **sole owner** of the `reqwest::Client` and the **sole caller** of `reqwest::Client::execute` in the entire crate. `idorra-core`'s public API does not expose `reqwest::Client` or any alternate send path — `Gate` doesn't `Deref` to it, doesn't return it.
- `Gate::send(RequestSpec) -> Result<RequestOutcome, GateError>` order of operations, unconditional, no bypass parameter:
  1. Extract host+port, check against `ScopeGuard` (loaded once, immutable for the run) → reject before constructing any `reqwest::Request` if no match; log the rejection.
  2. If `dry_run` (set at `Gate` construction from config/CLI, not per-call) → build the would-be request, log/print it, return a synthetic `RequestOutcome{dry_run: true}` — **does not** consume rate-limit tokens or concurrency permits, so a full large plan can be dry-run instantly.
  3. Await the `governor` rate-limiter token (`until_ready().await`), **then** acquire the concurrency semaphore permit. (Token first paces *admission*; the permit then bounds *in-flight* count and is held only for the actual request duration — cleaner than holding a permit while waiting on the limiter.)
  4. Log the outgoing request (redacted per config) with timestamp.
  5. Execute with redirects **disabled**; capture the response (including any `3xx` + `Location` as evidence — a redirect is data, not something to silently chase), log receipt, return `RequestOutcome`. If a redirect target should itself be tested, the engine enqueues it as a *new* `TestCase` that re-enters `Gate::send` and is scope-checked afresh — following a redirect is only ever possible *through* the gate, never around it.
- **How far the guarantee actually reaches (be precise):**
  - *External consumers* (`idorra-cli`, a future GUI) — enforced by the type system: `idorra-core`'s public API exposes no `reqwest` type and no send path except `Engine::run`, so a front-end literally cannot construct or fire an unchecked request.
  - *Within `idorra-core` itself* — Rust's module privacy does **not** stop another module from writing `reqwest::Client::new()`, so "unbypassable by construction" is aspirational at the crate's own boundary. Give it real teeth with: (a) the `reqwest::Client` field and the sole `execute` call kept private to `http/client.rs`; (b) a **clippy `disallowed-methods` / `disallowed-types` lint** (in `clippy.toml`) that fails CI if `reqwest::Client`/`ClientBuilder` is named anywhere outside `http/client.rs`; (c) redirects disabled (above) so an in-scope response can't relocate the client to an out-of-scope host. The crate stays small enough that this is reviewable.

## Rate limiting + concurrency

- **Concurrency cap**: `tokio::sync::Semaphore` sized to `max_concurrency`, acquired/released (RAII) inside `Gate::send`.
- **Rate limit**: `governor` crate — chosen over hand-rolling because this is a mandatory safety mechanism where a well-reviewed, async-friendly, burst-aware implementation is worth the dependency (avoids drift/thundering-herd bugs in a hand-rolled tick tracker).
  - **Quota construction note (avoids a compile error the naive form hits):** `governor::Quota::per_second` takes a `NonZeroU32`, so it can't express the fractional `requests_per_second = 2.0` (or a conservative `0.5` = 1 req / 2 s) from config. Build the quota from a period instead: `Quota::with_period(Duration::from_secs_f64(1.0 / requests_per_second)).unwrap().allow_burst(burst_nonzero)`. This handles both sub-1 and multi-per-second rates uniformly.
- Keep `burst` small (≈ `requests_per_second` rounded up, min 1) so run-start doesn't spike well above the configured rate.
- Order inside `Gate::send` is token-then-permit (see the choke-point steps): the limiter paces how fast requests *start*, the semaphore bounds how many are *in flight*. Engine spawns up to `max_concurrency` tasks over the `TestPlan` stream, but the semaphore inside `Gate` is the real hard ceiling — defense in depth even if the engine layer over-spawns.

## Response diffing / anomaly detection

- **Structural JSON diff** (`analysis/diff.rs`): path+kind-aware walk of both `serde_json::Value` trees → `added/removed/changed paths`, not raw deep-equal (avoids false positives from key ordering, and catches "same shape, same values" — the actual IDOR signal — vs "same shape, different legitimate values").
- **Sensitive-field detection**: case-insensitive substring match on JSON keys against a built-in list (email, phone, ssn, token, secret, address, dob, password, api_key, …) additively extended by `[analysis] sensitive_field_patterns`.
- **Status-code / body-length anomaly**: compare within a `comparison_group_id` (or against a method/param-location baseline); `body_length_anomaly_threshold_pct` — kept as a Low-confidence-only signal, never sufficient alone for High severity.
- **Scoring** (`analysis/scoring.rs`): a documented rule table, not ML — e.g. baseline-vs-other same 2xx status + near-identical diff + sensitive fields present → High/High; method tampering flips 401/403 → 2xx → High/Medium (needs human confirmation of actual mutation); param-location bypass → Medium/Medium; status-only anomaly with no usable body diff → Low/Low. Every rule carries a `ReasonCode`.
- **GraphQL-specific**: GraphQL typically returns `HTTP 200` even for auth failures and errors, so status-code rules are near-useless here — scoring leans on the body diff and the `errors[]`/`data` distinction instead. Distinguish a GraphQL `errors[]` response (schema/validation error — likely a stale query template) from a genuine `data: null` access-denied response, and surface the former as a distinct warning rather than "no vulnerability found" (avoids false negatives from template drift). Preserve the id's JSON type when substituting the variable (numeric vs string) or the server rejects it as a type error.

## Trickiest parts

1. **Async rate limiting under a concurrency cap**: ordering matters — scope check and dry-run must resolve *before* touching the semaphore or rate limiter, or dry-run becomes slow and scope violations waste concurrency slots. Fixed by the strict `Gate::send` ordering above.
2. **Response diffing across arbitrary JSON shapes**: real APIs vary (envelopes, field order, nullability) — start with whole-body path+kind-aware diffing; only add a per-endpoint "envelope unwrap" config hint later if false positives from wrapping show up in real usage. Don't over-engineer this upfront.
3. **N-session state threading**: correlate evidence across sessions for the *same* logical test via a `comparison_group_id` assigned once per logical test at `TestPlan` generation time (never from separate per-session loops, which would risk losing correlation).

## Risks / things to watch

- Redaction is on by default now (per your decision), but double-check `--include-secrets-in-log` output never accidentally lands in a report file you'd paste into a HackerOne submission without you noticing it contains full tokens.
- `dry_run` defaults true; consider requiring an explicit confirmation (or printing the resolved scope allowlist) the first time `--live` is used in a session, as cheap insurance against running against the wrong config.
- Findings evidence (full response bodies) could balloon report size on large enumeration runs — consider a `--min-severity` filter for what gets full evidence vs a summary line, once you're running this against real targets.
- Body-length-percent anomaly is inherently noisy (pagination, timestamps, personalization) — already scoped to Low-confidence-only in the scoring table; don't let it drift into a stronger signal without real-world validation.

## Build / distribution

```powershell
# from repo root, once the workspace exists
cargo build --release -p idorra-cli
# -> target\release\idorra-cli.exe  (or `idorra.exe` if you name the bin crate's package "idorra")
```

Environment is already set up (msvc target installed + active, VS Build Tools 2022 present) — no extra installs needed. For reproducibility in a README:
```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc -p idorra-cli
```

**Linker gotcha**: Git-for-Windows ships its own `link.exe` (unrelated coreutils tool) that may sit on `PATH`. Usually harmless — `rustc`/`cc` locate the MSVC linker via the Visual Studio installation, not `PATH` — but if you ever hit a confusing "linker not found"/"invalid argument" error, build from a "Developer PowerShell for VS 2022" shell to rule this out.

**`x86_64-pc-windows-gnu`**: alternative target linking against MinGW-w64 instead of MSVC — no VS Build Tools dependency, useful only if building on a machine without VS Build Tools installed. Not needed here.

**Cross-compiling from Linux later** (if you move your build machine): `cargo-xwin` (`cargo xwin build --release --target x86_64-pc-windows-msvc`, downloads MSVC CRT/SDK, produces an MSVC-ABI `.exe` without a Windows machine) or `cross`/manual `mingw-w64` + `x86_64-pc-windows-gnu` target (simpler toolchain, GNU-ABI binary). Not needed now.

## Verification

Once implemented:
1. `cargo build --release -p idorra-cli` succeeds and produces `target\release\idorra-cli.exe`.
2. `idorra init` scaffolds `idorra.toml` + gitignored `secrets.toml`; `git status` confirms `secrets.toml` is ignored.
3. Point config at a harmless local test server (e.g. a throwaway `httpbin`-style local service) with a deliberately out-of-scope host in one endpoint — confirm the out-of-scope request is rejected and logged, never sent (verify via the local server's own request log showing zero hits for that host).
4. **Redirect-can't-escape-scope test**: have the in-scope test server return `302 Location: http://<out-of-scope-host>/` — confirm the tool records the 302 as a response and does **not** emit any request to the out-of-scope host (redirects disabled; scope holds).
5. **Session-isolation test**: point two sessions at an endpoint that sets a `Set-Cookie` on response; confirm Session B's requests never carry Session A's cookie (no shared jar) — otherwise every IDOR comparison would be silently corrupted.
6. Run with `dry_run = true` — confirm the printed/logged "would send" output matches expectations and no network calls occur (and completes instantly on a large plan — dry-run consumes no rate-limit tokens or permits).
7. Run `--live` against the local test server with two sessions returning deliberately different/same data — confirm findings JSON + Markdown report is produced, cross-session matches are flagged, and Authorization/Cookie values are redacted in the log/report unless `--include-secrets-in-log` is passed.
8. Confirm `max_concurrency` and `requests_per_second` are respected under load (e.g. time a run against a rate-limited local test endpoint and check actual req/s stays within configured bounds).
9. **Lint-gate test**: add a throwaway `reqwest::Client::new()` in a module other than `http/client.rs` and confirm `cargo clippy` fails (proves the choke-point lint has teeth).
