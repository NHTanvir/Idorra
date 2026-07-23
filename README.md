# idorra

A desktop CLI for **authorized** testing of REST and GraphQL APIs for IDOR
(Insecure Direct Object Reference) and broken access control. You paste session
tokens/cookies captured from your own authenticated browser sessions, point it at
a target you're permitted to test, and it runs structured strategies and flags
likely issues — with request/response evidence — for you to review and write up.

> **Authorized use only.** Use this only against targets you have explicit
> permission to test (e.g. an in-scope HackerOne program). The scope allowlist,
> conservative rate limiting, and dry-run-by-default exist to keep you inside the
> lines — they are not a substitute for authorization.

## Safety model

Every outbound request funnels through a single choke point (`Gate`) that, in
strict order:

1. **Scope check** — the host/port must match `scope.allow`, or the request is
   refused *before it is even built*. The allowlist can't be empty.
2. **Dry-run** — on by default; prints/logs what it would send and consumes no
   rate-limit tokens, so you can preview a full plan instantly.
3. **Rate limit + concurrency cap** — a token bucket paces requests/second; a
   semaphore bounds in-flight requests.
4. **Audit log** — one timestamped JSON line per request, for your records.

Additional rails baked in:

- **Redirects are disabled** — a `302` is captured as evidence, never followed,
  so an in-scope host can't bounce the client to an out-of-scope one.
- **No shared cookie jar** — sessions are applied as explicit per-request headers,
  so session A's cookies can never leak into session B's requests (which would
  silently corrupt every comparison).
- **Secrets redacted by default** in logs and reports (opt out with
  `--include-secrets-in-log`).
- The client can only be constructed in one file; a clippy `disallowed_methods`
  lint (denied in CI) enforces it.

## Install / build (Windows)

Requires the Rust toolchain and, for the default MSVC target, the Visual Studio
Build Tools (for the linker).

```powershell
# Debug build + tests
cargo test

# Release binary -> target\release\idorra.exe
cargo build --release -p idorra-cli
```

For reproducibility in scripts/CI:

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc -p idorra-cli
```

**Linker gotcha:** Git-for-Windows ships its own unrelated `link.exe`. It's
usually harmless (rustc finds the MSVC linker via the VS install, not `PATH`),
but if you hit a confusing "linker not found"/"invalid argument" error, build
from a *Developer PowerShell for VS 2022* shell.

**Alternatives:** `x86_64-pc-windows-gnu` links against MinGW-w64 instead of MSVC
(no VS Build Tools needed). To cross-compile a Windows `.exe` from Linux later,
use `cargo-xwin` (`cargo xwin build --release --target x86_64-pc-windows-msvc`)
or `cross` with the `-gnu` target.

## Quick start

```powershell
# 1. Scaffold idorra.toml + a gitignored secrets.toml + a sample query
idorra init

# 2. Edit idorra.toml (scope + endpoints) and secrets.toml (your session tokens)

# 3. Preview the plan — sends nothing
idorra plan

# 4. Run for real (prompts for confirmation; --yes to skip in scripts)
idorra run --live
```

By default `run` is a dry run. `--live` sends requests; `--dry-run` forces a dry
run regardless of config.

## Configuration

Two files: the tracked `idorra.toml` (scope, targets, endpoints, pacing) and a
gitignored `secrets.toml` (session tokens/cookies). See
[`examples/config.example.toml`](examples/config.example.toml) for a fully
annotated reference. Config is validated fail-fast on load (unknown session
references, out-of-scope targets, missing placeholders, etc.).

## What it tests

| Strategy | What it does |
| --- | --- |
| Two-session compare | Same request under different sessions; flags when a non-baseline session receives the baseline's data (the core IDOR check) |
| ID enumeration | Drives the id range/list/file across the above |
| Method tampering | Same endpoint under different HTTP verbs; flags a verb that succeeds where the canonical one is denied |
| Parameter-location | Same id in path vs query vs header vs JSON body; flags a location that bypasses auth |
| GraphQL variation | Varies the id variable; distinguishes `errors[]` (stale template) from real allow/deny |

Findings carry separate **severity** and **confidence** axes and full
request/response evidence. Reports are written as JSON (full evidence) and
Markdown (human-readable) per run.

## Reports & logs

- `idorra-reports/idorra-<timestamp>.json` — machine-readable, full evidence
- `idorra-reports/idorra-<timestamp>.md` — human-readable summary for write-ups
- `idorra-logs/idorra-<timestamp>.jsonl` — per-request audit trail

## Project layout

```
crates/idorra-core/   # all testing logic (scope, gate, engine, analysis) — no terminal I/O
crates/idorra-cli/    # the `idorra` binary (arg parsing + output)
```

The core is a library so a future GUI can reuse it unchanged, and so the safety
rails apply no matter what front-end drives it.

## License

MIT OR Apache-2.0.
