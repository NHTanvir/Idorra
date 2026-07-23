//! `idorra-core` — the safety-railed engine for authorized IDOR / access-control
//! testing.
//!
//! # Safety model
//!
//! Every outbound HTTP request in this crate is funneled through a single
//! choke point, [`http::client::Gate`], which — in strict, unconditional order
//! — enforces the scope allowlist, honors dry-run, applies the rate limiter and
//! concurrency cap, and writes the audit log. No public API exposes a raw
//! request path, so a front-end (CLI or a future GUI) that depends only on this
//! crate cannot send an unchecked request.
//!
//! Within the crate itself, construction of [`reqwest::Client`] is confined to
//! `http/client.rs` and enforced by a clippy `disallowed-methods` lint (see
//! `clippy.toml`).

#![forbid(unsafe_code)]

pub mod analysis;
pub mod config;
pub mod error;
pub mod finding;
pub mod http;
pub mod logging;
pub mod outcome;
pub mod scope;
pub mod session;
pub mod testcase;

pub use config::Config;
pub use error::{Error, GateError, Result};
pub use finding::{Confidence, Finding, ReasonCode, Severity};
pub use http::{Gate, GateConfig, Limiter};
pub use outcome::{RequestOutcome, RequestSpec};
pub use scope::ScopeGuard;
pub use session::SessionStore;
pub use testcase::{HttpMethod, IdValue, ParamLocation, Protocol, TestCase, TestStrategy};
