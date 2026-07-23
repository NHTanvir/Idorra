//! Crate-wide error types.

use thiserror::Error;

/// The result type used throughout `idorra-core`.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error for configuration, I/O, and orchestration failures.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid or inconsistent configuration (bad schema, failed validation).
    #[error("configuration error: {0}")]
    Config(String),

    /// Filesystem I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A TOML document failed to parse.
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// A URL failed to parse.
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),

    /// A request was rejected or failed at the send gate.
    #[error(transparent)]
    Gate(#[from] GateError),

    /// JSON (de)serialization failure while writing reports.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Errors originating at the single outbound-HTTP choke point (`http::client::Gate`).
///
/// [`GateError::OutOfScope`] and [`GateError::PortNotAllowed`] are the
/// safety-critical rejections: they are returned *before* any network request
/// is constructed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GateError {
    /// The request's host is not covered by the scope allowlist.
    #[error("BLOCKED: host '{host}' is out of scope (not on the allowlist)")]
    OutOfScope {
        /// The rejected host.
        host: String,
    },

    /// The request's port is not on the (non-empty) allowed-port list.
    #[error("BLOCKED: port {port} on host '{host}' is not in the allowed-port list")]
    PortNotAllowed {
        /// The host that was otherwise in scope.
        host: String,
        /// The rejected port.
        port: u16,
    },

    /// The request URL had no host component to check.
    #[error("BLOCKED: request URL '{url}' has no host to scope-check")]
    MissingHost {
        /// The offending URL.
        url: String,
    },

    /// The underlying HTTP send failed (network error, timeout, etc.).
    #[error("HTTP send failed: {0}")]
    Send(String),
}
