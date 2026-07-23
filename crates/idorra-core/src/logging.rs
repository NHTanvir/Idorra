//! The request/response audit trail — one timestamped JSON line per event, for
//! the operator's own records and HackerOne report-writing.
//!
//! This is deliberately separate from diagnostic `tracing` output: the audit log
//! is a stable, append-only evidence artifact. Secret header values follow the
//! same redaction policy as reports.

use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

/// A single audit event, serialized as one JSON line.
#[derive(Debug, Serialize)]
pub struct AuditEntry<'a> {
    /// RFC 3339 timestamp.
    pub ts: String,
    /// Event kind: `blocked`, `dry_run`, `send`, `recv`, or `error`.
    pub event: &'a str,
    /// Correlating test-case id.
    pub test_case_id: String,
    /// Session name.
    pub session: &'a str,
    /// HTTP method token.
    pub method: &'a str,
    /// Request URL.
    pub url: &'a str,
    /// Response status, when known.
    pub status: Option<u16>,
    /// Free-form note (block reason, error text, redirect target).
    pub note: Option<String>,
}

/// Somewhere audit lines can be written. Implementations must be cheap and
/// thread-safe (the gate calls this from many concurrent tasks).
pub trait AuditSink: Send + Sync {
    /// Append one already-serialized JSON line.
    fn log_line(&self, line: &str);

    /// Serialize and append an entry (default impl).
    fn record(&self, entry: &AuditEntry<'_>) {
        if let Ok(line) = serde_json::to_string(entry) {
            self.log_line(&line);
        }
    }
}

/// An audit sink that appends JSON lines to a file.
#[derive(Debug)]
pub struct FileAuditLog {
    inner: Mutex<std::fs::File>,
}

impl FileAuditLog {
    /// Create (or truncate) an audit log file at `path`, creating parent dirs.
    pub fn create(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { inner: Mutex::new(file) })
    }
}

impl AuditSink for FileAuditLog {
    fn log_line(&self, line: &str) {
        if let Ok(mut f) = self.inner.lock() {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// An in-memory audit sink for tests.
#[derive(Debug, Default)]
pub struct MemAuditLog {
    /// Captured lines.
    pub lines: Mutex<Vec<String>>,
}

impl AuditSink for MemAuditLog {
    fn log_line(&self, line: &str) {
        if let Ok(mut v) = self.lines.lock() {
            v.push(line.to_string());
        }
    }
}

/// A sink that drops everything (used when auditing is not wired).
#[derive(Debug, Default)]
pub struct NullAuditLog;

impl AuditSink for NullAuditLog {
    fn log_line(&self, _line: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_sink_records_serialized_entries() {
        let sink = MemAuditLog::default();
        sink.record(&AuditEntry {
            ts: "2026-07-23T00:00:00Z".into(),
            event: "blocked",
            test_case_id: "tc1".into(),
            session: "a",
            method: "GET",
            url: "https://evil.com/",
            status: None,
            note: Some("out of scope".into()),
        });
        let lines = sink.lines.lock().unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"event\":\"blocked\""));
        assert!(lines[0].contains("out of scope"));
    }
}
