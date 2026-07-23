//! Response analysis: structural diffing, sensitive-field detection, and the
//! scoring rules that turn outcomes into findings.

pub mod diff;
pub mod scoring;
pub mod sensitive_fields;

pub use diff::{diff, JsonDiffSummary};
