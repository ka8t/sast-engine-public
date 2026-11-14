//! Analysis engine.
//!
//! Scope of this module for now: the **regex** executors (the most
//! used, cf. rule statistics from Decision #10 — 178/160/127/90/66
//! depending on language) and **file_contains**. The AST executor
//! (tree-sitter) and taint analysis are separate efforts, of comparable
//! size, not tackled here.
#![allow(dead_code)]

pub mod ast_matcher;
pub mod dispatch;
pub mod file_contains;
pub mod pattern;
pub mod rule_loader;
pub mod taint;

/// A detected finding — deliberately minimal subset of the Python
/// `Finding` (`sca/models.py`). Suppression fields
/// (`.sca-suppress.json`, `# sca-ignore`) and file classification
/// (production/test/vendor/...) are deliberately absent: they belong
/// to the orchestrator (Step 5), not the matcher — cf.
/// `Audit/sca/runner.py::_add_finding`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub category: String,
    pub severity: String,
    pub line: usize,
    /// Content of the line where the finding was detected (not
    /// truncated — Python truncates to 200 characters in
    /// `_add_finding`, out of scope here).
    pub code: String,
    pub confidence: i64,
}
