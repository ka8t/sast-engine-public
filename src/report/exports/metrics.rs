//! Machine-readable scan metrics (ticket #90): one JSON file per scan
//! with the numbers that otherwise only live in that run's stderr —
//! size of the scanned project, findings by severity, duration of each
//! pipeline phase, exit code. Opt-in through `scan --metrics-output`,
//! local file only (no network, see ticket #93), meant for CI pipelines
//! that track scan duration or findings over time. No Python
//! counterpart: Audit keeps its phase timings in the HTML report only.

use serde_json::{Value, json};

use crate::scan::orchestrator::ScanReport;

/// Version of the metrics document layout, bumped on any breaking
/// change of its keys so a consumer can detect it.
pub const METRICS_SCHEMA_VERSION: u32 = 1;

/// Severities always present in `findings.by_severity`, at 0 when
/// absent, so a consumer never has to handle a missing key.
const SEVERITIES: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/// Builds the metrics document of one finished scan. `timestamp` is
/// RFC 3339; `total_duration_ms` covers the whole `scan` command (rule
/// loading through report writing), so it is larger than the sum of the
/// phases. Phase labels are the console labels (translated per
/// `--lang`, phase A carries its per-language counts): their ORDER is
/// stable, so consumers should rely on the position or pass a fixed
/// `--lang` to compare runs.
pub fn build_scan_metrics(
    report: &ScanReport,
    tool_name: &str,
    tool_version: &str,
    timestamp: &str,
    total_duration_ms: u128,
    exit_code: u8,
) -> Value {
    let mut by_severity = serde_json::Map::new();
    for severity in SEVERITIES {
        let count = report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .count();
        by_severity.insert(severity.to_string(), json!(count));
    }
    let phases: Vec<Value> = report
        .phase_timings
        .iter()
        .map(|(label, duration)| json!({"label": label, "duration_ms": duration.as_millis()}))
        .collect();
    json!({
        "schema_version": METRICS_SCHEMA_VERSION,
        "tool": {"name": tool_name, "version": tool_version},
        "timestamp": timestamp,
        "files_scanned": report.files_scanned,
        "lines_of_code": report.total_loc,
        "languages": report.languages,
        "findings": {"total": report.findings.len(), "by_severity": by_severity},
        "phases": phases,
        "total_duration_ms": total_duration_ms,
        "exit_code": exit_code,
    })
}
