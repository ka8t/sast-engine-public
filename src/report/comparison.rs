//! Comparison of a scan's findings against a baseline (previous
//! scan) — port of the computation part of `Audit/sca/comparison.py`
//! (`_finding_key`/`_index_findings`/`_compare_with_baseline`).
//!
//! Not ported here: `_find_latest_baseline`/`_load_history` (reading
//! an `audit-datas/` directory with a timestamp-based naming
//! convention) and `_cleanup_old_reports` (retention) — these require
//! a persistent output/history directory that does not yet exist
//! on the `ScanConfig` side. `_export_json`/baseline loading live
//! in `report::export_json` (separate piece of work, same module as
//! the HTML assembly).

use std::collections::BTreeMap;

use crate::project::suppress::line_hash;
use crate::report::exports::sarif::ReportFinding;

/// Base key identifying a finding (file + rule + code fingerprint)
/// — port of `_finding_key`. Excludes the line number so it
/// survives a line shift caused by an unrelated change
/// elsewhere in the file.
fn finding_key(f: &ReportFinding) -> String {
    let hash = if f.code.is_empty() {
        0
    } else {
        line_hash(&f.code)
    };
    format!("{}:{}:{hash}", f.file, f.rule_name)
}

/// Indexes a list of findings by unique key — port of
/// `_index_findings`. Several findings can share the same base
/// key (same file, same rule, same code fingerprint) when an
/// identical pattern appears multiple times in a file; disambiguation
/// uses an index suffix assigned in line order within each group
/// sharing the same base key.
fn index_findings(findings: &[ReportFinding]) -> BTreeMap<String, &ReportFinding> {
    let mut grouped: BTreeMap<String, Vec<&ReportFinding>> = BTreeMap::new();
    for f in findings {
        grouped.entry(finding_key(f)).or_default().push(f);
    }
    let mut indexed = BTreeMap::new();
    for (base_key, mut group) in grouped {
        group.sort_by_key(|f| f.line);
        for (i, f) in group.into_iter().enumerate() {
            indexed.insert(format!("{base_key}:{i}"), f);
        }
    }
    indexed
}

#[derive(Debug, Clone, Default)]
pub struct ComparisonResult {
    pub new_findings: Vec<ReportFinding>,
    pub resolved_findings: Vec<ReportFinding>,
    pub unchanged_findings: Vec<ReportFinding>,
    pub baseline_date: String,
    pub baseline_totals: BTreeMap<String, usize>,
}

/// Compares current findings against a baseline — port of
/// `_compare_with_baseline` (without disk loading: `baseline`
/// is already deserialized by the caller).
pub fn compare_with_baseline(
    current: &[ReportFinding],
    baseline: &[ReportFinding],
    baseline_date: String,
    baseline_totals: BTreeMap<String, usize>,
) -> ComparisonResult {
    let baseline_indexed = index_findings(baseline);
    let current_indexed = index_findings(current);

    let baseline_keys: std::collections::BTreeSet<&String> = baseline_indexed.keys().collect();
    let current_keys: std::collections::BTreeSet<&String> = current_indexed.keys().collect();

    let new_findings = current_keys
        .difference(&baseline_keys)
        .map(|k| current_indexed[*k].clone())
        .collect();
    let resolved_findings = baseline_keys
        .difference(&current_keys)
        .map(|k| baseline_indexed[*k].clone())
        .collect();
    let unchanged_findings = current_keys
        .intersection(&baseline_keys)
        .map(|k| current_indexed[*k].clone())
        .collect();

    ComparisonResult {
        new_findings,
        resolved_findings,
        unchanged_findings,
        baseline_date,
        baseline_totals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(file: &str, rule_name: &str, code: &str, line: usize) -> ReportFinding {
        ReportFinding {
            rule_key: "r".to_string(),
            rule_name: rule_name.to_string(),
            category: "SECURITY".to_string(),
            severity: "HIGH".to_string(),
            risk: String::new(),
            file: file.to_string(),
            line,
            solution: None,
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: code.to_string(),
            context_before: String::new(),
            context_after: String::new(),
            confidence: 90,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
        }
    }

    #[test]
    fn test_identical_scans_are_all_unchanged() {
        let findings = vec![finding("a.py", "SQL Injection", "eval(x)", 10)];
        let result = compare_with_baseline(
            &findings,
            &findings,
            "2026-01-01".to_string(),
            BTreeMap::new(),
        );
        assert_eq!(result.unchanged_findings.len(), 1);
        assert!(result.new_findings.is_empty());
        assert!(result.resolved_findings.is_empty());
    }

    #[test]
    fn test_new_finding_not_in_baseline() {
        let baseline = vec![finding("a.py", "SQL Injection", "eval(x)", 10)];
        let current = vec![
            finding("a.py", "SQL Injection", "eval(x)", 10),
            finding("b.py", "XSS", "innerHTML = x", 5),
        ];
        let result = compare_with_baseline(
            &current,
            &baseline,
            "2026-01-01".to_string(),
            BTreeMap::new(),
        );
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.new_findings[0].file, "b.py");
        assert_eq!(result.unchanged_findings.len(), 1);
    }

    #[test]
    fn test_resolved_finding_missing_from_current() {
        let baseline = vec![
            finding("a.py", "SQL Injection", "eval(x)", 10),
            finding("b.py", "XSS", "innerHTML = x", 5),
        ];
        let current = vec![finding("a.py", "SQL Injection", "eval(x)", 10)];
        let result = compare_with_baseline(
            &current,
            &baseline,
            "2026-01-01".to_string(),
            BTreeMap::new(),
        );
        assert_eq!(result.resolved_findings.len(), 1);
        assert_eq!(result.resolved_findings[0].file, "b.py");
    }

    #[test]
    fn test_line_shift_does_not_count_as_new_finding() {
        // Same file/rule/code, different line -> same base key
        // (the line number is excluded from finding_key).
        let baseline = vec![finding("a.py", "SQL Injection", "eval(x)", 10)];
        let current = vec![finding("a.py", "SQL Injection", "eval(x)", 25)];
        let result = compare_with_baseline(
            &current,
            &baseline,
            "2026-01-01".to_string(),
            BTreeMap::new(),
        );
        assert_eq!(result.unchanged_findings.len(), 1);
        assert!(result.new_findings.is_empty());
    }

    #[test]
    fn test_duplicate_pattern_in_same_file_disambiguated_by_line_order() {
        // 2 identical occurrences (same file/rule/code) at different
        // lines -> 2 distinct entries, not a single one overwritten.
        let findings = vec![
            finding("a.py", "Hardcoded Secret", "KEY = 'x'", 5),
            finding("a.py", "Hardcoded Secret", "KEY = 'x'", 20),
        ];
        let indexed = index_findings(&findings);
        assert_eq!(indexed.len(), 2);
    }

    #[test]
    fn test_baseline_metadata_preserved() {
        let mut totals = BTreeMap::new();
        totals.insert("HIGH".to_string(), 3usize);
        let result = compare_with_baseline(&[], &[], "2026-08-20".to_string(), totals.clone());
        assert_eq!(result.baseline_date, "2026-08-20");
        assert_eq!(result.baseline_totals, totals);
    }
}
