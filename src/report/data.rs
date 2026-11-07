//! Aggregated report statistics (breakdown by severity/category, top
//! files, health score) — port of `_compute_report_data`
//! (`Audit/sca/report.py`).

use std::collections::BTreeMap;

use crate::report::exports::sarif::ReportFinding;
use crate::report::text::is_dependency;

const SEVERITIES: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
/// Severity weight for the weighted score of the most problematic
/// files (top 10) — `_sev_weights` on the Python side.
fn file_score_weight(sev: &str) -> i64 {
    match sev {
        "CRITICAL" => 10,
        "HIGH" => 5,
        "MEDIUM" => 2,
        "LOW" => 1,
        "INFO" => 0,
        _ => 1,
    }
}
/// Health-score penalties (SECURITY findings only) —
/// `security_penalties` on the Python side.
fn health_penalty_weight(sev: &str) -> i64 {
    match sev {
        "CRITICAL" => 10,
        "HIGH" => 5,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

/// Normalizes an unknown severity to `"MEDIUM"` — same fallback as
/// Python (`f.severity if f.severity in by_severity else "MEDIUM"`).
fn normalize_severity(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "MEDIUM" => "MEDIUM",
        "LOW" => "LOW",
        "INFO" => "INFO",
        _ => "MEDIUM",
    }
}

#[derive(Debug, Clone, Default)]
pub struct CategoryStats {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Default)]
pub struct HealthSeverityDetail {
    pub count: usize,
    pub penalty_each: i64,
    pub penalty_total: i64,
}

#[derive(Debug, Clone)]
pub struct TopFile {
    pub file: String,
    pub score: i64,
    /// All 5 severities — an accepted deviation from Python
    /// (`file_sev` there only tracks CRITICAL/HIGH/MEDIUM/LOW). INFO
    /// still has zero weight in `score` (`file_score_weight`), so it
    /// has no effect on ranking — it is only counted/displayed here.
    pub severities: BTreeMap<&'static str, usize>,
}

#[derive(Debug, Clone)]
pub struct ReportData<'f> {
    pub by_severity: BTreeMap<&'static str, Vec<&'f ReportFinding>>,
    pub total_critical: usize,
    pub total_high: usize,
    pub total_medium: usize,
    pub total_low: usize,
    pub total_info: usize,
    pub total_findings: usize,
    /// Always 0 for now: tracking "good practices" (`_add_success`,
    /// scattered across the `audit_*` methods of `runner.py`) is not
    /// yet ported on the AuditRust side — a separate effort, not just
    /// `report.py`.
    pub total_successes: usize,
    pub total_business: usize,
    pub total_deps: usize,
    pub by_category: BTreeMap<String, CategoryStats>,
    pub top_files: Vec<TopFile>,
    pub health_score: i64,
    pub health_severity_detail: BTreeMap<&'static str, HealthSeverityDetail>,
    pub health_penalty_detail: BTreeMap<&'static str, usize>,
    pub total_penalty: i64,
}

/// Computes the aggregated report statistics — port of
/// `_compute_report_data`. `total_lines_code` feeds the health-score
/// normalization factor (`loc_factor`).
pub fn compute_report_data(findings: &[ReportFinding], total_lines_code: usize) -> ReportData<'_> {
    let mut by_severity: BTreeMap<&'static str, Vec<&ReportFinding>> =
        SEVERITIES.iter().map(|s| (*s, Vec::new())).collect();
    for f in findings {
        let sev = normalize_severity(&f.severity);
        by_severity.get_mut(sev).unwrap().push(f);
    }

    let total_critical = by_severity["CRITICAL"].len();
    let total_high = by_severity["HIGH"].len();
    let total_medium = by_severity["MEDIUM"].len();
    let total_low = by_severity["LOW"].len();
    let total_info = by_severity["INFO"].len();
    let total_findings = total_critical + total_high + total_medium + total_low + total_info;

    let total_business = findings.iter().filter(|f| !is_dependency(&f.file)).count();
    let total_deps = findings.iter().filter(|f| is_dependency(&f.file)).count();

    let mut by_category: BTreeMap<String, CategoryStats> = BTreeMap::new();
    for f in findings {
        let entry = by_category.entry(f.category.clone()).or_default();
        entry.total += 1;
        match normalize_severity(&f.severity) {
            "CRITICAL" => entry.critical += 1,
            "HIGH" => entry.high += 1,
            "MEDIUM" => entry.medium += 1,
            "LOW" => entry.low += 1,
            "INFO" => entry.info += 1,
            _ => unreachable!(),
        }
    }

    // Top 10 most problematic files — weighted score, stable order
    // (the first finding encountered decides the order in case of a
    // score tie, like the insertion order of a Python dict).
    let mut file_order: Vec<String> = Vec::new();
    let mut file_scores: BTreeMap<String, i64> = BTreeMap::new();
    let mut file_sev: BTreeMap<String, BTreeMap<&'static str, usize>> = BTreeMap::new();
    for f in findings {
        let sev = normalize_severity(&f.severity);
        if !file_scores.contains_key(&f.file) {
            file_order.push(f.file.clone());
        }
        *file_scores.entry(f.file.clone()).or_insert(0) += file_score_weight(sev);
        // INFO counted and displayed like the other 4 (deliberate
        // improvement requested by the maintainer, see `TopFile::severities`) —
        // still carries no weight in `file_scores` above
        // (`file_score_weight("INFO") == 0`), so the ranking of the
        // most problematic files stays unchanged.
        let entry = file_sev
            .entry(f.file.clone())
            .or_insert_with(|| SEVERITIES.iter().map(|s| (*s, 0)).collect());
        *entry.get_mut(sev).unwrap() += 1;
    }
    let mut ranked: Vec<&String> = file_order.iter().collect();
    ranked.sort_by_key(|f| std::cmp::Reverse(file_scores[*f]));
    let top_files: Vec<TopFile> = ranked
        .into_iter()
        .take(10)
        .map(|f| TopFile {
            file: f.clone(),
            score: file_scores[f],
            severities: file_sev.get(f).cloned().unwrap_or_default(),
        })
        .collect();

    // Health score — SECURITY findings only.
    let mut health_penalty_detail: BTreeMap<&'static str, usize> =
        SEVERITIES.iter().map(|s| (*s, 0)).collect();
    let mut total_penalty: i64 = 0;
    for f in findings.iter().filter(|f| f.category == "SECURITY") {
        let sev = normalize_severity(&f.severity);
        *health_penalty_detail.get_mut(sev).unwrap() += 1;
        total_penalty += health_penalty_weight(sev);
    }
    let loc_factor = (total_lines_code as f64 / 1000.0).max(1.0);
    let health_score = if total_penalty > 0 {
        (100.0 / (1.0 + total_penalty as f64 / (20.0 * loc_factor))) as i64
    } else {
        100
    };

    let mut health_severity_detail: BTreeMap<&'static str, HealthSeverityDetail> = BTreeMap::new();
    // Includes INFO (penalty weight 0) — deliberate deviation from
    // Python (`report.py` line 91 excludes it), explicitly requested
    // by the maintainer so the breakdown chart shows all 5 severities instead
    // of 4, even though INFO never affects the score.
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] {
        let count = health_penalty_detail[sev];
        let penalty_each = health_penalty_weight(sev);
        health_severity_detail.insert(
            sev,
            HealthSeverityDetail {
                count,
                penalty_each,
                penalty_total: count as i64 * penalty_each,
            },
        );
    }

    ReportData {
        by_severity,
        total_critical,
        total_high,
        total_medium,
        total_low,
        total_info,
        total_findings,
        total_successes: 0,
        total_business,
        total_deps,
        by_category,
        top_files,
        health_score,
        health_severity_detail,
        health_penalty_detail,
        total_penalty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(category: &str, severity: &str, file: &str, line: usize) -> ReportFinding {
        ReportFinding {
            rule_key: "test_rule".to_string(),
            rule_name: "Test Rule".to_string(),
            category: category.to_string(),
            severity: severity.to_string(),
            risk: "risk".to_string(),
            file: file.to_string(),
            line,
            solution: Some("solution".to_string()),
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: "code".to_string(),
            context_before: String::new(),
            context_after: String::new(),
            confidence: 90,
            benefit: "benefit".to_string(),
            committer: None,
            rule_source: "json_builtin".to_string(),
        }
    }

    #[test]
    fn test_empty_findings_gives_perfect_health_score() {
        let data = compute_report_data(&[], 1000);
        assert_eq!(data.total_findings, 0);
        assert_eq!(data.health_score, 100);
        assert_eq!(data.total_penalty, 0);
    }

    #[test]
    fn test_severity_counts() {
        let findings = vec![
            finding("SECURITY", "CRITICAL", "a.py", 1),
            finding("SECURITY", "HIGH", "a.py", 2),
            finding("SECURITY", "HIGH", "b.py", 3),
            finding("ARCH", "LOW", "c.py", 4),
        ];
        let data = compute_report_data(&findings, 1000);
        assert_eq!(data.total_critical, 1);
        assert_eq!(data.total_high, 2);
        assert_eq!(data.total_low, 1);
        assert_eq!(data.total_findings, 4);
    }

    #[test]
    fn test_unknown_severity_falls_back_to_medium() {
        let findings = vec![finding("SECURITY", "WEIRD", "a.py", 1)];
        let data = compute_report_data(&findings, 1000);
        assert_eq!(data.total_medium, 1);
    }

    #[test]
    fn test_business_vs_dependency_split() {
        let findings = vec![
            finding("SECURITY", "HIGH", "src/app.py", 1),
            finding("SECURITY", "HIGH", "app/vendor/lib.py", 2),
        ];
        let data = compute_report_data(&findings, 1000);
        assert_eq!(data.total_business, 1);
        assert_eq!(data.total_deps, 1);
    }

    #[test]
    fn test_by_category_breakdown() {
        let findings = vec![
            finding("SECURITY", "HIGH", "a.py", 1),
            finding("SECURITY", "MEDIUM", "a.py", 2),
            finding("ARCH", "LOW", "b.py", 3),
        ];
        let data = compute_report_data(&findings, 1000);
        assert_eq!(data.by_category["SECURITY"].total, 2);
        assert_eq!(data.by_category["SECURITY"].high, 1);
        assert_eq!(data.by_category["SECURITY"].medium, 1);
        assert_eq!(data.by_category["ARCH"].total, 1);
    }

    #[test]
    fn test_top_files_ranked_by_weighted_score() {
        let findings = vec![
            finding("SECURITY", "CRITICAL", "a.py", 1), // 10
            finding("SECURITY", "LOW", "b.py", 1),      // 1
            finding("SECURITY", "HIGH", "b.py", 2),     // +5 = 6
        ];
        let data = compute_report_data(&findings, 1000);
        assert_eq!(data.top_files.len(), 2);
        assert_eq!(data.top_files[0].file, "a.py");
        assert_eq!(data.top_files[0].score, 10);
        assert_eq!(data.top_files[1].file, "b.py");
        assert_eq!(data.top_files[1].score, 6);
        assert_eq!(data.top_files[1].severities["LOW"], 1);
        assert_eq!(data.top_files[1].severities["HIGH"], 1);
    }

    #[test]
    fn test_top_files_capped_at_10() {
        let findings: Vec<ReportFinding> = (0..15)
            .map(|i| finding("SECURITY", "HIGH", &format!("f{i}.py"), 1))
            .collect();
        let data = compute_report_data(&findings, 1000);
        assert_eq!(data.top_files.len(), 10);
    }

    #[test]
    fn test_health_score_only_counts_security_category() {
        let findings = vec![finding("ARCH", "CRITICAL", "a.py", 1)];
        let data = compute_report_data(&findings, 1000);
        assert_eq!(data.health_score, 100);
        assert_eq!(data.total_penalty, 0);
    }

    #[test]
    fn test_health_score_degrades_with_critical_security_findings() {
        let findings = vec![finding("SECURITY", "CRITICAL", "a.py", 1)];
        let data = compute_report_data(&findings, 1000);
        // loc_factor = max(1, 1000/1000) = 1 ; penalty=10 ;
        // score = int(100 / (1 + 10/20)) = int(66.67) = 66
        assert_eq!(data.total_penalty, 10);
        assert_eq!(data.health_score, 66);
    }

    #[test]
    fn test_health_score_normalizes_by_loc() {
        let findings = vec![finding("SECURITY", "CRITICAL", "a.py", 1)];
        // loc_factor = max(1, 10000/1000) = 10 ; score = int(100/(1+10/200)) = 95
        let data = compute_report_data(&findings, 10000);
        assert_eq!(data.health_score, 95);
    }

    #[test]
    fn test_health_severity_detail_and_penalty_detail() {
        let findings = vec![
            finding("SECURITY", "HIGH", "a.py", 1),
            finding("SECURITY", "HIGH", "b.py", 2),
            finding("SECURITY", "LOW", "c.py", 3),
        ];
        let data = compute_report_data(&findings, 1000);
        assert_eq!(data.health_penalty_detail["HIGH"], 2);
        assert_eq!(data.health_penalty_detail["LOW"], 1);
        let hs = &data.health_severity_detail["HIGH"];
        assert_eq!(hs.count, 2);
        assert_eq!(hs.penalty_each, 5);
        assert_eq!(hs.penalty_total, 10);
    }
}
