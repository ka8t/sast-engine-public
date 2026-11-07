//! HTML rendering of the baseline comparison section — port of the
//! `comparison_html` block of `_generate_html` (`Audit/sca/report.py`).

use serde_json::Value;

use crate::i18n::t;
use crate::report::comparison::ComparisonResult;
use crate::report::data::ReportData;
use crate::report::exports::sarif::ReportFinding;
use crate::report::report_assets::load_template;
use crate::report::text::escape;

fn format_delta(d: i64) -> String {
    let (class, value) = if d > 0 {
        ("negative", format!("+{d}"))
    } else if d < 0 {
        ("positive", d.to_string())
    } else {
        ("neutral", "±0".to_string())
    };
    load_template("delta.html")
        .replace("{{class}}", class)
        .replace("{{value}}", &value)
}

fn render_finding_mini(f: &ReportFinding, resolved: bool) -> String {
    let (severity_class, badge_class, badge_text) = if resolved {
        (
            "resolved".to_string(),
            "success".to_string(),
            format!("✓ {}", f.severity),
        )
    } else {
        (
            f.severity.to_lowercase(),
            f.severity.to_lowercase(),
            f.severity.clone(),
        )
    };
    load_template("finding-mini.html")
        .replace("{{severity_class}}", &severity_class)
        .replace("{{badge_class}}", &badge_class)
        .replace("{{badge_text}}", &badge_text)
        .replace("{{rule}}", &escape(&f.rule_name))
        .replace("{{file}}", &escape(&f.file))
        .replace("{{line}}", &f.line.to_string())
}

fn sort_key(f: &ReportFinding) -> (bool, bool, String) {
    (f.severity != "HIGH", f.severity != "MEDIUM", f.file.clone())
}

/// Generates the HTML comparison section — port of the
/// `comparison_html` block of `_generate_html`. The totals come from
/// `data` (already computed once by `compute_report_data` for the rest
/// of the report) rather than being duplicated as parameters.
pub fn render_comparison_html(
    comparison: &ComparisonResult,
    data: &ReportData,
    report_locale: &Value,
) -> String {
    let total_high = data.total_high;
    let total_medium = data.total_medium;
    let total_low = data.total_low;
    // Deliberate improvement vs Python (whose comparison grid only
    // tracks HIGH/MEDIUM/LOW, see the 3-column `.cmp-sev-grid` on the
    // Audit side) — explicitly requested by the maintainer.
    let total_info = data.total_info;
    let total_findings = data.total_findings;

    let mut new_sorted = comparison.new_findings.clone();
    new_sorted.sort_by_key(sort_key);
    let new_items: String = new_sorted
        .iter()
        .map(|f| render_finding_mini(f, false))
        .collect();

    let mut resolved_sorted = comparison.resolved_findings.clone();
    resolved_sorted.sort_by_key(sort_key);
    let resolved_items: String = resolved_sorted
        .iter()
        .map(|f| render_finding_mini(f, true))
        .collect();

    let baseline_high = *comparison.baseline_totals.get("HIGH").unwrap_or(&0);
    let baseline_medium = *comparison.baseline_totals.get("MEDIUM").unwrap_or(&0);
    let baseline_low = *comparison.baseline_totals.get("LOW").unwrap_or(&0);
    let baseline_info = *comparison.baseline_totals.get("INFO").unwrap_or(&0);
    let delta_high = total_high as i64 - baseline_high as i64;
    let delta_medium = total_medium as i64 - baseline_medium as i64;
    let delta_low = total_low as i64 - baseline_low as i64;
    let delta_info = total_info as i64 - baseline_info as i64;

    let baseline_total: usize = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        .iter()
        .map(|s| *comparison.baseline_totals.get(*s).unwrap_or(&0))
        .sum();
    let current_total = total_findings;
    let total_delta = current_total as i64 - baseline_total as i64;
    let new_count = comparison.new_findings.len();
    let resolved_count = comparison.resolved_findings.len();

    let (trend_class, trend_icon, trend_label) =
        if total_delta < 0 || (total_delta == 0 && resolved_count > new_count) {
            (
                "improved",
                "📈",
                t(report_locale, "comparison_trend_improved"),
            )
        } else if total_delta > 0 || (total_delta == 0 && new_count > resolved_count) {
            (
                "regressed",
                "📉",
                t(report_locale, "comparison_trend_regressed"),
            )
        } else {
            ("stable", "➖", t(report_locale, "comparison_trend_stable"))
        };

    let mut trend_detail_parts = Vec::new();
    if resolved_count > 0 {
        trend_detail_parts.push(format!(
            "{resolved_count} {}",
            t(report_locale, "comparison_resolved_short")
        ));
    }
    if new_count > 0 {
        trend_detail_parts.push(format!(
            "{new_count} {}",
            t(report_locale, "comparison_new_short")
        ));
    }
    let trend_detail = if trend_detail_parts.is_empty() {
        t(report_locale, "comparison_no_change")
    } else {
        trend_detail_parts.join(" · ")
    };

    let no_new = format!(
        r#"<p class="empty">{}</p>"#,
        t(report_locale, "no_new_issues")
    );
    let no_resolved = format!(
        r#"<p class="empty">{}</p>"#,
        t(report_locale, "no_resolved_issues")
    );

    load_template("comparison-full.html")
        .replace("{{i18n_comparison}}", &t(report_locale, "comparison"))
        .replace("{{i18n_toc}}", &t(report_locale, "toc"))
        .replace("{{i18n_new_issues}}", &t(report_locale, "new_issues"))
        .replace(
            "{{i18n_resolved_issues}}",
            &t(report_locale, "resolved_issues"),
        )
        .replace(
            "{{i18n_baseline}}",
            &t(report_locale, "comparison_baseline"),
        )
        .replace("{{i18n_current}}", &t(report_locale, "comparison_current"))
        .replace("{{trend_class}}", trend_class)
        .replace("{{trend_icon}}", trend_icon)
        .replace("{{trend_label}}", &trend_label)
        .replace("{{trend_detail}}", &trend_detail)
        .replace("{{baseline_date}}", &escape(&comparison.baseline_date))
        .replace("{{baseline_total}}", &baseline_total.to_string())
        .replace("{{current_total}}", &current_total.to_string())
        .replace("{{baseline_high}}", &baseline_high.to_string())
        .replace("{{baseline_medium}}", &baseline_medium.to_string())
        .replace("{{baseline_low}}", &baseline_low.to_string())
        .replace("{{baseline_info}}", &baseline_info.to_string())
        .replace("{{total_high}}", &total_high.to_string())
        .replace("{{total_medium}}", &total_medium.to_string())
        .replace("{{total_low}}", &total_low.to_string())
        .replace("{{total_info}}", &total_info.to_string())
        .replace("{{delta_high}}", &format_delta(delta_high))
        .replace("{{delta_medium}}", &format_delta(delta_medium))
        .replace("{{delta_low}}", &format_delta(delta_low))
        .replace("{{delta_info}}", &format_delta(delta_info))
        .replace("{{new_count}}", &new_count.to_string())
        .replace("{{resolved_count}}", &resolved_count.to_string())
        .replace(
            "{{new_items}}",
            if new_items.is_empty() {
                &no_new
            } else {
                &new_items
            },
        )
        .replace(
            "{{resolved_items}}",
            if resolved_items.is_empty() {
                &no_resolved
            } else {
                &resolved_items
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;
    use crate::report::data::compute_report_data;
    use std::collections::BTreeMap;

    fn finding(file: &str, severity: &str, rule_name: &str) -> ReportFinding {
        ReportFinding {
            rule_key: "r".to_string(),
            rule_name: rule_name.to_string(),
            category: "SECURITY".to_string(),
            severity: severity.to_string(),
            risk: String::new(),
            file: file.to_string(),
            line: 1,
            solution: None,
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: String::new(),
            context_before: String::new(),
            context_after: String::new(),
            confidence: 90,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
        }
    }

    #[test]
    fn test_format_delta_positive_negative_zero() {
        assert!(format_delta(3).contains("negative"));
        assert!(format_delta(3).contains("+3"));
        assert!(format_delta(-2).contains("positive"));
        assert!(format_delta(-2).contains("-2"));
        assert!(format_delta(0).contains("neutral"));
        assert!(format_delta(0).contains("±0"));
    }

    #[test]
    fn test_render_comparison_html_improved_trend() {
        let en = load_report_locale("en");
        let mut baseline_totals = BTreeMap::new();
        baseline_totals.insert("HIGH".to_string(), 5usize);
        let comparison = ComparisonResult {
            new_findings: vec![],
            resolved_findings: vec![finding("a.py", "HIGH", "SQL Injection")],
            unchanged_findings: vec![],
            baseline_date: "2026-08-01".to_string(),
            baseline_totals,
        };
        // Current scan: 4 HIGH findings (baseline had 5 → improvement).
        let current_findings = vec![
            finding("a.py", "HIGH", "F1"),
            finding("b.py", "HIGH", "F2"),
            finding("c.py", "HIGH", "F3"),
            finding("d.py", "HIGH", "F4"),
        ];
        let data = compute_report_data(&current_findings, 0);
        let html = render_comparison_html(&comparison, &data, &en);
        assert!(html.contains("cmp-trend-improved"));
        assert!(html.contains("SQL Injection"));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn test_render_comparison_html_no_new_no_resolved_shows_empty_state() {
        let en = load_report_locale("en");
        let mut baseline_totals = BTreeMap::new();
        baseline_totals.insert("HIGH".to_string(), 1usize);
        let comparison = ComparisonResult {
            new_findings: vec![],
            resolved_findings: vec![],
            unchanged_findings: vec![finding("a.py", "HIGH", "SQL Injection")],
            baseline_date: "2026-08-01".to_string(),
            baseline_totals,
        };
        let current_findings = vec![finding("a.py", "HIGH", "SQL Injection")];
        let data = compute_report_data(&current_findings, 0);
        let html = render_comparison_html(&comparison, &data, &en);
        assert!(html.contains(&t(&en, "no_new_issues")));
        assert!(html.contains(&t(&en, "no_resolved_issues")));
        assert!(html.contains("cmp-trend-stable"));
    }

    #[test]
    fn test_render_comparison_html_regressed_trend_with_new_findings() {
        let en = load_report_locale("en");
        let comparison = ComparisonResult {
            new_findings: vec![finding("a.py", "HIGH", "New Issue")],
            resolved_findings: vec![],
            unchanged_findings: vec![],
            baseline_date: "2026-08-01".to_string(),
            baseline_totals: BTreeMap::new(),
        };
        let current_findings = vec![finding("a.py", "HIGH", "New Issue")];
        let data = compute_report_data(&current_findings, 0);
        let html = render_comparison_html(&comparison, &data, &en);
        assert!(html.contains("cmp-trend-regressed"));
        assert!(html.contains("New Issue"));
    }
}
