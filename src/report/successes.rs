//! "Verified good practices" — port of
//! `AuditRunner._generate_successes` (`Audit/sca/runner.py`), 3
//! sources. Unlike Python (computed during the scan, with the report
//! language already fixed at that point via `self.lang`), computed
//! here at HTML render time — this is the only place where AuditRust
//! knows the report language (`ScanConfig`/`run_scan` are
//! language-agnostic).
//!
//! **Not ported**: the "fixtures" coverage (2nd half of Source 2 in
//! Python, `self.fixture_validation.success_rate`) — Audit's internal
//! QA tooling that validates its own rule catalog against its fixture
//! corpus, not a customer-facing feature, same decision already made
//! for `_validate_fixtures` (see `testing.rs`, doc of `run_tests`).

use std::collections::{BTreeMap, HashSet};

use serde_json::Value;

use crate::i18n::t;
use crate::project::testing::TestResults;
use crate::report::exports::sarif::ReportFinding;
use crate::report::findings_html::{CATEGORIES, category_icon, category_title};
use crate::report::report_assets::load_template;
use crate::report::text::escape;
use crate::scan::orchestrator::{extract_i18n_block, rule_category};

/// Computes the good-practice messages per category.
pub fn compute_successes(
    findings: &[ReportFinding],
    rule_catalog: &BTreeMap<String, Value>,
    test_results: Option<&TestResults>,
    report_locale: &Value,
    lang: &str,
) -> BTreeMap<&'static str, Vec<String>> {
    let fired_keys: HashSet<&str> = findings.iter().map(|f| f.rule_key.as_str()).collect();
    let mut successes: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut seen: HashSet<(&'static str, String)> = HashSet::new();

    let add = |successes: &mut BTreeMap<&'static str, Vec<String>>,
               seen: &mut HashSet<(&'static str, String)>,
               cat: &'static str,
               msg: String| {
        if msg.is_empty() {
            return;
        }
        if seen.insert((cat, msg.clone())) {
            successes.entry(cat).or_default().push(msg);
        }
    };

    // Source 3 — a HIGH/CRITICAL rule from the catalog that produced
    // no finding anywhere in the scan → its benefit becomes a
    // verified good practice.
    for (rule_id, rule_json) in rule_catalog {
        let severity = rule_json
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_uppercase();
        if severity != "HIGH" && severity != "CRITICAL" {
            continue;
        }
        if fired_keys.contains(rule_id.as_str()) {
            continue;
        }
        let cat_raw = {
            let c = rule_category(rule_json);
            if c.is_empty() {
                "SECURITY".to_string()
            } else {
                c.to_uppercase()
            }
        };
        let Some(cat) = CATEGORIES
            .iter()
            .find(|(k, _, _)| *k == cat_raw)
            .map(|(k, _, _)| *k)
        else {
            continue;
        };
        let benefit = extract_i18n_block(rule_json, "benefit", lang);
        add(&mut successes, &mut seen, cat, benefit);
    }

    // Source 1 — a category with findings but no CRITICAL/HIGH.
    for (cat, _, _) in CATEGORIES {
        let cat_findings: Vec<&ReportFinding> =
            findings.iter().filter(|f| f.category == cat).collect();
        if cat_findings.is_empty() {
            continue;
        }
        let has_crit_or_high = cat_findings
            .iter()
            .any(|f| f.severity == "CRITICAL" || f.severity == "HIGH");
        if !has_crit_or_high {
            let msg = t(report_locale, "success_cat_no_critical").replace("{cat}", cat);
            add(&mut successes, &mut seen, cat, msg);
        }
    }

    // Source 2 — test coverage >= 80% (`--with-tests`).
    if let Some(tr) = test_results
        && tr.success_rate >= 80.0
    {
        let msg = t(report_locale, "success_tests_coverage")
            .replace("{rate}", &format!("{:.0}", tr.success_rate));
        add(&mut successes, &mut seen, "MAINTENANCE", msg);
    }

    successes
}

/// HTML rendering — one section per category with at least one
/// success, mirroring the `for cat in self.categories.values()` loop
/// in `_generate_html` (`report.py`).
pub fn render_successes_html(
    successes: &BTreeMap<&'static str, Vec<String>>,
    report_locale: &Value,
) -> String {
    let section_tpl = load_template("successes-section.html");
    let mut html = String::new();
    for (cat, messages) in successes {
        if messages.is_empty() {
            continue;
        }
        let items: String = messages
            .iter()
            .map(|s| format!(r#"<div class="success-item">{}</div>"#, escape(s)))
            .collect();
        let section = section_tpl
            .replace("{{icon}}", category_icon(cat))
            .replace("{{category}}", &category_title(report_locale, cat))
            .replace("{{cat_key}}", &cat.to_lowercase())
            .replace("{{count}}", &messages.len().to_string())
            .replace(
                "{{i18n_validation_count}}",
                &t(report_locale, "validation_count"),
            )
            .replace("{{items}}", &items);
        html.push_str(&section);
    }
    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;
    use serde_json::json;

    fn finding(rule_key: &str, category: &str, severity: &str) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_name: rule_key.to_string(),
            category: category.to_string(),
            severity: severity.to_string(),
            risk: String::new(),
            file: "a.py".to_string(),
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

    fn rule(id: &str, category: &str, severity: &str, benefit_en: &str) -> Value {
        json!({
            "id": id,
            "category": category,
            "severity": severity,
            "benefit": {"en": benefit_en},
        })
    }

    #[test]
    fn test_source3_unfired_high_rule_becomes_success() {
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        catalog.insert(
            "sql_injection".to_string(),
            rule(
                "sql_injection",
                "SECURITY",
                "HIGH",
                "No SQL injection found",
            ),
        );
        let successes = compute_successes(&[], &catalog, None, &en, "en");
        assert_eq!(
            successes.get("SECURITY").map(|v| v.as_slice()),
            Some(["No SQL injection found".to_string()].as_slice())
        );
    }

    #[test]
    fn test_source3_fired_rule_not_counted_as_success() {
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        catalog.insert(
            "sql_injection".to_string(),
            rule(
                "sql_injection",
                "SECURITY",
                "HIGH",
                "No SQL injection found",
            ),
        );
        let findings = vec![finding("sql_injection", "SECURITY", "HIGH")];
        let successes = compute_successes(&findings, &catalog, None, &en, "en");
        assert!(successes.is_empty());
    }

    #[test]
    fn test_source3_medium_rule_not_a_source3_candidate() {
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        catalog.insert(
            "weak_crypto".to_string(),
            rule("weak_crypto", "SECURITY", "MEDIUM", "No weak crypto"),
        );
        let successes = compute_successes(&[], &catalog, None, &en, "en");
        assert!(successes.is_empty());
    }

    #[test]
    fn test_source1_category_with_findings_but_no_critical_high() {
        let en = load_report_locale("en");
        let findings = vec![finding("missing_health_check", "MAINTENANCE", "INFO")];
        let successes = compute_successes(&findings, &BTreeMap::new(), None, &en, "en");
        let msgs = successes.get("MAINTENANCE").expect("MAINTENANCE success");
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("MAINTENANCE"));
    }

    #[test]
    fn test_source1_category_with_high_finding_not_a_success() {
        let en = load_report_locale("en");
        let findings = vec![finding("os_system_injection", "SECURITY", "HIGH")];
        let successes = compute_successes(&findings, &BTreeMap::new(), None, &en, "en");
        assert!(!successes.contains_key("SECURITY"));
    }

    #[test]
    fn test_source2_test_coverage_above_threshold() {
        let en = load_report_locale("en");
        let tr = TestResults {
            success_rate: 92.0,
            ..Default::default()
        };
        let successes = compute_successes(&[], &BTreeMap::new(), Some(&tr), &en, "en");
        let msgs = successes.get("MAINTENANCE").expect("MAINTENANCE success");
        assert!(msgs[0].contains("92"));
    }

    #[test]
    fn test_source2_test_coverage_below_threshold_no_success() {
        let en = load_report_locale("en");
        let tr = TestResults {
            success_rate: 50.0,
            ..Default::default()
        };
        let successes = compute_successes(&[], &BTreeMap::new(), Some(&tr), &en, "en");
        assert!(successes.is_empty());
    }

    #[test]
    fn test_render_successes_html_groups_by_category() {
        let en = load_report_locale("en");
        let mut successes = BTreeMap::new();
        successes.insert("SECURITY", vec!["No SQLi found".to_string()]);
        let html = render_successes_html(&successes, &en);
        assert!(html.contains("No SQLi found"));
        assert!(html.contains("section-success-security"));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn test_render_successes_html_empty_when_no_successes() {
        let en = load_report_locale("en");
        let html = render_successes_html(&BTreeMap::new(), &en);
        assert!(html.is_empty());
    }
}
