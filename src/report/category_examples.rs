//! Representative examples per category — port of
//! `_generate_category_examples_html` (`Audit/sca/report.py`). For
//! each major category (SECURITY/ARCH/UI/UX/MAINTENANCE, in this
//! order — the same 5 as Python, not the 8 of
//! `findings_html::CATEGORIES`), illustrates the most frequent issue
//! with a real occurrence detected in the audited project + the
//! generic fix from the `.sca` rule (`fix_before`/`fix_after`) — never
//! an automatic fix of the client's code, which remains forbidden
//! (RETEX Franck R22, see the comment on the source Python function).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::i18n::{rule_i18n, t};
use crate::report::exports::sarif::ReportFinding;
use crate::report::text::escape;

const CATEGORY_ORDER: [(&str, &str, &str); 5] = [
    ("SECURITY", "security", "🔒"),
    ("ARCH", "architecture", "🏗️"),
    ("UI", "ui", "🎨"),
    ("UX", "ux", "🧭"),
    ("MAINTENANCE", "maintenance", "🔧"),
];

/// Generates the "representative examples per category" section —
/// empty string if no category has an eligible rule (`fix_before`
/// AND `fix_after` non-empty) among its findings, matching Python.
pub fn render_category_examples_html(
    findings: &[ReportFinding],
    rule_catalog: &BTreeMap<String, Value>,
    report_locale: &Value,
) -> String {
    let detected_label = t(report_locale, "category_example_detected");
    let fix_label = t(report_locale, "category_example_fix");
    let occurrences_tpl = t(report_locale, "category_example_occurrences");
    let bridge_tpl = t(report_locale, "category_example_bridge");

    let mut blocks = String::new();
    for (cat_key, i18n_key, icon) in CATEGORY_ORDER {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        let mut example_by_rule: BTreeMap<&str, &ReportFinding> = BTreeMap::new();
        for f in findings.iter().filter(|f| f.category == cat_key) {
            if f.rule_key.is_empty() {
                continue;
            }
            let Some(rule) = rule_catalog.get(&f.rule_key) else {
                continue;
            };
            let has_before = rule
                .get("fix_before")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty());
            let has_after = rule
                .get("fix_after")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty());
            if !has_before || !has_after {
                continue;
            }
            *counts.entry(f.rule_key.as_str()).or_insert(0) += 1;
            example_by_rule.entry(f.rule_key.as_str()).or_insert(f);
        }

        let Some((&top_rule_key, &count)) = counts.iter().max_by_key(|(_, c)| **c) else {
            continue;
        };
        let finding = example_by_rule[top_rule_key];
        let rule = &rule_catalog[top_rule_key];
        let rule_i18n_data = rule_i18n(report_locale, top_rule_key);
        let cat_title = t(report_locale, &format!("category_titles.{i18n_key}"));
        let solution = &rule_i18n_data.solution;
        let bridge_html = if !solution.is_empty() {
            format!(
                r#"<p class="category-example-bridge">{}</p>"#,
                escape(&bridge_tpl.replace("{solution}", solution))
            )
        } else {
            String::new()
        };
        let fix_after = rule.get("fix_after").and_then(|v| v.as_str()).unwrap_or("");

        blocks.push_str(&format!(
            r#"
            <div class="category-example">
                <h4>{icon} {} — {}</h4>
                <p class="category-example-meta">{} — {}:{}</p>
                <div class="fix-before"><strong>❌ {detected_label}</strong>
                <pre><code>{}</code></pre></div>
                {bridge_html}
                <div class="fix-after"><strong>✅ {fix_label}</strong>
                <pre><code>{}</code></pre></div>
            </div>
            "#,
            escape(&cat_title),
            escape(&rule_i18n_data.name),
            occurrences_tpl.replace("{count}", &count.to_string()),
            escape(&finding.file),
            finding.line,
            escape(&finding.code),
            escape(fix_after),
        ));
    }

    if blocks.is_empty() {
        return String::new();
    }

    let title = t(report_locale, "category_examples_title");
    let subtitle = t(report_locale, "category_examples_subtitle");
    let toc = t(report_locale, "toc");
    format!(
        r##"
        <div class="section category-examples-section" id="section-category-examples" data-nav-section="{title}">
            <h2 class="section-title">🎓 {title} <a href="#sommaire" class="back-to-toc">↑ {toc}</a></h2>
            <p class="chart-subtitle">{subtitle}</p>
            {blocks}
        </div>
        "##
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;
    use serde_json::json;

    fn finding(
        category: &str,
        rule_key: &str,
        file: &str,
        line: usize,
        code: &str,
    ) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_name: "Rule".to_string(),
            category: category.to_string(),
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
    fn test_no_findings_returns_empty() {
        let en = load_report_locale("en");
        let out = render_category_examples_html(&[], &BTreeMap::new(), &en);
        assert_eq!(out, "");
    }

    #[test]
    fn test_findings_without_fix_before_after_excluded() {
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        catalog.insert("no_fix_rule".to_string(), json!({"name": "No fix"}));
        let findings = vec![finding("SECURITY", "no_fix_rule", "a.py", 1, "eval(x)")];
        let out = render_category_examples_html(&findings, &catalog, &en);
        assert_eq!(out, "");
    }

    #[test]
    fn test_picks_most_frequent_rule_per_category() {
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        catalog.insert(
            "rule_a".to_string(),
            json!({"fix_before": "eval(x)", "fix_after": "ast.literal_eval(x)"}),
        );
        catalog.insert(
            "rule_b".to_string(),
            json!({"fix_before": "b_before", "fix_after": "b_after"}),
        );
        let findings = vec![
            finding("SECURITY", "rule_a", "a.py", 1, "eval(x)"),
            finding("SECURITY", "rule_a", "a.py", 2, "eval(y)"),
            finding("SECURITY", "rule_b", "b.py", 3, "b_code"),
        ];
        let out = render_category_examples_html(&findings, &catalog, &en);
        assert!(out.contains("ast.literal_eval(x)"));
        assert!(!out.contains("b_after"));
        assert!(out.contains("a.py:1"));
        assert!(out.contains("category-examples-section"));
    }

    #[test]
    fn test_dependencies_category_not_included() {
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        catalog.insert(
            "dep_rule".to_string(),
            json!({"fix_before": "x", "fix_after": "y"}),
        );
        let findings = vec![finding(
            "DEPENDENCIES",
            "dep_rule",
            "requirements.txt",
            1,
            "flask",
        )];
        let out = render_category_examples_html(&findings, &catalog, &en);
        assert_eq!(out, "");
    }

    #[test]
    fn test_escapes_code_content() {
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        catalog.insert(
            "xss_rule".to_string(),
            json!({"fix_before": "<b>", "fix_after": "<script>evil()</script>"}),
        );
        let findings = vec![finding(
            "SECURITY",
            "xss_rule",
            "a.py",
            1,
            "<script>bad()</script>",
        )];
        let out = render_category_examples_html(&findings, &catalog, &en);
        assert!(!out.contains("<script>evil()</script>"));
        assert!(out.contains("&lt;script&gt;evil()&lt;/script&gt;"));
    }
}
