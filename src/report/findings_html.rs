//! HTML rendering of findings, grouped by severity → business/deps →
//! category → rule — port of `_generate_fix_suggestion` and the
//! nested functions `render_finding_item`/`render_findings`/
//! `render_by_category` from `_generate_html` (`Audit/sca/report.py`).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::i18n::t;
use crate::project::suppress::line_hash;
use crate::report::exports::sarif::ReportFinding;
use crate::report::playbook::render_playbook_inline;
use crate::report::report_assets::load_template;
use crate::report::text::{escape, is_dependency, lang_label, linkify_acronyms};

/// Icon + i18n key (`category_titles.<key>`) for the 8 fixed
/// categories — mirrors `self.categories`/`cat_i18n_map`
/// (`sca/runner.py`).
pub(crate) const CATEGORIES: [(&str, &str, &str); 8] = [
    ("SECURITY", "🛡️", "security"),
    ("ARCH", "🏗️", "architecture"),
    ("UI", "🎨", "ui"),
    ("UX", "🔔", "ux"),
    ("MAINTENANCE", "♻️", "maintenance"),
    ("DEPENDENCIES", "📦", "dependencies"),
    ("DATABASE", "🗄️", "database"),
    ("CICD", "⚙️", "cicd"),
];

pub(crate) fn category_icon(category: &str) -> &'static str {
    CATEGORIES
        .iter()
        .find(|(k, _, _)| *k == category)
        .map(|(_, icon, _)| *icon)
        .unwrap_or("")
}

pub(crate) fn category_title(report_locale: &Value, category: &str) -> String {
    let i18n_key = CATEGORIES
        .iter()
        .find(|(k, _, _)| *k == category)
        .map(|(_, _, k)| *k);
    match i18n_key {
        Some(k) => t(report_locale, &format!("category_titles.{k}")),
        None => category.to_string(),
    }
}

/// Generates a before/after block (`fix_before`/`fix_after`) from the
/// compiled DSL rule — port of `_generate_fix_suggestion`.
/// `rule_catalog`: rule id → compiled JSON (same objects as
/// `rule_jsons` in `orchestrator.rs`).
pub fn generate_fix_suggestion(
    rule_catalog: &BTreeMap<String, Value>,
    rule_key: &str,
    report_locale: &Value,
) -> String {
    let Some(rule) = rule_catalog.get(rule_key) else {
        return String::new();
    };
    let before = rule
        .get("fix_before")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let after = rule.get("fix_after").and_then(|v| v.as_str()).unwrap_or("");
    if before.is_empty() && after.is_empty() {
        return String::new();
    }
    let rule_name = crate::i18n::rule_i18n(report_locale, rule_key).name;
    let lbl = t(report_locale, "taint_fix_title");
    format!(
        r#"<details class="taint-fix"><summary>🔧 {lbl} — {rule_name}</summary><div class="fix-before"><strong>❌ {}</strong><pre><code>{}</code></pre></div><div class="fix-after"><strong>✅ {}</strong><pre><code>{}</code></pre></div></details>"#,
        t(report_locale, "taint_fix_before"),
        escape(before),
        t(report_locale, "taint_fix_after"),
        escape(after),
    )
}

/// Explains a `file_contains` rule (`requires: has/not_has`) in plain
/// terms — these rules have no "offending line" in the strict sense:
/// Python (`file_check.py::execute`) always anchors the finding to
/// line 1, with the first non-empty line of code as the displayed
/// snippet (same convention kept on the Rust side), which can be
/// misleading (e.g. `missing_csp_header` detected on a Flask file
/// shows `import sqlite3` on line 1, unrelated to the actual reason:
/// no CSP anywhere in the file). Rendered once per rule group (same
/// contract as `generate_fix_suggestion`), not per finding instance.
fn render_file_check_explanation(
    rule_catalog: &BTreeMap<String, Value>,
    rule_key: &str,
    report_locale: &Value,
) -> String {
    let Some(rule) = rule_catalog.get(rule_key) else {
        return String::new();
    };
    let Some(fc) = rule.get("file_contains") else {
        return String::new();
    };
    let has: Vec<String> = fc
        .get("has")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let not_has: Vec<String> = fc
        .get("not_has")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    if has.is_empty() && not_has.is_empty() {
        return String::new();
    }
    let mut body = format!("<p>{}</p>", t(report_locale, "file_check_scope_note"));
    if !has.is_empty() {
        let items: String = has
            .iter()
            .map(|p| format!("<code>{}</code>", escape(p)))
            .collect::<Vec<_>>()
            .join(", ");
        body.push_str(&format!(
            "<p>✅ {} : {items}</p>",
            t(report_locale, "file_check_has")
        ));
    }
    if !not_has.is_empty() {
        let items: String = not_has
            .iter()
            .map(|p| format!("<code>{}</code>", escape(p)))
            .collect::<Vec<_>>()
            .join(", ");
        body.push_str(&format!(
            "<p>🚫 {} : {items}</p>",
            t(report_locale, "file_check_not_has")
        ));
    }
    format!(
        r#"<details class="file-check-explain"><summary>🔍 {}</summary>{body}</details>"#,
        t(report_locale, "file_check_why")
    )
}

fn render_context_lines(context: &str) -> String {
    if context.is_empty() {
        return String::new();
    }
    context
        .trim_end()
        .split('\n')
        .filter(|l| !l.trim().is_empty())
        .map(|l| format!(r#"<div class="finding-code-context">{}</div>"#, escape(l)))
        .collect()
}

fn render_taint_trace(f: &ReportFinding, report_locale: &Value) -> String {
    let Some(flow) = &f.taint_flow else {
        return String::new();
    };
    let chain_items: String = flow
        .chain
        .iter()
        .filter(|(_, var, _)| var != "__sink__" && var != "Sink")
        .map(|(line, var, code)| {
            format!(
                r#"<div class="taint-step"><span class="taint-line">L{line}</span> <span class="taint-var">{}</span> <code>{}</code></div>"#,
                escape(var),
                escape(code)
            )
        })
        .collect();
    let source_kind = if flow.source_kind.is_empty() {
        "network"
    } else {
        flow.source_kind.as_str()
    };
    let kind_label = t(report_locale, &format!("taint_kind_{source_kind}"));
    let trace_summary = t(report_locale, "taint_trace_summary");
    let entry_label = t(report_locale, "taint_entry_point");
    let impact_label = t(report_locale, "taint_impact_point");
    format!(
        r#"<details class="taint-trace"><summary>🔬 {trace_summary} ({kind_label})</summary><div class="taint-source"><strong>🟢 {entry_label}</strong> L{}: <code>{}</code></div><div class="taint-chain">{chain_items}</div><div class="taint-sink"><strong>🔴 {impact_label}</strong> L{}: <code>{}</code></div></details>"#,
        flow.source_line,
        escape(&flow.source_expr),
        flow.sink_line,
        escape(&flow.sink_expr),
    )
}

fn render_finding_item(f: &ReportFinding, severity: &str, report_locale: &Value) -> String {
    let mut item = load_template("finding-item.html").to_string();
    item = item.replace("{{severity_class}}", &severity.to_lowercase());
    item = item.replace(
        "{{i18n_suppress_title}}",
        &t(report_locale, "suppress_button_title"),
    );
    item = item.replace("{{rule}}", &escape(&f.rule_name));
    item = item.replace("{{rule_key}}", &escape(&f.rule_key));
    let code_hash = if f.code.is_empty() {
        0
    } else {
        line_hash(&f.code)
    };
    item = item.replace("{{code_hash}}", &code_hash.to_string());
    item = item.replace("{{category_icon}}", category_icon(&f.category));
    item = item.replace(
        "{{category_name}}",
        &category_title(report_locale, &f.category),
    );
    item = item.replace("{{file}}", &escape(&f.file));
    item = item.replace("{{line}}", &f.line.to_string());
    item = item.replace(
        "{{context_before_html}}",
        &render_context_lines(&f.context_before),
    );
    item = item.replace("{{code}}", &escape(&f.code));
    item = item.replace(
        "{{context_after_html}}",
        &render_context_lines(&f.context_after),
    );

    let committer_display = match &f.committer {
        Some(c) if !c.is_empty() => {
            format!(
                r#" <span class="finding-committer" title="{}">👤 {}</span>"#,
                t(report_locale, "finding_committer"),
                escape(c)
            )
        }
        _ => String::new(),
    };
    item = item.replace("{{committer_display}}", &committer_display);

    let lang = lang_label(&f.file);
    let language_badge = if lang.is_empty() {
        String::new()
    } else {
        format!(
            r#" <span class="finding-badge finding-badge-lang">{}</span>"#,
            escape(lang)
        )
    };
    item = item.replace("{{language_badge}}", &language_badge);

    let has_taint = f.taint_flow.is_some();
    item = item.replace("{{taint_class}}", if has_taint { "has-taint" } else { "" });

    let mut badges_html = String::new();
    if has_taint {
        let label = t(report_locale, "taint_badge_traced");
        badges_html.push_str(&format!(
            r#" <span class="finding-badge finding-badge-taint" title="{label}">🔬 {label}</span>"#
        ));
    }
    match f.rule_source.as_str() {
        "json_custom" => {
            let label = t(report_locale, "taint_badge_custom");
            badges_html.push_str(&format!(
                r#" <span class="finding-badge finding-badge-custom" title="{label}">📜 {label}</span>"#
            ));
        }
        "json_official" => {
            let label = t(report_locale, "taint_badge_official");
            badges_html.push_str(&format!(
                r#" <span class="finding-badge finding-badge-builtin" title="{label}">✅ {label}</span>"#
            ));
        }
        "json_builtin" => {
            let label = t(report_locale, "taint_badge_builtin");
            badges_html.push_str(&format!(
                r#" <span class="finding-badge finding-badge-builtin" title="{label}">🛡️ {label}</span>"#
            ));
        }
        _ => {}
    }
    item = item.replace("{{taint_badges}}", &badges_html);
    item = item.replace("{{taint_trace}}", &render_taint_trace(f, report_locale));

    item
}

/// Groups a list of findings by rule name (first-encounter order),
/// with the shared risk/solution/playbook/fix block rendered only
/// once per group — port of `render_findings`.
fn render_findings(
    findings: &[&ReportFinding],
    severity: &str,
    report_locale: &Value,
    rule_catalog: &BTreeMap<String, Value>,
) -> String {
    let mut order: Vec<&str> = Vec::new();
    let mut by_rule: BTreeMap<&str, Vec<&ReportFinding>> = BTreeMap::new();
    for f in findings {
        let entry = by_rule.entry(f.rule_name.as_str()).or_insert_with(|| {
            order.push(f.rule_name.as_str());
            Vec::new()
        });
        entry.push(f);
    }

    let i18n_risk = t(report_locale, "finding_risk");
    let i18n_solution = t(report_locale, "finding_solution");
    let rule_group_tpl = load_template("findings-rule-group.html");

    let mut html = String::new();
    for rule_name in order {
        let rule_findings = &by_rule[rule_name];
        let first = rule_findings[0];
        let rk = &first.rule_key;

        let mut shared_html = String::new();
        if !first.risk.is_empty() {
            shared_html.push_str(&format!(
                r#"<details class="finding-risk-block" open><summary>⚠️ {i18n_risk}</summary><p>{}</p></details>"#,
                linkify_acronyms(report_locale, &escape(&first.risk))
            ));
        }
        if let Some(solution) = &first.solution
            && !solution.is_empty()
        {
            shared_html.push_str(&format!(
                r#"<details class="finding-solution-block" open><summary>🛠️ {i18n_solution}</summary><p>{}</p></details>"#,
                linkify_acronyms(report_locale, &escape(solution))
            ));
        }
        if !rk.is_empty() {
            shared_html.push_str(&render_file_check_explanation(
                rule_catalog,
                rk,
                report_locale,
            ));
            shared_html.push_str(&render_playbook_inline(rk, report_locale));
            shared_html.push_str(&generate_fix_suggestion(rule_catalog, rk, report_locale));
        }

        let items_html: String = rule_findings
            .iter()
            .map(|f| render_finding_item(f, severity, report_locale))
            .collect();

        let group = rule_group_tpl
            .replace("{{rule_name}}", &escape(rule_name))
            .replace("{{count}}", &rule_findings.len().to_string())
            .replace("{{content}}", &(shared_html + &items_html));
        html.push_str(&group);
    }
    html
}

const CATEGORY_ORDER: [&str; 8] = [
    "SECURITY",
    "ARCH",
    "UI",
    "UX",
    "MAINTENANCE",
    "DEPENDENCIES",
    "DATABASE",
    "CICD",
];

/// Groups a list of findings by category (fixed order) — port of
/// `render_by_category`. `None` if the list is empty.
fn render_by_category(
    findings: &[&ReportFinding],
    severity: &str,
    report_locale: &Value,
    rule_catalog: &BTreeMap<String, Value>,
) -> Option<String> {
    if findings.is_empty() {
        return None;
    }
    let mut by_cat: BTreeMap<&str, Vec<&ReportFinding>> = BTreeMap::new();
    for f in findings {
        by_cat.entry(f.category.as_str()).or_default().push(f);
    }
    let cat_group_tpl = load_template("findings-category-group.html");
    let mut html = String::new();
    for cat_key in CATEGORY_ORDER {
        let Some(cat_findings) = by_cat.get(cat_key) else {
            continue;
        };
        let cat_html = render_findings(cat_findings, severity, report_locale, rule_catalog);
        let group = cat_group_tpl
            .replace("{{category_key}}", cat_key)
            .replace("{{icon}}", category_icon(cat_key))
            .replace("{{title}}", &category_title(report_locale, cat_key))
            .replace("{{count}}", &cat_findings.len().to_string())
            .replace("{{content}}", &cat_html);
        html.push_str(&group);
    }
    Some(html)
}

/// Generates the full HTML for a severity section (business + deps,
/// each grouped by category then by rule) — port of the body of the
/// `for severity in [...]` loop in `_generate_html`.
pub fn render_severity_section(
    severity: &str,
    findings: &[&ReportFinding],
    report_locale: &Value,
    rule_catalog: &BTreeMap<String, Value>,
) -> String {
    let severity_meta = |sev: &str| -> (&'static str, &'static str, String) {
        match sev {
            "CRITICAL" => (
                "💀",
                "badge-critical",
                t(report_locale, "severity.critical"),
            ),
            "HIGH" => ("🚨", "badge-high", t(report_locale, "severity.high")),
            "MEDIUM" => ("⚠️", "badge-medium", t(report_locale, "severity.medium")),
            "LOW" => ("ℹ️", "badge-low", t(report_locale, "severity.low")),
            _ => ("📝", "badge-info", t(report_locale, "severity.info")),
        }
    };
    let (icon, _badge_class, title) = severity_meta(severity);

    let findings_html = if !findings.is_empty() {
        let deps_findings: Vec<&ReportFinding> = findings
            .iter()
            .filter(|f| is_dependency(&f.file))
            .copied()
            .collect();
        let business_findings: Vec<&ReportFinding> = findings
            .iter()
            .filter(|f| !is_dependency(&f.file))
            .copied()
            .collect();
        let group_tpl = load_template("findings-group.html");

        let business_html =
            render_by_category(&business_findings, severity, report_locale, rule_catalog)
                .unwrap_or_else(|| {
                    format!(
                        r#"<p class="empty-group">{}</p>"#,
                        t(report_locale, "no_issues_business")
                    )
                });
        let business_group = group_tpl
            .replace("{{icon}}", "📦")
            .replace("{{title}}", &t(report_locale, "stats.business_code"))
            .replace("{{count}}", &business_findings.len().to_string())
            .replace("{{content}}", &business_html);

        let deps_html = render_by_category(&deps_findings, severity, report_locale, rule_catalog)
            .unwrap_or_else(|| {
                format!(
                    r#"<p class="empty-group">{}</p>"#,
                    t(report_locale, "no_issues_deps")
                )
            });
        let deps_group = group_tpl
            .replace("{{icon}}", "🔗")
            .replace("{{title}}", &t(report_locale, "stats.dependencies"))
            .replace("{{count}}", &deps_findings.len().to_string())
            .replace("{{content}}", &deps_html);

        format!("{business_group}{deps_group}")
    } else {
        format!(
            r#"<p class="empty-section">✅ {}</p>"#,
            t(report_locale, "no_issues_category")
        )
    };

    load_template("severity-section.html")
        .replace("{{severity_class}}", &severity.to_lowercase())
        .replace("{{severity_id}}", &format!("section-{severity}"))
        .replace("{{icon}}", icon)
        .replace("{{severity}}", &title)
        .replace("{{count}}", &findings.len().to_string())
        .replace("{{issues_label}}", &t(report_locale, "issues_count_label"))
        .replace("{{content}}", &findings_html)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;

    fn finding(category: &str, rule_key: &str, rule_name: &str, file: &str) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_name: rule_name.to_string(),
            category: category.to_string(),
            severity: "HIGH".to_string(),
            risk: "Risque de test".to_string(),
            file: file.to_string(),
            line: 42,
            solution: Some("Solution de test".to_string()),
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: "cursor.execute(query)".to_string(),
            context_before: "line1\nline2".to_string(),
            context_after: "line3".to_string(),
            confidence: 90,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
        }
    }

    /// ADR-0037 (#143/#144): each rule origin gets its own badge —
    /// official CodeFixture pack, client rule, builtin catalog.
    #[test]
    fn test_render_finding_item_badge_per_rule_source() {
        let en = load_report_locale("en");
        let render = |source: &str| {
            let mut f = finding("SECURITY", "r", "R", "app.py");
            f.rule_source = source.to_string();
            render_finding_item(&f, "HIGH", &en)
        };
        let official = render("json_official");
        let client = render("json_custom");
        let builtin = render("json_builtin");
        assert!(official.contains("✅ Official"), "{official}");
        assert!(client.contains("finding-badge-custom"), "{client}");
        assert!(builtin.contains("🛡️ Builtin") && !builtin.contains("Official"));
    }

    #[test]
    fn test_render_taint_trace_uses_real_source_kind() {
        use crate::report::exports::sarif::TaintFlow;
        let en = load_report_locale("en");
        let mut f = finding("SECURITY", "taint_rce", "RCE", "app.py");
        f.taint_flow = Some(TaintFlow {
            rule_key: "taint_rce".to_string(),
            source_file: "app.py".to_string(),
            source_line: 5,
            source_expr: "request.args.get('cmd')".to_string(),
            chain: vec![],
            sink_file: "app.py".to_string(),
            sink_line: 10,
            sink_expr: "os.system(cmd)".to_string(),
            source_kind: "http".to_string(),
        });
        let html = render_taint_trace(&f, &en);
        assert!(html.contains(&t(&en, "taint_kind_http")));
    }

    #[test]
    fn test_render_taint_trace_falls_back_to_network_when_source_kind_empty() {
        use crate::report::exports::sarif::TaintFlow;
        let en = load_report_locale("en");
        let mut f = finding("SECURITY", "taint_rce", "RCE", "app.py");
        f.taint_flow = Some(TaintFlow {
            rule_key: "taint_rce".to_string(),
            source_file: "app.py".to_string(),
            source_line: 5,
            source_expr: "x".to_string(),
            chain: vec![],
            sink_file: "app.py".to_string(),
            sink_line: 10,
            sink_expr: "y".to_string(),
            source_kind: String::new(),
        });
        let html = render_taint_trace(&f, &en);
        assert!(html.contains(&t(&en, "taint_kind_network")));
    }

    #[test]
    fn test_render_file_check_explanation_shows_has_and_not_has() {
        use serde_json::json;
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        catalog.insert(
            "missing_csp_header".to_string(),
            json!({
                "id": "missing_csp_header",
                "file_contains": {
                    "has": ["(?:Flask\\s*\\(\\s*__name__|@app\\.route)"],
                    "not_has": ["(?:Talisman|content_security_policy|CSP)"],
                },
            }),
        );
        let html = render_file_check_explanation(&catalog, "missing_csp_header", &en);
        assert!(html.contains("Why this was detected"));
        assert!(html.contains("whole-file check"));
        assert!(html.contains("Flask"));
        assert!(html.contains("Talisman"));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn test_render_file_check_explanation_empty_without_file_contains() {
        use serde_json::json;
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        catalog.insert("taint_sqli".to_string(), json!({"id": "taint_sqli"}));
        let html = render_file_check_explanation(&catalog, "taint_sqli", &en);
        assert!(html.is_empty());
    }

    #[test]
    fn test_render_file_check_explanation_empty_unknown_rule() {
        let en = load_report_locale("en");
        let html = render_file_check_explanation(&BTreeMap::new(), "unknown_rule", &en);
        assert!(html.is_empty());
    }

    #[test]
    fn test_render_finding_item_contains_core_fields() {
        let en = load_report_locale("en");
        let f = finding(
            "SECURITY",
            "sql_injection_fstring",
            "SQL Injection",
            "src/app.py",
        );
        let html = render_finding_item(&f, "HIGH", &en);
        assert!(html.contains("SQL Injection"));
        assert!(html.contains("src/app.py"));
        assert!(html.contains('🛡')); // category icon SECURITY
        assert!(html.contains("cursor.execute(query)"));
        assert!(html.contains("finding-code-context"));
        assert!(html.contains("finding-badge-builtin"));
    }

    #[test]
    fn test_render_finding_item_no_taint_class_when_no_flow() {
        let en = load_report_locale("en");
        let f = finding("SECURITY", "r1", "Rule", "a.py");
        let html = render_finding_item(&f, "HIGH", &en);
        assert!(!html.contains("has-taint"));
        assert!(!html.contains("finding-badge-taint"));
    }

    #[test]
    fn test_render_findings_groups_by_rule_shows_risk_solution() {
        let en = load_report_locale("en");
        let f1 = finding("SECURITY", "r1", "Rule One", "a.py");
        let f2 = finding("SECURITY", "r1", "Rule One", "b.py");
        let refs = [&f1, &f2];
        let catalog = BTreeMap::new();
        let html = render_findings(&refs, "HIGH", &en, &catalog);
        assert_eq!(html.matches("class=\"rule-group\"").count(), 1); // a single group (same rule_key)
        assert!(html.contains("Risque de test"));
        assert!(html.contains("Solution de test"));
        assert!(html.contains(r#"class="rule-group-badge">2<"#));
    }

    #[test]
    fn test_render_by_category_groups_and_orders() {
        let en = load_report_locale("en");
        let sec = finding("SECURITY", "r1", "Rule Sec", "a.py");
        let arch = finding("ARCH", "r2", "Rule Arch", "b.py");
        let refs = [&arch, &sec]; // input order is the reverse of CATEGORY_ORDER
        let catalog = BTreeMap::new();
        let html = render_by_category(&refs, "HIGH", &en, &catalog).unwrap();
        let sec_pos = html.find("Rule Sec").unwrap();
        let arch_pos = html.find("Rule Arch").unwrap();
        assert!(
            sec_pos < arch_pos,
            "SECURITY doit precede ARCH (CATEGORY_ORDER)"
        );
    }

    #[test]
    fn test_render_by_category_empty_is_none() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        assert!(render_by_category(&[], "HIGH", &en, &catalog).is_none());
    }

    #[test]
    fn test_render_severity_section_empty_shows_no_issues() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let html = render_severity_section("CRITICAL", &[], &en, &catalog);
        assert!(html.contains("empty-section"));
        assert!(html.contains("section-CRITICAL"));
        assert!(html.contains('0'));
    }

    #[test]
    fn test_render_severity_section_splits_business_vs_deps() {
        let en = load_report_locale("en");
        let business = finding("SECURITY", "r1", "Rule", "src/app.py");
        let dep = finding("SECURITY", "r1", "Rule", "app/vendor/lib.py");
        let refs = [&business, &dep];
        let catalog = BTreeMap::new();
        let html = render_severity_section("HIGH", &refs, &en, &catalog);
        assert!(html.contains(&t(&en, "stats.business_code")));
        assert!(html.contains(&t(&en, "stats.dependencies")));
    }

    #[test]
    fn test_generate_fix_suggestion_empty_without_rule_data() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        assert_eq!(generate_fix_suggestion(&catalog, "no_such_rule", &en), "");
    }

    #[test]
    fn test_generate_fix_suggestion_with_fix_before_after() {
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        catalog.insert(
            "r1".to_string(),
            serde_json::json!({"fix_before": "eval(x)", "fix_after": "ast.literal_eval(x)"}),
        );
        let html = generate_fix_suggestion(&catalog, "r1", &en);
        assert!(html.contains("eval(x)"));
        assert!(html.contains("ast.literal_eval(x)"));
        assert!(html.contains("taint-fix"));
    }
}
