//! Final assembly of the HTML report — port of `_generate_html`
//! (`Audit/sca/report.py`) and its small companion helpers
//! (`_get_language_severity_data`, `_get_taint_chart_data`,
//! glossary, custom rules section).
//!
//! **Sections not wired in (product decision, not a bug)**: detailed
//! tests/fixtures/dependencies/database — computed in `ScanReport`
//! (`test_results`/`dependency_stats`/`database_stats`) but
//! deliberately not rendered in the HTML report; explicit decision by
//! the maintainer on 2026-08-25 not to wire in this display. SLA (config not
//! modeled) and git blame also remain unported. Baseline comparison
//! (`comparison.py`) IS wired in (`comparison: Option<&ComparisonResult>`
//! parameter of `generate_html`), as are the representative examples
//! per category (`_generate_category_examples_html`, see
//! `category_examples.rs`) and the audit parameters
//! (`_generate_audit_params_summary`, `audit_params:
//! Option<&audit_params::AuditParamsInfo>` parameter of
//! `generate_html`, see `audit_params.rs`).
//! All these sections use exactly the same default values as Python
//! when the corresponding feature is absent/disabled (`display:none`,
//! empty lists) — a real Python scan without
//! `--with-tests`/`--with-deps`/DB config produces the same rendering
//! for these blocks.

use std::collections::BTreeMap;

use fancy_regex::Regex;
use serde_json::{Value, json};

use crate::i18n::t;
use crate::report::compliance::{
    AsvsCompliance, Iso27001Compliance, NistCsfCompliance, compute_asvs_compliance,
    compute_iso27001_compliance, compute_nist_csf_compliance, load_rule_referential_scope,
};
use crate::report::compliance_html::{
    HealthThresholds, generate_asvs_html, generate_compliance_html, generate_nist_csf_html,
};
use crate::report::data::{ReportData, compute_report_data};
use crate::report::exports::sarif::ReportFinding;
use crate::report::findings_html::render_severity_section;
use crate::report::report_assets::{
    asset_data_uri, load_asset, load_template, load_vendor_chart_js,
};
use crate::report::summary_html::{
    build_exec_recommendations, build_exec_trend, build_threat_context, render_heatmap,
};
use crate::report::text::{escape, lang_label};

/// Inputs that can't be derived from the findings — project/tool
/// identity, timestamp, display thresholds. Everything else
/// (compliance, health score, stats) is recomputed from `findings`.
pub struct ReportContext<'a> {
    pub project_name: String,
    pub project_version: String,
    pub project_uuid: String,
    pub project_description: String,
    pub project_path: String,
    pub tool_name: String,
    pub tool_version: String,
    pub company_name: String,
    pub report_lang: String,
    pub date_str: String,
    pub timestamp: String,
    pub audit_total_time_secs: u64,
    pub total_lines_code: usize,
    pub total_files_scanned: usize,
    pub health_thresholds: HealthThresholds,
    pub rule_catalog: &'a BTreeMap<String, Value>,
}

fn category_severity_matrix(
    findings: &[ReportFinding],
) -> BTreeMap<String, BTreeMap<&'static str, usize>> {
    let mut matrix: BTreeMap<String, BTreeMap<&'static str, usize>> = BTreeMap::new();
    for f in findings {
        let lang = lang_label(&f.file);
        let lang = if lang.is_empty() { "Other" } else { lang };
        let entry = matrix.entry(lang.to_string()).or_insert_with(|| {
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                .iter()
                .map(|s| (*s, 0))
                .collect()
        });
        let sev = f.severity.to_uppercase();
        if let Some(c) = entry.get_mut(sev.as_str()) {
            *c += 1;
        }
    }
    matrix
}

/// Breakdown of findings by language × severity — port of
/// `_get_language_severity_data`.
fn language_severity_data(findings: &[ReportFinding]) -> Value {
    let matrix = category_severity_matrix(findings);
    let mut entries: Vec<(&String, &BTreeMap<&'static str, usize>)> = matrix.iter().collect();
    entries.sort_by_key(|(_, sevs)| std::cmp::Reverse(sevs.values().sum::<usize>()));
    let map: serde_json::Map<String, Value> = entries
        .into_iter()
        .map(|(lang, sevs)| (lang.clone(), json!(sevs)))
        .collect();
    Value::Object(map)
}

/// Taint chart data — port of `_get_taint_chart_data`.
/// `builtin_loaded`/`custom_loaded`: `_rule_engine_stats` doesn't
/// exist on the AuditRust side — approximated by the size of the
/// loaded rule catalog (no builtin/custom distinction, see
/// `rule_source` always `"json_builtin"`).
fn taint_chart_data(findings: &[ReportFinding], rule_catalog: &BTreeMap<String, Value>) -> Value {
    let taint_findings: Vec<&ReportFinding> =
        findings.iter().filter(|f| f.taint_flow.is_some()).collect();
    let mut by_rule: serde_json::Map<String, Value> = serde_json::Map::new();
    for f in &taint_findings {
        let c = by_rule
            .get(&f.rule_key)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        by_rule.insert(f.rule_key.clone(), json!(c + 1));
    }
    let mut by_source = serde_json::Map::new();
    by_source.insert("python".to_string(), json!(0));
    by_source.insert("json_builtin".to_string(), json!(0));
    by_source.insert("json_custom".to_string(), json!(0));
    for f in findings {
        if let Some(c) = by_source.get(&f.rule_source).and_then(|v| v.as_u64()) {
            by_source.insert(f.rule_source.clone(), json!(c + 1));
        }
    }
    json!({
        "enabled": !taint_findings.is_empty(),
        "totalFlows": taint_findings.len(),
        "byRule": by_rule,
        "bySource": by_source,
        "builtin_loaded": rule_catalog.len(),
        "custom_loaded": 0,
    })
}

fn compliance_chart_data(data: &Iso27001Compliance) -> Value {
    let themes: serde_json::Map<String, Value> = data
        .themes
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                json!({"covered": v.covered, "total": v.total, "withFindings": v.with_findings, "findingCount": v.finding_count}),
            )
        })
        .collect();
    json!({
        "enabled": true,
        "total": data.total_controls,
        "covered": data.covered_controls,
        "withFindings": data.with_findings,
        "notCovered": data.total_controls - data.covered_controls,
        "coveragePct": data.coverage_pct,
        "themes": themes,
    })
}

fn asvs_chart_data(data: &AsvsCompliance) -> Value {
    let chapters: serde_json::Map<String, Value> = data
        .chapters
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                json!({"covered": v.covered, "total": v.total, "withFindings": v.with_findings, "findingCount": v.finding_count}),
            )
        })
        .collect();
    let levels: serde_json::Map<String, Value> = data
        .levels
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                json!({"total": v.total, "covered": v.covered, "coverage_pct": v.coverage_pct}),
            )
        })
        .collect();
    json!({
        "enabled": true,
        "total": data.total_requirements,
        "covered": data.covered_requirements,
        "withFindings": data.with_findings,
        "notCovered": data.total_requirements - data.covered_requirements,
        "coveragePct": data.coverage_pct,
        "chapters": chapters,
        "levels": levels,
    })
}

fn nist_chart_data(data: &NistCsfCompliance) -> Value {
    let functions: serde_json::Map<String, Value> = data
        .by_function
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                json!({"name": v.name, "covered": v.covered, "total": v.total, "withFindings": v.with_findings, "findingCount": v.finding_count}),
            )
        })
        .collect();
    json!({
        "enabled": true,
        "total": data.total_subcategories,
        "covered": data.covered_subcategories,
        "withFindings": data.with_findings,
        "notCovered": data.total_subcategories - data.covered_subcategories,
        "coveragePct": data.coverage_pct,
        "functions": functions,
    })
}

const CATEGORY_I18N_KEYS: [(&str, &str); 8] = [
    ("SECURITY", "security"),
    ("ARCH", "architecture"),
    ("UI", "ui"),
    ("UX", "ux"),
    ("MAINTENANCE", "maintenance"),
    ("DEPENDENCIES", "dependencies"),
    ("DATABASE", "database"),
    ("CICD", "cicd"),
];

/// The 3 already-computed compliance matrices + the composite score —
/// grouped together so the parameter count doesn't blow up in the
/// functions that consume them together.
struct ComplianceResults<'a> {
    iso27001: &'a Iso27001Compliance,
    asvs: &'a AsvsCompliance,
    nist: &'a NistCsfCompliance,
    score: f64,
}

fn build_chart_data(
    report_locale: &Value,
    data: &ReportData,
    findings: &[ReportFinding],
    rule_catalog: &BTreeMap<String, Value>,
    compliance: &ComplianceResults,
) -> Value {
    let (compliance, asvs, nist, compliance_score) = (
        compliance.iso27001,
        compliance.asvs,
        compliance.nist,
        compliance.score,
    );
    let mut categories = serde_json::Map::new();
    let mut category_key_map = serde_json::Map::new();
    for (cat_key, stats) in &data.by_category {
        let i18n_key = CATEGORY_I18N_KEYS
            .iter()
            .find(|(k, _)| k == cat_key)
            .map(|(_, v)| *v)
            .unwrap_or(cat_key.as_str());
        let title = t(report_locale, &format!("category_titles.{i18n_key}"));
        categories.insert(title.clone(), json!(stats.total));
        category_key_map.insert(title, json!(cat_key));
    }

    let standards = vec![
        json!({"key": "iso27001", "label": "ISO 27001", "pct": compliance.coverage_pct}),
        json!({"key": "asvs", "label": "OWASP ASVS", "pct": asvs.coverage_pct}),
        json!({"key": "nist", "label": "NIST CSF", "pct": nist.coverage_pct}),
    ];

    let health_severity: serde_json::Map<String, Value> = data
        .health_severity_detail
        .iter()
        .map(|(sev, d)| {
            (
                sev.to_string(),
                json!({
                    "label": t(report_locale, &format!("severity.{}", sev.to_lowercase())),
                    "count": d.count,
                    "penaltyEach": d.penalty_each,
                    "penaltyTotal": d.penalty_total,
                }),
            )
        })
        .collect();

    json!({
        "severity": {"CRITICAL": data.total_critical, "HIGH": data.total_high, "MEDIUM": data.total_medium, "LOW": data.total_low, "INFO": data.total_info},
        "categories": categories,
        "categoryKeyMap": category_key_map,
        "codeVsDeps": {"business": data.total_business, "deps": data.total_deps},
        "healthScore": data.health_score,
        "tests": {"passed": 0, "failed": 0, "errors": 0, "skipped": 0, "successRate": 0},
        "fixtures": {"truePositives": 0, "trueNegatives": 0, "falseNegatives": 0, "falsePositives": 0, "successRate": 0},
        "dependencies": {"enabled": false, "vulnerable": 0, "unpinned": 0, "ok": 0, "total": 0},
        "database": {"enabled": false, "tables": 0, "columns": 0, "indexes": 0, "enums": 0,
                      "changes": {"added": {"tables": 0, "columns": 0, "indexes": 0}, "dropped": {"tables": 0, "columns": 0, "indexes": 0}, "modified": {"columns": 0}}},
        "compliance": compliance_chart_data(compliance),
        "asvs": asvs_chart_data(asvs),
        "nist": nist_chart_data(nist),
        "complianceScore": {"enabled": true, "score": compliance_score, "standards": standards},
        "healthPenalty": data.total_penalty,
        "healthSeverity": health_severity,
        "history": {"labels": [], "high": [], "medium": [], "low": [], "testsRate": [], "testsPassed": [], "testsFailed": [], "dbTables": [], "dbColumns": [], "dbChanges": []},
        "i18n": chart_i18n_labels(report_locale),
        "taint": taint_chart_data(findings, rule_catalog),
        "languageSeverity": language_severity_data(findings),
    })
}

/// (JS key, `chart_labels.<key>` key) — `json!({...})` over ~50 pairs
/// exceeds the macro's default recursion limit, hence this
/// loop-driven table instead of one giant literal.
const CHART_LABEL_KEYS: [(&str, &str); 46] = [
    ("critical", "critical"),
    ("high", "high"),
    ("medium", "medium"),
    ("low", "low"),
    ("info", "info"),
    ("issues", "issues"),
    ("businessCode", "business_code"),
    ("dependencies", "dependencies"),
    ("total", "total"),
    ("passed", "passed"),
    ("failed", "failed"),
    ("errors", "errors"),
    ("skipped", "skipped"),
    ("success", "success"),
    ("validated", "validated"),
    ("tables", "tables"),
    ("columns", "columns"),
    ("indexes", "indexes"),
    ("additions", "additions"),
    ("deletions", "deletions"),
    ("stable", "stable"),
    ("successRate", "success_rate"),
    ("testsPassed", "tests_passed"),
    ("rate", "rate"),
    ("count", "count"),
    ("structure", "structure"),
    ("changes", "changes"),
    ("vulnerable", "vulnerable"),
    ("unpinned", "unpinned"),
    ("depsOk", "deps_ok"),
    ("scanned", "scanned"),
    ("complianceCoverage", "compliance_coverage"),
    ("complianceCovered", "compliance_covered"),
    ("complianceFindings", "compliance_findings"),
    ("complianceNotCovered", "compliance_not_covered"),
    ("complianceCoverageChart", "compliance_coverage_chart"),
    ("complianceThemeChart", "compliance_theme_chart"),
    ("complianceStatusChart", "compliance_status_chart"),
    (
        "complianceTheme_organizational",
        "compliance_theme_organizational",
    ),
    ("complianceTheme_people", "compliance_theme_people"),
    ("complianceTheme_physical", "compliance_theme_physical"),
    (
        "complianceTheme_technological",
        "compliance_theme_technological",
    ),
    ("asvsCoverage", "asvs_coverage"),
    ("asvsCovered", "asvs_covered"),
    ("asvsFindings", "asvs_findings"),
    ("asvsNotCovered", "asvs_not_covered"),
];
const CHART_LABEL_KEYS_2: [(&str, &str); 11] = [
    ("asvsCoverageChart", "asvs_coverage_chart"),
    ("asvsChapterChart", "asvs_chapter_chart"),
    ("asvsStatusChart", "asvs_status_chart"),
    ("nistCoverage", "nist_coverage"),
    ("nistCovered", "nist_covered"),
    ("nistFindings", "nist_findings"),
    ("nistNotCovered", "nist_not_covered"),
    ("nistCoverageChart", "nist_coverage_chart"),
    ("nistFunctionChart", "nist_function_chart"),
    ("nistStatusChart", "nist_status_chart"),
    ("findingsByLangSeverity", "findings_by_lang_severity"),
];

fn chart_i18n_labels(v: &Value) -> Value {
    let mut map = serde_json::Map::new();
    for (js_key, locale_key) in CHART_LABEL_KEYS.iter().chain(CHART_LABEL_KEYS_2.iter()) {
        map.insert(
            (*js_key).to_string(),
            json!(t(v, &format!("chart_labels.{locale_key}"))),
        );
    }
    map.insert(
        "complianceCoverageBar".to_string(),
        json!(t(v, "chart_labels.compliance_coverage_bar")),
    );
    map.insert(
        "healthPenalty".to_string(),
        json!(t(v, "chart_labels.health_penalty")),
    );
    map.insert(
        "healthSeverityChart".to_string(),
        json!(t(v, "chart_labels.health_severity_chart")),
    );
    map.insert("taintFlows".to_string(), json!(t(v, "taint_trace_summary")));
    map.insert(
        "taintEntryPoint".to_string(),
        json!(t(v, "taint_entry_point")),
    );
    map.insert(
        "taintImpactPoint".to_string(),
        json!(t(v, "taint_impact_point")),
    );
    map.insert("taintByRule".to_string(), json!("Flows par règle"));
    map.insert("taintPython".to_string(), json!("Python"));
    map.insert("taintBuiltin".to_string(), json!("Builtin"));
    map.insert("taintCustom".to_string(), json!("Custom"));
    Value::Object(map)
}

fn render_glossary_html(report_locale: &Value) -> (String, String) {
    let glossary = crate::i18n::get_nested(report_locale, "glossary");
    let title = glossary
        .and_then(|g| g.get("title"))
        .and_then(|v| v.as_str())
        .unwrap_or("Glossary")
        .to_string();
    let Some(Value::Object(acronyms)) = glossary.and_then(|g| g.get("acronyms")) else {
        return (String::new(), title);
    };
    if acronyms.is_empty() {
        return (String::new(), title);
    }
    let col_acr = glossary
        .and_then(|g| g.get("col_acronym"))
        .and_then(|v| v.as_str())
        .unwrap_or("Acronym");
    let col_mean = glossary
        .and_then(|g| g.get("col_meaning"))
        .and_then(|v| v.as_str())
        .unwrap_or("Meaning");
    let col_desc = glossary
        .and_then(|g| g.get("col_description"))
        .and_then(|v| v.as_str())
        .unwrap_or("Description");
    let mut keys: Vec<&String> = acronyms.keys().collect();
    keys.sort();
    let rows: String = keys
        .into_iter()
        .map(|key| {
            let acr = &acronyms[key];
            let term = acr.get("term").and_then(|v| v.as_str()).unwrap_or("");
            let full = acr.get("full").and_then(|v| v.as_str()).unwrap_or("");
            let desc = acr.get("desc").and_then(|v| v.as_str()).unwrap_or("");
            format!(
                r#"<tr id="acr-{key}"><td class="glossary-term"><strong>{term}</strong></td><td class="glossary-full">{full}</td><td class="glossary-desc">{desc}</td></tr>"#
            )
        })
        .collect();
    let html = format!(
        r#"<!-- GLOSSARY_NO_LINKIFY --><table class="glossary-table"><thead><tr><th>{col_acr}</th><th>{col_mean}</th><th>{col_desc}</th></tr></thead><tbody>{rows}</tbody></table><!-- /GLOSSARY_NO_LINKIFY -->"#
    );
    (html, title)
}

/// "Custom rules" section — empty state only: AuditRust does not yet
/// distinguish builtin/custom (`ScanConfig` has only one
/// `rules_dir`), so `custom_rules` is always empty, like a real
/// Python scan with no `json_custom` rule loaded.
fn render_custom_rules_section(report_locale: &Value) -> String {
    let body = format!(
        r#"<div class="custom-rules-empty"><div class="custom-rules-empty-icon">📜</div><p class="custom-rules-empty-title">{}</p><p class="custom-rules-empty-desc">{}</p><code class="custom-rules-cmd">./run_audit.py . --create-rule</code></div>"#,
        t(report_locale, "custom_rules_none"),
        t(report_locale, "custom_rules_none_desc"),
    );
    load_template("custom-rules-section.html")
        .replace(
            "{{i18n_custom_rules_nav}}",
            &t(report_locale, "custom_rules_nav"),
        )
        .replace("{{i18n_toc}}", &t(report_locale, "toc"))
        .replace(
            "{{custom_rules_count_badge}}",
            r#"<span class="badge badge-neutral">0</span>"#,
        )
        .replace("{{custom_rules_body}}", &body)
}

/// Removes `<!--DEV_ONLY_DB-->...<!--/DEV_ONLY_DB-->` blocks — in the
/// compiled Python binary, this removal only happens in compiled mode
/// (`_check_is_binary()`); AuditRust is *always* a compiled binary,
/// so it is always applied, unconditionally.
fn remove_dev_only_db_blocks(html: &str) -> String {
    let re = Regex::new(r"(?s)<!--DEV_ONLY_DB-->.*?<!--/DEV_ONLY_DB-->")
        .expect("valid DEV_ONLY_DB pattern");
    re.replace_all(html, "").into_owned()
}

fn keep_block(html: &str, prefix: &str) -> String {
    html.replace(&format!("{{{{{prefix}_TOC_START}}}}"), "")
        .replace(&format!("{{{{{prefix}_TOC_END}}}}"), "")
        .replace(&format!("{{{{{prefix}_NAV_START}}}}"), "")
        .replace(&format!("{{{{{prefix}_NAV_END}}}}"), "")
        .replace(&format!("{{{{{prefix}_SECTION_START}}}}"), "")
        .replace(&format!("{{{{{prefix}_SECTION_END}}}}"), "")
}

/// Generates the full HTML report — port of `_generate_html`.
/// `comparison`: result of `comparison::compare_with_baseline`
/// against the last scan, `None` if this is the first audit (no
/// baseline available).
pub fn generate_html(
    findings: &[ReportFinding],
    ctx: &ReportContext,
    comparison: Option<&crate::report::comparison::ComparisonResult>,
    audit_params: Option<&crate::report::audit_params::AuditParamsInfo>,
    test_results: Option<&crate::project::testing::TestResults>,
) -> String {
    let report_locale = crate::i18n::load_report_locale(&ctx.report_lang);
    let data = compute_report_data(findings, ctx.total_lines_code);
    // Computed here (not in `compute_report_data`): needs the report
    // language and the rule catalog, both only available at HTML
    // render time on the Rust side — see the module doc of
    // `report::successes`.
    let successes = crate::report::successes::compute_successes(
        findings,
        ctx.rule_catalog,
        test_results,
        &report_locale,
        &ctx.report_lang,
    );
    let total_successes: usize = successes.values().map(|v| v.len()).sum();

    let scope = load_rule_referential_scope();
    let compliance = compute_iso27001_compliance(findings, &scope);
    let asvs = compute_asvs_compliance(findings, &scope);
    let nist = compute_nist_csf_compliance(findings, &scope);
    let compliance_pcts = [
        compliance.coverage_pct,
        asvs.coverage_pct,
        nist.coverage_pct,
    ];
    let compliance_score =
        (compliance_pcts.iter().sum::<i64>() as f64 / compliance_pcts.len() as f64 * 10.0).round()
            / 10.0;
    let compliance_results = ComplianceResults {
        iso27001: &compliance,
        asvs: &asvs,
        nist: &nist,
        score: compliance_score,
    };

    let chart_data = build_chart_data(
        &report_locale,
        &data,
        findings,
        ctx.rule_catalog,
        &compliance_results,
    );
    let charts_js = load_asset("charts.js").replace("{{CHART_DATA}}", &chart_data.to_string());

    let favicon_data = asset_data_uri("favicon.svg", "image/svg+xml").unwrap_or_default();
    let favicon_header_data =
        asset_data_uri("favicon-white.svg", "image/svg+xml").unwrap_or_default();

    let sections_html: String = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        .iter()
        .map(|sev| {
            render_severity_section(
                sev,
                &data.by_severity[sev],
                &report_locale,
                ctx.rule_catalog,
            )
        })
        .collect();

    let health_class = if data.health_score >= ctx.health_thresholds.good {
        "good"
    } else if data.health_score >= ctx.health_thresholds.warning {
        "warning"
    } else {
        "danger"
    };
    let compliance_class = if compliance_score as i64 >= ctx.health_thresholds.good {
        "good"
    } else if compliance_score as i64 >= ctx.health_thresholds.warning {
        "warning"
    } else {
        "danger"
    };
    let score_legend = t(&report_locale, "score_legend")
        .replace("{good}", &ctx.health_thresholds.good.to_string())
        .replace("{warning}", &ctx.health_thresholds.warning.to_string());
    let health_method = t(&report_locale, "health_method");
    let health_heading = t(&report_locale, "health_explanation_heading")
        .replace("{label}", &t(&report_locale, "health_score"));
    let health_explanation_html = format!(
        r#"<div class="health-explanation"><h4 class="health-explanation-title">ℹ️ {health_heading}</h4><p class="health-method">{health_method}</p></div>"#
    );

    let (glossary_html, glossary_title) = render_glossary_html(&report_locale);

    let mut html = load_template("report-base.html").to_string();

    // --- i18n / fixed labels -------------------------------------------
    for (placeholder, key) in [
        ("{{i18n_navigation}}", "navigation"),
        ("{{i18n_level_executive}}", "level_executive"),
        ("{{i18n_health_score}}", "health_score"),
        ("{{i18n_visualization}}", "visualization"),
        ("{{i18n_summary}}", "summary"),
        ("{{i18n_level_detail}}", "level_detail"),
        ("{{i18n_parameters}}", "parameters"),
        ("{{i18n_top_files_nav}}", "top_files_nav"),
        ("{{i18n_comparison}}", "comparison"),
        ("{{i18n_findings}}", "findings"),
        ("{{i18n_custom_rules_nav}}", "custom_rules_nav"),
        ("{{i18n_fixtures_nav}}", "fixtures_nav"),
        (
            "{{i18n_dependencies_title}}",
            "category_titles.dependencies",
        ),
        ("{{i18n_database_schema}}", "database_schema"),
        ("{{i18n_sla_title}}", "sla.title"),
        ("{{i18n_git_blame_title}}", "git_blame_section_title"),
        ("{{i18n_validations}}", "validations"),
        ("{{i18n_validations_intro}}", "validations_intro"),
        ("{{i18n_toc}}", "toc"),
        ("{{i18n_print_version}}", "print_version"),
        ("{{i18n_generated_on}}", "generated_on"),
        ("{{i18n_files_scanned}}", "files_scanned"),
        ("{{i18n_lines_of_code}}", "lines_of_code"),
        ("{{i18n_severity_distribution}}", "severity_distribution"),
        (
            "{{i18n_severity_distribution_subtitle}}",
            "severity_distribution_subtitle",
        ),
        ("{{i18n_by_category}}", "by_category"),
        ("{{i18n_by_category_subtitle}}", "by_category_subtitle"),
        (
            "{{i18n_findings_by_lang_severity}}",
            "chart_labels.findings_by_lang_severity",
        ),
        ("{{i18n_code_vs_deps}}", "code_vs_deps"),
        ("{{i18n_tests}}", "tests"),
        ("{{i18n_fixtures}}", "fixtures"),
        ("{{i18n_findings_evolution}}", "findings_evolution"),
        ("{{i18n_tests_evolution}}", "tests_evolution"),
        (
            "{{i18n_chart_subtitle_findings}}",
            "chart_subtitles.findings_history",
        ),
        (
            "{{i18n_chart_subtitle_tests}}",
            "chart_subtitles.tests_history",
        ),
        ("{{i18n_database_evolution}}", "database_evolution"),
        (
            "{{i18n_chart_subtitle_database}}",
            "chart_subtitles.database_history",
        ),
        ("{{i18n_exec_trend}}", "exec_trend"),
        ("{{i18n_exec_recommendations}}", "exec_recommendations"),
        ("{{i18n_severity_high}}", "severity.high"),
        ("{{i18n_severity_medium}}", "severity.medium"),
        ("{{i18n_severity_low}}", "severity.low"),
        ("{{i18n_severity_info}}", "severity.info"),
        ("{{i18n_business_code}}", "stats.business_code"),
        ("{{i18n_dependencies}}", "stats.dependencies"),
        ("{{i18n_audit_duration}}", "audit_duration"),
        ("{{i18n_top_files}}", "top_files"),
        ("{{i18n_top_files_subtitle}}", "top_files_subtitle"),
        ("{{i18n_deps_scanned}}", "deps_scanned"),
        ("{{i18n_deps_vulnerable}}", "deps_vulnerable"),
        ("{{i18n_deps_unpinned}}", "deps_unpinned"),
        ("{{i18n_deps_ok}}", "deps_ok"),
        ("{{i18n_tables}}", "stats.tables"),
        ("{{i18n_columns}}", "stats.columns"),
        ("{{i18n_indexes}}", "stats.indexes"),
        ("{{i18n_enums}}", "stats.enums"),
        ("{{i18n_additions}}", "stats.additions"),
        ("{{i18n_deletions}}", "stats.deletions"),
        ("{{i18n_modified}}", "stats.modified"),
        ("{{i18n_stability}}", "stats.stability"),
        ("{{i18n_taint_trace_summary}}", "taint_trace_summary"),
        ("{{i18n_glossary_subtitle}}", "glossary.subtitle"),
        ("{{i18n_suppress_download}}", "suppress_download"),
        ("{{i18n_suppress_copy}}", "suppress_copy"),
        ("{{i18n_suppress_clear}}", "suppress_clear"),
    ] {
        html = html.replace(placeholder, &t(&report_locale, key));
    }

    html = html.replace(
        "{{i18n_title}}",
        &format!("{} — {}", ctx.tool_name, t(&report_locale, "title")),
    );
    html = html.replace("{{i18n_glossary_title}}", &glossary_title);
    html = html.replace(
        "{{i18n_compliance_title}}",
        &t(&report_locale, "compliance.title"),
    );
    html = html.replace("{{i18n_asvs_title}}", &t(&report_locale, "asvs.title"));
    html = html.replace("{{i18n_nist_title}}", &t(&report_locale, "nist.title"));
    html = html.replace(
        "{{i18n_compliance_score}}",
        &t(&report_locale, "compliance_score"),
    );

    // --- identity / branding --------------------------------------------
    html = html.replace("{{lang}}", &ctx.report_lang);
    html = html.replace("{{lang_label}}", &t(&report_locale, "lang_label"));
    html = html.replace("{{project_name}}", &escape(&ctx.project_name));
    html = html.replace("{{timestamp}}", &ctx.timestamp);
    html = html.replace("{{project_version}}", &escape(&ctx.project_version));
    html = html.replace("{{tool_version}}", &escape(&ctx.tool_version));
    let project_version_display = if ctx.project_version.is_empty() {
        String::new()
    } else {
        format!("v{} ", ctx.project_version)
    };
    html = html.replace("{{project_version_display}}", &project_version_display);
    html = html.replace("{{tool_name}}", &escape(&ctx.tool_name));
    html = html.replace("{{company_name}}", &escape(&ctx.company_name));
    html = html.replace("{{date_str}}", &ctx.date_str);
    html = html.replace(
        "{{audit_total_time}}",
        &ctx.audit_total_time_secs.to_string(),
    );
    html = html.replace("{{total_lines_code}}", &ctx.total_lines_code.to_string());
    html = html.replace(
        "{{total_files_scanned}}",
        &ctx.total_files_scanned.to_string(),
    );

    let project_uuid_badge = if !ctx.project_uuid.is_empty() {
        format!(
            r#"<span class="uuid-badge">[{}]</span> "#,
            &ctx.project_uuid[..ctx.project_uuid.len().min(8)]
        )
    } else {
        String::new()
    };
    html = html.replace("{{project_uuid_badge}}", &project_uuid_badge);
    let project_description_html = if !ctx.project_description.is_empty() {
        format!(
            r#"<div class="project-description">{}</div>"#,
            escape(&ctx.project_description)
        )
    } else {
        String::new()
    };
    html = html.replace("{{project_description_html}}", &project_description_html);

    // --- template placeholders of the Python demo mode, always empty ---
    html = html.replace("{{demo_body_class}}", "");
    html = html.replace("{{demo_display}}", "display:none");
    html = html.replace("{{demo_banner_text}}", "");
    html = html.replace("{{demo_watermark_text}}", "");
    html = html.replace("{{demo_footer_text}}", "");
    html = html.replace("{{severity_filter_banner}}", "");

    // --- assets ---------------------------------------------------------
    html = html.replace("{{css}}", load_asset("report.css"));
    html = html.replace("{{js}}", load_asset("report.js"));
    html = html.replace("{{charts_js}}", &charts_js);
    html = html.replace("{{chartjs_lib}}", load_vendor_chart_js());
    html = html.replace("{{favicon_data}}", &favicon_data);
    html = html.replace("{{favicon_header_data}}", &favicon_header_data);
    html = html.replace("{{favicon_type}}", "image/svg+xml");

    // --- health / compliance (bars + gauges) ----------------------------
    html = html.replace("{{health_score}}", &data.health_score.to_string());
    html = html.replace("{{health_class}}", health_class);
    html = html.replace("{{score_legend}}", &score_legend);
    html = html.replace("{{health_explanation_html}}", &health_explanation_html);
    html = html.replace("{{compliance_score}}", &format!("{compliance_score}"));
    html = html.replace("{{compliance_class}}", compliance_class);
    for marker in [
        "COMPLIANCE_SCORE_BAR_START",
        "COMPLIANCE_SCORE_BAR_END",
        "COMPLIANCE_SCORE_GAUGE_START",
        "COMPLIANCE_SCORE_GAUGE_END",
    ] {
        html = html.replace(&format!("{{{{{marker}}}}}"), "");
    }

    // --- executive summary -----------------------------------------------
    html = html.replace(
        "{{exec_trend_html}}",
        &build_exec_trend(comparison, &report_locale),
    );
    html = html.replace(
        "{{exec_recommendations_html}}",
        &build_exec_recommendations(
            findings,
            data.total_high,
            data.total_medium,
            data.health_score,
            &report_locale,
        ),
    );
    html = html.replace(
        "{{threat_context_html}}",
        &build_threat_context(data.total_high, data.total_medium, &report_locale),
    );

    // --- stats -----------------------------------------------------------
    html = html.replace("{{total_high}}", &data.total_high.to_string());
    html = html.replace("{{total_medium}}", &data.total_medium.to_string());
    html = html.replace("{{total_low}}", &data.total_low.to_string());
    html = html.replace("{{total_info}}", &data.total_info.to_string());
    html = html.replace("{{total_findings}}", &data.total_findings.to_string());
    html = html.replace("{{total_successes}}", &total_successes.to_string());
    html = html.replace("{{total_business}}", &data.total_business.to_string());
    html = html.replace("{{total_deps}}", &data.total_deps.to_string());
    // Tests/fixtures: never active until testing.py is ported.
    html = html.replace("{{tests_color}}", "");
    html = html.replace("{{tests_rate}}", "0");
    html = html.replace("{{tests_total}}", "0");
    html = html.replace("{{fixtures_color}}", "color-danger");
    html = html.replace("{{fixtures_rate}}", "0");
    html = html.replace("{{fixtures_total}}", "0");
    html = html.replace("{{tests_chart_display}}", "display:none");

    // --- parameters section / top files ----------------------------------
    let audit_params_html = audit_params
        .map(|info| {
            crate::report::audit_params::render_audit_params_html(info, ctx, &report_locale)
        })
        .unwrap_or_default();
    html = html.replace("{{audit_params_html}}", &audit_params_html);
    let heatmap_html = render_heatmap(&data.top_files, &report_locale);
    let heatmap_html = if heatmap_html.is_empty() {
        format!(
            r#"<p class="empty">{}</p>"#,
            t(&report_locale, "no_problematic_files")
        )
    } else {
        heatmap_html
    };
    html = html.replace("{{heatmap_html}}", &heatmap_html);

    // --- comparison ---------------------------------------------------------
    let comparison_html = comparison
        .map(|c| crate::report::comparison_html::render_comparison_html(c, &data, &report_locale))
        .unwrap_or_default();
    html = html.replace(
        "{{comparison_display}}",
        if comparison.is_some() {
            ""
        } else {
            "display:none"
        },
    );
    html = html.replace("{{comparison_html}}", &comparison_html);

    // --- examples per category -----------------------------------------------
    let category_examples_html = crate::report::category_examples::render_category_examples_html(
        findings,
        ctx.rule_catalog,
        &report_locale,
    );
    html = html.replace("{{category_examples_html}}", &category_examples_html);

    // --- findings ----------------------------------------------------------
    html = html.replace("{{sections_html}}", &sections_html);
    html = html.replace(
        "{{custom_rules_html}}",
        &render_custom_rules_section(&report_locale),
    );

    // --- unported sections: tests/fixtures/dependencies/database/SLA/git-blame
    html = html.replace("{{tests_html}}", "");
    html = html.replace("{{fixtures_html}}", "");
    html = html.replace("{{fixtures_display}}", "display:none");
    html = html.replace("{{dependencies_display}}", "display:none");
    html = html.replace("{{deps_total_scanned}}", "0");
    html = html.replace("{{deps_vulnerable}}", "0");
    html = html.replace("{{deps_unpinned}}", "0");
    html = html.replace("{{deps_ok}}", "0");
    html = html.replace("{{deps_warnings_html}}", "");
    html = html.replace("{{deps_findings_html}}", "");
    html = html.replace("{{database_display}}", "display:none");
    for key in [
        "db_tables",
        "db_columns",
        "db_indexes",
        "db_enums",
        "db_added",
        "db_dropped",
        "db_modified",
    ] {
        html = html.replace(&format!("{{{{{key}}}}}"), "0");
    }
    html = html.replace("{{db_stability}}", "100");
    html = html.replace("{{db_stability_color}}", "success");
    html = html.replace("{{sla_display}}", "display:none");
    html = html.replace("{{sla_html}}", "");
    html = html.replace("{{git_blame_display}}", "display:none");
    html = html.replace("{{git_blame_html}}", "");
    html = html.replace("{{taint_display}}", "display:none");

    // --- compliance -----------------------------------------------------------
    let thresholds = ctx.health_thresholds;
    html = html.replace(
        "{{compliance_html}}",
        &generate_compliance_html(&compliance, &report_locale, thresholds),
    );
    html = html.replace(
        "{{compliance_covered}}",
        &compliance.covered_controls.to_string(),
    );
    html = html.replace(
        "{{compliance_total}}",
        &compliance.total_controls.to_string(),
    );
    html = keep_block(&html, "COMPLIANCE");

    html = html.replace(
        "{{asvs_html}}",
        &generate_asvs_html(&asvs, &report_locale, thresholds),
    );
    html = html.replace("{{asvs_covered}}", &asvs.covered_requirements.to_string());
    html = html.replace("{{asvs_total}}", &asvs.total_requirements.to_string());
    html = keep_block(&html, "ASVS");

    html = html.replace(
        "{{nist_html}}",
        &generate_nist_csf_html(&nist, &report_locale, thresholds),
    );
    html = html.replace("{{nist_covered}}", &nist.covered_subcategories.to_string());
    html = html.replace("{{nist_total}}", &nist.total_subcategories.to_string());
    html = keep_block(&html, "NIST");

    // --- glossaire / validations --------------------------------------------
    html = html.replace("{{glossary_html}}", &glossary_html);
    let successes_html =
        crate::report::successes::render_successes_html(&successes, &report_locale);
    let successes_html = if successes_html.is_empty() {
        format!(
            r#"<p class="empty">{}</p>"#,
            t(&report_locale, "no_problems")
        )
    } else {
        successes_html
    };
    html = html.replace("{{successes_html}}", &successes_html);

    html = remove_dev_only_db_blocks(&html);

    html
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(rule_catalog: &BTreeMap<String, Value>) -> ReportContext<'_> {
        ReportContext {
            project_name: "my-project".to_string(),
            project_version: "1.0.0".to_string(),
            project_uuid: String::new(),
            project_description: String::new(),
            project_path: "/home/user/my-project".to_string(),
            tool_name: "CodeFixture".to_string(),
            tool_version: "2.0.0".to_string(),
            company_name: "CodeFixture SAS".to_string(),
            report_lang: "en".to_string(),
            date_str: "25/08/2026 à 12:00".to_string(),
            timestamp: "20260825_120000".to_string(),
            audit_total_time_secs: 3,
            total_lines_code: 5000,
            total_files_scanned: 42,
            health_thresholds: HealthThresholds::default(),
            rule_catalog,
        }
    }

    fn finding(
        category: &str,
        severity: &str,
        rule_key: &str,
        rule_name: &str,
        file: &str,
    ) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_name: rule_name.to_string(),
            category: category.to_string(),
            severity: severity.to_string(),
            risk: "Risque".to_string(),
            file: file.to_string(),
            line: 10,
            solution: Some("Solution".to_string()),
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: "eval(x)".to_string(),
            context_before: String::new(),
            context_after: String::new(),
            confidence: 90,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
        }
    }

    #[test]
    fn test_generate_html_no_findings_is_valid_shell() {
        let catalog = BTreeMap::new();
        let context = ctx(&catalog);
        let html = generate_html(&[], &context, None, None, None);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.trim_end().ends_with("</html>"));
        assert!(
            !html.contains("{{"),
            "il ne doit rester aucun placeholder non substitué"
        );
        assert!(!html.contains("DEV_ONLY_DB"));
    }

    #[test]
    fn test_generate_html_contains_project_identity() {
        let catalog = BTreeMap::new();
        let context = ctx(&catalog);
        let html = generate_html(&[], &context, None, None, None);
        assert!(html.contains("my-project"));
        assert!(html.contains("CodeFixture"));
    }

    #[test]
    fn test_generate_html_with_findings_shows_severity_counts() {
        let catalog = BTreeMap::new();
        let findings = vec![
            finding(
                "SECURITY",
                "HIGH",
                "sql_injection_fstring",
                "SQL Injection",
                "src/app.py",
            ),
            finding(
                "SECURITY",
                "CRITICAL",
                "hardcoded_secret",
                "Hardcoded Secret",
                "src/config.py",
            ),
        ];
        let context = ctx(&catalog);
        let html = generate_html(&findings, &context, None, None, None);
        assert!(html.contains("SQL Injection"));
        assert!(html.contains("Hardcoded Secret"));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn test_generate_html_compliance_sections_present() {
        let catalog = BTreeMap::new();
        let context = ctx(&catalog);
        let html = generate_html(&[], &context, None, None, None);
        assert!(html.contains(r#"id="section-compliance""#));
        assert!(html.contains(r#"id="section-asvs""#));
        assert!(html.contains(r#"id="section-nist""#));
    }

    #[test]
    fn test_generate_html_french_locale() {
        let catalog = BTreeMap::new();
        let mut context = ctx(&catalog);
        context.report_lang = "fr".to_string();
        let html = generate_html(&[], &context, None, None, None);
        assert!(html.contains(r#"lang="fr""#));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn test_generate_html_with_comparison_shows_section() {
        let catalog = BTreeMap::new();
        let context = ctx(&catalog);
        let comparison = crate::report::comparison::ComparisonResult {
            new_findings: vec![],
            resolved_findings: vec![],
            unchanged_findings: vec![],
            baseline_date: "2026-08-01".to_string(),
            baseline_totals: BTreeMap::new(),
        };
        let html = generate_html(&[], &context, Some(&comparison), None, None);
        assert!(html.contains(r#"id="section-comparison""#));
        assert!(!html.contains("{{"));
    }
}
