//! HTML rendering of the 3 compliance matrices (ISO 27001 / ASVS / NIST
//! CSF) — port of the HTML-generation part of
//! `Audit/sca/compliance.py` (`_generate_compliance_html`,
//! `_generate_asvs_html`, `_generate_nist_csf_html` and their shared
//! helpers `_score_class`/`_pct_or_na`/`_render_compliance_dual_bars`/
//! `_render_shared_specific_breakdown`). The computation part lives in
//! `crate::report::compliance` (a separate work item, already ported).

use serde_json::Value;

use crate::i18n::{get_nested, t};
use crate::report::compliance::{
    AsvsCompliance, ComplianceStatus, Iso27001Compliance, NistCsfCompliance, SharedVsSpecific,
};
use crate::report::text::{escape, linkify_acronyms};

/// Thresholds for the good/warning/bad gradient of score bars — mirrors
/// `self.health_thresholds` (`sca/runner.py`, defaults 90/70).
#[derive(Debug, Clone, Copy)]
pub struct HealthThresholds {
    pub good: i64,
    pub warning: i64,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            good: 90,
            warning: 70,
        }
    }
}

fn score_class(pct: i64, thresholds: HealthThresholds) -> &'static str {
    if pct >= thresholds.good {
        "good"
    } else if pct >= thresholds.warning {
        "warning"
    } else {
        "danger"
    }
}

fn locale_str(v: &Value, path: &str, default: &str) -> String {
    let s = t(v, path);
    if s == path { default.to_string() } else { s }
}

fn pct_or_na(pct: i64, denom: usize, na_label: &str) -> String {
    if denom == 0 {
        na_label.to_string()
    } else {
        format!("{pct}%")
    }
}

fn render_compliance_dual_bars(
    report_locale: &Value,
    thresholds: HealthThresholds,
    total: usize,
    covered: usize,
    clean: usize,
) -> String {
    let applicability_pct = if total > 0 {
        (covered as f64 / total as f64 * 100.0).round() as i64
    } else {
        0
    };
    let clean_pct = if covered > 0 {
        (clean as f64 / covered as f64 * 100.0).round() as i64
    } else {
        0
    };
    let na_label = locale_str(report_locale, "compliance_na_label", "N/A");
    let applicability_label = locale_str(
        report_locale,
        "compliance_applicability_label",
        "SAST applicability",
    );
    let applicability_unit = locale_str(report_locale, "compliance_applicability_unit", "testable");
    let clean_label = locale_str(
        report_locale,
        "compliance_clean_label",
        "Compliance among testable",
    );
    let clean_unit = locale_str(report_locale, "compliance_clean_unit", "clean");
    let applicability_class = if total > 0 {
        score_class(applicability_pct, thresholds)
    } else {
        "na"
    };
    let clean_class = if covered > 0 {
        score_class(clean_pct, thresholds)
    } else {
        "na"
    };
    let applicability_display = pct_or_na(applicability_pct, total, &na_label);
    let clean_display = pct_or_na(clean_pct, covered, &na_label);
    let applicability_width = if total > 0 { applicability_pct } else { 0 };
    let clean_width = if covered > 0 { clean_pct } else { 0 };
    format!(
        r##"
            <div class="compliance-coverage">
                <span class="compliance-coverage-label">{applicability_label}</span>
                <span class="compliance-coverage-value">{covered}/{total} {applicability_unit} ({applicability_display})</span>
            </div>
            <div class="health-track"><div class="health-fill {applicability_class}" style="width: {applicability_width}%"></div></div>
            <div class="compliance-coverage compliance-coverage-secondary">
                <span class="compliance-coverage-label">{clean_label}</span>
                <span class="compliance-coverage-value">{clean}/{covered} {clean_unit} ({clean_display})</span>
            </div>
            <div class="health-track"><div class="health-fill {clean_class}" style="width: {clean_width}%"></div></div>
        "##
    )
}

fn render_shared_specific_breakdown(report_locale: &Value, sv: &SharedVsSpecific) -> String {
    if sv.shared_total == 0 && sv.specific_total == 0 {
        return String::new();
    }
    let shared_label = locale_str(
        report_locale,
        "compliance_shared_label",
        "Common core compliance (shared with other frameworks)",
    );
    let specific_label = locale_str(
        report_locale,
        "compliance_specific_label",
        "Framework-specific compliance (differentiating)",
    );
    let unit = locale_str(report_locale, "compliance_clean_unit", "clean");
    let na_label = locale_str(report_locale, "compliance_na_label", "N/A");
    let shared_display = pct_or_na(sv.shared_clean_pct, sv.shared_total, &na_label);
    let specific_display = pct_or_na(sv.specific_clean_pct, sv.specific_total, &na_label);
    let shared_clean = sv.shared_clean;
    let shared_total = sv.shared_total;
    let specific_clean = sv.specific_clean;
    let specific_total = sv.specific_total;
    format!(
        r##"
            <div class="compliance-shared-specific">
                <div class="compliance-coverage compliance-coverage-tertiary">
                    <span class="compliance-coverage-label">{shared_label}</span>
                    <span class="compliance-coverage-value">{shared_clean}/{shared_total} {unit} ({shared_display})</span>
                </div>
                <div class="compliance-coverage compliance-coverage-tertiary">
                    <span class="compliance-coverage-label">{specific_label}</span>
                    <span class="compliance-coverage-value">{specific_clean}/{specific_total} {unit} ({specific_display})</span>
                </div>
            </div>
        "##
    )
}

fn status_badge(
    status: ComplianceStatus,
    covered: &str,
    not_covered: &str,
    findings: &str,
) -> (&'static str, String) {
    match status {
        ComplianceStatus::Findings => ("compliance-findings", findings.to_string()),
        ComplianceStatus::Covered => ("compliance-covered", covered.to_string()),
        ComplianceStatus::NotCovered => ("compliance-not-covered", not_covered.to_string()),
    }
}

/// Generates the HTML for the ISO 27001 compliance section — port of
/// `_generate_compliance_html`.
pub fn generate_compliance_html(
    data: &Iso27001Compliance,
    report_locale: &Value,
    thresholds: HealthThresholds,
) -> String {
    let comp_t = get_nested(report_locale, "compliance");
    let get = |key: &str, default: &str| -> String {
        comp_t
            .and_then(|v| v.get(key))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(default)
            .to_string()
    };
    let disclaimer = get("disclaimer", "");
    let col_control = get("col_control", "Control");
    let col_name = get("col_name", "Name");
    let col_status = get("col_status", "Status");
    let col_findings = get("col_findings", "Findings");
    let col_rules = get("col_rules", "Rules");
    let status_covered = get("status_covered", "Covered");
    let status_not_covered = get("status_not_covered", "Not applicable");
    let status_findings = get("status_findings", "Issues found");
    let theme_labels: std::collections::HashMap<String, String> = comp_t
        .and_then(|v| v.get("themes"))
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let mut html = format!(
        r#"
        <div class="compliance-summary">
            <p class="compliance-disclaimer">{}</p>
            {}
            {}
        </div>
        "#,
        linkify_acronyms(report_locale, &escape(&disclaimer)),
        render_compliance_dual_bars(
            report_locale,
            thresholds,
            data.total_controls,
            data.covered_controls,
            data.clean_controls
        ),
        render_shared_specific_breakdown(report_locale, &data.shared_vs_specific),
    );

    let chart_labels = get_nested(report_locale, "chart_labels");
    let chart_str = |key: &str, default: &str| -> String {
        chart_labels
            .and_then(|v| v.get(key))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(default)
            .to_string()
    };
    let coverage_chart_title = chart_str("compliance_coverage_chart", "Overall Coverage (%)");
    let theme_chart_title = chart_str("compliance_theme_chart", "Coverage by Theme (%)");
    let status_chart_title = chart_str("compliance_status_chart", "Controls Status (count)");

    html.push_str(&format!(
        r#"
        <div class="charts-grid compliance-charts-grid">
            <div class="chart-card">
                <h3>📋 {coverage_chart_title}</h3>
                <div class="chart-container"><canvas id="complianceCoverageChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {theme_chart_title}</h3>
                <div class="chart-container"><canvas id="complianceThemeChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {status_chart_title}</h3>
                <div class="chart-container"><canvas id="complianceStatusChart"></canvas></div>
            </div>
        </div>
        "#
    ));

    let theme_order = [
        ("organizational", "🏢"),
        ("people", "👥"),
        ("physical", "🏗️"),
        ("technological", "💻"),
    ];
    for (theme_key, theme_icon) in theme_order {
        let theme_name = theme_labels.get(theme_key).cloned().unwrap_or_else(|| {
            let mut c = theme_key.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => theme_key.to_string(),
            }
        });
        let theme_data = &data.themes[theme_key];
        let mut theme_controls: Vec<_> = data
            .controls
            .values()
            .filter(|c| c.theme == theme_key)
            .collect();
        theme_controls.sort_by(|a, b| a.id.cmp(&b.id));

        html.push_str(&format!(
            r##"
            <div class="compliance-theme compliance-accordion open">
                <h4 onclick="this.parentElement.classList.toggle('open')">
                    {theme_icon} {theme_name}
                    <span class="compliance-theme-badge">{}/{}</span>
                    <span class="compliance-toggle">▶</span>
                </h4>
                <div class="compliance-accordion-content">
                <table class="compliance-matrix">
                    <thead><tr>
                        <th>{col_control}</th>
                        <th>{col_name}</th>
                        <th>{col_status}</th>
                        <th>{col_rules}</th>
                        <th>{col_findings}</th>
                    </tr></thead>
                    <tbody>
            "##,
            theme_data.covered, theme_data.total
        ));

        for ctrl in theme_controls {
            let (badge_class, badge_text) = status_badge(
                ctrl.status,
                &status_covered,
                &status_not_covered,
                &status_findings,
            );
            let finding_text = if ctrl.finding_count > 0 {
                ctrl.finding_count.to_string()
            } else {
                "—".to_string()
            };
            html.push_str(&format!(
                r##"
                        <tr class="{badge_class}-row">
                            <td class="compliance-ctrl-id">{}</td>
                            <td>{}</td>
                            <td><span class="compliance-badge {badge_class}">{badge_text}</span></td>
                            <td class="compliance-count">{}</td>
                            <td class="compliance-count">{finding_text}</td>
                        </tr>"##,
                ctrl.id,
                linkify_acronyms(report_locale, &escape(&ctrl.name)),
                ctrl.rules_count,
            ));
        }

        html.push_str(
            r#"
                    </tbody>
                </table>
                </div>
            </div>
            "#,
        );
    }

    html
}

/// Generates the HTML for the NIST CSF 2.0 compliance section — port
/// of `_generate_nist_csf_html`.
pub fn generate_nist_csf_html(
    data: &NistCsfCompliance,
    report_locale: &Value,
    thresholds: HealthThresholds,
) -> String {
    let nist_t = get_nested(report_locale, "nist");
    let get = |key: &str, default: &str| -> String {
        nist_t
            .and_then(|v| v.get(key))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(default)
            .to_string()
    };
    let disclaimer = get("disclaimer", "");
    let col_id = get("col_id", "ID");
    let col_name = get("col_name", "Subcategory");
    let col_status = get("col_status", "Status");
    let col_rules = get("col_rules", "Rules");
    let col_findings = get("col_findings", "Findings");
    let status_covered = get("status_covered", "Covered");
    let status_not_covered = get("status_not_covered", "Not applicable");
    let status_findings = get("status_findings", "Issues found");
    let function_labels: std::collections::HashMap<String, String> = nist_t
        .and_then(|v| v.get("functions"))
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let mut html = format!(
        r#"
        <div class="compliance-summary">
            <p class="compliance-disclaimer">{}</p>
            {}
            {}
        </div>
        "#,
        linkify_acronyms(report_locale, &escape(&disclaimer)),
        render_compliance_dual_bars(
            report_locale,
            thresholds,
            data.total_subcategories,
            data.covered_subcategories,
            data.clean_subcategories
        ),
        render_shared_specific_breakdown(report_locale, &data.shared_vs_specific),
    );

    let chart_labels = get_nested(report_locale, "chart_labels");
    let chart_str = |key: &str, default: &str| -> String {
        chart_labels
            .and_then(|v| v.get(key))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(default)
            .to_string()
    };
    let coverage_chart_title = chart_str("nist_coverage_chart", "Overall Coverage (%)");
    let function_chart_title = chart_str("nist_function_chart", "Coverage by Function (%)");
    let status_chart_title = chart_str("nist_status_chart", "Subcategories Status (count)");

    html.push_str(&format!(
        r#"
        <div class="charts-grid compliance-charts-grid">
            <div class="chart-card">
                <h3>📋 {coverage_chart_title}</h3>
                <div class="chart-container"><canvas id="nistCoverageChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {function_chart_title}</h3>
                <div class="chart-container"><canvas id="nistFunctionChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {status_chart_title}</h3>
                <div class="chart-container"><canvas id="nistStatusChart"></canvas></div>
            </div>
        </div>
        "#
    ));

    let function_order = [
        ("GV", "🏛️"),
        ("ID", "🔍"),
        ("PR", "🛡️"),
        ("DE", "📡"),
        ("RS", "🚨"),
        ("RC", "🔄"),
    ];
    for (func_code, func_icon) in function_order {
        let Some(func_data) = data.by_function.get(func_code) else {
            continue;
        };
        let func_name = function_labels
            .get(func_code)
            .cloned()
            .unwrap_or_else(|| func_data.name.clone());
        let mut func_subcats: Vec<_> = data
            .subcategories
            .values()
            .filter(|s| s.function == func_code)
            .collect();
        if func_subcats.is_empty() {
            continue;
        }
        func_subcats.sort_by(|a, b| a.id.cmp(&b.id));

        html.push_str(&format!(
            r##"
            <div class="compliance-theme compliance-accordion open">
                <h4 onclick="this.parentElement.classList.toggle('open')">
                    {func_icon} {func_code} — {func_name}
                    <span class="compliance-theme-badge">{}/{}</span>
                    <span class="compliance-toggle">▶</span>
                </h4>
                <div class="compliance-accordion-content">
                <table class="compliance-matrix">
                    <thead><tr>
                        <th>{col_id}</th>
                        <th>{col_name}</th>
                        <th>{col_status}</th>
                        <th>{col_rules}</th>
                        <th>{col_findings}</th>
                    </tr></thead>
                    <tbody>
            "##,
            func_data.covered, func_data.total
        ));

        for subcat in func_subcats {
            let (badge_class, badge_text) = status_badge(
                subcat.status,
                &status_covered,
                &status_not_covered,
                &status_findings,
            );
            let finding_text = if subcat.finding_count > 0 {
                subcat.finding_count.to_string()
            } else {
                "—".to_string()
            };
            html.push_str(&format!(
                r##"
                        <tr class="{badge_class}-row">
                            <td class="compliance-ctrl-id">{}</td>
                            <td>{}</td>
                            <td><span class="compliance-badge {badge_class}">{badge_text}</span></td>
                            <td class="compliance-count">{}</td>
                            <td class="compliance-count">{finding_text}</td>
                        </tr>"##,
                subcat.id,
                linkify_acronyms(report_locale, &escape(&subcat.name)),
                subcat.rules_count,
            ));
        }

        html.push_str(
            r#"
                    </tbody>
                </table>
                </div>
            </div>
            "#,
        );
    }

    html
}

/// Generates the HTML for the OWASP ASVS v5.0.0 compliance section —
/// port of `_generate_asvs_html`.
pub fn generate_asvs_html(
    data: &AsvsCompliance,
    report_locale: &Value,
    thresholds: HealthThresholds,
) -> String {
    let asvs_t = get_nested(report_locale, "asvs");
    let get = |key: &str, default: &str| -> String {
        asvs_t
            .and_then(|v| v.get(key))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(default)
            .to_string()
    };
    let disclaimer = get("disclaimer", "");
    let col_requirement = get("col_requirement", "Requirement");
    let col_name = get("col_name", "Name");
    let col_level = get("col_level", "Level");
    let col_status = get("col_status", "Status");
    let col_findings = get("col_findings", "Findings");
    let col_rules = get("col_rules", "Rules");
    let status_covered = get("status_covered", "Covered");
    let status_not_covered = get("status_not_covered", "Not applicable");
    let status_findings = get("status_findings", "Issues found");

    let mut html = format!(
        r#"
        <div class="compliance-summary">
            <p class="compliance-disclaimer">{}</p>
            {}
            {}
        </div>
        "#,
        linkify_acronyms(report_locale, &escape(&disclaimer)),
        render_compliance_dual_bars(
            report_locale,
            thresholds,
            data.total_requirements,
            data.covered_requirements,
            data.clean_requirements
        ),
        render_shared_specific_breakdown(report_locale, &data.shared_vs_specific),
    );

    let chart_labels = get_nested(report_locale, "chart_labels");
    let chart_str = |key: &str, default: &str| -> String {
        chart_labels
            .and_then(|v| v.get(key))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(default)
            .to_string()
    };
    let coverage_chart_title = chart_str("asvs_coverage_chart", "Overall Coverage (%)");
    let chapter_chart_title = chart_str("asvs_chapter_chart", "Coverage by Chapter (%)");
    let status_chart_title = chart_str("asvs_status_chart", "Requirements Status (count)");

    html.push_str(&format!(
        r#"
        <div class="charts-grid compliance-charts-grid">
            <div class="chart-card">
                <h3>🔰 {coverage_chart_title}</h3>
                <div class="chart-container"><canvas id="asvsCoverageChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {chapter_chart_title}</h3>
                <div class="chart-container"><canvas id="asvsChapterChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>📊 {status_chart_title}</h3>
                <div class="chart-container"><canvas id="asvsStatusChart"></canvas></div>
            </div>
        </div>
        "#
    ));

    const CHAPTER_ICONS: [(&str, &str); 17] = [
        ("V1", "🛡️"),
        ("V2", "✅"),
        ("V3", "🌐"),
        ("V4", "🔌"),
        ("V5", "📁"),
        ("V6", "🔑"),
        ("V7", "🔒"),
        ("V8", "👤"),
        ("V9", "🎟️"),
        ("V10", "🔗"),
        ("V11", "🔐"),
        ("V12", "📡"),
        ("V13", "⚙️"),
        ("V14", "💾"),
        ("V15", "🏗️"),
        ("V16", "📝"),
        ("V17", "📹"),
    ];

    let mut chapter_keys: Vec<&String> = data.chapters.keys().collect();
    chapter_keys.sort_by_key(|k| k[1..].parse::<u32>().unwrap_or(0));

    for ch_key in chapter_keys {
        let ch_data = &data.chapters[ch_key];
        let ch_icon = CHAPTER_ICONS
            .iter()
            .find(|(k, _)| k == ch_key)
            .map(|(_, i)| *i)
            .unwrap_or("📋");
        let ch_name = format!("{ch_key} — {}", ch_data.name);
        let mut ch_reqs: Vec<_> = data
            .requirements
            .values()
            .filter(|r| &r.chapter == ch_key)
            .collect();
        ch_reqs.sort_by(|a, b| a.id.cmp(&b.id));

        if ch_reqs.is_empty() {
            html.push_str(&format!(
                r##"
                <div class="compliance-theme compliance-accordion open">
                    <h4 onclick="this.parentElement.classList.toggle('open')">
                        {ch_icon} {ch_name}
                        <span class="compliance-theme-badge">{}/{}</span>
                        <span class="compliance-toggle">▶</span>
                    </h4>
                    <div class="compliance-accordion-content">
                        <p class="empty-group">{status_not_covered}</p>
                    </div>
                </div>
                "##,
                ch_data.covered, ch_data.total
            ));
            continue;
        }

        html.push_str(&format!(
            r##"
            <div class="compliance-theme compliance-accordion open">
                <h4 onclick="this.parentElement.classList.toggle('open')">
                    {ch_icon} {ch_name}
                    <span class="compliance-theme-badge">{}/{}</span>
                    <span class="compliance-toggle">▶</span>
                </h4>
                <div class="compliance-accordion-content">
                <table class="compliance-matrix">
                    <thead><tr>
                        <th>{col_requirement}</th>
                        <th>{col_name}</th>
                        <th>{col_level}</th>
                        <th>{col_status}</th>
                        <th>{col_rules}</th>
                        <th>{col_findings}</th>
                    </tr></thead>
                    <tbody>
            "##,
            ch_data.covered, ch_data.total
        ));

        for req in ch_reqs {
            let (badge_class, badge_text) = status_badge(
                req.status,
                &status_covered,
                &status_not_covered,
                &status_findings,
            );
            let finding_text = if req.finding_count > 0 {
                req.finding_count.to_string()
            } else {
                "—".to_string()
            };
            let level_class = format!("asvs-level-{}", req.level.to_lowercase());
            html.push_str(&format!(
                r##"
                        <tr class="{badge_class}-row">
                            <td class="compliance-ctrl-id">{}</td>
                            <td>{}</td>
                            <td><span class="asvs-level-badge {level_class}">{}</span></td>
                            <td><span class="compliance-badge {badge_class}">{badge_text}</span></td>
                            <td class="compliance-count">{}</td>
                            <td class="compliance-count">{finding_text}</td>
                        </tr>"##,
                req.id,
                linkify_acronyms(report_locale, &escape(&req.name)),
                req.level,
                req.rules_count,
            ));
        }

        html.push_str(
            r#"
                    </tbody>
                </table>
                </div>
            </div>
            "#,
        );
    }

    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;
    use crate::report::compliance::{
        compute_asvs_compliance, compute_iso27001_compliance, compute_nist_csf_compliance,
        load_rule_referential_scope,
    };
    use crate::report::exports::sarif::ReportFinding;

    fn finding(rule_key: &str, severity: &str) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_name: rule_key.to_string(),
            category: "SECURITY".to_string(),
            severity: severity.to_string(),
            risk: String::new(),
            file: "src/test.py".to_string(),
            line: 10,
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
    fn test_iso27001_html_not_empty_and_contains_coverage_bars() {
        let en = load_report_locale("en");
        let scope = load_rule_referential_scope();
        let data = compute_iso27001_compliance(&[], &scope);
        let html = generate_compliance_html(&data, &en, HealthThresholds::default());
        assert!(html.len() > 100);
        assert!(html.contains("compliance-coverage"));
        assert!(html.contains("compliance-coverage-secondary"));
        assert!(
            ["good", "warning", "danger"]
                .iter()
                .any(|c| html.contains(&format!("health-fill {c}\"")))
        );
    }

    #[test]
    fn test_iso27001_html_shared_specific_breakdown() {
        let en = load_report_locale("en");
        let scope = load_rule_referential_scope();
        let data = compute_iso27001_compliance(&[], &scope);
        let html = generate_compliance_html(&data, &en, HealthThresholds::default());
        assert!(html.contains("compliance-shared-specific"));
        assert!(html.contains("compliance-coverage-tertiary"));
    }

    #[test]
    fn test_iso27001_html_all_4_themes() {
        let en = load_report_locale("en");
        let scope = load_rule_referential_scope();
        let data = compute_iso27001_compliance(&[], &scope);
        let html = generate_compliance_html(&data, &en, HealthThresholds::default());
        assert!(html.contains("compliance-theme"));
        assert!(html.contains('🏢'));
        assert!(html.contains('👥'));
        assert!(html.contains("🏗️"));
        assert!(html.contains('💻'));
    }

    #[test]
    fn test_iso27001_html_contains_control_ids() {
        let en = load_report_locale("en");
        let scope = load_rule_referential_scope();
        let data = compute_iso27001_compliance(&[], &scope);
        let html = generate_compliance_html(&data, &en, HealthThresholds::default());
        assert!(html.contains("A.5.1"));
        assert!(html.contains("A.8.28"));
    }

    #[test]
    fn test_iso27001_html_badges_with_findings() {
        let en = load_report_locale("en");
        let scope = load_rule_referential_scope();
        let data = compute_iso27001_compliance(&[finding("hardcoded_secret", "HIGH")], &scope);
        let html = generate_compliance_html(&data, &en, HealthThresholds::default());
        assert!(html.contains("compliance-covered"));
        assert!(html.contains("compliance-not-covered"));
        assert!(html.contains("compliance-findings"));
    }

    #[test]
    fn test_asvs_html_contains_all_17_chapters() {
        let en = load_report_locale("en");
        let scope = load_rule_referential_scope();
        let data = compute_asvs_compliance(&[], &scope);
        let html = generate_asvs_html(&data, &en, HealthThresholds::default());
        for i in 1..=17 {
            assert!(html.contains(&format!("V{i}")), "chapitre V{i} manquant");
        }
    }

    #[test]
    fn test_asvs_html_level_badges() {
        let en = load_report_locale("en");
        let scope = load_rule_referential_scope();
        let data = compute_asvs_compliance(&[], &scope);
        let html = generate_asvs_html(&data, &en, HealthThresholds::default());
        assert!(html.contains("asvs-level-badge"));
        assert!(html.contains("asvs-level-l1"));
    }

    #[test]
    fn test_asvs_html_charts_no_radar() {
        let en = load_report_locale("en");
        let scope = load_rule_referential_scope();
        let data = compute_asvs_compliance(&[], &scope);
        let html = generate_asvs_html(&data, &en, HealthThresholds::default());
        assert!(html.contains("asvsCoverageChart"));
        assert!(html.contains("asvsChapterChart"));
        assert!(html.contains("asvsStatusChart"));
        assert!(!html.contains("asvsRadarChart"));
    }

    #[test]
    fn test_nist_html_no_na_on_clean_project() {
        let en = load_report_locale("en");
        let scope = load_rule_referential_scope();
        let data = compute_nist_csf_compliance(&[], &scope);
        assert!(data.total_subcategories > 0);
        assert!(data.covered_subcategories > 0);
        let html = generate_nist_csf_html(&data, &en, HealthThresholds::default());
        let primary_bars = html.split("compliance-shared-specific").next().unwrap();
        let na_label = t(&en, "compliance_na_label");
        assert!(!primary_bars.contains(&na_label));
    }

    #[test]
    fn test_render_compliance_dual_bars_na_when_zero_denominator() {
        let en = load_report_locale("en");
        let html = render_compliance_dual_bars(&en, HealthThresholds::default(), 10, 0, 0);
        let na_label = t(&en, "compliance_na_label");
        assert!(html.contains(&na_label));
        let after_secondary = html.split("compliance-coverage-secondary").nth(1).unwrap();
        assert!(!after_secondary.contains("(0%)"));
    }

    #[test]
    fn test_score_class_thresholds() {
        let t = HealthThresholds::default();
        assert_eq!(score_class(95, t), "good");
        assert_eq!(score_class(75, t), "warning");
        assert_eq!(score_class(50, t), "danger");
    }
}
