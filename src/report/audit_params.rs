//! HTML "audit parameters" section — port of
//! `_generate_audit_params_summary` (`Audit/sca/report.py`).
//!
//! **Assumed simplifications vs Python** (AuditRust has no
//! JSON-file-based configuration system, only CLI flags —
//! see `orchestrator::ScanConfig`):
//!   - **Categories**: Python displays an enabled/weighted badge per
//!     category, driven by `enabled_categories`/`category_weights`
//!     (project config, no CLI equivalent on the Python side either).
//!     AuditRust has no such notion — the badge simply reflects
//!     `only_category` (a single "active" category if filtered,
//!     all 5 otherwise), weight always displayed as `×1`.
//!   - **Scanned extensions**: derived from a static table
//!     (mirroring `SourceLanguage::from_extension`, `orchestrator.rs`)
//!     from the detected languages — not from a configurable
//!     `self._py_exts`/`_js_exts` as on the Python side.
//!   - **CLI options**: only the options that ACTUALLY exist
//!     in `sast-engine scan` are listed (`--quick`/
//!     `--only-category`/`--disable-rule`/`--severity`/`--with-tests`/
//!     `--with-deps`/`--lang`) — not `--fail-on-high`/`--sarif`/
//!     `--sbom`/`--debug` (Python), which have no Rust equivalent as
//!     of today (`--format sarif` exists, but as a value of
//!     `--format`, not a separate boolean).

use serde_json::Value;

use crate::i18n::t;
use crate::report::html::ReportContext;
use crate::report::report_assets::load_template;
use crate::report::text::escape;

/// Entries not derivable from the findings, for the "audit
/// parameters" section — mirrors the `ScanConfig` fields/CLI options
/// actually used for this scan.
pub struct AuditParamsInfo {
    /// Languages actually detected among the scanned files
    /// (`rule_tag()`, e.g. "python"/"java"/"javascript"/"php"), sorted.
    pub languages: Vec<String>,
    /// Explicitly included paths — empty = the whole project.
    pub include_paths: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub quick_mode: bool,
    pub only_category: Option<String>,
    pub disabled_rules: Vec<String>,
    pub with_tests: bool,
    pub with_deps: bool,
    pub database_configured: bool,
    pub severity_levels: Option<Vec<String>>,
    pub report_lang: String,
}

/// File extensions recognized per language — static mirror of
/// `SourceLanguage::from_extension` (`orchestrator.rs`), duplicated here
/// for display purposes rather than made public from the orchestrator
/// (otherwise there'd be a reverse report → orchestrator dependency).
const LANGUAGE_EXTENSIONS: [(&str, &[&str]); 4] = [
    ("python", &[".py"]),
    ("java", &[".java"]),
    ("javascript", &[".js", ".jsx", ".mjs", ".cjs", ".ts"]),
    ("php", &[".php"]),
];

const CATEGORY_ORDER: [(&str, &str, &str); 5] = [
    ("SECURITY", "security", "🔒"),
    ("ARCH", "architecture", "🏗️"),
    ("UI", "ui", "🎨"),
    ("UX", "ux", "🧭"),
    ("MAINTENANCE", "maintenance", "🔧"),
];

fn extensions_for(languages: &[String]) -> String {
    let mut parts = Vec::new();
    for lang in languages {
        if let Some((_, exts)) = LANGUAGE_EXTENSIONS.iter().find(|(l, _)| l == lang) {
            let exts_html = exts
                .iter()
                .map(|e| format!("<code>{}</code>", escape(e)))
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!("<code>{}</code>: {exts_html}", escape(lang)));
        }
    }
    parts.join("<br>")
}

fn category_badges(only_category: Option<&str>, report_locale: &Value) -> String {
    let badge_tpl = load_template("category-badge.html");
    let mut html = String::new();
    for (cat_key, i18n_key, _icon) in CATEGORY_ORDER {
        let enabled = match only_category {
            Some(only) => only.eq_ignore_ascii_case(cat_key),
            None => true,
        };
        let label = t(report_locale, &format!("category_titles.{i18n_key}"));
        let badge = badge_tpl
            .replace("{{class}}", if enabled { "enabled" } else { "disabled" })
            .replace("{{status}}", if enabled { "✓" } else { "✗" })
            .replace("{{label}}", &escape(&label))
            .replace("{{weight}}", "1");
        html.push_str(&badge);
        html.push(' ');
    }
    html
}

fn cli_options_html(info: &AuditParamsInfo, report_locale: &Value) -> String {
    let item_tpl = load_template("cli-option-item.html");
    let render = |active: bool, flag_display: String, desc: String| -> String {
        item_tpl
            .replace(
                "{{option_class}}",
                if active { "active" } else { "inactive" },
            )
            .replace("{{option_check}}", if active { "✅" } else { "⬜" })
            .replace("{{option_flag}}", &escape(&flag_display))
            .replace("{{option_desc}}", &escape(&desc))
    };

    let mut html = String::new();
    html.push_str(&render(
        info.quick_mode,
        "--quick".to_string(),
        t(report_locale, "cli_options_desc.quick"),
    ));
    let only_cat_flag = match &info.only_category {
        Some(c) => format!("--only-category {c}"),
        None => "--only-category".to_string(),
    };
    html.push_str(&render(
        info.only_category.is_some(),
        only_cat_flag,
        t(report_locale, "cli_options_desc.only_category"),
    ));
    let disable_flag = if info.disabled_rules.is_empty() {
        "--disable-rule".to_string()
    } else {
        format!("--disable-rule ({})", info.disabled_rules.len())
    };
    html.push_str(&render(
        !info.disabled_rules.is_empty(),
        disable_flag,
        t(report_locale, "cli_options_desc.disable_rule"),
    ));
    let severity_flag = match &info.severity_levels {
        Some(levels) => format!("--severity {}", levels.join(",")),
        None => "--severity".to_string(),
    };
    let severity_desc = t(report_locale, "cli_options_desc.severity").replace(
        "{levels}",
        &info
            .severity_levels
            .as_ref()
            .map(|l| l.join(", "))
            .unwrap_or_default(),
    );
    html.push_str(&render(
        info.severity_levels.is_some(),
        severity_flag,
        severity_desc,
    ));
    html.push_str(&render(
        info.with_tests,
        "--with-tests".to_string(),
        t(report_locale, "cli_options_desc.with_tests"),
    ));
    html.push_str(&render(
        info.with_deps,
        "--with-deps".to_string(),
        t(report_locale, "cli_options_desc.with_deps"),
    ));
    html.push_str(&render(
        info.database_configured,
        "--db-host".to_string(),
        t(report_locale, "cli_options_desc.with_database"),
    ));
    html.push_str(&render(
        true,
        format!("--lang {}", info.report_lang),
        t(report_locale, "cli_options_desc.report_lang"),
    ));
    html
}

/// Generates the complete "audit parameters" section. The project
/// identity comes from `ctx` (which already carries these fields for
/// the rest of the report) rather than being duplicated in the
/// parameters — avoids forcing a caller to unpack `ctx` field by field.
pub fn render_audit_params_html(
    info: &AuditParamsInfo,
    ctx: &ReportContext,
    report_locale: &Value,
) -> String {
    let project_name = ctx.project_name.as_str();
    let project_version = ctx.project_version.as_str();
    let project_description = ctx.project_description.as_str();
    let project_uuid = ctx.project_uuid.as_str();
    let project_path = ctx.project_path.as_str();
    let template = load_template("audit-params.html");

    let languages_html = if info.languages.is_empty() {
        format!("<em>{}</em>", t(report_locale, "none"))
    } else {
        info.languages
            .iter()
            .map(|l| format!("<code>{}</code>", escape(l)))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let extensions_html = {
        let ext = extensions_for(&info.languages);
        if ext.is_empty() {
            format!("<em>{}</em>", t(report_locale, "none"))
        } else {
            ext
        }
    };

    let include_html = if info.include_paths.is_empty() {
        format!("<em>{}</em>", t(report_locale, "all"))
    } else {
        info.include_paths
            .iter()
            .map(|p| format!("<code>{}</code>", escape(p)))
            .collect::<Vec<_>>()
            .join(" ")
    };

    let exclude_html = if info.exclude_patterns.is_empty() {
        format!("<em>{}</em>", t(report_locale, "none"))
    } else {
        info.exclude_patterns
            .iter()
            .map(|p| format!("<code>{}</code>", escape(p)))
            .collect::<Vec<_>>()
            .join(" ")
    };

    let mode_label = if info.quick_mode {
        t(report_locale, "mode_quick")
    } else {
        t(report_locale, "mode_full")
    };

    let only_cat_html = match &info.only_category {
        Some(c) => format!("<code>{}</code>", escape(c)),
        None => format!("<em>{}</em>", t(report_locale, "all")),
    };

    let disabled_html = if info.disabled_rules.is_empty() {
        format!("<em>{}</em>", t(report_locale, "none"))
    } else {
        let mut sorted = info.disabled_rules.clone();
        sorted.sort();
        sorted
            .iter()
            .map(|r| format!("<code>{}</code>", escape(r)))
            .collect::<Vec<_>>()
            .join(", ")
    };

    template
        .replace("{{i18n_parameters}}", &t(report_locale, "parameters"))
        .replace(
            "{{i18n_project_info}}",
            &t(report_locale, "audit_params.project_info"),
        )
        .replace(
            "{{i18n_project_name}}",
            &t(report_locale, "audit_params.project_name"),
        )
        .replace(
            "{{i18n_project_description}}",
            &t(report_locale, "audit_params.project_description"),
        )
        .replace(
            "{{i18n_project_id}}",
            &t(report_locale, "audit_params.project_id"),
        )
        .replace(
            "{{i18n_project_path}}",
            &t(report_locale, "audit_params.project_path"),
        )
        .replace("{{project_name}}", &escape(project_name))
        .replace(
            "{{project_version}}",
            &if project_version.is_empty() {
                String::new()
            } else {
                format!("<code>v{}</code>", escape(project_version))
            },
        )
        .replace(
            "{{project_description}}",
            &if project_description.is_empty() {
                format!("<em>{}</em>", t(report_locale, "none"))
            } else {
                escape(project_description)
            },
        )
        .replace(
            "{{project_id}}",
            &if project_uuid.is_empty() {
                format!("<em>{}</em>", t(report_locale, "none"))
            } else {
                escape(project_uuid)
            },
        )
        .replace("{{project_path}}", &escape(project_path))
        .replace("{{i18n_audit_scope}}", &t(report_locale, "audit_scope"))
        .replace(
            "{{i18n_languages}}",
            &t(report_locale, "audit_params.languages"),
        )
        .replace("{{languages}}", &languages_html)
        .replace(
            "{{i18n_scanned_extensions}}",
            &t(report_locale, "audit_params.scanned_extensions"),
        )
        .replace("{{scanned_extensions}}", &extensions_html)
        .replace(
            "{{i18n_analyzed_dirs}}",
            &t(report_locale, "audit_params.analyzed_dirs"),
        )
        .replace("{{include_paths}}", &include_html)
        .replace(
            "{{i18n_excluded_patterns}}",
            &t(report_locale, "audit_params.excluded_patterns"),
        )
        .replace("{{exclude_patterns}}", &exclude_html)
        .replace("{{i18n_mode}}", &t(report_locale, "audit_params.mode"))
        .replace("{{mode}}", &escape(&mode_label))
        .replace(
            "{{i18n_filtered_category}}",
            &t(report_locale, "audit_params.filtered_category"),
        )
        .replace("{{only_category}}", &only_cat_html)
        .replace(
            "{{i18n_disabled_rules}}",
            &t(report_locale, "audit_params.disabled_rules"),
        )
        .replace("{{disabled_rules}}", &disabled_html)
        .replace(
            "{{i18n_categories}}",
            &t(report_locale, "audit_params.categories"),
        )
        .replace(
            "{{categories}}",
            &category_badges(info.only_category.as_deref(), report_locale),
        )
        .replace(
            "{{i18n_cli_options}}",
            &t(report_locale, "audit_params.cli_options"),
        )
        .replace(
            "{{cli_options_html}}",
            &cli_options_html(info, report_locale),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;
    use crate::report::compliance_html::HealthThresholds;
    use std::collections::BTreeMap;

    fn base_info() -> AuditParamsInfo {
        AuditParamsInfo {
            languages: vec!["python".to_string()],
            include_paths: vec![],
            exclude_patterns: vec![],
            quick_mode: false,
            only_category: None,
            disabled_rules: vec![],
            with_tests: false,
            with_deps: false,
            database_configured: false,
            severity_levels: None,
            report_lang: "en".to_string(),
        }
    }

    /// Builds a minimal `ReportContext` for the tests — only the 5
    /// project identity fields vary from one test to another, the
    /// rest (out of scope for this section) is neutral.
    fn test_ctx<'a>(
        project_name: &str,
        project_version: &str,
        project_description: &str,
        project_uuid: &str,
        project_path: &str,
        rule_catalog: &'a BTreeMap<String, Value>,
    ) -> ReportContext<'a> {
        ReportContext {
            project_name: project_name.to_string(),
            project_version: project_version.to_string(),
            project_uuid: project_uuid.to_string(),
            project_description: project_description.to_string(),
            project_path: project_path.to_string(),
            tool_name: "CodeFixture".to_string(),
            tool_version: "2.0.0".to_string(),
            company_name: "CodeFixture SAS".to_string(),
            report_lang: "en".to_string(),
            date_str: String::new(),
            timestamp: String::new(),
            audit_total_time_secs: 0,
            total_lines_code: 0,
            total_files_scanned: 0,
            health_thresholds: HealthThresholds::default(),
            rule_catalog,
        }
    }

    #[test]
    fn test_renders_project_identity() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx(
            "MyProject",
            "1.2.3",
            "A test project",
            "uuid-1234",
            "/home/user/myproject",
            &catalog,
        );
        let html = render_audit_params_html(&base_info(), &ctx, &en);
        assert!(html.contains("MyProject"));
        assert!(html.contains("v1.2.3"));
        assert!(html.contains("A test project"));
        assert!(html.contains("uuid-1234"));
        assert!(html.contains("/home/user/myproject"));
    }

    #[test]
    fn test_empty_include_paths_shows_all() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let html = render_audit_params_html(&base_info(), &ctx, &en);
        assert!(html.contains(&t(&en, "all")));
    }

    #[test]
    fn test_languages_rendered_as_code() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.languages = vec!["java".to_string(), "python".to_string()];
        let html = render_audit_params_html(&info, &ctx, &en);
        assert!(html.contains("<code>java</code>"));
        assert!(html.contains("<code>python</code>"));
    }

    #[test]
    fn test_no_languages_shows_none() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.languages = vec![];
        let html = render_audit_params_html(&info, &ctx, &en);
        assert!(html.contains(&t(&en, "none")));
    }

    #[test]
    fn test_quick_mode_label() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.quick_mode = true;
        let html = render_audit_params_html(&info, &ctx, &en);
        assert!(html.contains(&t(&en, "mode_quick")));
    }

    #[test]
    fn test_only_category_shown_and_others_disabled() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.only_category = Some("security".to_string());
        let html = render_audit_params_html(&info, &ctx, &en);
        assert!(html.contains("<code>security</code>"));
        // The SECURITY badge must be "enabled", the others "disabled".
        assert!(html.contains(r#"cat-badge enabled"#));
        assert!(html.contains(r#"cat-badge disabled"#));
    }

    #[test]
    fn test_disabled_rules_sorted_and_listed() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.disabled_rules = vec!["zeta_rule".to_string(), "alpha_rule".to_string()];
        let html = render_audit_params_html(&info, &ctx, &en);
        let alpha_pos = html.find("alpha_rule").unwrap();
        let zeta_pos = html.find("zeta_rule").unwrap();
        assert!(alpha_pos < zeta_pos, "triés alphabétiquement");
    }

    #[test]
    fn test_cli_options_reflect_active_flags() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.with_tests = true;
        info.with_deps = true;
        info.severity_levels = Some(vec!["HIGH".to_string(), "CRITICAL".to_string()]);
        let html = render_audit_params_html(&info, &ctx, &en);
        assert!(html.contains("--with-tests"));
        assert!(html.contains("--with-deps"));
        assert!(html.contains("--severity HIGH,CRITICAL"));
        assert!(html.contains("option-item active"));
    }

    #[test]
    fn test_extensions_reflect_detected_languages() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.languages = vec!["php".to_string()];
        let html = render_audit_params_html(&info, &ctx, &en);
        assert!(html.contains("<code>.php</code>"));
    }
}
