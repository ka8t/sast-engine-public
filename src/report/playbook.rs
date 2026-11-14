//! Inline remediation playbook (diagnostic/fix/verification steps +
//! CWE/CVE/OWASP/ISO27001/WCAG references) — port of
//! `_load_playbook`/`_render_playbook_inline` (`Audit/sca/report.py`).
//!
//! `resources/remediation-playbook.json` (560 rules) is static and
//! embedded at compile time — same choice as the other report
//! resources (`report_assets.rs`, `compliance.rs`).

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::i18n::t;
use crate::report::text::escape;

const PLAYBOOK_JSON: &str = include_str!("../../resources/remediation-playbook.json");

#[derive(Debug, Deserialize)]
struct PlaybookStep {
    action: String,
    /// Translations of a rule-specific step (`fr`, `es`, `de`); the two
    /// generic steps and the fix step are translated elsewhere (see
    /// `step_text`).
    #[serde(default)]
    action_i18n: BTreeMap<String, String>,
    #[serde(rename = "type")]
    step_type: String,
}

#[derive(Debug, Deserialize, Default)]
struct PlaybookRefs {
    cwe: Option<Value>,
    cwe_url: Option<String>,
    cve: Option<Value>,
    owasp: Option<String>,
    iso27001: Option<Vec<String>>,
    wcag: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct PlaybookEntry {
    #[serde(default)]
    steps: Vec<PlaybookStep>,
    #[serde(default)]
    references: PlaybookRefs,
    #[serde(default)]
    benefit: String,
}

#[derive(Debug, Deserialize)]
struct PlaybookFile {
    rules: BTreeMap<String, PlaybookEntry>,
}

fn load_playbook() -> PlaybookFile {
    serde_json::from_str(PLAYBOOK_JSON).expect("invalid embedded remediation-playbook.json")
}

/// A JSON value that can be either a single string or a list of
/// strings on the Python side (`isinstance(x, str)`/`isinstance(x,
/// list)`).
fn as_string_list(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|i| i.as_str().map(|s| s.to_string()))
            .collect(),
        _ => vec![],
    }
}

fn step_icon(step_type: &str) -> &'static str {
    match step_type {
        "diagnostic" => "🔍",
        "code_change" => "🔧",
        "verification" => "✅",
        _ => "▸",
    }
}

/// Generates the inline playbook HTML block for a `rule_key`, or an
/// empty string if the rule has no playbook entry (or no step and no
/// reference) — port of `_render_playbook_inline`.
/// The text of a playbook step in the report's language.
///
/// The playbook file is written in English. In another language: the
/// two generic steps ("Locate…", "Run the audit again…") come from the
/// report locale, the fix step is the rule's own `solution` in that
/// language (the playbook copies the English one), and a rule-specific
/// step uses its `action_i18n`. English text stays only as a last
/// resort. Fixed after a French report showed an English playbook
/// (2026-11-14); the Python report has the same English-only playbook.
fn step_text(step: &PlaybookStep, lang: &str, report_locale: &Value, solution: Option<&str>) -> String {
    const LOCATE: &str = "Locate the vulnerable code pattern in the file";
    const RERUN: &str = "Run the audit again to verify the finding is resolved";
    if lang == "en" {
        return step.action.clone();
    }
    match step.step_type.as_str() {
        "diagnostic" if step.action == LOCATE => t(report_locale, "playbook_step_locate"),
        "verification" if step.action == RERUN => t(report_locale, "playbook_step_rerun"),
        "code_change" => solution
            .filter(|s| !s.is_empty())
            .map_or_else(|| step.action.clone(), str::to_string),
        _ => step
            .action_i18n
            .get(lang)
            .cloned()
            .unwrap_or_else(|| step.action.clone()),
    }
}

/// Renders the playbook of `rule_key` in the report's language.
/// `solution` and `benefit` are the rule's own texts, already in that
/// language (`ReportFinding`): they replace the English copies the
/// playbook file holds.
pub fn render_playbook_inline(
    rule_key: &str,
    report_locale: &Value,
    solution: Option<&str>,
    benefit: &str,
) -> String {
    let lang = t(report_locale, "locale_code");
    let playbook = load_playbook();
    let Some(entry) = playbook.rules.get(rule_key) else {
        return String::new();
    };
    if entry.steps.is_empty() && entry.references.cwe.is_none() && entry.references.cve.is_none() {
        return String::new();
    }

    let label = t(report_locale, "playbook_link");

    let steps_html: String = entry
        .steps
        .iter()
        .map(|s| {
            format!(
                "<li>{} {}</li>",
                step_icon(&s.step_type),
                escape(&step_text(s, &lang, report_locale, solution))
            )
        })
        .collect();

    let mut refs_html = String::new();
    if let Some(cwe) = &entry.references.cwe {
        let cwe_text = as_string_list(cwe).join(", ");
        let url = entry.references.cwe_url.clone().unwrap_or_default();
        refs_html.push_str(&format!(
            r#"<a href="{url}" target="_blank" class="playbook-ref">{cwe_text}</a> "#
        ));
    }
    if let Some(cve) = &entry.references.cve {
        for c in as_string_list(cve) {
            let nvd_url = format!("https://nvd.nist.gov/vuln/detail/{c}");
            refs_html.push_str(&format!(
                r#"<a href="{nvd_url}" target="_blank" class="playbook-ref">{c}</a> "#
            ));
        }
    }
    if let Some(owasp) = &entry.references.owasp {
        refs_html.push_str(&format!(r#"<span class="playbook-ref">{owasp}</span> "#));
    }
    if let Some(iso) = &entry.references.iso27001 {
        let iso_list = iso.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
        refs_html.push_str(&format!(
            r#"<span class="playbook-ref">ISO {iso_list}</span>"#
        ));
    }
    if let Some(wcag) = &entry.references.wcag {
        for w in as_string_list(wcag).into_iter().take(3) {
            let slug = w.replace('.', "-");
            let url = format!("https://www.w3.org/WAI/WCAG21/Understanding/{slug}");
            refs_html.push_str(&format!(
                r#"<a href="{url}" target="_blank" class="playbook-ref">WCAG {w}</a> "#
            ));
        }
    }

    let benefit = if lang != "en" && !benefit.is_empty() {
        benefit
    } else {
        entry.benefit.as_str()
    };
    let benefit_html = if !benefit.is_empty() {
        format!(r#"<p class="playbook-benefit">💡 {}</p>"#, escape(benefit))
    } else {
        String::new()
    };

    format!(
        r#"<details class="playbook-details"><summary>📋 {label}</summary><ol class="playbook-steps">{steps_html}</ol>{benefit_html}<div class="playbook-refs">{refs_html}</div></details>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;

    /// The embedded playbook parses and its `total_rules` header matches
    /// the entries it holds (it said 204 for 225 entries before #157,
    /// which filled one entry per security rule of the catalog).
    #[test]
    fn test_playbook_loads_and_total_rules_matches() {
        let p = load_playbook();
        let header: Value = serde_json::from_str(PLAYBOOK_JSON).unwrap();
        assert_eq!(
            header["total_rules"].as_u64(),
            Some(p.rules.len() as u64),
            "total_rules is stale"
        );
        assert!(p.rules.len() >= 560, "{}", p.rules.len());
    }

    #[test]
    fn test_render_playbook_in_french_has_no_english_step() {
        // A French report showed this playbook in English (2026-11-14).
        let fr = load_report_locale("fr");
        let html = render_playbook_inline(
            "html_th_scope_missing",
            &fr,
            Some("Ajoutez scope=\"col\" ou scope=\"row\"."),
            "Rend les tableaux lisibles au lecteur d'écran.",
        );
        assert!(html.contains("Repérez tous les éléments &lt;th&gt;"), "{html}");
        assert!(html.contains("Ajoutez scope="), "{html}");
        assert!(html.contains("Rend les tableaux lisibles"), "{html}");
        assert!(html.contains("lecteur d&#x27;écran") || html.contains("lecteur d'écran"), "{html}");
        for english in ["Find all", "Test with a screen reader", "Run the audit"] {
            assert!(!html.contains(english), "{english}: {html}");
        }
        let generic = render_playbook_inline("xss_unsafe_html_construction", &fr, None, "");
        assert!(generic.contains("Repérez le code vulnérable"), "{generic}");
        assert!(generic.contains("Relancez l"), "{generic}");
    }

    #[test]
    fn test_render_playbook_known_rule() {
        let en = load_report_locale("en");
        let html = render_playbook_inline("autoplay_media", &en, None, "");
        assert!(html.contains("playbook-details"));
        assert!(html.contains("Locate the vulnerable code pattern"));
        assert!(html.contains("playbook-benefit"));
    }

    #[test]
    fn test_render_playbook_cwe_reference_link() {
        let en = load_report_locale("en");
        let html = render_playbook_inline("catch_all_exception", &en, None, "");
        assert!(html.contains("CWE-396"));
        assert!(html.contains("https://cwe.mitre.org/data/definitions/396.html"));
    }

    #[test]
    fn test_render_playbook_unknown_rule_is_empty() {
        let en = load_report_locale("en");
        assert_eq!(render_playbook_inline("does_not_exist_xyz", &en, None, ""), "");
    }
}
