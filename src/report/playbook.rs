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
pub fn render_playbook_inline(rule_key: &str, report_locale: &Value) -> String {
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
        .map(|s| format!("<li>{} {}</li>", step_icon(&s.step_type), escape(&s.action)))
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

    let benefit_html = if !entry.benefit.is_empty() {
        format!(
            r#"<p class="playbook-benefit">💡 {}</p>"#,
            escape(&entry.benefit)
        )
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
    fn test_render_playbook_known_rule() {
        let en = load_report_locale("en");
        let html = render_playbook_inline("autoplay_media", &en);
        assert!(html.contains("playbook-details"));
        assert!(html.contains("Locate the vulnerable code pattern"));
        assert!(html.contains("playbook-benefit"));
    }

    #[test]
    fn test_render_playbook_cwe_reference_link() {
        let en = load_report_locale("en");
        let html = render_playbook_inline("catch_all_exception", &en);
        assert!(html.contains("CWE-396"));
        assert!(html.contains("https://cwe.mitre.org/data/definitions/396.html"));
    }

    #[test]
    fn test_render_playbook_unknown_rule_is_empty() {
        let en = load_report_locale("en");
        assert_eq!(render_playbook_inline("does_not_exist_xyz", &en), "");
    }
}
