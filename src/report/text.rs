//! Small text utilities for the HTML report — port of `_escape`,
//! `_is_dependency`, `_lang_label`, `_linkify_acronyms`,
//! `_linkify_acronyms_in_html` (`Audit/sca/report.py`) and
//! `get_context` (`Audit/sca/utils.py`).

use fancy_regex::Regex;
use serde_json::Value;

/// Escapes special HTML characters — port of `_escape`.
pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Context lines around a detected line (1-indexed), returned as
/// (before, after) joined with `\n` — port of
/// `sca/utils.py::get_context` (`context_size=2` by default: 2 lines
/// before, 2 after). `lines` is 0-indexed (element `i` = line `i+1`).
pub fn context_lines(lines: &[String], line: usize, context_size: usize) -> (String, String) {
    let mut before = Vec::new();
    let mut after = Vec::new();
    for (idx, content) in lines.iter().enumerate() {
        let ln = idx + 1;
        if line.saturating_sub(context_size) <= ln && ln < line {
            before.push(content.trim_end());
        } else if line < ln && ln <= line + context_size {
            after.push(content.trim_end());
        }
    }
    (before.join("\n"), after.join("\n"))
}

const DEPENDENCY_PATH_PATTERNS: [&str; 8] = [
    "/vendor/",
    "/lib/",
    "/node_modules/",
    "/dist/",
    "/build/",
    "/assets/vendor/",
    ".min.js",
    ".bundle.js",
];
const DEPENDENCY_EXTRA_PATTERNS: [&str; 2] = ["/alembic/", "alembic/"];
const DEPENDENCY_FILENAMES: [&str; 7] = [
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
];

/// Determines whether a file is part of the external dependencies —
/// port of `_is_dependency`.
pub fn is_dependency(filepath: &str) -> bool {
    let lower = filepath.to_lowercase();
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    if DEPENDENCY_FILENAMES.contains(&basename) {
        return true;
    }
    DEPENDENCY_PATH_PATTERNS
        .iter()
        .chain(DEPENDENCY_EXTRA_PATTERNS.iter())
        .any(|p| lower.contains(p))
}

/// Language label inferred from the file extension — port of
/// `_lang_label`.
pub fn lang_label(file: &str) -> &'static str {
    let basename = file.rsplit('/').next().unwrap_or(file);
    if basename.eq_ignore_ascii_case("dockerfile") {
        return "Dockerfile";
    }
    let ext = basename.rsplit_once('.').map(|(_, e)| e.to_lowercase());
    match ext.as_deref() {
        Some("py") | Some("pyw") => "Python",
        Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => "JavaScript",
        Some("ts") | Some("tsx") => "TypeScript",
        Some("java") => "Java",
        Some("cs") => "C#",
        Some("php") => "PHP",
        Some("html") | Some("htm") => "HTML",
        Some("yml") | Some("yaml") => "YAML",
        _ => "",
    }
}

struct AcronymEntry {
    key: String,
    term: String,
    tooltip: String,
}

fn glossary_entries(report_locale: &Value) -> Vec<AcronymEntry> {
    let mut entries = Vec::new();
    if let Some(Value::Object(acronyms)) =
        crate::i18n::get_nested(report_locale, "glossary.acronyms")
    {
        for (key, acr) in acronyms {
            let term = acr
                .get("term")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let full = acr.get("full").and_then(|v| v.as_str()).unwrap_or("");
            let desc = acr.get("desc").and_then(|v| v.as_str()).unwrap_or("");
            entries.push(AcronymEntry {
                key: key.clone(),
                term,
                tooltip: format!("{full} — {desc}"),
            });
        }
    }
    entries.sort_by_key(|a| std::cmp::Reverse(a.term.len()));
    entries
}

/// Replaces known acronyms with links to the glossary, with a
/// tooltip — port of `_linkify_acronyms`. Applies to text that has
/// already been escaped (see `escape`); for full HTML, see
/// `linkify_acronyms_in_html`.
pub fn linkify_acronyms(report_locale: &Value, text: &str) -> String {
    let entries = glossary_entries(report_locale);
    if entries.is_empty() {
        return text.to_string();
    }
    let mut out = text.to_string();
    for e in &entries {
        let escaped_term = fancy_regex::escape(&e.term);
        let pattern = format!(r"(?<![>\w/]){escaped_term}(?![<\w])");
        let re = Regex::new(&pattern).expect("valid acronym pattern");
        let tooltip = escape(&e.tooltip);
        let replacement = format!(
            r##"<a href="#acr-{}" class="glossary-link" data-tooltip="{}">{}</a>"##,
            e.key, tooltip, e.term
        );
        out = re
            .replace_all(&out, |_: &fancy_regex::Captures<'_, str>| {
                replacement.clone()
            })
            .into_owned();
    }
    out
}

/// Applies acronym linkification to the full report HTML — port of
/// `_linkify_acronyms_in_html`. Only processes visible text content:
/// ignores tags, `<script>`/`<style>`/`<code>`/`<pre>`/`<a>`, and links
/// already in place. Replacement done in a single pass (combined
/// regex) to avoid nested-replacement artifacts in `data-tooltip`
/// attributes.
pub fn linkify_acronyms_in_html(report_locale: &Value, html: &str) -> String {
    let entries = glossary_entries(report_locale);
    if entries.is_empty() {
        return html.to_string();
    }

    let mut term_to_link: std::collections::HashMap<&str, String> =
        std::collections::HashMap::new();
    let mut sorted_terms: Vec<&str> = Vec::with_capacity(entries.len());
    for e in &entries {
        let tooltip = escape(&e.tooltip);
        let link = format!(
            r##"<a href="#acr-{}" class="glossary-link" data-tooltip="{}">{}</a>"##,
            e.key, tooltip, e.term
        );
        term_to_link.insert(e.term.as_str(), link);
        sorted_terms.push(e.term.as_str());
    }
    sorted_terms.sort_by_key(|a| std::cmp::Reverse(a.len()));

    let all_terms = sorted_terms
        .iter()
        .map(|t| fancy_regex::escape(t).into_owned())
        .collect::<Vec<_>>()
        .join("|");
    let combined = Regex::new(&format!(r"(?<![\w/])({all_terms})(?![\w])"))
        .expect("valid combined acronym pattern");

    let tag_re = Regex::new(r"(?s)(<[^>]+>|<!--.*?-->)").expect("valid tag pattern");

    let mut segments: Vec<String> = Vec::new();
    let mut last_end = 0;
    for m in tag_re.find_iter(html) {
        let Ok(m) = m else { continue };
        if m.start() > last_end {
            segments.push(html[last_end..m.start()].to_string());
        }
        segments.push(html[m.start()..m.end()].to_string());
        last_end = m.end();
    }
    if last_end < html.len() {
        segments.push(html[last_end..].to_string());
    }

    const SKIP_TAGS: [&str; 5] = ["script", "style", "code", "pre", "a"];
    let mut skip_depth: i32 = 0;
    let mut glossary_skip = false;

    for segment in segments.iter_mut() {
        if segment.starts_with('<') {
            if segment == "<!-- GLOSSARY_NO_LINKIFY -->" {
                glossary_skip = true;
                continue;
            }
            if segment == "<!-- /GLOSSARY_NO_LINKIFY -->" {
                glossary_skip = false;
                continue;
            }
            let trimmed = segment.trim_start_matches('<');
            let is_closing = trimmed.starts_with('/');
            let name_part = trimmed.trim_start_matches('/');
            let tag_name: String = name_part
                .chars()
                .take_while(|c| c.is_alphanumeric())
                .collect::<String>()
                .to_lowercase();
            if SKIP_TAGS.contains(&tag_name.as_str()) {
                if is_closing {
                    skip_depth = (skip_depth - 1).max(0);
                } else if !segment.ends_with("/>") {
                    skip_depth += 1;
                }
            }
            continue;
        }

        if skip_depth > 0 || glossary_skip || segment.trim().is_empty() {
            continue;
        }

        *segment = combined
            .replace_all(segment, |caps: &fancy_regex::Captures<'_, str>| {
                let matched = caps.get(0).expect("group 0 always present").as_str();
                term_to_link
                    .get(matched)
                    .cloned()
                    .unwrap_or_else(|| matched.to_string())
            })
            .into_owned();
    }

    segments.concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;

    #[test]
    fn test_context_lines_middle_of_file() {
        let lines: Vec<String> = (1..=10).map(|n| format!("line{n}")).collect();
        let (before, after) = context_lines(&lines, 5, 2);
        assert_eq!(before, "line3\nline4");
        assert_eq!(after, "line6\nline7");
    }

    #[test]
    fn test_context_lines_at_start_of_file() {
        let lines: Vec<String> = (1..=5).map(|n| format!("line{n}")).collect();
        let (before, after) = context_lines(&lines, 1, 2);
        assert_eq!(before, "");
        assert_eq!(after, "line2\nline3");
    }

    #[test]
    fn test_context_lines_at_end_of_file() {
        let lines: Vec<String> = (1..=5).map(|n| format!("line{n}")).collect();
        let (before, after) = context_lines(&lines, 5, 2);
        assert_eq!(before, "line3\nline4");
        assert_eq!(after, "");
    }

    #[test]
    fn test_context_lines_trims_trailing_whitespace() {
        let lines = vec!["a  ".to_string(), "b\t".to_string(), "c".to_string()];
        let (before, _) = context_lines(&lines, 3, 2);
        assert_eq!(before, "a\nb");
    }

    #[test]
    fn test_escape_all_special_chars() {
        assert_eq!(
            escape(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;'"
        );
    }

    #[test]
    fn test_escape_preserves_plain_text() {
        assert_eq!(escape("hello world"), "hello world");
    }

    #[test]
    fn test_is_dependency_vendor_path() {
        assert!(is_dependency("app/vendor/lib.js"));
        assert!(is_dependency("src/node_modules/foo/bar.js"));
        assert!(is_dependency("src/foo.min.js"));
    }

    #[test]
    fn test_is_dependency_declaration_files() {
        assert!(is_dependency("requirements.txt"));
        assert!(is_dependency("PACKAGE.JSON"));
    }

    #[test]
    fn test_is_dependency_business_code_is_false() {
        assert!(!is_dependency("src/app/views.py"));
    }

    #[test]
    fn test_lang_label_known_extensions() {
        assert_eq!(lang_label("app.py"), "Python");
        assert_eq!(lang_label("app.tsx"), "TypeScript");
        assert_eq!(lang_label("Dockerfile"), "Dockerfile");
        assert_eq!(lang_label("path/to/Dockerfile"), "Dockerfile");
    }

    #[test]
    fn test_lang_label_unknown_extension_is_empty() {
        assert_eq!(lang_label("data.bin"), "");
    }

    #[test]
    fn test_linkify_acronyms_wraps_known_term() {
        let en = load_report_locale("en");
        let out = linkify_acronyms(&en, "This uses ASVS heavily.");
        assert!(out.contains(r##"href="#acr-asvs""##));
        assert!(out.contains(">ASVS<"));
    }

    #[test]
    fn test_linkify_acronyms_no_match_unchanged() {
        let en = load_report_locale("en");
        let out = linkify_acronyms(&en, "no acronym here");
        assert_eq!(out, "no acronym here");
    }

    #[test]
    fn test_linkify_acronyms_in_html_skips_code_blocks() {
        let en = load_report_locale("en");
        let html = "<p>ASVS coverage</p><pre><code>ASVS</code></pre>";
        let out = linkify_acronyms_in_html(&en, html);
        assert_eq!(out.matches("glossary-link").count(), 1);
        assert!(out.contains("<pre><code>ASVS</code></pre>"));
    }

    #[test]
    fn test_linkify_acronyms_in_html_skips_existing_links() {
        let en = load_report_locale("en");
        let html = r##"<a href="#x">ASVS</a> and ASVS again"##;
        let out = linkify_acronyms_in_html(&en, html);
        assert_eq!(out.matches("glossary-link").count(), 1);
    }

    #[test]
    fn test_linkify_acronyms_in_html_respects_glossary_no_linkify() {
        let en = load_report_locale("en");
        let html = "<!-- GLOSSARY_NO_LINKIFY -->ASVS<!-- /GLOSSARY_NO_LINKIFY --><p>ASVS</p>";
        let out = linkify_acronyms_in_html(&en, html);
        assert_eq!(out.matches("glossary-link").count(), 1);
    }

    #[test]
    fn test_linkify_acronyms_prefix_term_not_double_matched() {
        let en = load_report_locale("en");
        // If both HTTP and HTTPS are in the glossary, HTTPS must not
        // get partially re-matched by HTTP once linkified.
        let glossary = crate::i18n::get_nested(&en, "glossary.acronyms").unwrap();
        if glossary.get("http").is_some() && glossary.get("https").is_some() {
            let out = linkify_acronyms(&en, "HTTPS is secure");
            assert_eq!(out.matches("glossary-link").count(), 1);
        }
    }
}
