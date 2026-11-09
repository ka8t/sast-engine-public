//! Runtime brand customization ("white-label", ticket #87/spec #83) —
//! reads an optional `brand.json` file and supplies the values that
//! replace the "CodeFixture" defaults hardcoded in `main.rs`.
//!
//! The file sits in the same location as `custom-rules/`/`rules-updates/`, resolved the same
//! way — cf. `main.rs`. Missing
//! file, invalid JSON, or an unexpected schema: silent fallback to
//! the "CodeFixture" defaults (no blocking error), same philosophy as
//! `custom_rules_dir`/`rule_updates_dir` — an optional mechanism must
//! never break a scan that worked before its introduction. Each field
//! is independent: a partial `brand.json` (e.g. only `tool_name`)
//! touches ONLY that field, every other field stays at the
//! CodeFixture default — never an empty string displayed in place of
//! an absent field.
//!
//! Binary logo/favicon/icon: explicitly out of scope (cf. ticket #87's
//! body).

use std::path::Path;

use serde::Deserialize;

/// `brand.json` schema — all fields optional and independent (cf.
/// module doc). Field names aligned with the admin-side generator
/// (ticket #86): `tool_name`/`company_name`/`prefix`/
/// `primary_color`/`accent_color`/`background_color`/`website_url`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Brand {
    pub tool_name: Option<String>,
    pub company_name: Option<String>,
    /// Prefix for history files (`ScanConfig::brand_prefix`, default
    /// `"SCA"` — NOT "CodeFixture", cf. `ScanConfig::default()` in
    /// `orchestrator.rs`; only `tool_name`/`company_name` actually
    /// default to "CodeFixture").
    pub prefix: Option<String>,
    pub primary_color: Option<String>,
    pub accent_color: Option<String>,
    pub background_color: Option<String>,
    pub website_url: Option<String>,
}

/// Loads `brand.json` from `path`. `None` on any anomaly (missing,
/// unreadable file, invalid JSON) — never an error propagated to the
/// caller, cf. module doc.
pub fn load_brand_file(path: &Path) -> Option<Brand> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Effective tool name: `brand.tool_name` if present, otherwise the
/// historical CodeFixture default.
pub fn effective_tool_name(brand: &Brand) -> String {
    brand
        .tool_name
        .clone()
        .unwrap_or_else(|| "CodeFixture".to_string())
}

/// Effective company name: same contract as [`effective_tool_name`].
pub fn effective_company_name(brand: &Brand) -> String {
    brand
        .company_name
        .clone()
        .unwrap_or_else(|| "CodeFixture".to_string())
}

/// Effective URL for `informationUri` (SARIF export): `brand.website_url`
/// if present, otherwise the historical CodeFixture default.
pub fn effective_website_url(brand: &Brand) -> String {
    brand
        .website_url
        .clone()
        .unwrap_or_else(|| "https://codefixture.com".to_string())
}

/// Effective prefix for history files: `brand.prefix` if present,
/// otherwise the `"SCA"` default from `ScanConfig::default()`.
pub fn effective_prefix(brand: &Brand) -> String {
    brand.prefix.clone().unwrap_or_else(|| "SCA".to_string())
}

/// Characters accepted in a CSS color value injected directly into a
/// `<style>` block (not passed through the template's HTML escaping,
/// unlike `tool_name`/`company_name` which go through the same
/// substitution mechanism as the already-in-place "CodeFixture"
/// default). Covers hex (`#1e3a5f`), CSS color names (`steelblue`),
/// and the functional forms (`rgb(30, 58, 95)`/`rgba(...)`/`hsl(...)`)
/// — rejects everything else (notably `<`, `>`, `"`, `;`, `{`, `}`),
/// as defense in depth against injection into the generated HTML if
/// `brand.json` were ever tampered with (validating it before
/// injecting it as-is into HTML costs nothing).
fn is_safe_css_color(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "#(),. %-".contains(c))
}

/// Builds the `<style>` block that overrides brand colors, or `None`
/// if none of the 3 colors is supplied (or if every supplied value
/// fails the validation above — treated as absent, never injected
/// as-is).
///
/// **CSS targets chosen** (verified against `resources/templates/report.css`,
/// not assumed): only `--primary`/`--primary-light` actually exist as
/// variables named "primary color" — there is NO predefined
/// `--accent`/`--background` despite what ticket #87's description
/// suggested. `accent_color` overrides `--info` (already the de facto
/// accent role: links, chevrons, highlight borders) and
/// `background_color` overrides `--gray-50` (used directly by
/// `body { background: var(--gray-50); }`) — the semantically closest
/// targets rather than inventing variables that the main stylesheet
/// consumes nowhere.
pub fn brand_style_block(brand: &Brand) -> Option<String> {
    let mut overrides = String::new();
    if let Some(c) = brand
        .primary_color
        .as_deref()
        .filter(|c| is_safe_css_color(c))
    {
        overrides.push_str(&format!("--primary:{c};--primary-light:{c};"));
    }
    if let Some(c) = brand
        .accent_color
        .as_deref()
        .filter(|c| is_safe_css_color(c))
    {
        overrides.push_str(&format!("--info:{c};"));
    }
    if let Some(c) = brand
        .background_color
        .as_deref()
        .filter(|c| is_safe_css_color(c))
    {
        overrides.push_str(&format!("--gray-50:{c};"));
    }
    if overrides.is_empty() {
        return None;
    }
    Some(format!("<style>:root {{{overrides}}}</style>"))
}

/// Injects [`brand_style_block`] just before `</head>` of an
/// already-generated HTML document — after the main stylesheet
/// (`{{css}}` from `resources/templates/report-base.html`, substituted before
/// `</head>`), so the CSS cascade lets these overrides win without
/// touching the embedded static `.css` file. No-op if `html` doesn't
/// contain `</head>` (conservative fallback, never a panic on an
/// unexpected template) or if `block` is `None`.
pub fn inject_brand_style(html: String, block: Option<&str>) -> String {
    let Some(block) = block else { return html };
    match html.find("</head>") {
        Some(idx) => {
            let mut out = String::with_capacity(html.len() + block.len());
            out.push_str(&html[..idx]);
            out.push_str(block);
            out.push_str(&html[idx..]);
            out
        }
        None => html,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_brand(dir: &std::path::Path, content: &str) -> std::path::PathBuf {
        let path = dir.join("brand.json");
        std::fs::write(&path, content).unwrap();
        path
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sast-engine-test-brand-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ------------------------------------------------------- load_brand_file

    #[test]
    fn test_load_brand_file_absent_returns_none() {
        let dir = temp_dir("absent");
        assert!(load_brand_file(&dir.join("brand.json")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_brand_file_invalid_json_returns_none() {
        let dir = temp_dir("invalid-json");
        let path = write_brand(&dir, "{ not json");
        assert!(load_brand_file(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_brand_file_empty_object_is_valid_all_none() {
        let dir = temp_dir("empty");
        let path = write_brand(&dir, "{}");
        let brand = load_brand_file(&path).unwrap();
        assert!(brand.tool_name.is_none());
        assert!(brand.company_name.is_none());
        assert!(brand.prefix.is_none());
        assert!(brand.primary_color.is_none());
        assert!(brand.accent_color.is_none());
        assert!(brand.background_color.is_none());
        assert!(brand.website_url.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_brand_file_full_object() {
        let dir = temp_dir("full");
        let path = write_brand(
            &dir,
            r##"{
                "tool_name": "Acme Scan",
                "company_name": "Acme Inc",
                "prefix": "ACME",
                "primary_color": "#112233",
                "accent_color": "#445566",
                "background_color": "#f0f0f0",
                "website_url": "https://acme.example"
            }"##,
        );
        let brand = load_brand_file(&path).unwrap();
        assert_eq!(brand.tool_name.as_deref(), Some("Acme Scan"));
        assert_eq!(brand.company_name.as_deref(), Some("Acme Inc"));
        assert_eq!(brand.prefix.as_deref(), Some("ACME"));
        assert_eq!(brand.primary_color.as_deref(), Some("#112233"));
        assert_eq!(brand.accent_color.as_deref(), Some("#445566"));
        assert_eq!(brand.background_color.as_deref(), Some("#f0f0f0"));
        assert_eq!(brand.website_url.as_deref(), Some("https://acme.example"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_brand_file_partial_object_other_fields_none() {
        let dir = temp_dir("partial");
        let path = write_brand(&dir, r#"{"tool_name": "Acme Scan"}"#);
        let brand = load_brand_file(&path).unwrap();
        assert_eq!(brand.tool_name.as_deref(), Some("Acme Scan"));
        assert!(brand.company_name.is_none());
        assert!(brand.primary_color.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_brand_file_unknown_extra_fields_ignored() {
        let dir = temp_dir("extra-fields");
        let path = write_brand(
            &dir,
            r#"{"tool_name": "Acme Scan", "logo_url": "ignored.png"}"#,
        );
        let brand = load_brand_file(&path).unwrap();
        assert_eq!(brand.tool_name.as_deref(), Some("Acme Scan"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------- effective_* getters

    #[test]
    fn test_effective_tool_name_defaults_to_codefixture() {
        assert_eq!(effective_tool_name(&Brand::default()), "CodeFixture");
    }

    #[test]
    fn test_effective_tool_name_uses_brand_value() {
        let brand = Brand {
            tool_name: Some("Acme Scan".to_string()),
            ..Default::default()
        };
        assert_eq!(effective_tool_name(&brand), "Acme Scan");
    }

    #[test]
    fn test_effective_company_name_defaults_to_codefixture() {
        assert_eq!(effective_company_name(&Brand::default()), "CodeFixture");
    }

    #[test]
    fn test_effective_company_name_uses_brand_value() {
        let brand = Brand {
            company_name: Some("Acme Inc".to_string()),
            ..Default::default()
        };
        assert_eq!(effective_company_name(&brand), "Acme Inc");
    }

    #[test]
    fn test_effective_website_url_defaults_to_codefixture() {
        assert_eq!(
            effective_website_url(&Brand::default()),
            "https://codefixture.com"
        );
    }

    #[test]
    fn test_effective_website_url_uses_brand_value() {
        let brand = Brand {
            website_url: Some("https://acme.example".to_string()),
            ..Default::default()
        };
        assert_eq!(effective_website_url(&brand), "https://acme.example");
    }

    #[test]
    fn test_effective_prefix_defaults_to_sca() {
        assert_eq!(effective_prefix(&Brand::default()), "SCA");
    }

    #[test]
    fn test_effective_prefix_uses_brand_value() {
        let brand = Brand {
            prefix: Some("ACME".to_string()),
            ..Default::default()
        };
        assert_eq!(effective_prefix(&brand), "ACME");
    }

    // -------------------------------------------------- brand_style_block

    #[test]
    fn test_brand_style_block_none_when_no_colors() {
        assert!(brand_style_block(&Brand::default()).is_none());
    }

    #[test]
    fn test_brand_style_block_primary_only() {
        let brand = Brand {
            primary_color: Some("#112233".to_string()),
            ..Default::default()
        };
        let block = brand_style_block(&brand).unwrap();
        assert!(block.contains("--primary:#112233"));
        assert!(block.contains("--primary-light:#112233"));
        assert!(!block.contains("--info"));
        assert!(!block.contains("--gray-50"));
    }

    #[test]
    fn test_brand_style_block_accent_maps_to_info_var() {
        let brand = Brand {
            accent_color: Some("#445566".to_string()),
            ..Default::default()
        };
        let block = brand_style_block(&brand).unwrap();
        assert!(block.contains("--info:#445566"));
    }

    #[test]
    fn test_brand_style_block_background_maps_to_gray_50_var() {
        let brand = Brand {
            background_color: Some("#f0f0f0".to_string()),
            ..Default::default()
        };
        let block = brand_style_block(&brand).unwrap();
        assert!(block.contains("--gray-50:#f0f0f0"));
    }

    #[test]
    fn test_brand_style_block_all_three_colors() {
        let brand = Brand {
            primary_color: Some("#112233".to_string()),
            accent_color: Some("#445566".to_string()),
            background_color: Some("#f0f0f0".to_string()),
            ..Default::default()
        };
        let block = brand_style_block(&brand).unwrap();
        assert!(block.contains("--primary:#112233"));
        assert!(block.contains("--info:#445566"));
        assert!(block.contains("--gray-50:#f0f0f0"));
        assert!(block.starts_with("<style>"));
        assert!(block.ends_with("</style>"));
    }

    #[test]
    fn test_brand_style_block_rejects_injection_attempt() {
        let brand = Brand {
            primary_color: Some("red;}</style><script>alert(1)</script>".to_string()),
            ..Default::default()
        };
        // Invalid value (contains `<`/`>`/`;`/`/`) -> treated as
        // absent, no block produced.
        assert!(brand_style_block(&brand).is_none());
    }

    #[test]
    fn test_brand_style_block_accepts_functional_color_forms() {
        let brand = Brand {
            primary_color: Some("rgb(30, 58, 95)".to_string()),
            ..Default::default()
        };
        let block = brand_style_block(&brand).unwrap();
        assert!(block.contains("--primary:rgb(30, 58, 95)"));
    }

    // -------------------------------------------------- inject_brand_style

    #[test]
    fn test_inject_brand_style_none_block_is_noop() {
        let html = "<html><head></head><body></body></html>".to_string();
        assert_eq!(inject_brand_style(html.clone(), None), html);
    }

    #[test]
    fn test_inject_brand_style_inserts_before_closing_head() {
        let html = "<html><head><style>body{}</style></head><body></body></html>".to_string();
        let out = inject_brand_style(html, Some("<style>:root{--primary:red;}</style>"));
        assert!(out.contains("<style>body{}</style><style>:root{--primary:red;}</style></head>"));
    }

    #[test]
    fn test_inject_brand_style_missing_head_tag_is_noop() {
        let html = "<html><body>no head here</body></html>".to_string();
        let out = inject_brand_style(html.clone(), Some("<style>:root{--primary:red;}</style>"));
        assert_eq!(out, html);
    }
}
