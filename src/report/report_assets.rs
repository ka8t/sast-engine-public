//! HTML/CSS/JS templates, favicons and Chart.js library for the report —
//! port of `_load_template`/`_load_asset` (`Audit/sca/report.py`).
//!
//! Unlike Python (`resources/templates/`/`resources/assets/`/`resources/vendor/` files sitting
//! next to the compiled binary, read at runtime — cf. `SCRIPT_DIR` in
//! compiled mode in `sca/__init__.py`), these resources are embedded
//! here at compile time via `include_str!`/`include_bytes!`: they are
//! static, not editable by the client, and embedding eliminates
//! the "file forgotten next to the binary" failure mode with no
//! extra complexity — the same choice as for locales (`i18n/mod.rs`) and
//! the compliance mappings (`compliance.rs`).

use base64::Engine;

macro_rules! templates {
    ($(($name:literal, $path:literal)),+ $(,)?) => {
        const TEMPLATES: &[(&str, &str)] = &[
            $(($name, include_str!($path))),+
        ];
    };
}

templates! {
    ("audit-params.html", "../../resources/templates/audit-params.html"),
    ("audit.config.template.json", "../../resources/templates/audit.config.template.json"),
    ("category-badge.html", "../../resources/templates/category-badge.html"),
    ("charts.js", "../../resources/templates/charts.js"),
    ("charts.min.js", "../../resources/templates/charts.min.js"),
    ("cli-option-item.html", "../../resources/templates/cli-option-item.html"),
    ("comparison-full.html", "../../resources/templates/comparison-full.html"),
    ("comparison-item.html", "../../resources/templates/comparison-item.html"),
    ("comparison-section.html", "../../resources/templates/comparison-section.html"),
    ("custom-rules-section.html", "../../resources/templates/custom-rules-section.html"),
    ("delta.html", "../../resources/templates/delta.html"),
    ("finding-item.html", "../../resources/templates/finding-item.html"),
    ("finding-mini.html", "../../resources/templates/finding-mini.html"),
    ("findings-category-group.html", "../../resources/templates/findings-category-group.html"),
    ("findings-group.html", "../../resources/templates/findings-group.html"),
    ("findings-rule-group.html", "../../resources/templates/findings-rule-group.html"),
    ("fixture-detail.html", "../../resources/templates/fixture-detail.html"),
    ("fixture-status-span.html", "../../resources/templates/fixture-status-span.html"),
    ("fixture-type-span.html", "../../resources/templates/fixture-type-span.html"),
    ("fixtures-failures-wrapper.html", "../../resources/templates/fixtures-failures-wrapper.html"),
    ("fixtures-list.html", "../../resources/templates/fixtures-list.html"),
    ("fixtures-more.html", "../../resources/templates/fixtures-more.html"),
    ("fixtures-section.html", "../../resources/templates/fixtures-section.html"),
    ("health-category-card.html", "../../resources/templates/health-category-card.html"),
    ("heatmap-item.html", "../../resources/templates/heatmap-item.html"),
    ("report-base.html", "../../resources/templates/report-base.html"),
    ("report.css", "../../resources/templates/report.css"),
    ("report.js", "../../resources/templates/report.js"),
    ("report.min.css", "../../resources/templates/report.min.css"),
    ("report.min.js", "../../resources/templates/report.min.js"),
    ("severity-section.html", "../../resources/templates/severity-section.html"),
    ("successes-section.html", "../../resources/templates/successes-section.html"),
    ("test-failed-item.html", "../../resources/templates/test-failed-item.html"),
    ("tests-failed-list.html", "../../resources/templates/tests-failed-list.html"),
    ("tests-section.html", "../../resources/templates/tests-section.html"),
}

const VENDOR_CHART_JS: &str = include_str!("../../resources/vendor/chart.min.js");

macro_rules! assets {
    ($(($name:literal, $path:literal)),+ $(,)?) => {
        const ASSETS: &[(&str, &[u8])] = &[
            $(($name, include_bytes!($path))),+
        ];
    };
}

assets! {
    ("apple-touch-icon.png", "../../resources/assets/apple-touch-icon.png"),
    ("favicon-16x16.png", "../../resources/assets/favicon-16x16.png"),
    ("favicon-192x192.png", "../../resources/assets/favicon-192x192.png"),
    ("favicon-32x32.png", "../../resources/assets/favicon-32x32.png"),
    ("favicon-512x512.png", "../../resources/assets/favicon-512x512.png"),
    ("favicon-white.svg", "../../resources/assets/favicon-white.svg"),
    ("favicon.ico", "../../resources/assets/favicon.ico"),
    ("favicon.svg", "../../resources/assets/favicon.svg"),
    ("youtube-profile-800x800.png", "../../resources/assets/youtube-profile-800x800.png"),
}

/// Loads a template by its file name — port of `_load_template`
/// (without the `subdir="vendor"` parameter, cf. `load_vendor_chart_js`).
/// Panics on an unknown name: the catalog is fixed at compile time,
/// so a missing name is a typo on the caller's side, not a runtime
/// state to absorb (unlike Python, where the file can be
/// missing next to the binary).
pub fn load_template(name: &str) -> &'static str {
    TEMPLATES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, c)| *c)
        .unwrap_or_else(|| panic!("gabarit inconnu: {name}"))
}

/// Loads a CSS/JS asset, preferring its `.min.*` version if it
/// exists — port of `_load_asset`.
pub fn load_asset(name: &str) -> &'static str {
    if let Some((base, ext)) = name.rsplit_once('.') {
        let min_name = format!("{base}.min.{ext}");
        if TEMPLATES.iter().any(|(n, _)| *n == min_name) {
            return load_template(&min_name);
        }
    }
    load_template(name)
}

/// Vendored Chart.js library — port of
/// `_load_template("chart.min.js", "vendor")`.
pub fn load_vendor_chart_js() -> &'static str {
    VENDOR_CHART_JS
}

/// Loads a binary asset (favicon/logo) by its file name.
pub fn load_asset_bytes(name: &str) -> Option<&'static [u8]> {
    ASSETS.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}

/// Builds a `data:{mime};base64,...` data URI for an asset —
/// port of the core of `_load_logo`/the favicon fallback in `_generate_html`.
pub fn asset_data_uri(name: &str, mime: &str) -> Option<String> {
    let bytes = load_asset_bytes(name)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    Some(format!("data:{mime};base64,{b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_template_report_base_contains_placeholders() {
        let html = load_template("report-base.html");
        assert!(html.contains("{{"));
    }

    #[test]
    fn test_load_asset_prefers_min_version() {
        assert_eq!(load_asset("report.css"), load_template("report.min.css"));
        assert_eq!(load_asset("report.js"), load_template("report.min.js"));
        assert_eq!(load_asset("charts.js"), load_template("charts.min.js"));
    }

    #[test]
    #[should_panic(expected = "gabarit inconnu")]
    fn test_load_template_unknown_name_panics() {
        load_template("does-not-exist.html");
    }

    #[test]
    fn test_vendor_chart_js_not_empty() {
        assert!(load_vendor_chart_js().len() > 1000);
    }

    #[test]
    fn test_asset_data_uri_favicon() {
        let uri = asset_data_uri("favicon.svg", "image/svg+xml").expect("favicon.svg doit exister");
        assert!(uri.starts_with("data:image/svg+xml;base64,"));
    }

    #[test]
    fn test_asset_data_uri_unknown_returns_none() {
        assert!(asset_data_uri("does-not-exist.png", "image/png").is_none());
    }

    #[test]
    fn test_all_35_templates_present() {
        assert_eq!(TEMPLATES.len(), 35);
    }

    #[test]
    fn test_all_9_assets_present() {
        assert_eq!(ASSETS.len(), 9);
    }
}
