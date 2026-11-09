//! Reads `audit.config.json` (`paths.include`/`paths.exclude`) and
//! auto-detects project structure when this file is
//! absent — **partial** port of `Audit/sca/projects.py::
//! _auto_detect_project` (languages + root directories containing
//! code → proposed `paths.include`) and of `sca/config.py::load_config`
//! (reading `paths.include`/`paths.exclude`). Version/name detection
//! via `package.json`/`pyproject.toml` and the full interactive
//! wizard (7 steps, `sca/cli.py::_interactive_init`) are not
//! ported — out of scope (only `paths.include`/`paths.exclude`
//! affects file discovery, which is the reason this module exists).
//!
//! **Accepted deviation from Python, confirmed with the maintainer (2026-08-26)**:
//! on the Python side, this file is **silently** auto-generated on
//! each scan if absent (`sca/cli.py:1108-1111`,
//! `_init_project_config(force_init=False)`) — never interactive outside
//! an explicit `--init`. The maintainer explicitly requested an **interactive
//! proposal** on the Rust side rather than a silent write
//! (confirmed by asking, not assumed): the interaction logic
//! (prompting, TTY detection) lives in `main.rs`, this
//! module only detects/reads/writes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::scan::discovery::{WalkEntry, classify_entry};
use crate::scan::orchestrator::SourceLanguage;

/// Directories never relevant for detection — exact mirror of
/// `sca/projects.py::_EXCLUDED_DIRS`. Hidden directories
/// (`.` prefix) are excluded separately, same rule as Python.
const EXCLUDED_DIRS: &[&str] = &[
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "vendor",
    ".git",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
];

/// The engine's own output directories (reports, JSON history),
/// skipped by the detection walk on top of `EXCLUDED_DIRS` (ticket
/// #132): an HTML report from a previous scan made the prompt list
/// `html` among the project's languages. Kept apart from
/// `EXCLUDED_DIRS` so the `exclude` list written to `audit.config.json`
/// stays the Python one; the scan itself excludes these directories
/// through `main.rs::DEFAULT_EXCLUDES`, which now always applies.
const ENGINE_OUTPUT_DIRS: &[&str] = &["audit-reports", "audit-datas"];

/// Result of [`auto_detect_project`]: what the interactive prompt
/// proposes to write into `audit.config.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedProjectInfo {
    pub languages: Vec<String>,
    pub include_paths: Vec<String>,
    pub exclude_patterns: Vec<String>,
}

/// Detects the languages present and the root directories containing
/// code, to propose a restricted `paths.include` rather than
/// walking the whole project (mirror of `_auto_detect_project`, without
/// version/name detection — out of scope here, reserved for
/// the full interactive wizard on the Python side).
pub fn auto_detect_project(root: &Path) -> DetectedProjectInfo {
    let mut languages: BTreeSet<String> = BTreeSet::new();
    let mut top_level_dirs: BTreeSet<String> = BTreeSet::new();
    let mut has_root_level_files = false;

    walk_detect(
        root,
        root,
        &mut languages,
        &mut top_level_dirs,
        &mut has_root_level_files,
    );

    let mut include_paths: Vec<String> = top_level_dirs
        .into_iter()
        .map(|d| format!("{d}/"))
        .collect();
    if has_root_level_files || include_paths.is_empty() {
        include_paths.push(".".to_string());
    }
    include_paths.sort();
    include_paths.dedup();

    DetectedProjectInfo {
        languages: languages.into_iter().collect(),
        include_paths,
        exclude_patterns: EXCLUDED_DIRS.iter().map(|d| format!("**/{d}/**")).collect(),
    }
}

fn walk_detect(
    root: &Path,
    dir: &Path,
    languages: &mut BTreeSet<String>,
    top_level_dirs: &mut BTreeSet<String>,
    has_root_level_files: &mut bool,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        // Links to directories are not followed, like the scan walk
        // (`discovery::classify_entry`): a link to a parent folder would
        // otherwise recurse forever.
        let kind = classify_entry(&entry);
        if kind == WalkEntry::Skip {
            continue;
        }
        if kind == WalkEntry::Dir {
            if EXCLUDED_DIRS.contains(&name.as_str())
                || ENGINE_OUTPUT_DIRS.contains(&name.as_str())
                || name.starts_with('.')
            {
                continue;
            }
            walk_detect(root, &path, languages, top_level_dirs, has_root_level_files);
            continue;
        }
        let Some(lang) = SourceLanguage::from_path(&path) else {
            continue;
        };
        languages.insert(language_label(lang).to_string());
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let mut components = rel.components();
        let first = components.next();
        if components.next().is_some() {
            // Nested file: the 1st component of the relative path
            // is the detected root directory.
            if let Some(std::path::Component::Normal(top)) = first {
                top_level_dirs.insert(top.to_string_lossy().into_owned());
            }
        } else {
            *has_root_level_files = true;
        }
    }
}

fn language_label(lang: SourceLanguage) -> &'static str {
    match lang {
        SourceLanguage::Python => "python",
        SourceLanguage::Java => "java",
        SourceLanguage::JavaScript => "javascript",
        SourceLanguage::TypeScript => "typescript",
        SourceLanguage::Php => "php",
        SourceLanguage::CSharp => "csharp",
        SourceLanguage::Html => "html",
        SourceLanguage::Yaml => "yaml",
        SourceLanguage::Dockerfile => "dockerfile",
    }
}

/// Single reader of `audit.config.json` at the project root, shared by
/// every `read_*_config` function of this module (ticket #137).
///
/// - `Ok(None)`: no file — the only case where the caller may offer to
///   create one.
/// - `Ok(Some(json))`: the parsed file. A leading UTF-8 BOM is skipped:
///   Windows Notepad and PowerShell `Out-File` write one, and
///   `serde_json` rejects it, which made the whole file silently
///   ignored. Deliberate deviation from Python, whose
///   `json.load(open(...))` also fails on a BOM.
/// - `Err(message)`: the file exists but cannot be read or is not valid
///   JSON. The caller must say so, never treat it as absent: treating it
///   as absent offered to create the file and overwrote the user's
///   configuration.
pub fn load_config_json(root: &Path) -> Result<Option<serde_json::Value>, String> {
    let path = root.join("audit.config.json");
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let content = content.strip_prefix('\u{feff}').unwrap_or(&content);
    serde_json::from_str(content)
        .map(Some)
        .map_err(|e| e.to_string())
}

/// The parsed `audit.config.json`, or `None` when it is absent or
/// invalid — for the readers of optional sections, where both cases fall
/// back to the defaults (the invalid case is reported once, by the
/// caller of [`load_config_json`]).
fn config_json(root: &Path) -> Option<serde_json::Value> {
    load_config_json(root).ok().flatten()
}

/// Reads `paths.include`/`paths.exclude` from an existing
/// `audit.config.json` at the project root. `None` only if the file is
/// absent or invalid. A valid file without a `paths` section (or without
/// one of its two keys) returns empty lists, which the caller replaces by
/// the defaults: until ticket #137, a missing `paths` section made the
/// file look absent.
pub fn read_paths_config(root: &Path) -> Option<(Vec<String>, Vec<String>)> {
    let json = config_json(root)?;
    let paths = json.get("paths");
    let as_string_vec = |key: &str| -> Vec<String> {
        paths
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    };
    Some((as_string_vec("include"), as_string_vec("exclude")))
}

/// Keys of `audit.config.json` that should restrict the scan but are
/// ignored, wholly or partly, by [`read_paths_config`] — ticket #140. A
/// tester rewrote the file, the scan silently fell back to the whole
/// project, and nothing said why. Reported, in this order:
///
/// - `paths`: present but not an object (`"paths": []`);
/// - `paths.include` / `paths.exclude`: not an array (`"include": "src"`)
///   or holding a non-string item (dropped one by one);
/// - `include` / `exclude` at the top level instead of under `paths`.
///
/// Empty when the file is absent or invalid JSON (reported elsewhere) or
/// when every key is well formed. Python ignores all these cases silently
/// (`sca/config.py::load_config`); the warning is a deliberate addition,
/// the scan itself still behaves the same.
pub fn malformed_paths_keys(root: &Path) -> Vec<String> {
    let Some(json) = config_json(root) else {
        return Vec::new();
    };
    let Some(top_level) = json.as_object() else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    match top_level.get("paths") {
        Some(serde_json::Value::Object(paths)) => {
            for key in ["include", "exclude"] {
                let well_formed = match paths.get(key) {
                    None => true,
                    Some(serde_json::Value::Array(items)) => items.iter().all(|v| v.is_string()),
                    Some(_) => false,
                };
                if !well_formed {
                    keys.push(format!("paths.{key}"));
                }
            }
        }
        Some(_) => keys.push("paths".to_string()),
        None => {}
    }
    for key in ["include", "exclude"] {
        if top_level.contains_key(key) {
            keys.push(key.to_string());
        }
    }
    keys
}

/// Reads `rules.disabled` (list of rule ids) from an existing
/// `audit.config.json` at the project root — ticket #40/spec #27 (section
/// silently ignored until now, only `paths.*` was read). Empty if
/// the file is absent, unreadable, invalid, or does not contain this
/// section — same contract as `read_paths_config`, but returns
/// `Vec<String>` directly (no `Option`): an absent section and
/// an absent file must produce the same result for the caller
/// (empty list), which does not need to distinguish them, unlike
/// `read_paths_config` where the absence of the file triggers
/// interactive auto-detection.
///
/// Does NOT resolve the CLI priority `--disable-rule` > file > default:
/// that resolution lives in the caller (`main.rs::run_scan_command`),
/// this module only reads.
pub fn read_disabled_rules_config(root: &Path) -> Vec<String> {
    let Some(json) = config_json(root) else {
        return Vec::new();
    };
    json.get("rules")
        .and_then(|rules| rules.get("disabled"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Alias between the category name on the `audit.config.json` side (key
/// `architecture`, inherited from the Python naming
/// `sca/config.py::DEFAULT_CONFIG["categories"]`) and the `category`
/// value actually present in `.sca` rules (`arch`, short
/// name, cf. `rules/builtin/*/arch/`). Without this alias,
/// `categories.architecture.enabled` would never match any rule
/// — the same naming deviation already implicit for `--only-category`, which
/// expects `arch` and not `architecture`.
fn normalize_category_name(name: &str) -> String {
    if name.eq_ignore_ascii_case("architecture") {
        "arch".to_string()
    } else {
        name.to_lowercase()
    }
}

/// Reads `categories.<name>.enabled` from an existing `audit.config.json`
/// at the project root — ticket #41/spec #27. Mirror of
/// `AuditRunner.enabled_categories` on the Python side (`runner.py:104-112`):
/// a complete map, NOT a translation to `only_category`
/// (a distinct CLI mechanism, cf. the doc on `ScanConfig::category_overrides`
/// in `orchestrator.rs` for the detailed justification of this
/// separation). Empty map if the file is absent, unreadable,
/// invalid, or does not contain a `categories` section — an entry
/// absent from the returned map must be treated by the caller as
/// "enabled by default" (`true`), not as "disabled", exactly
/// like `enabled_categories.get(cat_key, True)` on the Python side.
pub fn read_category_overrides_config(root: &Path) -> BTreeMap<String, bool> {
    let Some(json) = config_json(root) else {
        return BTreeMap::new();
    };
    let Some(categories) = json.get("categories").and_then(|v| v.as_object()) else {
        return BTreeMap::new();
    };
    categories
        .iter()
        .filter_map(|(name, value)| {
            value
                .get("enabled")
                .and_then(|v| v.as_bool())
                .map(|enabled| (normalize_category_name(name), enabled))
        })
        .collect()
}

/// Reads `thresholds.max_high` from an existing `audit.config.json` at
/// the project root — ticket #42/spec #27. `0` (current behavior:
/// failure as soon as at least one HIGH/CRITICAL finding exists) if the
/// file is absent, unreadable, invalid, or does not contain this
/// key — same default as on the Python side
/// (`Audit/sca/cli.py::thresholds.get("max_high", 0)`).
///
/// **Accepted deviation from Python, confirmed with the maintainer (2026-09-01)**:
/// `thresholds.max_medium`/`thresholds.min_health` (also defined
/// in `sca/config.py::DEFAULT_CONFIG["thresholds"]`) are in
/// fact NEVER consumed anywhere in the Python code (exhaustive search
/// of the Python repo — dead config, like the "phantom ids"
/// of the compliance mappings documented elsewhere in this repo): not
/// ported here. The `confidence >= 80` filter on HIGH findings
/// ("verified HIGH", `sca/runner.py:783-791`, which totally excludes
/// CRITICAL from the count) and the `--fail-on-high` rule
/// (`sca/cli.py:1200`, which silently disables the whole gate as
/// soon as `max_high > 0` without this CLI flag, absent on the Rust side)
/// are also not reproduced — judged too surprising for a
/// limited benefit. The Rust gate remains unconditional and counts HIGH+CRITICAL
/// without a confidence filter (already existing behavior, unchanged),
/// only the threshold becomes configurable.
pub fn read_max_high_threshold_config(root: &Path) -> i64 {
    let Some(json) = config_json(root) else {
        return 0;
    };
    json.get("thresholds")
        .and_then(|t| t.get("max_high"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
}

/// Top-level sections deliberately not supported by
/// AuditRust as of today — ticket #43/spec #27. CLOSED and
/// exhaustive list (no heuristic detection of "unknown key", which
/// would produce false positives on future legitimate keys): `rules`
/// (ticket #40), `categories` (ticket #41), `thresholds` (ticket #42)
/// and `paths` (already handled, `read_paths_config`) are deliberately
/// excluded from it.
const UNSUPPORTED_CONFIG_SECTIONS: &[&str] = &[
    "tests",
    "fixtures",
    "retention",
    "database",
    "brand",
    "reports",
];

/// Detects unsupported top-level sections present
/// in an existing `audit.config.json` at the project root — ticket
/// #43/spec #27, to warn rather than silently ignore. Sorted list
/// (reproducible order for the caller, which displays a single
/// message listing all the offending keys). Empty if the file is
/// absent, unreadable, invalid, or contains only supported keys.
pub fn unsupported_config_sections(root: &Path) -> Vec<String> {
    let Some(json) = config_json(root) else {
        return Vec::new();
    };
    let Some(top_level) = json.as_object() else {
        return Vec::new();
    };
    let mut found: Vec<String> = UNSUPPORTED_CONFIG_SECTIONS
        .iter()
        .filter(|key| top_level.contains_key(**key))
        .map(|key| key.to_string())
        .collect();
    found.sort();
    found
}

/// Writes a minimal `audit.config.json` (just `project.name` +
/// `paths.include`/`paths.exclude`) from a detection — not the
/// full `DEFAULT_CONFIG` structure on the Python side (brand/reports/
/// categories/rules/tests/fixtures), out of scope for what affects
/// file discovery. A richer existing file (written by
/// Audit itself, or by the Python interactive wizard) remains
/// compatible: `read_paths_config` only reads `paths.*`.
pub fn write_audit_config_json(
    root: &Path,
    info: &DetectedProjectInfo,
) -> std::io::Result<PathBuf> {
    let path = root.join("audit.config.json");
    let project_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project");
    let json = serde_json::json!({
        "project": { "name": project_name },
        "languages": info.languages,
        "paths": {
            "include": info.include_paths,
            "exclude": info.exclude_patterns,
        }
    });
    let mut text = serde_json::to_string_pretty(&json).expect("sérialisation JSON valide");
    text.push('\n');
    // `create_new` (ticket #137): never overwrite an existing file, even
    // if a caller wrongly concluded it was absent — that is how a user's
    // configuration used to be replaced by the detected one.
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(text.as_bytes())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// A link to a parent folder no longer recurses forever, and a link to
    /// another folder adds no top-level directory of its own.
    #[cfg(unix)]
    #[test]
    fn test_walk_detect_skips_directory_links() {
        let dir = std::env::temp_dir().join(format!("sast-pc-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(&dir, "web/app.js", "let x = 1;\n");
        std::fs::create_dir_all(dir.join("mirror")).unwrap();
        std::os::unix::fs::symlink("../web", dir.join("mirror/web_link")).unwrap();
        std::os::unix::fs::symlink("..", dir.join("web/loop")).unwrap();

        let mut languages = BTreeSet::new();
        let mut top_level_dirs = BTreeSet::new();
        let mut has_root_level_files = false;
        walk_detect(
            &dir,
            &dir,
            &mut languages,
            &mut top_level_dirs,
            &mut has_root_level_files,
        );
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(top_level_dirs.into_iter().collect::<Vec<_>>(), ["web"]);
        assert!(!has_root_level_files);
    }

    #[test]
    fn test_walk_detect_collects_languages_and_top_dirs() {
        let dir = std::env::temp_dir().join(format!("sast-pc-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(&dir, "main.py", "x = 1\n");
        write_file(&dir, "web/app.ts", "let x = 1;\n");
        write_file(&dir, "web/deep/util.js", "let y = 2;\n");
        write_file(&dir, "notes.txt", "not code\n");
        write_file(&dir, "node_modules/pkg/index.js", "x;\n");
        write_file(&dir, ".git/hooks/pre-commit.py", "x = 1\n");
        write_file(&dir, "audit-reports/SCA-REPORT-x.html", "<html></html>");

        let mut languages = BTreeSet::new();
        let mut top_level_dirs = BTreeSet::new();
        let mut has_root_level_files = false;
        walk_detect(
            &dir,
            &dir,
            &mut languages,
            &mut top_level_dirs,
            &mut has_root_level_files,
        );
        std::fs::remove_dir_all(&dir).unwrap();

        let languages: Vec<String> = languages.into_iter().collect();
        assert_eq!(
            languages,
            ["javascript", "python", "typescript"].map(String::from)
        );
        assert_eq!(
            top_level_dirs.into_iter().collect::<Vec<_>>(),
            vec!["web".to_string()]
        );
        assert!(has_root_level_files);
    }

    #[test]
    fn test_config_json_absent_invalid_and_valid() {
        let dir = std::env::temp_dir().join(format!("sast-pc-cfgjson-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let absent = config_json(&dir);
        write_file(&dir, "audit.config.json", "{not json");
        let invalid = config_json(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"thresholds": {"max_high": 2}}"#,
        );
        let valid = config_json(&dir);
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(absent, None);
        assert_eq!(invalid, None, "invalid falls back like absent");
        assert_eq!(
            valid,
            Some(serde_json::json!({"thresholds": {"max_high": 2}}))
        );
    }

    #[test]
    fn test_auto_detect_finds_top_level_dirs() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(&dir, "sca/runner.py", "x = 1\n");
        write_file(&dir, "tests/test_x.py", "x = 1\n");
        write_file(&dir, ".venv/lib/numpy/core.py", "x = 1\n");
        write_file(&dir, "node_modules/pkg/index.js", "x = 1;\n");

        let info = auto_detect_project(&dir);
        assert_eq!(info.languages, vec!["python".to_string()]);
        assert_eq!(
            info.include_paths,
            vec!["sca/".to_string(), "tests/".to_string()]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_auto_detect_root_level_file_included_as_dot() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(&dir, "main.py", "x = 1\n");

        let info = auto_detect_project(&dir);
        assert_eq!(info.include_paths, vec![".".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_paths_config_absent_file_returns_none() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read_paths_config(&dir).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Ticket #137: a file without a `paths` section is present, not
    /// absent — empty lists (the caller applies the defaults), never
    /// `None`, which offered to create the file and overwrote it.
    #[test]
    fn test_read_paths_config_file_without_paths_section_is_present() {
        let dir = std::env::temp_dir().join(format!("sast-pc-137a-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"rules": {"disabled": ["x"]}}"#,
        );
        assert_eq!(read_paths_config(&dir), Some((Vec::new(), Vec::new())));
        assert_eq!(read_disabled_rules_config(&dir), vec!["x".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Ticket #137: a UTF-8 BOM (Windows Notepad, PowerShell) no longer
    /// hides the whole file from every reader.
    #[test]
    fn test_config_with_utf8_bom_is_read() {
        let dir = std::env::temp_dir().join(format!("sast-pc-137b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            "\u{feff}{\"paths\": {\"include\": [\"app/\"]}, \"thresholds\": {\"max_high\": 3}}",
        );
        assert_eq!(
            read_paths_config(&dir),
            Some((vec!["app/".to_string()], Vec::new()))
        );
        assert_eq!(read_max_high_threshold_config(&dir), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Ticket #137: absent and invalid are told apart, so the caller
    /// reports an invalid file instead of offering to replace it.
    #[test]
    fn test_load_config_json_distinguishes_absent_and_invalid() {
        let dir = std::env::temp_dir().join(format!("sast-pc-137c-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let absent = load_config_json(&dir);
        assert_eq!(absent, Ok(None));
        write_file(
            &dir,
            "audit.config.json",
            r#"{"paths": {"include": ["a/"],}}"#,
        );
        let invalid = load_config_json(&dir);
        assert!(invalid.is_err());
        assert_eq!(read_paths_config(&dir), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Ticket #137: writing never replaces an existing file.
    #[test]
    fn test_write_audit_config_json_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("sast-pc-137d-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(&dir, "audit.config.json", "{not json");
        let info = auto_detect_project(&dir);
        assert!(write_audit_config_json(&dir, &info).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join("audit.config.json")).unwrap(),
            "{not json"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Ticket #132: the engine's report directories don't feed the
    /// detected languages (a previous HTML report listed `html`).
    #[test]
    fn test_auto_detect_skips_engine_output_dirs() {
        let dir = std::env::temp_dir().join(format!("sast-pc-132-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(&dir, "app.py", "x = 1\n");
        write_file(
            &dir.join("docs/audit-reports"),
            "SCA-REPORT-x.html",
            "<html></html>",
        );
        let info = auto_detect_project(&dir);
        assert_eq!(info.languages, vec!["python".to_string()]);
        assert_eq!(info.include_paths, vec![".".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_paths_config_reads_include_and_exclude() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"paths": {"include": ["sca/"], "exclude": ["**/vendor/**"]}}"#,
        );
        let (include, exclude) = read_paths_config(&dir).expect("fichier présent et valide");
        assert_eq!(include, vec!["sca/".to_string()]);
        assert_eq!(exclude, vec!["**/vendor/**".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_disabled_rules_config_absent_file_returns_empty() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test6-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let rules = read_disabled_rules_config(&dir);
        assert!(rules.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_disabled_rules_config_absent_section_returns_empty() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test7-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"paths": {"include": ["sca/"]}}"#,
        );
        let rules = read_disabled_rules_config(&dir);
        assert!(rules.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_disabled_rules_config_reads_rules_disabled() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test8-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"rules": {"disabled": ["eval_usage", "base64_eval"]}}"#,
        );
        assert_eq!(
            read_disabled_rules_config(&dir),
            vec!["eval_usage".to_string(), "base64_eval".to_string()]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_category_overrides_config_absent_file_returns_empty() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test9-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read_category_overrides_config(&dir).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_category_overrides_config_absent_section_returns_empty() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test10-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"paths": {"include": ["sca/"]}}"#,
        );
        assert!(read_category_overrides_config(&dir).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_category_overrides_config_reads_enabled_flags() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test11-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"categories": {"security": {"enabled": false}, "ui": {"enabled": true}}}"#,
        );
        let overrides = read_category_overrides_config(&dir);
        assert_eq!(overrides.get("security"), Some(&false));
        assert_eq!(overrides.get("ui"), Some(&true));
        assert_eq!(overrides.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_category_overrides_config_aliases_architecture_to_arch() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test12-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"categories": {"architecture": {"enabled": false}}}"#,
        );
        let overrides = read_category_overrides_config(&dir);
        assert_eq!(overrides.get("arch"), Some(&false));
        assert!(!overrides.contains_key("architecture"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_max_high_threshold_config_absent_file_returns_zero() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test13-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let threshold = read_max_high_threshold_config(&dir);
        assert_eq!(threshold, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_max_high_threshold_config_absent_section_returns_zero() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test14-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"paths": {"include": ["sca/"]}}"#,
        );
        assert_eq!(read_max_high_threshold_config(&dir), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_max_high_threshold_config_reads_custom_value() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test15-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"thresholds": {"max_high": 3}}"#,
        );
        assert_eq!(read_max_high_threshold_config(&dir), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Ticket #140: every malformed or misplaced paths key is named; a
    /// well-formed file, an absent file and invalid JSON report nothing.
    #[test]
    fn test_malformed_paths_keys_cases() {
        let dir = std::env::temp_dir().join(format!("sast-pc-malformed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let check = |content: Option<&str>| -> Vec<String> {
            let path = dir.join("audit.config.json");
            match content {
                Some(text) => std::fs::write(&path, text).unwrap(),
                None => {
                    let _ = std::fs::remove_file(&path);
                }
            }
            malformed_paths_keys(&dir)
        };
        let cases: [(Option<&str>, &[&str]); 9] = [
            (None, &[]),
            (Some("{not json"), &[]),
            (
                Some(r#"{"paths": {"include": ["src"], "exclude": ["x/"]}}"#),
                &[],
            ),
            (Some(r#"{"project": {"name": "a"}}"#), &[]),
            (Some(r#"{"paths": {"include": "src"}}"#), &["paths.include"]),
            (
                Some(r#"{"paths": {"include": ["src", 3], "exclude": {}}}"#),
                &["paths.include", "paths.exclude"],
            ),
            (Some(r#"{"paths": []}"#), &["paths"]),
            (Some(r#"{"include": ["src"]}"#), &["include"]),
            (
                Some(r#"{"paths": "src", "include": ["a"], "exclude": ["b"]}"#),
                &["paths", "include", "exclude"],
            ),
        ];
        let results: Vec<Vec<String>> = cases.iter().map(|(text, _)| check(*text)).collect();
        std::fs::remove_dir_all(&dir).unwrap();
        for ((text, expected), got) in cases.iter().zip(results) {
            assert_eq!(got, expected.to_vec(), "{text:?}");
        }
    }

    #[test]
    fn test_unsupported_config_sections_absent_file_returns_empty() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test16-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sections = unsupported_config_sections(&dir);
        assert!(sections.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_unsupported_config_sections_none_when_only_supported_keys() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test17-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"paths": {"include": ["."]}, "rules": {"disabled": []}, "categories": {}, "thresholds": {"max_high": 0}}"#,
        );
        assert!(unsupported_config_sections(&dir).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_unsupported_config_sections_detects_single_key() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test18-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"database": {"enabled": true}}"#,
        );
        assert_eq!(
            unsupported_config_sections(&dir),
            vec!["database".to_string()]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_unsupported_config_sections_detects_and_sorts_multiple_keys() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test19-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_file(
            &dir,
            "audit.config.json",
            r#"{"reports": {}, "brand": {}, "tests": {"enabled": true}}"#,
        );
        assert_eq!(
            unsupported_config_sections(&dir),
            vec![
                "brand".to_string(),
                "reports".to_string(),
                "tests".to_string()
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_write_then_read_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sast-pc-test5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let info = DetectedProjectInfo {
            languages: vec!["python".to_string()],
            include_paths: vec!["src/".to_string()],
            exclude_patterns: vec!["**/vendor/**".to_string()],
        };
        write_audit_config_json(&dir, &info).unwrap();
        let (include, exclude) = read_paths_config(&dir).unwrap();
        assert_eq!(include, info.include_paths);
        assert_eq!(exclude, info.exclude_patterns);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
