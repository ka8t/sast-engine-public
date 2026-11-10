//! The rule catalog: plain `.sca` files read at run time, file by file,
//! from a rules folder (ADR-0038) — `rules/` next to the executable by
//! default, `--rules <DIR>` otherwise. Replaces the encrypted rule packs
//! of ADR-0037: no key, no signature, no pack format.
//!
//! The catalog is laid out by language, `<language>/<category>/<rule>.sca`
//! (`python/security/eval_usage.sca`). A scan only reads the folders of
//! its target languages ([`rule_start_paths`]): the `languages` key of
//! the project's `audit.config.json`, or the languages of the files it
//! found. `build.rs` copies `rules/builtin` of the repository into
//! `rules/` next to the compiled binary, so `cargo build`/`cargo run`/the
//! CLI tests always have a catalog beside the binary.

use std::path::{Path, PathBuf};

/// One rule file: path relative to the catalog root, with `/` separators
/// (`python/security/eval_usage.sca`), and its `.sca` source.
pub type RuleSource = (String, String);

/// Language folders of a catalog, which are also the values of a rule's
/// `language` field (`SourceLanguage::rule_tag`). TypeScript has no folder
/// of its own: its files run the `javascript` rules.
pub const RULE_LANGUAGES: [&str; 8] = [
    "csharp",
    "dockerfile",
    "html",
    "java",
    "javascript",
    "php",
    "python",
    "yaml",
];

/// Default rules folder: `rules/` next to the running executable. `None`
/// only if the executable path is unknown.
pub fn default_rules_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("rules")))
}

/// Whether `dir` holds at least one `.sca` file, at any depth. The CLI
/// stops on a rules folder without any, rather than scanning with no rule.
pub fn has_rule_files(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        match entry.file_type() {
            Ok(t) if t.is_dir() => has_rule_files(&path),
            Ok(t) if t.is_file() => path.extension().is_some_and(|e| e == "sca"),
            _ => false,
        }
    })
}

/// Start paths, relative to `rules_dir`, of the rule files a scan reads
/// for `languages` (rule tags, see [`RULE_LANGUAGES`]), sorted by name.
///
/// A first-level folder named after a language is kept only when that
/// language is targeted: the rules of the other languages are never read.
/// Any other first-level entry (a flat test catalog, a client's
/// `custom-rules/` without language folders) is kept: its files are read,
/// and the caller drops the compiled rules whose `language` is not
/// targeted. Empty when `rules_dir` cannot be read.
pub fn rule_start_paths(rules_dir: &Path, languages: &[String]) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(rules_dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_language_dir = entry.file_type().is_ok_and(|t| t.is_dir())
                && RULE_LANGUAGES.contains(&name.as_str());
            (!is_language_dir || languages.contains(&name)).then(|| PathBuf::from(name))
        })
        .collect();
    paths.sort();
    paths
}

/// Every `.sca` file under `dir`, recursively, as [`RuleSource`]s sorted
/// by path — for `list-rules`, which lists the whole catalog whatever the
/// project. An unreadable file is skipped. Symbolic links to folders are
/// not followed, like the scan walk (ticket #147).
pub fn read_rule_sources(dir: &Path) -> Vec<RuleSource> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<RuleSource>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                walk(root, &path, out);
            } else if file_type.is_file() && path.extension().is_some_and(|e| e == "sca") {
                let Ok(content) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let rel = path
                    .strip_prefix(root)
                    .expect("the file comes from root")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, content));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Compiles rule sources in memory: compiled rules plus one error per
/// invalid file, same shape as `orchestrator::load_rules`.
pub fn compile_catalog(files: &[RuleSource]) -> (Vec<serde_json::Value>, Vec<(PathBuf, String)>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for (rel_path, content) in files {
        match crate::scan::parser::compile_sca_to_json(content, rel_path) {
            Ok(compiled) => rules.extend(compiled),
            Err(e) => errors.push((PathBuf::from(rel_path), e.to_string())),
        }
    }
    (rules, errors)
}

/// Listing metadata of one catalog rule, for `sast-engine list-rules`.
#[derive(Debug, Clone)]
pub struct RuleListing {
    /// Rule identifier (`rule <id>` in the `.sca` file).
    pub id: String,
    /// Category = the rule's folder (`security`, `arch`, `ux`, `cicd`…),
    /// NOT the `category` field of the rule — same choice as
    /// `Audit/sca/cli.py::_build_rule_metadata` (`parts[1]` of the path
    /// relative to `rules/builtin`).
    pub category_dir: String,
    /// Compiled `risk` block (`{"en": …, "fr": …}`), `Null` if absent.
    pub risk: serde_json::Value,
}

/// One entry per distinct rule id of `files`, sorted by id — port of
/// `_build_rule_metadata`. A rule id defined in several languages (e.g.
/// `taint_xss` for Python, Java and C#) is listed once, like the Python
/// dict keyed by id; the first file in catalog order wins (Python keeps
/// the last one in `rglob` order, which is filesystem-dependent — a
/// stable choice is preferred here).
pub fn rule_listing(files: &[RuleSource]) -> Vec<RuleListing> {
    let mut by_id: std::collections::BTreeMap<String, RuleListing> =
        std::collections::BTreeMap::new();
    for (rel_path, content) in files {
        let category_dir = rel_path
            .split(['/', '\\'])
            .nth(1)
            .unwrap_or("security")
            .to_string();
        let Ok(compiled) = crate::scan::parser::compile_sca_to_json(content, rel_path) else {
            continue;
        };
        for rule in compiled {
            let Some(id) = rule.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            by_id.entry(id.to_string()).or_insert_with(|| RuleListing {
                id: id.to_string(),
                category_dir: category_dir.clone(),
                risk: rule.get("risk").cloned().unwrap_or(serde_json::Value::Null),
            });
        }
    }
    by_id.into_values().collect()
}

/// `rules/builtin` of this repository — the folder `build.rs` copies next
/// to the binary. For tests that scan with the real catalog.
#[cfg(test)]
pub(crate) fn builtin_rules_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("rules")
        .join("builtin")
}

/// The `.sca` sources of `rules/builtin`. For tests that check the
/// catalog itself.
#[cfg(test)]
pub(crate) fn source_catalog() -> Vec<RuleSource> {
    read_rule_sources(&builtin_rules_dir())
}

/// Set of rule ids of the compiled source catalog — ticket #37/spec #26
/// (compliance-mapping drift safeguard): each mapping test compares its
/// own file's keys against this set. `BTreeSet` for a reproducible error
/// message.
#[cfg(test)]
pub(crate) fn compiled_rule_ids() -> std::collections::BTreeSet<String> {
    compile_catalog(&source_catalog())
        .0
        .iter()
        .filter_map(|rule| rule.get("id").and_then(|id| id.as_str()).map(String::from))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sast_catalog_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_rule_listing_uses_folder_category_and_unique_ids() {
        let listing = rule_listing(&source_catalog());
        let ids: std::collections::BTreeSet<&str> = listing.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids.len(), listing.len(), "ids are unique");
        let cicd = listing
            .iter()
            .find(|r| r.category_dir == "cicd")
            .expect("YAML CI/CD rules are listed under their folder category");
        assert!(!cicd.id.is_empty());
        assert!(listing.iter().all(|r| !r.category_dir.ends_with(".sca")));
    }

    #[test]
    fn test_source_catalog_compiles_without_errors_for_four_languages() {
        let files = source_catalog();
        for lang in ["python/", "java/", "javascript/", "php/"] {
            let found = files.iter().any(|(rel, _)| rel.starts_with(lang));
            assert!(found, "no rule for {lang}");
        }
        let (rules, errors) = compile_catalog(&files);
        assert!(errors.is_empty(), "invalid rules: {errors:?}");
        assert!(!rules.is_empty());
    }

    /// Every first-level folder of the real catalog is a language folder:
    /// otherwise its rules would be read for every project. Files there
    /// (a macOS `.DS_Store`) are not rules and do not count.
    #[test]
    fn test_builtin_catalog_has_only_language_folders() {
        let entries = std::fs::read_dir(builtin_rules_dir()).unwrap();
        for entry in entries.flatten().filter(|e| e.path().is_dir()) {
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(
                RULE_LANGUAGES.contains(&name.as_str()),
                "rules/builtin/{name} is not a language folder"
            );
        }
    }

    /// ADR-0038: only the targeted language folders are walked; any other
    /// entry is kept (filtered later on each rule's `language`).
    #[test]
    fn test_rule_start_paths_keeps_targeted_languages_and_other_entries() {
        let dir = temp_dir("start_paths");
        for sub in ["python/security", "java/security", "shared"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        std::fs::write(dir.join("flat.sca"), "").unwrap();
        let paths = rule_start_paths(&dir, &["python".to_string()]);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("flat.sca"),
                PathBuf::from("python"),
                PathBuf::from("shared")
            ]
        );
        let none = rule_start_paths(&dir, &[]);
        assert_eq!(
            none,
            vec![PathBuf::from("flat.sca"), PathBuf::from("shared")]
        );
        assert!(rule_start_paths(&dir.join("missing"), &[]).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_has_rule_files_and_read_rule_sources() {
        let dir = temp_dir("sources");
        assert!(!has_rule_files(&dir));
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        std::fs::write(dir.join("python/security/notes.txt"), "x").unwrap();
        assert!(!has_rule_files(&dir), "only .sca files count");
        std::fs::write(dir.join("python/security/b.sca"), "B").unwrap();
        std::fs::write(dir.join("a.sca"), "A").unwrap();
        assert!(has_rule_files(&dir));
        assert_eq!(
            read_rule_sources(&dir),
            vec![
                ("a.sca".to_string(), "A".to_string()),
                ("python/security/b.sca".to_string(), "B".to_string())
            ]
        );
        assert!(!has_rule_files(&dir.join("missing")));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_default_rules_dir_is_rules_next_to_executable() {
        let dir = default_rules_dir().expect("current_exe is known in tests");
        assert_eq!(dir.file_name().unwrap(), "rules");
    }
}
