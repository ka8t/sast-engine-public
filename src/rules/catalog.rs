//! The rule catalog, read at run time from a rules folder (ADR-0039):
//! `rules/` next to the executable by default, `--rules <DIR>` otherwise.
//! The folder holds two kinds of rule sources, read side by side:
//!
//! - **plain `.sca` files**, laid out by language
//!   (`<language>/<category>/<rule>.sca`). `build.rs` copies
//!   `rules/builtin` there: the full catalog in this repository, the demo
//!   rules in the shared one, so every build is usable as it is;
//! - **rule packs** (`*.scapack`, ADR-0037), directly in the folder: rule
//!   files encrypted with the public demo key or with a client key, signed
//!   when CodeFixture built them. This is how the editor hands a client
//!   the rules beyond the demo set.
//!
//! A scan only keeps the rule files of its target languages
//! ([`is_targeted_rule_path`]): the plain folders of the other languages
//! are listed, for the counts, but never read. When the same rule file
//! (same relative path, `python/security/eval_usage.sca`) exists in
//! several sources, it is read once, from the first source in this order:
//! signed CodeFixture packs, client packs, plain files, demo-key packs
//! ([`SourceRank`]). A plain file thus wins over a demo-key pack left over
//! from an older build, and a delivered pack wins over the demo copy of
//! the same rule.
//!
//! Signed packs (ticket #144) are checked against the CodeFixture public
//! key before they are decrypted; one whose signature does not verify is
//! rejected, never loaded as client rules. Every compiled rule carries
//! its origin (`RuleOrigin`) for the report.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::pack_format::{self, PACK_EXTENSION};

pub use super::pack_format::RuleSource;

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

/// Where a rule comes from, written as `"origin"` on each compiled rule so
/// the report can tell CodeFixture's rules from the client's (ADR-0037).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleOrigin {
    /// Plain `.sca` file of the rules folder, or pack encrypted with the
    /// public demo key: the catalog the build ships.
    Builtin,
    /// Signed pack whose CodeFixture signature verified.
    Official,
    /// The client's own rules: an unsigned pack encrypted with the client
    /// key, or a file of the custom rules folder.
    Client,
}

impl RuleOrigin {
    /// Value of the `"origin"` field of a compiled rule.
    pub fn as_str(self) -> &'static str {
        match self {
            RuleOrigin::Builtin => "builtin",
            RuleOrigin::Official => "official",
            RuleOrigin::Client => "client",
        }
    }
}

/// Order in which the sources of one rules folder are read; for a rule
/// file found in several of them, the first one wins (module comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SourceRank {
    OfficialPack,
    ClientPack,
    PlainFile,
    DemoPack,
}

/// Checks the signature of a signed pack: `(signed bytes, signature)`.
pub type SignatureCheck<'a> = &'a dyn Fn(&[u8], &[u8; 64]) -> Result<(), String>;

/// One rule file kept for a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedRuleFile {
    /// Path relative to the rules folder or inside the pack, with `/`
    /// separators: the key used to read each rule file once.
    pub rel_path: String,
    /// Name given to the compiler, shown in rule errors: the full path of
    /// a plain file, `<pack>.scapack:<relative path>` for a pack entry.
    pub source_name: String,
    /// `.sca` source.
    pub content: String,
    /// Origin written on the compiled rules.
    pub origin: RuleOrigin,
}

/// A rule pack opened while loading a rules folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedPack {
    /// Pack file.
    pub path: PathBuf,
    /// Origin of its rules: `Official` (signed), `Client` or `Builtin`
    /// (demo key).
    pub origin: RuleOrigin,
    /// Rule files it holds, every language.
    pub rule_files: usize,
}

/// What a rules folder gave a scan: the rule files kept, plus the counts
/// the CLI prints so a reader sees what was actually loaded (feedback of
/// 2026-11-10: a full catalog copied in an unread format went unnoticed).
#[derive(Debug, Default)]
pub struct LoadedRuleFolder {
    /// The rules folder.
    pub dir: PathBuf,
    /// Rule files kept for the target languages, in reading order
    /// ([`SourceRank`], then path).
    pub files: Vec<LoadedRuleFile>,
    /// Plain `.sca` files found in the folder, every language.
    pub plain_files: usize,
    /// Packs opened, in file name order.
    pub packs: Vec<OpenedPack>,
    /// Distinct rule files available, every source and language merged.
    pub files_available: usize,
    /// Rule files found again in a later source and not read twice.
    pub duplicates: usize,
    /// Packs or files that could not be read or opened, with the reason.
    /// One unreadable source never stops the others.
    pub errors: Vec<(PathBuf, String)>,
    /// Valid packs skipped because they need a key the engine does not
    /// have: path and the fingerprint of the key they need.
    pub foreign_packs: Vec<(PathBuf, String)>,
}

/// The counts of a [`LoadedRuleFolder`], without the rule sources: what
/// the scan report keeps for the CLI's rule lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleFolderSummary {
    /// The rules folder.
    pub dir: PathBuf,
    /// Plain `.sca` files found, every language.
    pub plain_files: usize,
    /// Packs opened.
    pub packs: Vec<OpenedPack>,
    /// Distinct rule files available, every source and language merged.
    pub files_available: usize,
    /// Rule files kept for the target languages.
    pub files_read: usize,
    /// Rule files found in several sources and read once.
    pub duplicates: usize,
}

impl LoadedRuleFolder {
    /// The counts of this folder, for the scan report.
    pub fn summary(&self) -> RuleFolderSummary {
        RuleFolderSummary {
            dir: self.dir.clone(),
            plain_files: self.plain_files,
            packs: self.packs.clone(),
            files_available: self.files_available,
            files_read: self.files.len(),
            duplicates: self.duplicates,
        }
    }
}

/// Default rules folder: `rules/` next to the running executable. `None`
/// only if the executable path is unknown.
pub fn default_rules_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("rules")))
}

/// Whether `dir` holds a rule source: a `.sca` file at any depth, or a
/// `*.scapack` pack directly inside it. The CLI stops on a rules folder
/// without any, rather than scanning with no rule.
pub fn has_rule_files(dir: &Path) -> bool {
    !pack_files(dir).is_empty() || has_sca_file(dir)
}

/// Whether `dir` holds a `.sca` file at any depth.
fn has_sca_file(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        match entry.file_type() {
            Ok(t) if t.is_dir() => has_sca_file(&path),
            Ok(t) if t.is_file() => path.extension().is_some_and(|e| e == "sca"),
            _ => false,
        }
    })
}

/// The `*.scapack` files directly inside `dir`, sorted by name. Empty if
/// `dir` is missing or unreadable.
pub fn pack_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut packs: Vec<PathBuf> = read_dir
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file() && path.extension().and_then(|e| e.to_str()) == Some(PACK_EXTENSION)
        })
        .collect();
    packs.sort();
    packs
}

/// Whether a rule file at `rel_path` (relative, `/` separators) is read
/// for the rule languages `languages`. A file under a language folder
/// (`java/…`) is read only when that language is targeted; any other file
/// (a flat test catalog, a client's custom folder without language
/// folders) is read, and the caller drops its compiled rules whose
/// `language` is not targeted.
pub fn is_targeted_rule_path(rel_path: &str, languages: &[String]) -> bool {
    match rel_path.split_once('/') {
        Some((first, _)) if RULE_LANGUAGES.contains(&first) => languages.iter().any(|l| l == first),
        _ => true,
    }
}

/// Relative paths (`/` separators) of every `.sca` file under `dir`,
/// sorted, without reading them. Symbolic links to folders are not
/// followed, like the scan walk (ticket #147).
fn sca_paths(dir: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
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
                let rel = path
                    .strip_prefix(root)
                    .expect("the file comes from root")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(rel);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Every `.sca` file under `dir`, recursively, as [`RuleSource`]s sorted
/// by path. An unreadable file is skipped. For the tests that check the
/// plain catalog itself.
pub fn read_rule_sources(dir: &Path) -> Vec<RuleSource> {
    sca_paths(dir)
        .into_iter()
        .filter_map(|rel| {
            std::fs::read_to_string(dir.join(&rel))
                .ok()
                .map(|content| (rel, content))
        })
        .collect()
}

/// Loads the rule files of `dir` for the rule languages `languages`:
/// plain `.sca` files and the packs that the demo key or `client_key`
/// opens, checking signed packs with the CodeFixture public key of this
/// build. `plain_origin` labels the plain files: `Builtin` for the rules
/// folder, `Client` for the custom rules folder.
pub fn load_rule_folder(
    dir: &Path,
    languages: &[String],
    client_key: Option<&[u8; 32]>,
    plain_origin: RuleOrigin,
) -> LoadedRuleFolder {
    load_rule_folder_checked(
        dir,
        languages,
        client_key,
        plain_origin,
        &super::rule_packs::verify_pack_signature,
    )
}

/// [`load_rule_folder`] with the signature check passed in (tests use
/// their own CodeFixture key pair).
///
/// Approach: open every pack first (each one is decrypted once, the key
/// chosen from the fingerprint in its header), list the plain files, then
/// walk all sources in [`SourceRank`] order, keeping the first copy of
/// each relative path. Only the plain files that are kept and targeted
/// are read from disk.
pub fn load_rule_folder_checked(
    dir: &Path,
    languages: &[String],
    client_key: Option<&[u8; 32]>,
    plain_origin: RuleOrigin,
    check_signature: SignatureCheck,
) -> LoadedRuleFolder {
    let mut folder = LoadedRuleFolder {
        dir: dir.to_path_buf(),
        ..LoadedRuleFolder::default()
    };
    let mut ranked: Vec<(SourceRank, Vec<RuleSource>, Option<&Path>, RuleOrigin)> = Vec::new();
    let opened = open_packs(dir, client_key, check_signature, &mut folder);
    for (pack, files) in &opened {
        let rank = match pack.origin {
            RuleOrigin::Official => SourceRank::OfficialPack,
            RuleOrigin::Client => SourceRank::ClientPack,
            RuleOrigin::Builtin => SourceRank::DemoPack,
        };
        ranked.push((rank, files.clone(), Some(pack.path.as_path()), pack.origin));
    }
    // Plain files: paths only, the content is read once a file is kept.
    let plain: Vec<RuleSource> = sca_paths(dir)
        .into_iter()
        .map(|rel| (rel, String::new()))
        .collect();
    folder.plain_files = plain.len();
    ranked.push((SourceRank::PlainFile, plain, None, plain_origin));
    // Stable sort: packs of the same rank stay in file name order.
    ranked.sort_by_key(|(rank, ..)| *rank);

    let mut seen: HashSet<String> = HashSet::new();
    for (_, files, pack_path, origin) in ranked {
        for (rel, content) in files {
            if !seen.insert(rel.clone()) {
                folder.duplicates += 1;
                continue;
            }
            folder.files_available += 1;
            if !is_targeted_rule_path(&rel, languages) {
                continue;
            }
            let (source_name, content) = match pack_path {
                Some(pack) => (format!("{}:{rel}", pack.display()), content),
                None => {
                    let path = dir.join(&rel);
                    match std::fs::read_to_string(&path) {
                        Ok(text) => (path.to_string_lossy().into_owned(), text),
                        Err(e) => {
                            folder
                                .errors
                                .push((path, format!("unreadable rule file: {e}")));
                            continue;
                        }
                    }
                }
            };
            folder.files.push(LoadedRuleFile {
                rel_path: rel,
                source_name,
                content,
                origin,
            });
        }
    }
    folder
}

/// Opens the packs of `dir` (see [`load_rule_folder_checked`]), recording
/// each opened pack, error and foreign pack in `folder`. Returns each
/// opened pack with its rule files.
fn open_packs(
    dir: &Path,
    client_key: Option<&[u8; 32]>,
    check_signature: SignatureCheck,
    folder: &mut LoadedRuleFolder,
) -> Vec<(OpenedPack, Vec<RuleSource>)> {
    let demo_fingerprint = pack_format::key_fingerprint(&pack_format::demo_key());
    let mut keys = vec![pack_format::demo_key()];
    keys.extend(client_key.copied());
    let mut opened = Vec::new();
    for path in pack_files(dir) {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                folder
                    .errors
                    .push((path, format!("unreadable rule pack: {e}")));
                continue;
            }
        };
        let header = match pack_format::read_header(&bytes) {
            Ok(header) => header,
            Err(reason) => {
                folder.errors.push((path, reason));
                continue;
            }
        };
        let Some(key) = keys
            .iter()
            .find(|key| pack_format::key_fingerprint(key) == header.key_fingerprint)
        else {
            folder.foreign_packs.push((path, header.key_fingerprint));
            continue;
        };
        // Signature first: a forged or altered official pack is rejected
        // before anything is decrypted.
        let origin = match pack_format::signed_content(&bytes) {
            Ok(Some((message, signature))) => match check_signature(message, &signature) {
                Ok(()) => RuleOrigin::Official,
                Err(reason) => {
                    folder
                        .errors
                        .push((path, format!("signed rule pack rejected: {reason}")));
                    continue;
                }
            },
            Ok(None) if header.key_fingerprint == demo_fingerprint => RuleOrigin::Builtin,
            Ok(None) => RuleOrigin::Client,
            Err(reason) => {
                folder.errors.push((path, reason));
                continue;
            }
        };
        match pack_format::open_pack(&bytes, key) {
            Ok((_, files)) => {
                let pack = OpenedPack {
                    path,
                    origin,
                    rule_files: files.len(),
                };
                folder.packs.push(pack.clone());
                opened.push((pack, files));
            }
            Err(reason) => folder.errors.push((path, reason)),
        }
    }
    opened
}

/// Compiles rule sources **entirely in memory** (`compile_sca_to_json`
/// takes a string, not a path): compiled rules plus one error per
/// invalid file.
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

/// Compiles the rule files of a loaded folder: each compiled rule gets
/// its `"origin"` field, and a rule whose `language` is not in
/// `languages` is dropped (a rule without `language` is kept). One error
/// per invalid file, which never stops the others.
pub fn compile_rule_folder(
    folder: &LoadedRuleFolder,
    languages: &[String],
) -> (Vec<serde_json::Value>, Vec<(PathBuf, String)>) {
    let targeted = |rule: &serde_json::Value| match rule.get("language").and_then(|v| v.as_str()) {
        Some(language) => languages.iter().any(|l| l == language),
        None => true,
    };
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for file in &folder.files {
        match crate::scan::parser::compile_sca_to_json(&file.content, &file.source_name) {
            Ok(compiled) => {
                for mut rule in compiled.into_iter().filter(targeted) {
                    if let Some(obj) = rule.as_object_mut() {
                        obj.insert("origin".to_string(), file.origin.as_str().into());
                    }
                    rules.push(rule);
                }
            }
            Err(e) => errors.push((PathBuf::from(&file.source_name), e.to_string())),
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

    fn langs(list: &[&str]) -> Vec<String> {
        list.iter().map(|l| l.to_string()).collect()
    }

    const RULE: &str = "rule pack_rule\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  PACK_MARKER\n    scope    line\n  end\nend\n";

    fn rule_named(id: &str, language: &str) -> String {
        RULE.replace("pack_rule", id).replace("python", language)
    }

    /// Relative paths of the kept files, with their origin.
    fn kept(folder: &LoadedRuleFolder) -> Vec<(String, RuleOrigin)> {
        folder
            .files
            .iter()
            .map(|f| (f.rel_path.clone(), f.origin))
            .collect()
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

    #[test]
    fn test_is_targeted_rule_path_filters_language_folders_only() {
        let python = langs(&["python"]);
        assert!(is_targeted_rule_path("python/security/a.sca", &python));
        assert!(!is_targeted_rule_path("java/security/a.sca", &python));
        assert!(is_targeted_rule_path("flat.sca", &python));
        assert!(is_targeted_rule_path("shared/a.sca", &python));
        assert!(!is_targeted_rule_path("python/a.sca", &[]));
    }

    #[test]
    fn test_has_rule_files_and_read_rule_sources() {
        let dir = temp_dir("sources");
        assert!(!has_rule_files(&dir));
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        std::fs::write(dir.join("python/security/notes.txt"), "x").unwrap();
        assert!(!has_rule_files(&dir), "only .sca files and packs count");
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

        let packs_only = temp_dir("packs_only");
        let pack = pack_format::write_pack("demo", &[], &pack_format::demo_key());
        std::fs::write(packs_only.join("demo.scapack"), pack).unwrap();
        assert!(has_rule_files(&packs_only), "a pack alone is a rule source");
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&packs_only).ok();
    }

    /// Plain files: only the targeted language folders are kept, the
    /// counts cover every language, and the compiled rules are filtered
    /// on their `language` (a flat Java file is read, then dropped).
    #[test]
    fn test_load_rule_folder_plain_files_for_target_languages() {
        let dir = temp_dir("plain");
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        std::fs::create_dir_all(dir.join("java/security")).unwrap();
        std::fs::write(dir.join("python/security/p.sca"), rule_named("p", "python")).unwrap();
        std::fs::write(dir.join("java/security/j.sca"), rule_named("j", "java")).unwrap();
        std::fs::write(dir.join("flat.sca"), rule_named("flat_java", "java")).unwrap();

        let folder = load_rule_folder(&dir, &langs(&["python"]), None, RuleOrigin::Builtin);
        let (rules, errors) = compile_rule_folder(&folder, &langs(&["python"]));
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(folder.plain_files, 3);
        assert_eq!(folder.files_available, 3);
        assert_eq!(
            kept(&folder),
            [
                ("flat.sca".to_string(), RuleOrigin::Builtin),
                ("python/security/p.sca".to_string(), RuleOrigin::Builtin)
            ]
        );
        assert!(errors.is_empty(), "{errors:?}");
        let ids: Vec<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();
        assert_eq!(ids, ["p"]);
        assert_eq!(rules[0]["origin"], "builtin");
    }

    /// Feedback of 2026-11-10: a full catalog delivered as a pack next to
    /// the demo `.sca` files is read. A rule file present in both is read
    /// once: a plain file wins over a demo-key pack, a client pack wins
    /// over a plain file.
    #[test]
    fn test_load_rule_folder_merges_packs_and_plain_files_once() {
        let dir = temp_dir("merge");
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        std::fs::write(
            dir.join("python/security/demo.sca"),
            rule_named("demo", "python"),
        )
        .unwrap();
        std::fs::write(
            dir.join("python/security/edited.sca"),
            rule_named("edited_plain", "python"),
        )
        .unwrap();
        let demo_pack = vec![
            (
                "python/security/edited.sca".to_string(),
                rule_named("edited_stale", "python"),
            ),
            (
                "python/security/more.sca".to_string(),
                rule_named("more", "python"),
            ),
            ("java/security/j.sca".to_string(), rule_named("j", "java")),
        ];
        std::fs::write(
            dir.join("builtin.scapack"),
            pack_format::write_pack("builtin", &demo_pack, &pack_format::demo_key()),
        )
        .unwrap();
        let client_key = [0xC1u8; 32];
        let client_pack = vec![(
            "python/security/demo.sca".to_string(),
            rule_named("demo_full", "python"),
        )];
        std::fs::write(
            dir.join("full.scapack"),
            pack_format::write_pack("full", &client_pack, &client_key),
        )
        .unwrap();

        let folder = load_rule_folder(
            &dir,
            &langs(&["python"]),
            Some(&client_key),
            RuleOrigin::Builtin,
        );
        let (rules, _) = compile_rule_folder(&folder, &langs(&["python"]));
        std::fs::remove_dir_all(&dir).ok();

        assert!(folder.errors.is_empty(), "{:?}", folder.errors);
        assert_eq!(folder.packs.len(), 2);
        assert_eq!(folder.plain_files, 2);
        assert_eq!(folder.files_available, 4, "demo, edited, more, j");
        assert_eq!(folder.duplicates, 2);
        let mut ids: Vec<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();
        ids.sort();
        assert_eq!(ids, ["demo_full", "edited_plain", "more"]);
        let origin_of = |id: &str| {
            rules
                .iter()
                .find(|r| r["id"] == id)
                .and_then(|r| r["origin"].as_str())
                .map(String::from)
        };
        assert_eq!(origin_of("demo_full").as_deref(), Some("client"));
        assert_eq!(origin_of("more").as_deref(), Some("builtin"));
    }

    /// Ticket #141 acceptance: a corrupt or truncated pack is reported
    /// with its path and skipped; the other packs still load. Packs are
    /// read in file name order; non-pack files are ignored. A pack for
    /// another key is listed apart.
    #[test]
    fn test_load_rule_folder_skips_corrupt_truncated_and_foreign_key_packs() {
        let dir = temp_dir("mixed");
        let files = vec![("python/r.sca".to_string(), RULE.to_string())];
        let good = pack_format::write_pack("good", &files, &pack_format::demo_key());
        std::fs::write(dir.join("b_good.scapack"), &good).unwrap();
        let mut corrupt = good.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        std::fs::write(dir.join("a_corrupt.scapack"), &corrupt).unwrap();
        std::fs::write(dir.join("c_truncated.scapack"), &good[..12]).unwrap();
        let foreign = pack_format::write_pack("client", &files, &[9u8; 32]);
        std::fs::write(dir.join("d_client.scapack"), &foreign).unwrap();
        std::fs::write(dir.join("notes.txt"), "not a pack").unwrap();

        let folder = load_rule_folder(&dir, &langs(&["python"]), None, RuleOrigin::Builtin);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(folder.packs.len(), 1);
        assert_eq!(
            kept(&folder),
            [("python/r.sca".to_string(), RuleOrigin::Builtin)]
        );
        let foreign: Vec<String> = folder
            .foreign_packs
            .iter()
            .map(|(p, fp)| format!("{}:{fp}", p.file_name().unwrap().to_string_lossy()))
            .collect();
        let expected = format!(
            "d_client.scapack:{}",
            pack_format::key_fingerprint(&[9u8; 32])
        );
        assert_eq!(foreign, [expected]);
        let reasons: Vec<(String, &str)> = folder
            .errors
            .iter()
            .map(|(p, r)| {
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    r.as_str(),
                )
            })
            .collect();
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(reasons[0].0 == "a_corrupt.scapack" && reasons[0].1.contains("corrupt"));
        assert!(reasons[1].0 == "c_truncated.scapack" && reasons[1].1.contains("truncated"));
    }

    /// Ticket #142: without a client key only the demo pack opens; with
    /// client A's key, A's pack opens too and B's pack is skipped.
    #[test]
    fn test_load_rule_folder_with_client_key_opens_own_pack_only() {
        let dir = temp_dir("clients");
        let (key_a, key_b) = ([0xA1u8; 32], [0xB2u8; 32]);
        let write = |name: &str, id: &str, key: &[u8; 32]| {
            let files = vec![(format!("python/{id}.sca"), rule_named(id, "python"))];
            std::fs::write(
                dir.join(format!("{name}.scapack")),
                pack_format::write_pack(name, &files, key),
            )
            .unwrap();
        };
        write("demo", "demo_rule", &pack_format::demo_key());
        write("acme", "a_rule", &key_a);
        write("beta", "b_rule", &key_b);
        let python = langs(&["python"]);

        let without = load_rule_folder(&dir, &python, None, RuleOrigin::Builtin);
        let with_a = load_rule_folder(&dir, &python, Some(&key_a), RuleOrigin::Builtin);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            kept(&without),
            [("python/demo_rule.sca".to_string(), RuleOrigin::Builtin)]
        );
        assert_eq!(without.foreign_packs.len(), 2);
        assert_eq!(
            kept(&with_a),
            [
                ("python/a_rule.sca".to_string(), RuleOrigin::Client),
                ("python/demo_rule.sca".to_string(), RuleOrigin::Builtin)
            ],
            "a client pack is read before a demo-key pack"
        );
        let skipped: Vec<&str> = with_a
            .foreign_packs
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(skipped, ["beta.scapack"]);
        assert_eq!(
            with_a.foreign_packs[0].1,
            pack_format::key_fingerprint(&key_b)
        );
        assert!(with_a.errors.is_empty());
    }

    /// Ticket #144 acceptance: a pack signed by CodeFixture loads as
    /// official; the same pack with one byte changed (payload or header)
    /// is rejected with a clear message, not loaded as client rules; an
    /// unsigned client pack loads as client rules; the demo pack keeps
    /// its own origin. Origins reach the compiled rules.
    #[test]
    fn test_signed_packs_official_tampered_rejected_unsigned_client() {
        use ed25519_dalek::SigningKey;
        let signing = SigningKey::from_bytes(&[4u8; 32]);
        let public_hex: String = signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let check = |message: &[u8], signature: &[u8; 64]| {
            super::super::rule_packs::verify_pack_signature_with_key(
                message,
                signature,
                &public_hex,
            )
        };
        let client_key = [0xC1u8; 32];
        let official_files = vec![(
            "python/o.sca".to_string(),
            rule_named("official_rule", "python"),
        )];
        let client_files = vec![(
            "python/c.sca".to_string(),
            rule_named("client_rule", "python"),
        )];
        let demo_files = vec![(
            "python/d.sca".to_string(),
            rule_named("builtin_rule", "python"),
        )];
        let official = super::super::rule_packs::write_official_pack(
            "official",
            &official_files,
            &client_key,
            &signing,
        );
        let python = langs(&["python"]);

        let dir = temp_dir("signed");
        std::fs::write(dir.join("a_official.scapack"), &official).unwrap();
        let client_pack = pack_format::write_pack("mine", &client_files, &client_key);
        std::fs::write(dir.join("b_client.scapack"), client_pack).unwrap();
        let demo_pack = pack_format::write_pack("builtin", &demo_files, &pack_format::demo_key());
        std::fs::write(dir.join("c_builtin.scapack"), demo_pack).unwrap();
        let loaded = load_rule_folder_checked(
            &dir,
            &python,
            Some(&client_key),
            RuleOrigin::Builtin,
            &check,
        );
        let (rules, _) = compile_rule_folder(&loaded, &python);

        // One byte of the encrypted payload, then one byte of the header.
        let tampered_dir = temp_dir("tampered");
        let mut payload_changed = official.clone();
        let in_payload = official.len() - 64 - 5;
        payload_changed[in_payload] ^= 1;
        std::fs::write(tampered_dir.join("payload.scapack"), payload_changed).unwrap();
        let mut header_changed = official.clone();
        let name_at = official
            .windows(b"official".len())
            .position(|w| w == b"official")
            .unwrap();
        header_changed[name_at] = b'O';
        std::fs::write(tampered_dir.join("header.scapack"), header_changed).unwrap();
        let tampered = load_rule_folder_checked(
            &tampered_dir,
            &python,
            Some(&client_key),
            RuleOrigin::Builtin,
            &check,
        );
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&tampered_dir).ok();

        assert!(loaded.errors.is_empty(), "{:?}", loaded.errors);
        let origins: Vec<RuleOrigin> = loaded.packs.iter().map(|p| p.origin).collect();
        assert_eq!(
            origins,
            [
                RuleOrigin::Official,
                RuleOrigin::Client,
                RuleOrigin::Builtin
            ]
        );
        let origin_of = |id: &str| {
            rules
                .iter()
                .find(|r| r["id"] == id)
                .and_then(|r| r["origin"].as_str())
                .map(String::from)
        };
        assert_eq!(origin_of("official_rule").as_deref(), Some("official"));
        assert_eq!(origin_of("client_rule").as_deref(), Some("client"));
        assert_eq!(origin_of("builtin_rule").as_deref(), Some("builtin"));

        assert!(
            tampered.files.is_empty(),
            "nothing loads from an altered signed pack"
        );
        assert_eq!(tampered.errors.len(), 2, "{:?}", tampered.errors);
        for (_, reason) in &tampered.errors {
            assert!(reason.contains("signed rule pack rejected"), "{reason}");
        }
    }

    #[test]
    fn test_pack_files_and_load_rule_folder_on_missing_dir() {
        let missing = Path::new("/nonexistent/sast/packs");
        assert!(pack_files(missing).is_empty());
        let folder = load_rule_folder(missing, &langs(&["python"]), None, RuleOrigin::Builtin);
        assert!(folder.packs.is_empty() && folder.files.is_empty());
        assert!(folder.errors.is_empty());
        assert_eq!(folder.files_available, 0);
    }

    #[test]
    fn test_default_rules_dir_is_rules_next_to_executable() {
        let dir = default_rules_dir().expect("current_exe is known in tests");
        assert_eq!(dir.file_name().unwrap(), "rules");
    }
}
