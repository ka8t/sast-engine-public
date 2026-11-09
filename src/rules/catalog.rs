//! The rule catalog, loaded at run time from encrypted rule packs
//! (ADR-0037, ticket #141) — replaces the catalog compiled into the
//! binary since ticket #65.
//!
//! The engine reads every `*.scapack` file of a packs directory
//! (`rules/` next to the executable by default, see `main.rs`), opens
//! each one with the key its header names, and compiles the `.sca`
//! sources in memory, never writing them to disk. The keys are the
//! public demo key and, when a `sast-engine.key` file is found, the
//! client key (ticket #142, `client_key.rs`). A pack needing another key
//! (another client's pack) is skipped and listed apart from broken packs,
//! so the CLI can report all of them in one notice.
//!
//! `build.rs` writes `rules/builtin.scapack` next to the compiled
//! binary from the `.sca` files of `rules/builtin`, encrypted with the
//! demo key, so `cargo build`/`cargo run`/the CLI tests keep a catalog.
//! No rule source is embedded in the binary any more.
//!
//! Signed packs (ticket #144) are checked against the CodeFixture public
//! key before they are decrypted; one whose signature does not verify is
//! rejected, never loaded as client rules. Every rule then carries its
//! origin (`RuleOrigin`): the public builtin catalog, an official
//! CodeFixture pack, or the client's own rules.

use std::path::{Path, PathBuf};

use super::pack_format::{self, PACK_EXTENSION, RuleSource};

/// Rule files gathered from a packs directory, plus one error per pack
/// that could not be opened (path, reason). An unreadable pack never
/// stops the others from loading.
#[derive(Debug, Default)]
pub struct LoadedCatalog {
    /// Rule sources of every opened pack, in pack file name order, each
    /// pack's files in path order.
    pub files: Vec<RuleSource>,
    /// Packs that could not be read or opened (corrupt, truncated, not a
    /// pack), with the reason.
    pub errors: Vec<(PathBuf, String)>,
    /// Valid packs skipped because they need a key the engine does not
    /// have: path and the fingerprint of the key they need.
    pub foreign_packs: Vec<(PathBuf, String)>,
    /// Number of packs opened.
    pub packs_opened: usize,
    /// Origin of each entry of `files` (same length and order).
    pub origins: Vec<RuleOrigin>,
}

/// Where a rule comes from, written as `"origin"` on each compiled rule so
/// the report can tell CodeFixture's rules from the client's (ADR-0037).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleOrigin {
    /// Unsigned pack encrypted with the public demo key: the builtin
    /// catalog written by `build.rs` (demo rules in the shared repository).
    Builtin,
    /// Signed pack whose CodeFixture signature verified.
    Official,
    /// Unsigned pack encrypted with the client key: the client's own rules.
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

/// Checks the signature of a signed pack: `(signed bytes, signature)`.
pub type SignatureCheck<'a> = &'a dyn Fn(&[u8], &[u8; 64]) -> Result<(), String>;

/// Default packs directory: `rules/` next to the running executable.
/// `None` only if the executable path is unknown.
pub fn default_packs_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("rules")))
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

/// Opens every pack of `dir` that the demo key or `client_key` can open,
/// checking signed packs with the CodeFixture public key of this build.
/// The key is chosen from the fingerprint in each pack's header, so a
/// pack is decrypted at most once.
pub fn load_catalog(dir: &Path, client_key: Option<&[u8; 32]>) -> LoadedCatalog {
    load_catalog_checked(dir, client_key, &super::rule_packs::verify_pack_signature)
}

/// [`load_catalog`] with the signature check passed in (tests use their
/// own CodeFixture key pair).
pub fn load_catalog_checked(
    dir: &Path,
    client_key: Option<&[u8; 32]>,
    check_signature: SignatureCheck,
) -> LoadedCatalog {
    let demo_fingerprint = pack_format::key_fingerprint(&pack_format::demo_key());
    let mut keys = vec![pack_format::demo_key()];
    keys.extend(client_key.copied());
    let mut catalog = LoadedCatalog::default();
    for path in pack_files(dir) {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                catalog
                    .errors
                    .push((path, format!("unreadable rule pack: {e}")));
                continue;
            }
        };
        let header = match pack_format::read_header(&bytes) {
            Ok(header) => header,
            Err(reason) => {
                catalog.errors.push((path, reason));
                continue;
            }
        };
        let Some(key) = keys
            .iter()
            .find(|key| pack_format::key_fingerprint(key) == header.key_fingerprint)
        else {
            catalog.foreign_packs.push((path, header.key_fingerprint));
            continue;
        };
        // Signature first: a forged or altered official pack is rejected
        // before anything is decrypted.
        let origin = match pack_format::signed_content(&bytes) {
            Ok(Some((message, signature))) => match check_signature(message, &signature) {
                Ok(()) => RuleOrigin::Official,
                Err(reason) => {
                    catalog
                        .errors
                        .push((path, format!("signed rule pack rejected: {reason}")));
                    continue;
                }
            },
            Ok(None) if header.key_fingerprint == demo_fingerprint => RuleOrigin::Builtin,
            Ok(None) => RuleOrigin::Client,
            Err(reason) => {
                catalog.errors.push((path, reason));
                continue;
            }
        };
        match pack_format::open_pack(&bytes, key) {
            Ok((_, mut files)) => {
                catalog
                    .origins
                    .extend(std::iter::repeat_n(origin, files.len()));
                catalog.files.append(&mut files);
                catalog.packs_opened += 1;
            }
            Err(reason) => catalog.errors.push((path, reason)),
        }
    }
    catalog
}

/// Compiles rule sources **entirely in memory** (`compile_sca_to_json`
/// takes a string, not a path): compiled rules plus one error per
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

/// [`compile_catalog`] for a loaded catalog: every compiled rule gets an
/// `"origin"` field (`builtin`/`official`/`client`, see [`RuleOrigin`]).
pub fn compile_loaded_catalog(
    catalog: &LoadedCatalog,
) -> (Vec<serde_json::Value>, Vec<(PathBuf, String)>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for (file, origin) in catalog.files.iter().zip(&catalog.origins) {
        let (mut compiled, mut file_errors) = compile_catalog(std::slice::from_ref(file));
        for rule in &mut compiled {
            if let Some(obj) = rule.as_object_mut() {
                obj.insert("origin".to_string(), origin.as_str().into());
            }
        }
        rules.append(&mut compiled);
        errors.append(&mut file_errors);
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

/// The `.sca` sources of `rules/builtin` in this repository — what
/// `build.rs` packs. For tests that check the catalog itself.
#[cfg(test)]
pub(crate) fn source_catalog() -> Vec<RuleSource> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("rules")
        .join("builtin");
    pack_format::collect_sca_sources(&root)
}

/// A packs directory holding `rules/builtin` packed with the demo key,
/// built once per test process — the test counterpart of the
/// `rules/builtin.scapack` that `build.rs` writes next to the binary
/// (unit test binaries live in `deps/`, not next to it).
#[cfg(test)]
pub(crate) fn test_packs_dir() -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("sast_test_packs_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("test packs dir");
        let pack = pack_format::write_pack("builtin", &source_catalog(), &pack_format::demo_key());
        std::fs::write(dir.join("builtin.scapack"), pack).expect("test pack");
        dir
    })
    .clone()
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

    const RULE: &str = "rule pack_rule\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  PACK_MARKER\n    scope    line\n  end\nend\n";

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

    /// The pack written for the tests (same code as `build.rs`) opens
    /// with the demo key and gives back exactly the source catalog.
    #[test]
    fn test_load_catalog_opens_builtin_pack_with_demo_key() {
        let dir = test_packs_dir();
        let catalog = load_catalog(&dir, None);
        assert!(catalog.errors.is_empty(), "{:?}", catalog.errors);
        assert_eq!(catalog.packs_opened, 1);
        assert_eq!(catalog.files, source_catalog());
    }

    /// Ticket #141 acceptance: a corrupt or truncated pack is reported
    /// with its path and skipped; the other packs still load. Packs are
    /// read in file name order; non-pack files are ignored.
    #[test]
    fn test_load_catalog_skips_corrupt_truncated_and_foreign_key_packs() {
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

        let catalog = load_catalog(&dir, None);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(catalog.packs_opened, 1);
        assert_eq!(catalog.files, files);
        let foreign: Vec<String> = catalog
            .foreign_packs
            .iter()
            .map(|(p, fp)| format!("{}:{fp}", p.file_name().unwrap().to_string_lossy()))
            .collect();
        let expected = format!(
            "d_client.scapack:{}",
            pack_format::key_fingerprint(&[9u8; 32])
        );
        assert_eq!(foreign, [expected]);
        let reasons: Vec<(String, &str)> = catalog
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
    fn test_load_catalog_with_client_key_opens_own_pack_only() {
        let dir = temp_dir("clients");
        let demo_files = vec![("python/demo.sca".to_string(), RULE.to_string())];
        let a_files = vec![(
            "python/a.sca".to_string(),
            RULE.replace("pack_rule", "a_rule"),
        )];
        let b_files = vec![(
            "python/b.sca".to_string(),
            RULE.replace("pack_rule", "b_rule"),
        )];
        let (key_a, key_b) = ([0xA1u8; 32], [0xB2u8; 32]);
        let demo_pack = pack_format::write_pack("demo", &demo_files, &pack_format::demo_key());
        std::fs::write(dir.join("demo.scapack"), demo_pack).unwrap();
        std::fs::write(
            dir.join("acme.scapack"),
            pack_format::write_pack("acme", &a_files, &key_a),
        )
        .unwrap();
        std::fs::write(
            dir.join("beta.scapack"),
            pack_format::write_pack("beta", &b_files, &key_b),
        )
        .unwrap();

        let without = load_catalog(&dir, None);
        let with_a = load_catalog(&dir, Some(&key_a));
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(without.files, demo_files);
        assert_eq!(without.foreign_packs.len(), 2);
        let mut expected = a_files.clone();
        expected.extend(demo_files);
        assert_eq!(
            with_a.files, expected,
            "acme.scapack sorts before demo.scapack"
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
    /// unsigned client pack loads as client rules; the builtin pack keeps
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
            RULE.replace("pack_rule", "official_rule"),
        )];
        let client_files = vec![(
            "python/c.sca".to_string(),
            RULE.replace("pack_rule", "client_rule"),
        )];
        let demo_files = vec![(
            "python/d.sca".to_string(),
            RULE.replace("pack_rule", "builtin_rule"),
        )];
        let official = super::super::rule_packs::write_official_pack(
            "official",
            &official_files,
            &client_key,
            &signing,
        );

        let dir = temp_dir("signed");
        std::fs::write(dir.join("a_official.scapack"), &official).unwrap();
        let client_pack = pack_format::write_pack("mine", &client_files, &client_key);
        std::fs::write(dir.join("b_client.scapack"), client_pack).unwrap();
        let demo_pack = pack_format::write_pack("builtin", &demo_files, &pack_format::demo_key());
        std::fs::write(dir.join("c_builtin.scapack"), demo_pack).unwrap();
        let loaded = load_catalog_checked(&dir, Some(&client_key), &check);
        let (rules, _) = compile_loaded_catalog(&loaded);

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
        let tampered = load_catalog_checked(&tampered_dir, Some(&client_key), &check);
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&tampered_dir).ok();

        assert!(loaded.errors.is_empty(), "{:?}", loaded.errors);
        assert_eq!(
            loaded.origins,
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
    fn test_pack_files_and_load_catalog_on_missing_dir() {
        let missing = Path::new("/nonexistent/sast/packs");
        assert!(pack_files(missing).is_empty());
        let catalog = load_catalog(missing, None);
        assert_eq!(catalog.packs_opened, 0);
        assert!(catalog.files.is_empty() && catalog.errors.is_empty());
    }

    #[test]
    fn test_default_packs_dir_is_rules_next_to_executable() {
        let dir = default_packs_dir().expect("current_exe is known in tests");
        assert_eq!(dir.file_name().unwrap(), "rules");
    }
}
