//! Finding suppression — `.sca-suppress.json` + inline `# sca-ignore`
//! (Step 5). Faithful port of
//! `Audit/sca/runner.py::_load_suppressions`/`_add_suppression`/
//! `_is_suppressed`, and of the inline filter in `_add_finding`.
//!
//! **Deliberately narrowed scope**: only `.sca-suppress.json` (the
//! file format, loadable independently of
//! `audit.config.json::rules.suppress`, which shares the same
//! `{"suppressions": [...]}` schema) and `# sca-ignore` are ported
//! here — not `disabled_rules` (a separate and trivial mechanism on
//! the Python side, a simple set of rule_ids to exclude, left to the
//! orchestrator, Step 5, not yet built).
//!
//! Temporary `#![allow(dead_code)]`: not yet wired up to the CLI.
#![allow(dead_code)]

use std::collections::HashMap;

/// Value of a suppression entry's `code_hash`, as stored after JSON
/// parsing — explicitly distinguishes absence (`Any`, suppresses
/// every occurrence) from a value that is present but of a
/// non-numeric type (`Invalid`, never matches). Python stores the raw
/// value without validation; an `==` comparison there between a
/// computed integer and a value of another type is always false (no
/// exception) — `Invalid` reproduces this behavior without confusing
/// "absent" with "present but invalid".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeHashSpec {
    Any,
    Exact(u32),
    Invalid,
}

/// Registry of suppressions loaded from `.sca-suppress.json` (or
/// `audit.config.json::rules.suppress`, same schema).
#[derive(Debug, Default)]
pub struct Suppressions {
    entries: HashMap<(String, String), Vec<CodeHashSpec>>,
}

impl Suppressions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads suppressions from the JSON content of
    /// `.sca-suppress.json`. Invalid JSON, or a missing/mistyped
    /// `"suppressions"` key → empty registry, never an error (mirrors
    /// the `logger.warning` + silent continuation on the Python side).
    pub fn load_from_json(json_str: &str) -> Self {
        let mut out = Suppressions::new();
        let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
            return out;
        };
        let Some(entries) = value.get("suppressions").and_then(|v| v.as_array()) else {
            return out;
        };
        for entry in entries {
            let rule_key = entry
                .get("rule_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let file = entry
                .get("file")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let code_hash = match entry.get("code_hash") {
                None | Some(serde_json::Value::Null) => CodeHashSpec::Any,
                Some(v) => v
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .map(CodeHashSpec::Exact)
                    .unwrap_or(CodeHashSpec::Invalid),
            };
            out.add(rule_key, file, code_hash);
        }
        out
    }

    fn add(&mut self, rule_key: String, file: String, code_hash: CodeHashSpec) {
        if rule_key.is_empty() || file.is_empty() {
            return;
        }
        self.entries
            .entry((rule_key, file))
            .or_default()
            .push(code_hash);
    }

    /// True if the finding `(rule_key, rel_path)` is covered by a
    /// `.sca-suppress.json` entry. A `code_hash: null` entry (or
    /// absent) suppresses every occurrence of this rule in this file;
    /// otherwise the CRC32 of the first 50 characters of `code` (the
    /// finding's source line text) must match exactly.
    pub fn is_suppressed(&self, rule_key: &str, rel_path: &str, code: &str) -> bool {
        let key = (rule_key.to_string(), rel_path.to_string());
        let Some(hashes) = self.entries.get(&key) else {
            return false;
        };
        let code_hash = if code.is_empty() { 0 } else { line_hash(code) };
        hashes.iter().any(|h| match h {
            CodeHashSpec::Any => true,
            CodeHashSpec::Exact(v) => *v == code_hash,
            CodeHashSpec::Invalid => false,
        })
    }
}

/// CRC32 of the first 50 characters (Unicode, not bytes) of `code` —
/// exact mirror of `zlib.crc32(code[:50].encode("utf-8")) & 0xFFFFFFFF`.
/// `pub(crate)`: reused as-is by `report::findings_html` for the
/// `{{code_hash}}` in `finding-item.html` (the exact same computation).
pub(crate) fn line_hash(code: &str) -> u32 {
    let truncated: String = code.chars().take(50).collect();
    crc32fast::hash(truncated.as_bytes())
}

/// True if the source line `code` carries a `# sca-ignore` marker
/// covering `rule_key` — `# sca-ignore` alone (nothing after)
/// suppresses every rule on that line; `# sca-ignore:rule_a,rule_b`
/// suppresses if `rule_key` appears after the colon.
///
/// **Accepted quirk, reproduced as-is**: the "parsing" after `:` on
/// the Python side is a simple substring containment check (`in`),
/// not a real CSV split with exact equality — a short `rule_key` can
/// therefore match by substring inside a longer marker (e.g. `"sql"`
/// matches in `"# sca-ignore:sql_injection_advanced"`). Not fixed:
/// this is the actual production behavior, not a porting bug.
pub fn is_inline_ignored(code: &str, rule_key: &str) -> bool {
    // rfind, not find: Python does `code.split("# sca-ignore")[-1]`
    // (last occurrence) when the marker appears more than once.
    let Some(idx) = code.rfind("# sca-ignore") else {
        return false;
    };
    let ignore_marker = code[idx + "# sca-ignore".len()..].trim();
    ignore_marker.is_empty() || (ignore_marker.starts_with(':') && ignore_marker.contains(rule_key))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_matches_python_zlib_reference_values() {
        // Reference values computed with `python3 -c "import zlib;
        // print(zlib.crc32(b'...') & 0xFFFFFFFF)"` — verifies
        // cross-language compatibility empirically, not assumed.
        assert_eq!(crc32fast::hash(b""), 0);
        assert_eq!(crc32fast::hash(b"hello"), 907060870);
        assert_eq!(crc32fast::hash(b"x = 1"), 1197187446);
        assert_eq!(crc32fast::hash(&b"a".repeat(50)), 1205320317);
    }

    #[test]
    fn test_load_from_json_basic_exact_hash() {
        let json =
            r#"{"suppressions": [{"rule_key": "xss", "file": "app.py", "code_hash": 1197187446}]}"#;
        let s = Suppressions::load_from_json(json);
        assert!(s.is_suppressed("xss", "app.py", "x = 1"));
        assert!(
            !s.is_suppressed("xss", "app.py", "y = 2"),
            "hash différent -> pas supprimé"
        );
    }

    #[test]
    fn test_load_from_json_null_code_hash_suppresses_all() {
        let json = r#"{"suppressions": [{"rule_key": "sql_injection", "file": "src/app.py", "code_hash": null}]}"#;
        let s = Suppressions::load_from_json(json);
        assert!(s.is_suppressed("sql_injection", "src/app.py", "n'importe quel texte"));
        assert!(s.is_suppressed("sql_injection", "src/app.py", "autre ligne"));
    }

    #[test]
    fn test_load_from_json_missing_code_hash_field_suppresses_all() {
        let json = r#"{"suppressions": [{"rule_key": "xss", "file": "view.py"}]}"#;
        let s = Suppressions::load_from_json(json);
        assert!(s.is_suppressed("xss", "view.py", "peu importe"));
    }

    #[test]
    fn test_load_from_json_invalid_code_hash_type_never_matches() {
        let json = r#"{"suppressions": [{"rule_key": "xss", "file": "view.py", "code_hash": "not-a-number"}]}"#;
        let s = Suppressions::load_from_json(json);
        assert!(
            !s.is_suppressed("xss", "view.py", "n'importe quoi"),
            "type invalide -> jamais supprimé (pas 'supprime tout')"
        );
    }

    #[test]
    fn test_load_from_json_invalid_json_returns_empty() {
        let s = Suppressions::load_from_json("{ ceci n'est pas du json");
        assert!(!s.is_suppressed("xss", "app.py", "x = 1"));
    }

    #[test]
    fn test_load_from_json_missing_suppressions_key_returns_empty() {
        let s = Suppressions::load_from_json(r#"{"version": "1.0"}"#);
        assert!(!s.is_suppressed("xss", "app.py", "x = 1"));
    }

    #[test]
    fn test_is_suppressed_wrong_rule_or_file_not_suppressed() {
        let json =
            r#"{"suppressions": [{"rule_key": "xss", "file": "app.py", "code_hash": null}]}"#;
        let s = Suppressions::load_from_json(json);
        assert!(
            !s.is_suppressed("sql_injection", "app.py", "x"),
            "règle différente"
        );
        assert!(
            !s.is_suppressed("xss", "other.py", "x"),
            "fichier différent"
        );
    }

    #[test]
    fn test_add_ignores_entry_with_empty_rule_key_or_file() {
        let json = r#"{"suppressions": [
            {"rule_key": "", "file": "app.py", "code_hash": null},
            {"rule_key": "xss", "file": "", "code_hash": null}
        ]}"#;
        let s = Suppressions::load_from_json(json);
        assert!(!s.is_suppressed("", "app.py", "x"));
        assert!(!s.is_suppressed("xss", "", "x"));
    }

    #[test]
    fn test_inline_ignore_bare_suppresses_all_rules() {
        assert!(is_inline_ignored("x = eval(y)  # sca-ignore", "any_rule"));
        assert!(is_inline_ignored("x = eval(y)  # sca-ignore", "other_rule"));
    }

    #[test]
    fn test_inline_ignore_targeted_matches_rule_key() {
        assert!(is_inline_ignored(
            "re.compile(r'(a+)+')  # sca-ignore:redos_nested_quantifier,redos_vulnerable",
            "redos_nested_quantifier"
        ));
    }

    #[test]
    fn test_inline_ignore_targeted_does_not_match_unrelated_rule() {
        assert!(!is_inline_ignored(
            "x = eval(y)  # sca-ignore:other_rule",
            "eval_usage"
        ));
    }

    #[test]
    fn test_inline_ignore_absent_marker_not_ignored() {
        assert!(!is_inline_ignored(
            "x = eval(y)  # commentaire normal",
            "eval_usage"
        ));
    }

    #[test]
    fn test_inline_ignore_substring_quirk_reproduced() {
        // Accepted quirk: "sql" matches by substring inside a longer
        // marker -- real Python behavior, not a regression.
        assert!(is_inline_ignored(
            "x = 1  # sca-ignore:sql_injection_advanced",
            "sql"
        ));
    }

    #[test]
    fn test_inline_ignore_last_occurrence_used_when_marker_repeated() {
        // Python: code.split("# sca-ignore")[-1] -> last occurrence.
        let code = "x = 1  # sca-ignore:foo  # sca-ignore:bar";
        assert!(is_inline_ignored(code, "bar"));
        assert!(
            !is_inline_ignored(code, "foo"),
            "seule la dernière occurrence est consultée"
        );
    }
}
