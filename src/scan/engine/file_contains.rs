//! `file_contains` executor — faithful port of
//! `Audit/sca/executors/file_check.py`.
//!
//! Two uses, as on the Python side: `matches()` (a predicate, usable
//! as a pre-filter for a `match` + `requires` combo) and
//! `execute_file_contains_rule()` (produces a file-level
//! finding, line 1, if the conditions are met).

use super::Finding;
use fancy_regex::Regex;
use std::path::Path;

/// Already-compiled conditions — mirrors `_compile_rule_patterns` for
/// the `file_contains` subset.
pub struct FileContainsCondition {
    /// ALL must match.
    pub has: Vec<Regex>,
    /// NONE may match.
    pub not_has: Vec<Regex>,
    pub min_lines: i64,
    pub path_contains: Vec<String>,
    /// "Governance" file names whose presence (walking up the
    /// directory tree from the scanned file's folder, up to 5
    /// levels) suppresses the finding.
    pub not_path_has_file: Vec<String>,
}

pub struct CompiledFileContainsRule {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub confidence: i64,
    pub file_contains: FileContainsCondition,
}

fn is_match(re: &Regex, text: &str) -> bool {
    re.is_match(text).unwrap_or(false)
}

/// Checks whether a file's content satisfies the `file_contains`
/// conditions. `filepath`, when supplied, is used for `path_contains` and
/// `not_path_has_file` (the latter does real disk I/O, as
/// on the Python side).
pub fn matches(
    fc: &FileContainsCondition,
    content: &str,
    filepath: Option<&Path>,
    line_count: usize,
) -> bool {
    for pat in &fc.has {
        if !is_match(pat, content) {
            return false;
        }
    }
    for pat in &fc.not_has {
        if is_match(pat, content) {
            return false;
        }
    }

    if fc.min_lines > 0 && (line_count as i64) < fc.min_lines {
        return false;
    }

    if !fc.path_contains.is_empty()
        && let Some(fp) = filepath
    {
        let fp_lower = fp.to_string_lossy().to_lowercase().replace('\\', "/");
        if !fc
            .path_contains
            .iter()
            .any(|seg| fp_lower.contains(&seg.to_lowercase()))
        {
            return false;
        }
    }

    if !fc.not_path_has_file.is_empty()
        && let Some(fp) = filepath
        && governance_file_found(fp, &fc.not_path_has_file)
    {
        return false; // governance file present → no finding
    }

    true
}

/// Which of `names` the governance check of `filepath` finds, as one
/// `0`/`1` per name: the only thing outside the file that a pattern rule
/// reads, hence part of the file's key in the scan cache (`scan_cache`).
pub fn governance_fingerprint(filepath: &Path, names: &[String]) -> String {
    names
        .iter()
        .map(|n| if governance_file_found(filepath, std::slice::from_ref(n)) { '1' } else { '0' })
        .collect()
}

/// Walks up the directory tree from `filepath`'s folder (up to 5
/// levels) looking for one of the `check_files` — mirrors the
/// Python loop, with an identical anti-traversal guard (rejects any name
/// containing `..` or a path separator: those aren't plain
/// file names).
fn governance_file_found(filepath: &Path, check_files: &[String]) -> bool {
    // Computed once, reused for each check_file (no
    // recomputing filepath.parent() inside the loop).
    let Some(dir) = filepath.parent() else {
        return false;
    };

    for check_file in check_files {
        if check_file.contains("..") || check_file.contains('/') || check_file.contains('\\') {
            continue;
        }
        let mut current = dir.to_path_buf();
        for _ in 0..5 {
            if current.join(check_file).exists() {
                return true;
            }
            match current.parent() {
                Some(parent) if parent != current => current = parent.to_path_buf(),
                _ => break,
            }
        }
    }
    false
}

/// Produces a file-level finding (line 1, `file_contains` convention) if
/// the conditions are met — mirrors `execute()` (file_check.py).
pub fn execute_file_contains_rule(
    rule: &CompiledFileContainsRule,
    filepath: &Path,
    content: &str,
    all_lines: &[(usize, String)],
) -> Option<Finding> {
    if !matches(
        &rule.file_contains,
        content,
        Some(filepath),
        all_lines.len(),
    ) {
        return None;
    }

    let code = all_lines
        .iter()
        .find(|(_, text)| !text.trim().is_empty())
        .map(|(_, text)| text.clone())
        .unwrap_or_default();

    Some(Finding {
        rule_id: rule.id.clone(),
        category: rule.category.to_uppercase(),
        severity: rule.severity.clone(),
        line: 1,
        code,
        confidence: rule.confidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_condition() -> FileContainsCondition {
        FileContainsCondition {
            has: vec![],
            not_has: vec![],
            min_lines: 0,
            path_contains: vec![],
            not_path_has_file: vec![],
        }
    }

    #[test]
    fn test_has_all_must_match() {
        let mut fc = empty_condition();
        fc.has = vec![Regex::new("flask").unwrap(), Regex::new("import").unwrap()];
        assert!(matches(&fc, "import flask", None, 1));
        assert!(!matches(&fc, "import django", None, 1));
    }

    #[test]
    fn test_not_has_none_must_match() {
        let mut fc = empty_condition();
        fc.not_has = vec![Regex::new("CSRFProtect").unwrap()];
        assert!(matches(&fc, "app = Flask(__name__)", None, 1));
        assert!(!matches(&fc, "from flask_wtf import CSRFProtect", None, 1));
    }

    #[test]
    fn test_min_lines_threshold() {
        let mut fc = empty_condition();
        fc.min_lines = 10;
        assert!(!matches(&fc, "x", None, 5));
        assert!(matches(&fc, "x", None, 10));
        assert!(matches(&fc, "x", None, 11));
    }

    #[test]
    fn test_path_contains_case_insensitive_and_backslash_normalized() {
        let mut fc = empty_condition();
        fc.path_contains = vec!["Migrations".to_string()];
        assert!(matches(
            &fc,
            "x",
            Some(Path::new(r"src\migrations\0001.py")),
            1
        ));
        assert!(!matches(&fc, "x", Some(Path::new("src/models/user.py")), 1));
    }

    #[test]
    fn test_path_contains_without_filepath_does_not_block() {
        // Python: `if path_segments and filepath:` — without a filepath, the
        // path_contains condition is ignored (no blocking).
        let mut fc = empty_condition();
        fc.path_contains = vec!["migrations".to_string()];
        assert!(matches(&fc, "x", None, 1));
    }

    #[test]
    fn test_not_path_has_file_rejects_traversal_names() {
        let mut fc = empty_condition();
        fc.not_path_has_file = vec!["../escape".to_string(), "sub/dir".to_string()];
        // Both of these names are rejected by the anti-traversal guard — so
        // they're never looked up on disk, never found → no blocking.
        let dir = std::env::temp_dir();
        let fake_file = dir.join("some_scanned_file.py");
        assert!(matches(&fc, "x", Some(&fake_file), 1));
    }

    #[test]
    fn test_execute_produces_finding_at_line_1_with_first_nonempty_line() {
        let rule = CompiledFileContainsRule {
            id: "missing_helmet".to_string(),
            category: "security".to_string(),
            severity: "MEDIUM".to_string(),
            confidence: 80,
            file_contains: {
                let mut fc = empty_condition();
                fc.has = vec![Regex::new("express").unwrap()];
                fc
            },
        };
        let all_lines = vec![
            (1, "".to_string()),
            (2, "const app = express();".to_string()),
        ];
        let finding = execute_file_contains_rule(
            &rule,
            Path::new("app.js"),
            "const app = express();",
            &all_lines,
        )
        .expect("finding attendu");
        assert_eq!(finding.line, 1);
        assert_eq!(finding.code, "const app = express();");
    }

    #[test]
    fn test_execute_returns_none_when_conditions_not_met() {
        let rule = CompiledFileContainsRule {
            id: "x".to_string(),
            category: "security".to_string(),
            severity: "LOW".to_string(),
            confidence: 80,
            file_contains: {
                let mut fc = empty_condition();
                fc.has = vec![Regex::new("nope").unwrap()];
                fc
            },
        };
        let all_lines = vec![(1, "hello".to_string())];
        assert!(
            execute_file_contains_rule(&rule, Path::new("f.py"), "hello", &all_lines).is_none()
        );
    }
}
