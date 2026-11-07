//! Compiles a DSL rule (compiled JSON) into runtime structures for the
//! regex/file_contains executors — a faithful port of the logic in
//! `Audit/sca/rule_loader.py::_compile_rule_patterns`.
//!
//! Simpler than the taint bridge (`dataflow::rule_loader`): the JSON
//! already carries the **raw** DSL pattern text, compiled directly to
//! a regex at runtime — no glob translation needed (verified
//! empirically against the Python source code before porting).
#![allow(dead_code)]

use fancy_regex::Regex;
use serde_json::Value;

use super::file_contains::{CompiledFileContainsRule, FileContainsCondition};
use super::pattern::{CompiledPattern, CompiledRegexRule};

fn json_str<'a>(v: &'a Value, key: &str, default: &'a str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or(default)
}

fn json_str_array(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn json_regex_array(v: &Value, key: &str) -> Vec<Regex> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str())
                .filter_map(|s| Regex::new(s).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Compiles the `patterns[]` subset (regex/regex+taint mode) of a JSON
/// rule into a `CompiledRegexRule`. `None` if `patterns` is absent/
/// empty or if no pattern is compilable (invalid regex — should never
/// happen on JSON produced by the DSL parser, already validated at
/// `.sca`→JSON compile time, but stays defensive).
pub fn compile_regex_rule_from_json(rule_json: &Value) -> Option<CompiledRegexRule> {
    let patterns_json = rule_json.get("patterns").and_then(|v| v.as_array())?;

    let id = json_str(rule_json, "id", "").to_string();
    let category = json_str(rule_json, "category", "").to_string();
    let severity = json_str(rule_json, "severity", "MEDIUM").to_string();
    let confidence = rule_json
        .get("confidence")
        .and_then(|v| v.as_i64())
        .unwrap_or(70);
    let language = json_str(rule_json, "language", "").to_string();

    let mut patterns = Vec::new();
    for p in patterns_json {
        let pattern_text = json_str(p, "pattern", "");
        let match_scope = json_str(p, "match", "line").to_string();
        // `context-N` scope: Python compiles `pattern`/`with`/`pattern-not`
        // with `re.DOTALL` so `.` matches `\n` and a pattern can span the
        // lines of the window (`rule_loader.py::_compile_rule_patterns`,
        // present since the DSL migration of 2026-04-12). Missing from the
        // initial port: every `context-N` rule using `.` was blind to
        // multi-line constructs (e.g. `secret_logged_fstring` on a
        // `logger.info(` whose f-string sits on the next line) — found by
        // the Python/Rust differential scan of 2026-11-04. `(?s)` is the
        // inline equivalent of `re.DOTALL`; `line`/`file` keep flags = 0.
        let compile = |s: &str| {
            if match_scope.starts_with("context-") {
                Regex::new(&format!("(?s){s}"))
            } else {
                Regex::new(s)
            }
        };
        let Ok(compiled) = compile(pattern_text) else {
            continue;
        };
        let compiled_with = p
            .get("with")
            .and_then(|v| v.as_str())
            .and_then(|s| compile(s).ok());
        let compiled_pattern_not = p
            .get("pattern-not")
            .and_then(|v| v.as_str())
            .and_then(|s| compile(s).ok());
        patterns.push(CompiledPattern {
            match_scope,
            compiled,
            compiled_with,
            compiled_pattern_not,
        });
    }
    if patterns.is_empty() {
        return None;
    }

    Some(CompiledRegexRule {
        id,
        category,
        severity,
        confidence,
        language,
        patterns,
    })
}

/// Compiles the `file_contains` block of a JSON rule into a
/// `CompiledFileContainsRule`. `None` if the block is absent.
pub fn compile_file_contains_rule_from_json(rule_json: &Value) -> Option<CompiledFileContainsRule> {
    let fc_json = rule_json.get("file_contains")?;

    let id = json_str(rule_json, "id", "").to_string();
    let category = json_str(rule_json, "category", "").to_string();
    let severity = json_str(rule_json, "severity", "MEDIUM").to_string();
    let confidence = rule_json
        .get("confidence")
        .and_then(|v| v.as_i64())
        .unwrap_or(70);

    let has = json_regex_array(fc_json, "has");
    let not_has = json_regex_array(fc_json, "not_has");
    let min_lines = fc_json
        .get("min_lines")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let path_contains = json_str_array(fc_json, "path_contains");
    let not_path_has_file = json_str_array(fc_json, "not_path_has_file");

    Some(CompiledFileContainsRule {
        id,
        category,
        severity,
        confidence,
        file_contains: FileContainsCondition {
            has,
            not_has,
            min_lines,
            path_contains,
            not_path_has_file,
        },
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compile_regex_rule_basic() {
        let rule = json!({
            "id": "eval_usage",
            "category": "Injection",
            "severity": "HIGH",
            "confidence": 85,
            "language": "python",
            "patterns": [{"pattern": r"eval\(", "match": "line"}],
        });
        let compiled = compile_regex_rule_from_json(&rule).expect("patterns présent -> Some");
        assert_eq!(compiled.id, "eval_usage");
        assert_eq!(compiled.category, "Injection");
        assert_eq!(compiled.severity, "HIGH");
        assert_eq!(compiled.confidence, 85);
        assert_eq!(compiled.language, "python");
        assert_eq!(compiled.patterns.len(), 1);
        assert_eq!(compiled.patterns[0].match_scope, "line");
        assert!(
            compiled.patterns[0]
                .compiled
                .is_match("x = eval(y)")
                .unwrap()
        );
    }

    #[test]
    fn test_compile_regex_rule_with_and_pattern_not() {
        let rule = json!({
            "id": "r",
            "patterns": [{
                "pattern": r"subprocess\.call",
                "match": "line",
                "with": "shell=True",
                "pattern-not": "shlex\\.quote",
            }],
        });
        let compiled = compile_regex_rule_from_json(&rule).unwrap();
        assert!(compiled.patterns[0].compiled_with.is_some());
        assert!(compiled.patterns[0].compiled_pattern_not.is_some());
    }

    /// `context-N` scope: `.` must cross line terminators (Python
    /// compiles with `re.DOTALL`, `rule_loader.py::_compile_rule_patterns`)
    /// — for `pattern`, `with` and `pattern-not` alike. Reproduces the
    /// `secret_logged_fstring` miss on a call split across lines.
    #[test]
    fn test_context_scope_compiles_with_dotall() {
        let rule = json!({
            "id": "r",
            "patterns": [{
                "pattern": r"logger\.\w+\s*\(.*\{password\}",
                "match": "context-4",
                "with": r"info.*password",
                "pattern-not": r"info.*redacted",
            }],
        });
        let compiled = compile_regex_rule_from_json(&rule).unwrap();
        let block = "logger.info(\n    f\"x {password}\"\n)\n";
        let p = &compiled.patterns[0];
        assert!(p.compiled.is_match(block).unwrap());
        assert!(p.compiled_with.as_ref().unwrap().is_match(block).unwrap());
        assert!(
            p.compiled_pattern_not
                .as_ref()
                .unwrap()
                .is_match("info(\nredacted")
                .unwrap()
        );
    }

    /// `line`/`file` scopes keep the default flags: `.` never crosses a
    /// newline (Python: `flags = 0` outside `context-N`).
    #[test]
    fn test_line_scope_keeps_dot_single_line() {
        let rule = json!({"id": "r", "patterns": [{"pattern": "a.*b", "match": "line"}]});
        let compiled = compile_regex_rule_from_json(&rule).unwrap();
        assert!(!compiled.patterns[0].compiled.is_match("a\nb").unwrap());
    }

    #[test]
    fn test_compile_regex_rule_none_without_patterns() {
        let rule = json!({"id": "r"});
        assert!(compile_regex_rule_from_json(&rule).is_none());
    }

    #[test]
    fn test_compile_regex_rule_skips_invalid_pattern_but_keeps_valid_ones() {
        let rule = json!({
            "id": "r",
            "patterns": [
                {"pattern": "(", "match": "line"},
                {"pattern": r"os\.system", "match": "line"},
            ],
        });
        let compiled = compile_regex_rule_from_json(&rule).unwrap();
        assert_eq!(
            compiled.patterns.len(),
            1,
            "le pattern invalide est ignoré, le valide reste"
        );
    }

    #[test]
    fn test_compile_regex_rule_confidence_defaults_to_70() {
        let rule = json!({"id": "r", "patterns": [{"pattern": "x", "match": "line"}]});
        let compiled = compile_regex_rule_from_json(&rule).unwrap();
        assert_eq!(compiled.confidence, 70);
    }

    #[test]
    fn test_compile_file_contains_rule_basic() {
        let rule = json!({
            "id": "missing_dockerignore",
            "category": "Config",
            "severity": "LOW",
            "confidence": 60,
            "file_contains": {
                "has": [r"FROM\s+\w+"],
                "not_has": [],
                "min_lines": 3,
                "path_contains": ["Dockerfile"],
                "not_path_has_file": [".dockerignore"],
            },
        });
        let compiled =
            compile_file_contains_rule_from_json(&rule).expect("file_contains présent -> Some");
        assert_eq!(compiled.id, "missing_dockerignore");
        assert_eq!(compiled.file_contains.has.len(), 1);
        assert_eq!(compiled.file_contains.min_lines, 3);
        assert_eq!(
            compiled.file_contains.path_contains,
            vec!["Dockerfile".to_string()]
        );
        assert_eq!(
            compiled.file_contains.not_path_has_file,
            vec![".dockerignore".to_string()]
        );
    }

    #[test]
    fn test_compile_file_contains_rule_none_without_block() {
        let rule = json!({"id": "r"});
        assert!(compile_file_contains_rule_from_json(&rule).is_none());
    }

    #[test]
    fn test_compile_file_contains_rule_defaults_when_fields_absent() {
        let rule = json!({"id": "r", "file_contains": {}});
        let compiled = compile_file_contains_rule_from_json(&rule).unwrap();
        assert!(compiled.file_contains.has.is_empty());
        assert!(compiled.file_contains.not_has.is_empty());
        assert_eq!(compiled.file_contains.min_lines, 0);
    }
}
