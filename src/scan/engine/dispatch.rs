//! Dispatches a JSON rule to the right executor — faithful port of
//! `Audit/sca/rule_engine.py::_dispatch_rule`. The mode is inferred from the
//! fields present in the compiled JSON, not from a single `mode` field.
#![allow(dead_code)]

use std::path::Path;

use serde_json::Value;

use super::Finding;
use super::file_contains::{execute_file_contains_rule, matches as file_contains_matches};
use super::pattern::execute_regex_rule;
use super::rule_loader::{compile_file_contains_rule_from_json, compile_regex_rule_from_json};

#[derive(Debug, Clone, PartialEq)]
pub enum DispatchOutcome {
    /// Handled separately by the caller: needs the full tree-sitter
    /// tree, not a line-by-line scan (Step 5, not yet wired up).
    Ast,
    /// Handled separately by the caller: cross-file analysis
    /// (`dataflow::worklist::analyze` + `call_graph`).
    Taint,
    /// `hook` (custom code on the Python source side) — out of scope
    /// for the Rust port, no portable generic equivalent.
    Hook,
    /// The rule produced these findings (may be empty: a `file_contains`
    /// combo that doesn't match, or a rule that fails to compile).
    Findings(Vec<Finding>),
}

/// Python truthiness of a JSON value (`bool(x)`) — empty list/object,
/// `null`, empty string, `0`/`0.0` are falsy; everything else is truthy.
fn is_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_none_or(|f| f != 0.0),
    }
}

/// Dispatches a JSON rule to the right executor. Mode inferred
/// automatically from the fields present (`patterns`/`file_contains`/
/// `hook`/`ast_patterns`/`mode`).
pub fn dispatch_rule(
    rule_json: &Value,
    filepath: &Path,
    all_lines: &[(usize, String)],
    content: &str,
) -> DispatchOutcome {
    let mode = rule_json.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    let has_patterns = is_truthy(rule_json.get("patterns"));
    let has_fc = is_truthy(rule_json.get("file_contains"));
    let has_hook = is_truthy(rule_json.get("hook"));
    let has_ast = is_truthy(rule_json.get("ast_patterns"));

    // AST: handled separately (needs the tree, not line-by-line).
    if has_ast || mode == "ast" {
        return DispatchOutcome::Ast;
    }
    // Taint: handled separately (cross-file).
    if (mode == "taint" || mode == "regex+taint") && !has_patterns {
        return DispatchOutcome::Taint;
    }
    // Hook: direct execution on the Python side, out of scope here.
    if has_hook {
        return DispatchOutcome::Hook;
    }
    // match + requires combo: regex filtered by file conditions.
    if has_patterns && has_fc {
        let Some(compiled_fc) = compile_file_contains_rule_from_json(rule_json) else {
            return DispatchOutcome::Findings(Vec::new());
        };
        if !file_contains_matches(
            &compiled_fc.file_contains,
            content,
            Some(filepath),
            all_lines.len(),
        ) {
            return DispatchOutcome::Findings(Vec::new());
        }
        return DispatchOutcome::Findings(
            compile_regex_rule_from_json(rule_json)
                .map(|r| execute_regex_rule(&r, all_lines))
                .unwrap_or_default(),
        );
    }
    // Regex only.
    if has_patterns {
        return DispatchOutcome::Findings(
            compile_regex_rule_from_json(rule_json)
                .map(|r| execute_regex_rule(&r, all_lines))
                .unwrap_or_default(),
        );
    }
    // file_contains only (file-level finding).
    if has_fc {
        let findings = compile_file_contains_rule_from_json(rule_json)
            .and_then(|r| execute_file_contains_rule(&r, filepath, content, all_lines))
            .into_iter()
            .collect();
        return DispatchOutcome::Findings(findings);
    }
    DispatchOutcome::Findings(Vec::new())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lines(text: &str) -> Vec<(usize, String)> {
        text.lines()
            .enumerate()
            .map(|(i, l)| (i + 1, format!("{l}\n")))
            .collect()
    }

    #[test]
    fn test_dispatch_ast_mode_returns_ast_outcome() {
        let rule = json!({"id": "r", "mode": "ast", "ast_patterns": [{}]});
        let out = dispatch_rule(&rule, Path::new("f.py"), &[], "");
        assert_eq!(out, DispatchOutcome::Ast);
    }

    #[test]
    fn test_dispatch_ast_patterns_present_without_mode() {
        let rule = json!({"id": "r", "ast_patterns": [{"pattern": "x"}]});
        let out = dispatch_rule(&rule, Path::new("f.py"), &[], "");
        assert_eq!(out, DispatchOutcome::Ast);
    }

    #[test]
    fn test_dispatch_taint_mode_without_patterns_returns_taint() {
        let rule = json!({"id": "r", "mode": "taint", "sources": [{"pattern": "input"}], "sinks": [{"pattern": "eval"}]});
        let out = dispatch_rule(&rule, Path::new("f.py"), &[], "");
        assert_eq!(out, DispatchOutcome::Taint);
    }

    #[test]
    fn test_dispatch_regex_plus_taint_with_patterns_is_not_taint_outcome() {
        // mode "regex+taint" WITH patterns -> treated as regex here
        // (the taint side is handled separately elsewhere, on the
        // same JSON, cf. rule_engine.py which also routes this JSON to
        // the taint pipeline in parallel -- out of scope for this test).
        let rule = json!({
            "id": "r",
            "mode": "regex+taint",
            "patterns": [{"pattern": r"eval\(", "match": "line"}],
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": "eval"}],
        });
        let out = dispatch_rule(
            &rule,
            Path::new("f.py"),
            &lines("x = eval(y)\n"),
            "x = eval(y)\n",
        );
        assert!(matches!(out, DispatchOutcome::Findings(_)));
    }

    #[test]
    fn test_dispatch_hook_returns_hook_outcome() {
        let rule = json!({"id": "r", "hook": "some_custom_hook"});
        let out = dispatch_rule(&rule, Path::new("f.py"), &[], "");
        assert_eq!(out, DispatchOutcome::Hook);
    }

    #[test]
    fn test_dispatch_regex_only_produces_findings() {
        let rule = json!({"id": "eval_usage", "category": "Injection", "severity": "HIGH", "patterns": [{"pattern": r"eval\(", "match": "line"}]});
        let content = "x = eval(y)\n";
        let out = dispatch_rule(&rule, Path::new("f.py"), &lines(content), content);
        match out {
            DispatchOutcome::Findings(f) => assert_eq!(f.len(), 1),
            other => panic!("attendu Findings, eu {other:?}"),
        }
    }

    #[test]
    fn test_dispatch_file_contains_only_produces_finding() {
        let rule = json!({
            "id": "missing_x",
            "file_contains": {"has": [], "not_has": ["forbidden_word"], "scope": "file"},
        });
        let content = "safe content\n";
        let out = dispatch_rule(&rule, Path::new("f.py"), &lines(content), content);
        match out {
            DispatchOutcome::Findings(f) => assert_eq!(f.len(), 1),
            other => panic!("attendu Findings, eu {other:?}"),
        }
    }

    #[test]
    fn test_dispatch_combo_skipped_when_file_contains_does_not_match() {
        let rule = json!({
            "id": "r",
            "patterns": [{"pattern": r"eval\(", "match": "line"}],
            "file_contains": {"has": ["must_be_present_marker"], "not_has": [], "scope": "file"},
        });
        let content = "x = eval(y)\n"; // doesn't contain the required marker
        let out = dispatch_rule(&rule, Path::new("f.py"), &lines(content), content);
        match out {
            DispatchOutcome::Findings(f) => assert!(
                f.is_empty(),
                "file_contains ne matche pas -> regex jamais lancée"
            ),
            other => panic!("attendu Findings vide, eu {other:?}"),
        }
    }

    #[test]
    fn test_dispatch_combo_runs_regex_when_file_contains_matches() {
        let rule = json!({
            "id": "r",
            "patterns": [{"pattern": r"eval\(", "match": "line"}],
            "file_contains": {"has": ["must_be_present_marker"], "not_has": [], "scope": "file"},
        });
        let content = "must_be_present_marker\nx = eval(y)\n";
        let out = dispatch_rule(&rule, Path::new("f.py"), &lines(content), content);
        match out {
            DispatchOutcome::Findings(f) => assert_eq!(f.len(), 1),
            other => panic!("attendu Findings, eu {other:?}"),
        }
    }

    #[test]
    fn test_dispatch_neither_patterns_nor_fc_returns_empty_findings() {
        let rule = json!({"id": "r"});
        let out = dispatch_rule(&rule, Path::new("f.py"), &[], "");
        assert_eq!(out, DispatchOutcome::Findings(Vec::new()));
    }
}
