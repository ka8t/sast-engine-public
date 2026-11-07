//! AST executor (tree-sitter) — faithful port of
//! `Audit/sca/executors/ast.py` + `Audit/sca/treesitter_engine.py`.
//!
//! Python-only scope (Decision #10) — a single language, no need
//! for `TreeSitterManager`'s multi-grammar cache.
//!
//! **Context note (2026-08-24)**: none of the 703 real rules in the
//! builtin catalog use `ast` mode today (verified
//! empirically against the Decision #2 corpus) — only 2
//! synthetic examples exist, in the Python DSL tests. Built here by
//! explicit choice (completeness/anticipation), not because a
//! real need currently demands it. Consequence: unlike the
//! regex/file_contains executors, there is **no real corpus**
//! to validate Python/Rust parity against — the tests below
//! validate the Rust matcher's behavior in isolation, not
//! side-by-side parity.
//!
//! Query predicates (`#match?`, `#eq?`, `#any-of?`): the
//! `tree-sitter` crate (contrary to an initial cautious assumption)
//! evaluates them automatically in `QueryCursor::matches()`, as
//! long as the source text is supplied as a `TextProvider` — verified
//! in the crate's source code (`satisfies_text_predicates` called
//! internally by the `QueryMatches` iterator). No need to
//! reimplement them by hand, contrary to the initial concern.

use super::Finding;
use tree_sitter::{Node, Parser, Query, QueryCursor, StreamingIterator, Tree};

pub struct AstMatcher {
    parser: Parser,
}

#[derive(Debug)]
pub enum AstError {
    LanguageSetupFailed(String),
    InvalidQuery(String),
}

impl AstMatcher {
    pub fn new_python() -> Result<Self, AstError> {
        let mut parser = Parser::new();
        let language: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
        parser
            .set_language(&language)
            .map_err(|e| AstError::LanguageSetupFailed(e.to_string()))?;
        Ok(AstMatcher { parser })
    }

    pub fn parse(&mut self, source: &[u8]) -> Option<Tree> {
        self.parser.parse(source, None)
    }
}

/// A single S-expression query match — the "main" node is the
/// first capture encountered (same convention as
/// `TreeSitterManager.query()` on the Python side: the first entry inserted
/// into the result dict becomes `result["node"]`).
pub struct AstMatch {
    pub node_start_line: usize, // 1-indexed, cf. get_node_line Python
}

/// Executes an S-expression query against an already-parsed tree.
/// Mirrors `TreeSitterManager.query()`.
pub fn query_tree(
    language: &tree_sitter::Language,
    tree: &Tree,
    source: &[u8],
    pattern: &str,
) -> Result<Vec<AstMatch>, AstError> {
    let query = Query::new(language, pattern).map_err(|e| AstError::InvalidQuery(e.to_string()))?;

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source);

    let mut results = Vec::new();
    while let Some(m) = matches.next() {
        if let Some(first_capture) = m.captures.first() {
            results.push(AstMatch {
                node_start_line: node_line(first_capture.node),
            });
        }
    }
    Ok(results)
}

/// 1-indexed line number of a node — mirrors
/// `get_node_line` (`node.start_point[0] + 1`).
fn node_line(node: Node) -> usize {
    node.start_position().row + 1
}

pub struct CompiledAstRule {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub confidence: i64,
    /// Each entry is the raw text of an S-expression pattern
    /// (`ast_patterns[].pattern` from the compiled JSON).
    pub patterns: Vec<String>,
}

/// Executes an AST rule against an already-parsed file — one finding per
/// match. Mirrors `_execute_ast_rule` (ast.py). The reported
/// line is that of the match's first capture (as on the
/// Python side); `code` must be supplied by the caller (Python re-reads the
/// line from the file via `_get_line_content` — out of scope for
/// this module, cf. the discipline already applied to pattern.rs/
/// file_contains.rs: the matcher doesn't do file I/O itself).
pub fn execute_ast_rule(
    rule: &CompiledAstRule,
    language: &tree_sitter::Language,
    tree: &Tree,
    source: &[u8],
    line_content: impl Fn(usize) -> String,
) -> Result<Vec<Finding>, AstError> {
    let mut findings = Vec::new();
    for pattern in &rule.patterns {
        let matches = query_tree(language, tree, source, pattern)?;
        for m in matches {
            findings.push(Finding {
                rule_id: rule.id.clone(),
                category: rule.category.to_uppercase(),
                severity: rule.severity.clone(),
                line: m.node_start_line,
                code: line_content(m.node_start_line),
                confidence: rule.confidence,
            });
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn python_language() -> tree_sitter::Language {
        tree_sitter_python::LANGUAGE.into()
    }

    #[test]
    fn test_parse_python_source() {
        let mut matcher = AstMatcher::new_python().unwrap();
        let tree = matcher.parse(b"x = 1\n").unwrap();
        assert_eq!(tree.root_node().kind(), "module");
    }

    #[test]
    fn test_simple_query_finds_call() {
        let mut matcher = AstMatcher::new_python().unwrap();
        let source = b"eval(x)\n";
        let tree = matcher.parse(source).unwrap();
        let lang = python_language();
        let matches =
            query_tree(&lang, &tree, source, "(call function: (identifier) @fn)").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].node_start_line, 1);
    }

    #[test]
    fn test_match_predicate_filters_captures() {
        // Confirms that #match? is indeed applied automatically (no
        // need for manual filtering) — cf. module docstring.
        let mut matcher = AstMatcher::new_python().unwrap();
        let source = b"eval(x)\nsafe_call(y)\n";
        let tree = matcher.parse(source).unwrap();
        let lang = python_language();
        let pattern = r#"(call function: (identifier) @fn (#match? @fn "^eval$"))"#;
        let matches = query_tree(&lang, &tree, source, pattern).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].node_start_line, 1);
    }

    #[test]
    fn test_no_match_returns_empty() {
        let mut matcher = AstMatcher::new_python().unwrap();
        let source = b"x = 1\n";
        let tree = matcher.parse(source).unwrap();
        let lang = python_language();
        let matches =
            query_tree(&lang, &tree, source, "(call function: (identifier) @fn)").unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn test_invalid_query_returns_error() {
        let mut matcher = AstMatcher::new_python().unwrap();
        let source = b"x = 1\n";
        let tree = matcher.parse(source).unwrap();
        let lang = python_language();
        let result = query_tree(&lang, &tree, source, "(this is not valid @@@");
        assert!(matches!(result, Err(AstError::InvalidQuery(_))));
    }

    #[test]
    fn test_execute_ast_rule_produces_findings_with_line_content() {
        let rule = CompiledAstRule {
            id: "test_eval".to_string(),
            category: "security".to_string(),
            severity: "HIGH".to_string(),
            confidence: 90,
            patterns: vec![
                r#"(call function: (identifier) @fn (#match? @fn "^eval$"))"#.to_string(),
            ],
        };
        let mut matcher = AstMatcher::new_python().unwrap();
        let source = b"x = 1\neval(user_input)\n";
        let tree = matcher.parse(source).unwrap();
        let lang = python_language();

        let findings =
            execute_ast_rule(&rule, &lang, &tree, source, |line| format!("line-{line}")).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].code, "line-2");
    }

    #[test]
    fn test_multiline_query_from_ast_rule_fixture() {
        // The S-expression pattern from the grammar corpus (Decision #2,
        // grammar__ast_rule.sca / AST_RULE on the Python side) — the only
        // real (though synthetic) example available.
        let pattern = "(for_statement body: (block (expression_statement (call function: (attribute attribute: (identifier) @method) (#match? @method \"^(execute|query|get|filter)$\")))))";
        let mut matcher = AstMatcher::new_python().unwrap();
        let source = b"for item in items:\n    db.execute(item)\n";
        let tree = matcher.parse(source).unwrap();
        let lang = python_language();
        let matches = query_tree(&lang, &tree, source, pattern).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].node_start_line, 2);
    }
}
