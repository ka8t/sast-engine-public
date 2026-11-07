//! Discovery of PHP functions and summaries for interprocedural
//! analysis — direct template of `js_summary.rs`.
//!
//! **Maximum sharing, not a port**: `compute_summary_from_cfg_generic`
//! (`summary.rs`) already carries 100% of the probing algorithm —
//! language-neutral. `compute_php_summary` below only builds the PHP
//! CFG and then delegates to `summary::compute_php_summary_from_cfg`;
//! no duplicated logic.
//!
//! **Interprocedural resolution wired on 08/30** (`php_call_graph.rs`,
//! orchestrator): `php_call_graph.rs::PhpCallGraph::build` directly
//! reuses `collect_php_functions`, and `resolve_summaries` calls
//! `compute_php_summary` below for each node — the summary
//! computation written here is therefore no longer pending
//! "groundwork". This module serves two well-separated needs:
//!   1. `collect_php_functions` — the list of functions/CFGs to
//!      scan, consumed by both `php_taint_scan.rs` and
//!      `php_call_graph.rs`.
//!   2. `compute_php_summary`/`compute_php_file_summaries` — summary
//!      computation, consumed by
//!      `php_call_graph.rs::PhpCallGraph::compute_one`.
//!
//! **Recursive discovery** (same choice as JS, for the same reason:
//! a good part of vulnerable PHP code lives in closures passed as
//! arguments — framework callbacks, anonymous route handlers):
//! `collect_php_functions` walks the whole tree, not just top-level
//! declarations.
//!
//! **Accepted v1 limitation, BROADER than in JS**: `fn($x) => ...`
//! (arrow function) NEVER has a `compound_statement` body in PHP
//! (unlike JS, where only CERTAIN arrow functions have an
//! expression body) — EVERY PHP arrow function is therefore excluded
//! from collection, since `php_cfg.rs::build_php_cfg` requires a
//! `compound_statement`. A `function($x) use ($y) {...}` closure
//! (`anonymous_function`, classic block form) is still collected
//! normally.

use super::transfer::{FunctionSummary, RuleSpecs};
use tree_sitter::Node;

/// Metadata for a PHP function (top-level function, class method,
/// `function(...) {...}` closure).
pub struct PhpFunctionInfo<'tree> {
    pub name: String,
    pub body_node: Node<'tree>,
    pub param_names: Vec<String>,
    pub lineno: usize,
}

const FUNCTION_LIKE_KINDS: [&str; 4] = [
    "function_definition",
    "method_declaration",
    "anonymous_function",
    "arrow_function",
];

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

fn param_names<'tree>(params_node: Option<Node<'tree>>, source: &[u8]) -> Vec<String> {
    let Some(params_node) = params_node else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut w = params_node.walk();
    for p in params_node.named_children(&mut w) {
        match p.kind() {
            "simple_parameter" | "variadic_parameter" | "property_promotion_parameter" => {
                if let Some(name_node) = p.child_by_field_name("name") {
                    names.push(text(name_node, source));
                }
            }
            "variable_name" => names.push(text(p, source)),
            _ => {}
        }
    }
    names
}

/// Best available name for an anonymous closure, inferred from the
/// immediate syntactic context (parent node): carrying variable
/// (`$foo = function() {...};`). `None` if no identifiable named
/// context (closure passed directly as an argument, the dominant
/// pattern for framework handlers).
fn inferred_name_from_context<'tree>(node: Node<'tree>, source: &[u8]) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() != "assignment_expression" {
        return None;
    }
    let left = parent.child_by_field_name("left")?;
    if left.kind() == "variable_name" {
        Some(text(left, source))
    } else {
        None
    }
}

/// Lists all functions/methods/closures in a PHP file (full
/// recursive walk, see module doc). A function whose body is not a
/// `compound_statement` (arrow function — ALWAYS the case in PHP,
/// see module doc) is skipped.
pub fn collect_php_functions<'tree>(
    root: Node<'tree>,
    source: &[u8],
) -> Vec<PhpFunctionInfo<'tree>> {
    let mut functions = Vec::new();
    collect_functions_rec(root, source, &mut functions);
    functions
}

fn collect_functions_rec<'tree>(
    node: Node<'tree>,
    source: &[u8],
    out: &mut Vec<PhpFunctionInfo<'tree>>,
) {
    if FUNCTION_LIKE_KINDS.contains(&node.kind())
        && let Some(body) = node.child_by_field_name("body")
        && body.kind() == "compound_statement"
    {
        let name = function_name(node, source);
        out.push(PhpFunctionInfo {
            name,
            body_node: body,
            param_names: param_names(node.child_by_field_name("parameters"), source),
            lineno: node.start_position().row + 1,
        });
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        collect_functions_rec(child, source, out);
    }
}

fn function_name(node: Node, source: &[u8]) -> String {
    if let Some(name_node) = node.child_by_field_name("name") {
        return text(name_node, source);
    }
    if let Some(inferred) = inferred_name_from_context(node, source) {
        return inferred;
    }
    format!("<anonymous>:{}", node.start_position().row + 1)
}

// ============================================================================
// Summary computation (groundwork, not yet consumed)
// ============================================================================

pub fn compute_php_summary<'tree>(
    fn_info: &PhpFunctionInfo<'tree>,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
) -> FunctionSummary {
    let cfg = super::php_cfg::build_php_cfg(fn_info.body_node, source);
    super::summary::compute_php_summary_from_cfg(
        &cfg,
        &fn_info.name,
        &fn_info.param_names,
        specs,
        source,
        source_lines,
        fn_info.lineno,
    )
}

pub fn compute_php_file_summaries<'tree>(
    root: Node<'tree>,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
) -> std::collections::BTreeMap<String, FunctionSummary> {
    let mut summaries = std::collections::BTreeMap::new();
    for fn_info in collect_php_functions(root, source) {
        let summary = compute_php_summary(&fn_info, specs, source, source_lines);
        summaries.insert(fn_info.name.clone(), summary);
    }
    summaries
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_php(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn test_collect_named_function_definition() {
        let src = "<?php\nfunction foo($a, $b) { return $a + $b; }\n";
        let tree = parse_php(src);
        let functions = collect_php_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "foo");
        assert_eq!(functions[0].param_names, vec!["$a", "$b"]);
    }

    #[test]
    fn test_collect_closure_assigned_to_variable() {
        let src = "<?php\n$handler = function($req, $res) { $res->send($req); };\n";
        let tree = parse_php(src);
        let functions = collect_php_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "$handler");
        assert_eq!(functions[0].param_names, vec!["$req", "$res"]);
    }

    #[test]
    fn test_collect_anonymous_callback_gets_synthetic_name() {
        let src = "<?php\napp_get('/x', function($req, $res) { $res->send($req); });\n";
        let tree = parse_php(src);
        let functions = collect_php_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert!(functions[0].name.starts_with("<anonymous>:"));
    }

    #[test]
    fn test_arrow_function_never_collected() {
        // Accepted v1 limitation: fn() => ... never has a
        // compound_statement body in PHP — see module doc.
        let src = "<?php\n$f = fn($a) => $a + 1;\n";
        let tree = parse_php(src);
        let functions = collect_php_functions(tree.root_node(), src.as_bytes());
        assert!(functions.is_empty());
    }

    #[test]
    fn test_collect_class_method() {
        let src = "<?php\nclass C { function method($x) { return $x; } }\n";
        let tree = parse_php(src);
        let functions = collect_php_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "method");
    }

    #[test]
    fn test_collect_nested_functions() {
        let src = "<?php\nfunction outer() {\n  $inner = function() { return 1; };\n  return $inner();\n}\n";
        let tree = parse_php(src);
        let functions = collect_php_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 2);
    }

    #[test]
    fn test_no_functions_in_plain_statements() {
        let src = "<?php\n$x = 1;\n$y = $x + 1;\n";
        let tree = parse_php(src);
        let functions = collect_php_functions(tree.root_node(), src.as_bytes());
        assert!(functions.is_empty());
    }

    #[test]
    fn test_compute_php_summary_no_sink_no_findings() {
        let src = "<?php\nfunction safe($a) { return $a; }\n";
        let tree = parse_php(src);
        let functions = collect_php_functions(tree.root_node(), src.as_bytes());
        let specs = RuleSpecs {
            rule_id: "test_rule".to_string(),
            severity: "HIGH".to_string(),
            message: String::new(),
            cwe: None,
            sources: vec![],
            sinks: vec![],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: Default::default(),
            type_map: Default::default(),
        };
        let summary = compute_php_summary(&functions[0], &specs, src.as_bytes(), None);
        assert_eq!(summary.name, "safe");
        assert_eq!(summary.param_names, vec!["$a"]);
    }
}
