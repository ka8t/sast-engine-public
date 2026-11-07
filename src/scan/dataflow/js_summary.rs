//! Discovery of JS functions and summaries for interprocedural
//! analysis — direct template of `java_summary.rs`.
//!
//! **Maximal reuse, not a port**: `compute_summary_from_cfg_generic`
//! (`summary.rs`) already carries 100% of the probing algorithm —
//! language-neutral. `compute_js_summary` below only builds the JS CFG
//! and then delegates to `summary::compute_js_summary_from_cfg`; no
//! duplicated logic.
//!
//! **Interprocedural resolution wired in on 08/30** (`js_call_graph.rs`,
//! orchestrator): `js_call_graph.rs::JsCallGraph::build` builds its
//! graph by directly reusing `collect_js_functions`
//! (`JsFunctionInfo`), and `resolve_summaries` calls `compute_js_summary`
//! below for each node — the summary computation written here is
//! therefore no longer pending "groundwork", it is the core of
//! multi-file resolution. This module serves two well-separated needs:
//!   1. `collect_js_functions` — the list of functions/CFGs to scan,
//!      consumed directly by `js_taint_scan.rs` AND by
//!      `js_call_graph.rs` (needed even without a call graph: a scan
//!      must still analyze EVERY function in the file).
//!   2. `compute_js_summary`/`compute_js_file_summaries` — summary
//!      computation, consumed by `js_call_graph.rs::JsCallGraph::compute_one`.
//!
//! **Recursive discovery, not just top-level** (deliberate difference
//! from Java, whose `collect_java_functions` only descends into
//! top-level type declarations): unlike Java, the vast majority of
//! vulnerable JS code in practice lives in anonymous callbacks passed
//! as arguments (`app.get('/x', (req, res) =>
//! {...})` — the dominant Express pattern), not in named top-level
//! functions. `collect_js_functions` therefore walks the whole tree,
//! without limiting itself to top-level statements.
//!
//! **Accepted v1 limitation**: an `arrow_function` with an
//! expression-only body (`x => x + 1`, no `{ ... }`) is NOT collected
//! — `js_cfg.rs::build_js_cfg` requires a `statement_block` node as
//! input (same contract as Java `block`/
//! `constructor_body`). A simple-expression callback containing a
//! direct sink (`req => eval(req.query.q)`) will therefore not be
//! detected by the AST engine in v1 — documented gap, to be closed if
//! calibration reveals this pattern is common in practice (would
//! require a synthetic single-node CFG, not built here for now).

use super::transfer::{FunctionSummary, RuleSpecs};
use tree_sitter::Node;

/// Metadata of a JS function (function declaration/expression, block-
/// bodied arrow function, class/object method).
///
/// `name`: best available name for debugging/future summaries — the
/// declaration's name, the name of the carrying variable/property for
/// an anonymous function that is assigned, or `"<anonymous>:<line>"` as
/// a last resort (callback passed directly as a call argument, e.g.
/// `app.get('/x', (req, res) => {...})`). NOT qualified by an enclosing
/// class in v1 (unlike Java's `Class.method`) — not needed as long as
/// no interprocedural resolution consumes this name.
pub struct JsFunctionInfo<'tree> {
    pub name: String,
    pub body_node: Node<'tree>,
    pub param_names: Vec<String>,
    pub lineno: usize,
}

const FUNCTION_LIKE_KINDS: [&str; 6] = [
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "generator_function",
    "arrow_function",
    "method_definition",
];

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

fn param_names<'tree>(params_node: Option<Node<'tree>>, source: &[u8]) -> Vec<String> {
    let Some(params_node) = params_node else {
        return Vec::new();
    };
    // `x => ...` — single parameter without parentheses, the
    // `parameters` node is directly an `identifier`.
    if params_node.kind() == "identifier" {
        return vec![text(params_node, source)];
    }
    let mut names = Vec::new();
    let mut w = params_node.walk();
    for p in params_node.named_children(&mut w) {
        match p.kind() {
            "identifier" => names.push(text(p, source)),
            "required_parameter" | "optional_parameter" => {
                if let Some(pat) = p.named_children(&mut p.walk()).next()
                    && pat.kind() == "identifier"
                {
                    names.push(text(pat, source));
                }
            }
            "assignment_pattern" => {
                if let Some(left) = p.child_by_field_name("left")
                    && left.kind() == "identifier"
                {
                    names.push(text(left, source));
                }
            }
            "rest_pattern" => {
                if let Some(inner) = p.named_children(&mut p.walk()).next() {
                    names.push(text(inner, source));
                }
            }
            _ => {}
        }
    }
    names
}

/// Best available name for an anonymous function, inferred from the
/// immediate syntactic context (parent node): carrying
/// variable/property (`const foo = function() {...}`/`const foo = () => {...}`)
/// or object key (`{ key: () => {...} }`). `None` if no identifiable
/// named context exists (callback as a direct argument).
fn inferred_name_from_context<'tree>(node: Node<'tree>, source: &[u8]) -> Option<String> {
    let parent = node.parent()?;
    let candidate = match parent.kind() {
        "variable_declarator" => parent.child_by_field_name("name"),
        "pair" => parent.child_by_field_name("key"),
        "assignment_expression" => parent.child_by_field_name("left"),
        _ => None,
    }?;
    if candidate.kind() == "identifier" || candidate.kind() == "property_identifier" {
        Some(text(candidate, source))
    } else {
        None
    }
}

/// Lists all functions/methods of a JS file (full recursive tree walk,
/// see module doc). A function whose body is not a `statement_block`
/// (expression-bodied arrow) is skipped (accepted v1 limitation, see
/// module doc).
pub fn collect_js_functions<'tree>(root: Node<'tree>, source: &[u8]) -> Vec<JsFunctionInfo<'tree>> {
    let mut functions = Vec::new();
    collect_functions_rec(root, source, &mut functions);
    functions
}

fn collect_functions_rec<'tree>(
    node: Node<'tree>,
    source: &[u8],
    out: &mut Vec<JsFunctionInfo<'tree>>,
) {
    if FUNCTION_LIKE_KINDS.contains(&node.kind())
        && let Some(body) = node.child_by_field_name("body")
        && body.kind() == "statement_block"
    {
        let name = function_name(node, source);
        out.push(JsFunctionInfo {
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
// Summary computation (Phase 3 groundwork, not yet consumed)
// ============================================================================

/// Computes the summary of a JS function. Builds the CFG from
/// `fn_info.body_node` then delegates to
/// `summary::compute_js_summary_from_cfg` (no duplication of the
/// probing algorithm).
pub fn compute_js_summary<'tree>(
    fn_info: &JsFunctionInfo<'tree>,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
) -> FunctionSummary {
    let cfg = super::js_cfg::build_js_cfg(fn_info.body_node, source);
    super::summary::compute_js_summary_from_cfg(
        &cfg,
        &fn_info.name,
        &fn_info.param_names,
        specs,
        source,
        source_lines,
        fn_info.lineno,
    )
}

/// Computes the summaries of every function in a JS file. Mirror of
/// `compute_java_file_summaries` — no bare-name alias (unlike Java):
/// JS names are already not qualified by a class in v1, nothing to
/// disambiguate.
pub fn compute_js_file_summaries<'tree>(
    root: Node<'tree>,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
) -> std::collections::BTreeMap<String, FunctionSummary> {
    let mut summaries = std::collections::BTreeMap::new();
    for fn_info in collect_js_functions(root, source) {
        let summary = compute_js_summary(&fn_info, specs, source, source_lines);
        summaries.insert(fn_info.name.clone(), summary);
    }
    summaries
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_js(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn test_collect_named_function_declaration() {
        let src = "function foo(a, b) { return a + b; }";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "foo");
        assert_eq!(functions[0].param_names, vec!["a", "b"]);
        assert_eq!(functions[0].lineno, 1);
    }

    #[test]
    fn test_collect_arrow_assigned_to_const() {
        let src = "const handler = (req, res) => { res.send(req.query.q); };";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "handler");
        assert_eq!(functions[0].param_names, vec!["req", "res"]);
    }

    #[test]
    fn test_collect_anonymous_callback_gets_synthetic_name() {
        let src = "app.get('/x', function(req, res) { res.send(req.query.q); });";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert!(functions[0].name.starts_with("<anonymous>:"));
    }

    #[test]
    fn test_collect_arrow_callback_in_call_argument() {
        let src = "app.get('/x', (req, res) => { res.send(req.query.q); });";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
    }

    #[test]
    fn test_expression_bodied_arrow_not_collected() {
        let src = "const f = (a) => a + 1;";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert!(
            functions.is_empty(),
            "limitation acceptée v1, cf. doc de module"
        );
    }

    #[test]
    fn test_collect_class_method() {
        let src = "class C { method(x) { return x; } }";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "method");
    }

    #[test]
    fn test_collect_object_method_shorthand() {
        let src = "const obj = { m(a) { return a; } };";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "m");
    }

    #[test]
    fn test_collect_nested_functions() {
        let src = "function outer() { function inner() { return 1; } return inner(); }";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 2);
    }

    #[test]
    fn test_collect_generator_declaration() {
        let src = "function* gen() { yield 1; }";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "gen");
    }

    #[test]
    fn test_no_functions_in_plain_statements() {
        let src = "const x = 1; const y = x + 1;";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert!(functions.is_empty());
    }

    #[test]
    fn test_compute_js_summary_no_sink_no_findings() {
        let src = "function safe(a) { return a; }";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
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
        let summary = compute_js_summary(&functions[0], &specs, src.as_bytes(), None);
        assert_eq!(summary.name, "safe");
        assert_eq!(summary.param_names, vec!["a"]);
    }
}
