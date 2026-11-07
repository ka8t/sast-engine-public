//! Function summaries for Java interprocedural analysis — faithful
//! port of `Audit/sca/dataflow/java_summary.py`.
//!
//! Complements the Java front-end (see `dataflow/mod.rs` doc) —
//! equivalent of the "collection + summary computation" part of
//! `summary.rs` (Python side), consumed by the future
//! `java_call_graph.rs`.
//!
//! **Maximum sharing, not a port**: `compute_summary_from_cfg_generic`
//! (`summary.rs`, § generalized on 2026-08-25) already carries 100% of
//! the probing algorithm (base pass + one pass per parameter) —
//! language-neutral, it only consumes the generic IR and the CFG.
//! `compute_java_summary` below only builds the Java CFG
//! then delegates to `summary::compute_java_summary_from_cfg`;
//! no duplicated logic.
//!
//! What genuinely differs per language — and justifies this separate
//! file:
//!   - **Function discovery**: Java has no top-level functions
//!     (Python's `collect_functions` walks the entire AST) —
//!     only methods/constructors of classes/interfaces/
//!     enums/records, discovered by scanning top-level type
//!     bodies.
//!   - **Building the CFG from a function**: on the Python side,
//!     `function_to_sub_module` must wrap the body in a fake
//!     module. On the Java side, unnecessary: `build_java_cfg` already
//!     accepts a `block`/`constructor_body` node directly.
//!
//! Spring route parameters (`@RequestParam`/`@RequestBody`/...):
//! see `route_param_names`/`JavaFunctionInfo::route_param_names`
//! further down — Java equivalent of `route_source_params` (`summary.rs`),
//! consumed by the future `java_taint_scan.rs` to seed
//! `initial_state`.

use std::collections::BTreeMap;
use std::sync::Arc;

use tree_sitter::Node;

pub use super::transfer::FunctionSummary;
use super::transfer::RuleSpecs;

const TOP_LEVEL_TYPE_DECLS: [&str; 4] = [
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
];

/// Metadata for a Java method/constructor.
///
/// `name`: dotted name `"ClassName.method"` (methods) or
/// `"ClassName.<init>"` (constructors — Java bytecode convention,
/// avoids the `Foo.Foo` collision with a method named like the
/// class). `body_node`: tree-sitter node for the body (`block`/
/// `constructor_body`), directly consumable by `build_java_cfg`.
/// `route_param_names`: subset of `param_names` bound by Spring
/// right at handler entry — annotated (`@RequestParam`/...) or, for a
/// mapped handler (`@GetMapping`/...), not annotated at all (implicit
/// binding by name) — see [`route_param_names`]. Empty for
/// constructors (Spring never binds a constructor).
pub struct JavaFunctionInfo<'tree> {
    pub name: String,
    pub body_node: Node<'tree>,
    pub param_names: Vec<String>,
    pub lineno: usize,
    pub route_param_names: Vec<String>,
}

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

fn param_names<'tree>(params_node: Option<Node<'tree>>, source: &[u8]) -> Vec<String> {
    let Some(params_node) = params_node else {
        return Vec::new();
    };
    let mut w = params_node.walk();
    params_node
        .named_children(&mut w)
        .filter(|p| p.kind() == "formal_parameter")
        .filter_map(|p| p.child_by_field_name("name"))
        .map(|n| text(n, source))
        .collect()
}

// ============================================================================
// Spring route parameters — Java equivalent of `route_source_params`
// (`summary.rs`, Python engine): a handler parameter annotated
// `@RequestParam`/... is tainted right at method entry, without
// waiting for a `source` regex match on an expression. Same scalar
// filter as the Spring lexical profile (`sca/profiles/java/
// spring.profile`) — never a technical object
// (`HttpServletRequest`, custom DTO...).
// ============================================================================

const SPRING_SOURCE_ANNOTATIONS: [&str; 8] = [
    "RequestParam",
    "RequestBody",
    "PathVariable",
    "RequestHeader",
    "CookieValue",
    "RequestPart",
    "ModelAttribute",
    "MatrixVariable",
];
const ROUTE_SCALAR_TYPES: [&str; 15] = [
    "String", "int", "Integer", "long", "Long", "boolean", "Boolean", "double", "Double", "float",
    "Float", "short", "Short", "byte", "Byte",
];

// Implicit binding (carried over from lexical_taint.py Phase 2a, Spring
// plan §4.1): a Spring handler parameter WITHOUT ANY annotation
// is still bound by Spring, by its name alone. A whitelist broader
// than `ROUTE_SCALAR_TYPES` (same types as
// `lexical_taint.py::_SPRING_BINDABLE_BASE_TYPES`) — Spring also binds
// `List`/`Map`/`MultipartFile` implicitly, not just pure
// scalars. Types injected by the container (never user
// data) are explicitly excluded even if they mistakenly appeared
// in the whitelist above.
const SPRING_MAPPING_ANNOTATIONS: [&str; 5] = [
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "DeleteMapping",
    "PatchMapping",
];
const SPRING_MAPPING_ANNOTATION_REQUEST: &str = "RequestMapping";
const SPRING_IMPLICIT_BINDABLE_TYPES: [&str; 15] = [
    "String", "Integer", "int", "Long", "long", "Double", "double", "Float", "float", "Boolean",
    "boolean", "Short", "short", "Byte", "byte",
];
const SPRING_IMPLICIT_BINDABLE_EXTRA: [&str; 4] = ["BigDecimal", "List", "Map", "MultipartFile"];
const SPRING_CONTAINER_TYPES: [&str; 20] = [
    "HttpServletRequest",
    "HttpServletResponse",
    "HttpSession",
    "Model",
    "ModelMap",
    "ModelAndView",
    "BindingResult",
    "Errors",
    "Principal",
    "Authentication",
    "Locale",
    "RedirectAttributes",
    "UriComponentsBuilder",
    "WebRequest",
    "HttpEntity",
    "OutputStream",
    "Writer",
    "InputStream",
    "Reader",
    "Exception",
];

fn param_annotation_names(param_node: Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut w = param_node.walk();
    for child in param_node.children(&mut w) {
        if child.kind() != "modifiers" {
            continue;
        }
        let mut mw = child.walk();
        for m in child.named_children(&mut mw) {
            if m.kind() != "marker_annotation" && m.kind() != "annotation" {
                continue;
            }
            if let Some(name_node) = m.child_by_field_name("name") {
                names.push(text(name_node, source));
            }
        }
    }
    names
}

/// True if `method_node` carries a `@GetMapping`/
/// `@PostMapping`/... annotation — enables implicit binding (unannotated
/// parameters).
fn method_has_spring_mapping(method_node: Node, source: &[u8]) -> bool {
    let mut w = method_node.walk();
    for child in method_node.children(&mut w) {
        if child.kind() != "modifiers" {
            continue;
        }
        let mut mw = child.walk();
        for m in child.named_children(&mut mw) {
            if m.kind() != "marker_annotation" && m.kind() != "annotation" {
                continue;
            }
            if let Some(name_node) = m.child_by_field_name("name") {
                let name = text(name_node, source);
                if SPRING_MAPPING_ANNOTATIONS.contains(&name.as_str())
                    || name == SPRING_MAPPING_ANNOTATION_REQUEST
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Returns the parameters tainted right at method entry:
///   - annotated by a Spring binding annotation (`@RequestParam`/
///     ...) AND of a bindable scalar type (`ROUTE_SCALAR_TYPES`);
///   - OR (if `method_is_mapped`) WITHOUT ANY annotation, type in
///     `SPRING_IMPLICIT_BINDABLE_TYPES`/`_EXTRA` and not in
///     `SPRING_CONTAINER_TYPES` — implicit Spring binding.
///
/// An unknown annotation on the same parameter conservatively excludes
/// it in both cases (same safeguard as on the lexical side).
fn route_param_names<'tree>(
    params_node: Option<Node<'tree>>,
    method_is_mapped: bool,
    source: &[u8],
) -> Vec<String> {
    let Some(params_node) = params_node else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut w = params_node.walk();
    for p in params_node.named_children(&mut w) {
        if p.kind() != "formal_parameter" {
            continue;
        }
        let annotations = param_annotation_names(p, source);
        let simple_type = p
            .child_by_field_name("type")
            .map(|t| simple_type_name(t, source));
        let simple_type = simple_type.as_deref();
        if !annotations.is_empty() {
            if !annotations
                .iter()
                .any(|a| SPRING_SOURCE_ANNOTATIONS.contains(&a.as_str()))
            {
                continue;
            }
            if !simple_type.is_some_and(|t| ROUTE_SCALAR_TYPES.contains(&t)) {
                continue;
            }
        } else {
            if !method_is_mapped {
                continue;
            }
            if simple_type.is_some_and(|t| SPRING_CONTAINER_TYPES.contains(&t)) {
                continue;
            }
            let implicit = simple_type.is_some_and(|t| {
                SPRING_IMPLICIT_BINDABLE_TYPES.contains(&t)
                    || SPRING_IMPLICIT_BINDABLE_EXTRA.contains(&t)
            });
            if !implicit {
                continue;
            }
        }
        if let Some(name_node) = p.child_by_field_name("name") {
            names.push(text(name_node, source));
        }
    }
    names
}

// ============================================================================
// Method/constructor discovery
// ============================================================================

/// Lists the methods/constructors of the classes/interfaces/enums/
/// records of a Java file (`program`), nested classes included
/// (round 6 calibration — the `private class Test { ... }` pattern is
/// common in OWASP BenchmarkJava).
///
/// A nested class is indexed under its simple name (not qualified
/// by its enclosing class): consistent with how `new Test().method()`
/// is resolved (`transfer.rs::eval_call`, round 6), which only knows
/// "Test". On a name collision between two classes in the same
/// file, the last one encountered wins (accepted limitation).
///
/// An abstract method (interface, no body) is ignored — nothing to
/// analyze. Out of scope: anonymous classes (`new X() { ... }`, no
/// stable name).
pub fn collect_java_functions<'tree>(
    root: Node<'tree>,
    source: &[u8],
) -> Vec<JavaFunctionInfo<'tree>> {
    let mut functions = Vec::new();
    let mut w = root.walk();
    for type_decl in root.named_children(&mut w) {
        if TOP_LEVEL_TYPE_DECLS.contains(&type_decl.kind()) {
            collect_type_members(type_decl, source, &mut functions);
        }
    }
    functions
}

fn collect_type_members<'tree>(
    type_decl: Node<'tree>,
    source: &[u8],
    out: &mut Vec<JavaFunctionInfo<'tree>>,
) {
    let Some(name_node) = type_decl.child_by_field_name("name") else {
        return;
    };
    let Some(body) = type_decl.child_by_field_name("body") else {
        return;
    };
    let class_name = text(name_node, source);
    let mut w = body.walk();
    for member in body.named_children(&mut w) {
        match member.kind() {
            "method_declaration" => {
                if let Some(fn_info) = method_info(member, &class_name, source) {
                    out.push(fn_info);
                }
            }
            "constructor_declaration" => {
                if let Some(fn_info) = constructor_info(member, &class_name, source) {
                    out.push(fn_info);
                }
            }
            k if TOP_LEVEL_TYPE_DECLS.contains(&k) => {
                collect_type_members(member, source, out);
            }
            _ => {}
        }
    }
}

fn method_info<'tree>(
    node: Node<'tree>,
    class_name: &str,
    source: &[u8],
) -> Option<JavaFunctionInfo<'tree>> {
    let body = node.child_by_field_name("body")?; // abstract method/interface: nothing to analyze
    let method_name = node
        .child_by_field_name("name")
        .map(|n| text(n, source))
        .unwrap_or_else(|| "?".to_string());
    let params_node = node.child_by_field_name("parameters");
    Some(JavaFunctionInfo {
        name: format!("{class_name}.{method_name}"),
        body_node: body,
        param_names: param_names(params_node, source),
        lineno: node.start_position().row + 1,
        route_param_names: route_param_names(
            params_node,
            method_has_spring_mapping(node, source),
            source,
        ),
    })
}

fn constructor_info<'tree>(
    node: Node<'tree>,
    class_name: &str,
    source: &[u8],
) -> Option<JavaFunctionInfo<'tree>> {
    let body = node.child_by_field_name("body")?;
    Some(JavaFunctionInfo {
        name: format!("{class_name}.<init>"),
        body_node: body,
        param_names: param_names(node.child_by_field_name("parameters"), source),
        lineno: node.start_position().row + 1,
        route_param_names: Vec::new(),
    })
}

// ============================================================================
// Summary computation
// ============================================================================

/// Computes the summary of a Java method/constructor.
///
/// Builds the CFG from `fn.body_node` then delegates to
/// `summary::compute_java_summary_from_cfg` (language-neutral at the
/// algorithm level, Java-specialized via `analyze_java`/
/// `java_lowering::lower_node_to_ir`) — no duplication of
/// the probing algorithm.
pub fn compute_java_summary<'tree>(
    fn_info: &JavaFunctionInfo<'tree>,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
) -> FunctionSummary {
    let cfg = super::java_cfg::build_java_cfg(fn_info.body_node, source);
    super::summary::compute_java_summary_from_cfg(
        &cfg,
        &fn_info.name,
        &fn_info.param_names,
        specs,
        source,
        source_lines,
        fn_info.lineno,
    )
}

/// Computes the summaries of all methods/constructors of a
/// Java file. Mirrors `compute_file_summaries` (Python). A
/// method whose sub-analysis fails... — in Rust, `compute_java_summary`
/// cannot fail with a panic for a malformed CFG (unlike
/// Python's generic `try/except Exception`); robustness ensured
/// otherwise (the CFG builder never panics on valid syntax,
/// empirically verified — see `java_cfg.rs`).
///
/// Also exposes each method under its **bare** name (without class
/// prefix) when unambiguous — Java specificity with no Python equivalent:
/// `runQuery(x)` calls a method of the SAME class without a prefix
/// (unlike `self.run_query(x)`, always qualified in Python).
/// Without this alias, the vast majority of intra-class calls (the
/// dominant case in Java) would never resolve via summaries — see
/// [`add_bare_name_aliases`].
pub fn compute_java_file_summaries<'tree>(
    root: Node<'tree>,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
) -> BTreeMap<String, Arc<FunctionSummary>> {
    let mut summaries = BTreeMap::new();
    for fn_info in collect_java_functions(root, source) {
        let summary = Arc::new(compute_java_summary(&fn_info, specs, source, source_lines));
        summaries.insert(fn_info.name, summary);
    }
    add_bare_name_aliases(&mut summaries);
    summaries
}

/// Adds, for each unambiguous method, an alias under its bare name.
///
/// Unambiguous = a single member carrying that name across THE WHOLE file
/// (all top-level classes combined). Ambiguous (same name in two
/// classes of the same file) → no bare alias created for that name,
/// anti-FP (better to miss a flow than resolve to the wrong
/// class). Constructors (`Class.<init>`) are excluded — `<init>`
/// is never a valid Java identifier anyway, a bare call
/// could never match it.
pub(crate) fn add_bare_name_aliases(summaries: &mut BTreeMap<String, Arc<FunctionSummary>>) {
    let mut owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for dotted in summaries.keys() {
        let Some((_, member)) = dotted.rsplit_once('.') else {
            continue;
        };
        if member == "<init>" {
            continue;
        }
        owners
            .entry(member.to_string())
            .or_default()
            .push(dotted.clone());
    }
    for (member, dotted_keys) in owners {
        if dotted_keys.len() == 1 && !summaries.contains_key(&member) {
            let summary = summaries[&dotted_keys[0]].clone();
            summaries.insert(member, summary);
        }
    }
}

// ============================================================================
// Round 5 (OWASP BenchmarkJava calibration) — declared types of
// local variables
// ============================================================================

/// Simple name of a type node, generic and package stripped
/// (`java.util.List<String>` → `"List"`).
fn simple_type_name(type_node: Node, source: &[u8]) -> String {
    let text = text(type_node, source);
    let before_generic = text.split('<').next().unwrap_or(&text);
    before_generic
        .rsplit('.')
        .next()
        .unwrap_or(before_generic)
        .to_string()
}

fn collect_local_var_types(node: Node, source: &[u8], out: &mut BTreeMap<String, String>) {
    if node.kind() == "local_variable_declaration"
        && let Some(type_node) = node.child_by_field_name("type")
    {
        let simple = simple_type_name(type_node, source);
        if !simple.is_empty() {
            let mut w = node.walk();
            for decl in node.named_children(&mut w) {
                if decl.kind() != "variable_declarator" {
                    continue;
                }
                if let Some(name_node) = decl.child_by_field_name("name") {
                    out.insert(text(name_node, source), simple.clone());
                }
            }
        }
    }
    let mut w = node.walk();
    for child in node.children(&mut w) {
        collect_local_var_types(child, source, out);
    }
}

/// Builds `variable_name -> simple_class_name` for each
/// local variable declaration in the file (all methods
/// combined).
///
/// Lets `scr.method()` resolve to the summary
/// `SeparateClassRequest.method` when `scr` is declared as
/// `SeparateClassRequest scr = ...` — a call qualified by a
/// variable never directly matches a summary (always indexed
/// by class name).
///
/// Accepted simplification: built over THE WHOLE file, not per
/// method scope — on a variable name collision between two
/// methods of different types, the last declaration encountered
/// wins. Method PARAMETERS (`formal_parameter`) are not
/// covered (out of scope for the current need, which targets
/// local variables like `SeparateClassRequest scr = new ...`).
pub fn collect_java_local_types(root: Node, source: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for fn_info in collect_java_functions(root, source) {
        collect_local_var_types(fn_info.body_node, source, &mut out);
    }
    out
}

// ============================================================================
// Typed field resolution (3bis.2 — Java call graph parity)
// ============================================================================

/// Builds `field_name -> simple_class_name` for the fields
/// (`field_declaration`) of each top-level (and nested) type in the
/// file — complements `collect_java_local_types`, which only sees
/// local variables, never fields (`private final CommentsCache
/// comments;` then `comments.parseXml(...)` in a method).
///
/// Same simplification as `collect_java_local_types`: whole-file
/// scope, not per class — on a name collision between
/// two classes, the last declaration encountered wins.
pub fn collect_java_field_types(root: Node, source: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut w = root.walk();
    for type_decl in root.named_children(&mut w) {
        if TOP_LEVEL_TYPE_DECLS.contains(&type_decl.kind()) {
            collect_type_field_types(type_decl, source, &mut out);
        }
    }
    out
}

/// `type_decl` is a `class_declaration`/... node (not a
/// container) — same contract as `collect_type_members`, of which this is
/// the equivalent for fields rather than methods.
fn collect_type_field_types(type_decl: Node, source: &[u8], out: &mut BTreeMap<String, String>) {
    let Some(body) = type_decl.child_by_field_name("body") else {
        return;
    };
    let mut w = body.walk();
    for member in body.named_children(&mut w) {
        match member.kind() {
            "field_declaration" => {
                let Some(type_node) = member.child_by_field_name("type") else {
                    continue;
                };
                let simple = simple_type_name(type_node, source);
                if simple.is_empty() {
                    continue;
                }
                let mut mw = member.walk();
                for decl in member.named_children(&mut mw) {
                    if decl.kind() != "variable_declarator" {
                        continue;
                    }
                    if let Some(name_node) = decl.child_by_field_name("name") {
                        out.insert(text(name_node, source), simple.clone());
                    }
                }
            }
            k if TOP_LEVEL_TYPE_DECLS.contains(&k) => {
                collect_type_field_types(member, source, out);
            }
            _ => {}
        }
    }
}

// ============================================================================
// Tests — partial mirror of `Audit/tests/dataflow/test_java_summary.py`
// (excluding `JavaModuleRegistry` integration, see the future `java_call_graph.rs`).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::{SinkSpec, SourceSpec};
    use tree_sitter::Parser;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(src, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "syntaxe Java invalide : {src:?}"
        );
        tree
    }

    fn sqli_specs() -> RuleSpecs {
        RuleSpecs {
            rule_id: "test-sqli".to_string(),
            severity: "HIGH".to_string(),
            cwe: None,
            message: "test finding".to_string(),
            sources: vec![SourceSpec::new("*.getParameter", "http")],
            sinks: vec![SinkSpec::new("*.execute")],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
        }
    }

    // ------------------------------------------------- collect_java_functions

    #[test]
    fn test_single_method() {
        let tree = parse("class Foo { void bar() {} }");
        let fns = collect_java_functions(tree.root_node(), b"class Foo { void bar() {} }");
        assert_eq!(
            fns.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            vec!["Foo.bar"]
        );
    }

    #[test]
    fn test_multiple_methods_and_params() {
        let src =
            "class Foo { void run(String query, Object db) {} int compute(int x) { return x; } }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        let names: std::collections::BTreeSet<&str> = fns.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from(["Foo.run", "Foo.compute"])
        );
        let run = fns.iter().find(|f| f.name == "Foo.run").unwrap();
        assert_eq!(run.param_names, vec!["query".to_string(), "db".to_string()]);
        let compute = fns.iter().find(|f| f.name == "Foo.compute").unwrap();
        assert_eq!(compute.param_names, vec!["x".to_string()]);
    }

    #[test]
    fn test_constructor_named_init() {
        let src = "class Foo { Foo(String x) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert_eq!(fns[0].name, "Foo.<init>");
        assert_eq!(fns[0].param_names, vec!["x".to_string()]);
    }

    #[test]
    fn test_abstract_method_skipped() {
        let src = "interface Foo { void bar(); }";
        let tree = parse(src);
        assert!(collect_java_functions(tree.root_node(), src.as_bytes()).is_empty());
    }

    #[test]
    fn test_multiple_top_level_classes() {
        let src = "class Foo { void a() {} } class Bar { void b() {} }";
        let tree = parse(src);
        let names: std::collections::BTreeSet<String> =
            collect_java_functions(tree.root_node(), src.as_bytes())
                .into_iter()
                .map(|f| f.name)
                .collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from(["Foo.a".to_string(), "Bar.b".to_string()])
        );
    }

    #[test]
    fn test_empty_file() {
        let src = "class Foo {}";
        let tree = parse(src);
        assert!(collect_java_functions(tree.root_node(), src.as_bytes()).is_empty());
    }

    #[test]
    fn test_nested_class_method_discovered() {
        let src = "class Api { void handler() {} private class Test { String doSomething(String p) { return p; } } }";
        let tree = parse(src);
        let names: std::collections::BTreeSet<String> =
            collect_java_functions(tree.root_node(), src.as_bytes())
                .into_iter()
                .map(|f| f.name)
                .collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from([
                "Api.handler".to_string(),
                "Test.doSomething".to_string()
            ])
        );
    }

    #[test]
    fn test_doubly_nested_class_method_discovered() {
        let src = "class Api { private class Mid { private class Inner { void deep() {} } } }";
        let tree = parse(src);
        let names: std::collections::BTreeSet<String> =
            collect_java_functions(tree.root_node(), src.as_bytes())
                .into_iter()
                .map(|f| f.name)
                .collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from(["Inner.deep".to_string()])
        );
    }

    // ------------------------------------- compute_java_summary(_file_summaries)

    #[test]
    fn test_return_tainted_uncond() {
        let src = "class Api { String getInput(HttpServletRequest req) { return req.getParameter(\"q\"); } }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_java_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(sums.contains_key("Api.getInput"));
        assert!(sums["Api.getInput"].return_tainted_uncond);
    }

    #[test]
    fn test_sink_param_finding() {
        let src = "class Api { void runQuery(String query, Statement db) { db.execute(query); } }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_java_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(sums.contains_key("Api.runQuery"));
        assert!(sums["Api.runQuery"].sink_param_findings.contains_key(&0));
    }

    #[test]
    fn test_clean_function_no_taint() {
        let src = "class Api { int add(int a, int b) { return a + b; } }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_java_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(!sums["Api.add"].return_tainted_uncond);
        assert!(sums["Api.add"].sink_param_findings.is_empty());
    }

    #[test]
    fn test_bare_name_alias_for_unambiguous_method() {
        let src = "class Api { void runQuery(String query, Statement db) { db.execute(query); } }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_java_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(sums.contains_key("Api.runQuery"));
        assert!(sums.contains_key("runQuery"));
        assert_eq!(
            sums["runQuery"].sink_param_findings,
            sums["Api.runQuery"].sink_param_findings
        );
    }

    #[test]
    fn test_bare_name_alias_not_created_when_ambiguous() {
        let src = "class Foo { void run(String query, Statement db) { db.execute(query); } } class Bar { void run(String query, Statement db) { } }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_java_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(sums.contains_key("Foo.run") && sums.contains_key("Bar.run"));
        assert!(!sums.contains_key("run"));
    }

    #[test]
    fn test_bare_name_alias_excludes_constructors() {
        let src = "class Foo { Foo(String x) {} }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_java_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(sums.contains_key("Foo.<init>"));
        assert!(!sums.contains_key("<init>"));
        assert!(!sums.contains_key("Foo"));
    }

    #[test]
    fn test_broken_method_does_not_abort_others() {
        let src = "class Api { int ok(int x) { return x; } void other(String s, Statement db) { db.execute(s); } }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_java_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(sums.contains_key("Api.ok"));
        assert!(sums.contains_key("Api.other"));
    }

    // ------------------------------------------------- collect_java_local_types

    #[test]
    fn test_simple_declaration() {
        let src = "class Api { void handler() { QueryRunner qr = new QueryRunner(); } }";
        let tree = parse(src);
        let types = collect_java_local_types(tree.root_node(), src.as_bytes());
        assert_eq!(types.get("qr"), Some(&"QueryRunner".to_string()));
    }

    #[test]
    fn test_fully_qualified_type_stripped_to_simple_name() {
        let src = "class Api { void handler() { org.acme.util.QueryRunner qr = new org.acme.util.QueryRunner(); } }";
        let tree = parse(src);
        let types = collect_java_local_types(tree.root_node(), src.as_bytes());
        assert_eq!(types.get("qr"), Some(&"QueryRunner".to_string()));
    }

    #[test]
    fn test_generic_type_stripped() {
        let src = "class Api { void handler() { java.util.List<String> xs = new java.util.ArrayList<>(); } }";
        let tree = parse(src);
        let types = collect_java_local_types(tree.root_node(), src.as_bytes());
        assert_eq!(types.get("xs"), Some(&"List".to_string()));
    }

    #[test]
    fn test_multiple_variables_across_methods() {
        let src = "class Api { void a() { QueryRunner qr = new QueryRunner(); } void b() { Helper h = new Helper(); } }";
        let tree = parse(src);
        let types = collect_java_local_types(tree.root_node(), src.as_bytes());
        assert_eq!(
            types,
            BTreeMap::from([
                ("qr".to_string(), "QueryRunner".to_string()),
                ("h".to_string(), "Helper".to_string()),
            ])
        );
    }

    #[test]
    fn test_no_local_variables() {
        let src = "class Api { void handler() { doIt(); } }";
        let tree = parse(src);
        assert!(collect_java_local_types(tree.root_node(), src.as_bytes()).is_empty());
    }

    // -------------------------------------------------------- route_param_names

    #[test]
    fn test_request_param_scalar_detected() {
        let src = "class H { void completed(@RequestParam String account) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert_eq!(fns[0].route_param_names, vec!["account".to_string()]);
    }

    #[test]
    fn test_multiple_annotated_params() {
        let src = "class H { void completed(@RequestParam String a, @PathVariable Integer b) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        let set: std::collections::BTreeSet<&String> = fns[0].route_param_names.iter().collect();
        assert_eq!(
            set,
            std::collections::BTreeSet::from([&"a".to_string(), &"b".to_string()])
        );
    }

    #[test]
    fn test_unannotated_param_excluded() {
        let src = "class H { void completed(String account) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert!(fns[0].route_param_names.is_empty());
    }

    #[test]
    fn test_container_type_excluded_even_if_annotated() {
        let src = "class H { void completed(@RequestParam HttpServletRequest r) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert!(fns[0].route_param_names.is_empty());
    }

    #[test]
    fn test_unknown_annotation_excludes_param() {
        let src = "class H { void completed(@AuthenticationPrincipal String u) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert!(fns[0].route_param_names.is_empty());
    }

    #[test]
    fn test_constructor_never_gets_route_params() {
        let src = "class H { H(@RequestParam String account) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert_eq!(fns[0].name, "H.<init>");
        assert!(fns[0].route_param_names.is_empty());
    }

    #[test]
    fn test_no_annotation_at_all_plain_method() {
        let src = "class H { void handler() {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert!(fns[0].route_param_names.is_empty());
    }

    // ------------------------------------------------- collect_java_field_types

    #[test]
    fn test_single_field() {
        let src = "class Foo { private final CommentsCache comments; }";
        let tree = parse(src);
        assert_eq!(
            collect_java_field_types(tree.root_node(), src.as_bytes()),
            BTreeMap::from([("comments".to_string(), "CommentsCache".to_string())])
        );
    }

    #[test]
    fn test_field_with_initializer() {
        let src = "class Foo { private String other = \"x\"; }";
        let tree = parse(src);
        assert_eq!(
            collect_java_field_types(tree.root_node(), src.as_bytes()),
            BTreeMap::from([("other".to_string(), "String".to_string())])
        );
    }

    #[test]
    fn test_multiple_fields() {
        let src = "class Foo { private final CommentsCache comments; private Helper helper; }";
        let tree = parse(src);
        assert_eq!(
            collect_java_field_types(tree.root_node(), src.as_bytes()),
            BTreeMap::from([
                ("comments".to_string(), "CommentsCache".to_string()),
                ("helper".to_string(), "Helper".to_string()),
            ])
        );
    }

    #[test]
    fn test_generic_and_qualified_type_stripped() {
        let src =
            "class Foo { private java.util.List<String> xs; private org.acme.Runner runner; }";
        let tree = parse(src);
        assert_eq!(
            collect_java_field_types(tree.root_node(), src.as_bytes()),
            BTreeMap::from([
                ("xs".to_string(), "List".to_string()),
                ("runner".to_string(), "Runner".to_string()),
            ])
        );
    }

    #[test]
    fn test_nested_class_fields_collected() {
        let src = "class Outer { class Inner { private CommentsCache comments; } }";
        let tree = parse(src);
        assert_eq!(
            collect_java_field_types(tree.root_node(), src.as_bytes()),
            BTreeMap::from([("comments".to_string(), "CommentsCache".to_string())])
        );
    }

    #[test]
    fn test_no_fields() {
        let src = "class Foo { void m() {} }";
        let tree = parse(src);
        assert!(collect_java_field_types(tree.root_node(), src.as_bytes()).is_empty());
    }

    // ------------------------------------------- liaison implicite Spring

    #[test]
    fn test_unannotated_param_on_mapped_handler_detected() {
        let src = "class H { @PostMapping(\"/x\") void completed(String account) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert_eq!(fns[0].route_param_names, vec!["account".to_string()]);
    }

    #[test]
    fn test_unannotated_param_not_mapped_handler_excluded() {
        let src = "class H { void completed(String account) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert!(fns[0].route_param_names.is_empty());
    }

    #[test]
    fn test_container_type_excluded_even_on_mapped_handler() {
        let src = "class H { @GetMapping(\"/x\") void completed(HttpServletRequest request) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert!(fns[0].route_param_names.is_empty());
    }

    #[test]
    fn test_unknown_annotation_excludes_even_on_mapped_handler() {
        let src =
            "class H { @PostMapping(\"/x\") void completed(@AuthenticationPrincipal String u) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert!(fns[0].route_param_names.is_empty());
    }

    #[test]
    fn test_known_annotation_still_detected_on_mapped_handler() {
        let src = "class H { @PostMapping(\"/x\") void completed(@RequestParam String q) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert_eq!(fns[0].route_param_names, vec!["q".to_string()]);
    }

    #[test]
    fn test_implicit_binding_covers_list_map_multipartfile() {
        let src = "class H { @PostMapping(\"/x\") void completed(List items, Map data, MultipartFile file) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        let set: std::collections::BTreeSet<&String> = fns[0].route_param_names.iter().collect();
        assert_eq!(
            set,
            std::collections::BTreeSet::from([
                &"items".to_string(),
                &"data".to_string(),
                &"file".to_string()
            ])
        );
    }

    #[test]
    fn test_non_bindable_type_excluded_even_implicit() {
        let src = "class H { @PostMapping(\"/x\") void completed(SearchCriteria criteria) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert!(fns[0].route_param_names.is_empty());
    }

    #[test]
    fn test_request_mapping_annotation_also_triggers_implicit() {
        let src = "class H { @RequestMapping(\"/x\") void completed(String account) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert_eq!(fns[0].route_param_names, vec!["account".to_string()]);
    }

    #[test]
    fn test_reader_and_exception_container_types_excluded_even_implicit() {
        // Regression: SPRING_CONTAINER_TYPES must cover all 20 types
        // from Audit/sca/dataflow/java_summary.py, not just the first
        // 18 — Reader/Exception were missing from an earlier
        // version of this port, discovered by recounting against the source.
        let src = "class H { @PostMapping(\"/x\") void completed(Reader r, Exception e) {} }";
        let tree = parse(src);
        let fns = collect_java_functions(tree.root_node(), src.as_bytes());
        assert!(fns[0].route_param_names.is_empty());
    }
}
