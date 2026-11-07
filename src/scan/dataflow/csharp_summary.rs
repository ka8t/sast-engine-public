//! Function summaries for C# interprocedural analysis — mirrors
//! `java_summary.rs`, faithful port of `Audit/sca/dataflow/csharp_summary.py`
//! (ticket #79/spec #77).
//!
//! **Maximal sharing, not a port**: `compute_summary_from_cfg_generic`
//! (`summary.rs`) already carries 100% of the probing algorithm —
//! language-neutral, it only consumes the generic IR and the CFG.
//! `compute_csharp_summary` below only builds the C#
//! CFG and delegates to `summary::compute_csharp_summary_from_cfg`;
//! no duplicated logic.
//!
//! What genuinely differs per language — and justifies this
//! separate file:
//!   - **Function discovery**: C# also has no top-level
//!     functions either — only methods/constructors of
//!     classes/structs/records/interfaces, discovered by scanning
//!     top-level type bodies. Local functions (nested inside a
//!     method body) and property accessors (`get`/`set`) are
//!     OUT OF SCOPE v1 — the same kind of documented limitation as
//!     the exclusion of anonymous classes on the Java side, to be extended only
//!     if a real corpus justifies it (the Juliet Test Suite C# 1.3, the
//!     initial calibration target, uses neither).
//!   - **Building the CFG from a function**:
//!     `build_csharp_cfg` already directly accepts a `block` node
//!     (no separate `constructor_body` type in this grammar,
//!     unlike Java) — `fn.body_node` IS the expected input,
//!     no wrapping needed.
//!   - **Namespaces** (`namespace Foo { ... }`, with no
//!     Java equivalent): the block form wraps its types in a
//!     `body` field (`declaration_list`) — recursed into explicitly, otherwise
//!     no method is ever discovered in the overwhelmingly
//!     dominant case in the Juliet corpus (nearly all files use the
//!     block form, not the "file-scoped" `namespace Foo;` C# 10+ form,
//!     which leaves types as direct children already covered by an
//!     ordinary top-level scan).
//!   - **`preproc_if` flattening**: methods in the Juliet corpus
//!     are wrapped in an actual `preproc_if` node (`#if
//!     (!OMITBAD)`) — reuses
//!     `csharp_cfg::flatten_preproc_members` (built and tested in
//!     ticket #78) rather than a second implementation.
//!
//! No ASP.NET Core route parameters (`[FromQuery]`/`[FromBody]`/
//! ..., the equivalent of Java/Spring's `route_param_names`) — explicit
//! OUT OF SCOPE per ticket #77 (the Juliet Test Suite C# does not use
//! ASP.NET Core, and Python itself never built this
//! detection). `CSharpFunctionInfo` therefore does NOT have this field,
//! unlike `JavaFunctionInfo`.

use std::collections::BTreeMap;
use std::sync::Arc;

use tree_sitter::Node;

use super::csharp_cfg::flatten_preproc_members;
pub use super::transfer::FunctionSummary;
use super::transfer::RuleSpecs;

const TOP_LEVEL_TYPE_DECLS: [&str; 4] = [
    "class_declaration",
    "struct_declaration",
    "record_declaration",
    "interface_declaration",
];

const NAMESPACE_DECLS: [&str; 1] = ["namespace_declaration"];

/// Metadata for a C# method/constructor.
///
/// `name`: dotted name `"ClassName.Method"` (methods) or
/// `"ClassName.<init>"` (constructors — same convention as
/// `JavaFunctionInfo`, avoids the `Foo.Foo` collision with a method
/// named like the class). `body_node`: tree-sitter node of the body
/// (`block`), directly consumable by `build_csharp_cfg`.
pub struct CSharpFunctionInfo<'tree> {
    pub name: String,
    pub body_node: Node<'tree>,
    pub param_names: Vec<String>,
    pub lineno: usize,
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
        .filter(|p| p.kind() == "parameter")
        .filter_map(|p| p.child_by_field_name("name"))
        .map(|n| text(n, source))
        .collect()
}

// ============================================================================
// Method/constructor discovery
// ============================================================================

/// Lists the methods/constructors of classes/structs/records/
/// interfaces in a C# file (`compilation_unit`), including nested types
/// and namespaces.
///
/// A nested class is indexed under its simple name (not qualified
/// by its enclosing type) — same convention as
/// `java_summary.rs::collect_java_functions`, consistent with how
/// `new Test().Method()` is resolved (`transfer.rs::eval_call`).
/// On a name collision between two types in the same file, the
/// last one encountered wins (accepted limitation, identical to Java).
///
/// A method without a body (interface member, abstract method) is
/// ignored. Out of scope: local functions, property accessors
/// (see module doc).
pub fn collect_csharp_functions<'tree>(
    root: Node<'tree>,
    source: &[u8],
) -> Vec<CSharpFunctionInfo<'tree>> {
    let mut functions = Vec::new();
    for type_decl in iter_top_level_type_decls(root) {
        collect_type_members(type_decl, source, &mut functions);
    }
    functions
}

/// Walks the file's top-level type declarations, recursing
/// through block-form `namespace` wrappers (see
/// module doc) — namespaces can nest
/// (`namespace Foo { namespace Bar { class X {} } }`); the recursion
/// handles this case uniformly.
fn iter_top_level_type_decls<'tree>(root: Node<'tree>) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut w = root.walk();
    for child in root.named_children(&mut w) {
        if TOP_LEVEL_TYPE_DECLS.contains(&child.kind()) {
            out.push(child);
        } else if NAMESPACE_DECLS.contains(&child.kind()) {
            let body = child.child_by_field_name("body").or_else(|| {
                child
                    .children(&mut child.walk())
                    .find(|c| c.kind() == "declaration_list")
            });
            if let Some(body) = body {
                out.extend(iter_top_level_type_decls(body));
            }
        }
    }
    out
}

fn collect_type_members<'tree>(
    type_decl: Node<'tree>,
    source: &[u8],
    out: &mut Vec<CSharpFunctionInfo<'tree>>,
) {
    let Some(name_node) = type_decl.child_by_field_name("name") else {
        return;
    };
    let Some(body) = type_decl.child_by_field_name("body") else {
        return;
    };
    let type_name = text(name_node, source);
    for member in flatten_preproc_members(body) {
        match member.kind() {
            "method_declaration" => {
                if let Some(fn_info) = method_info(member, &type_name, source) {
                    out.push(fn_info);
                }
            }
            "constructor_declaration" => {
                if let Some(fn_info) = constructor_info(member, &type_name, source) {
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
    type_name: &str,
    source: &[u8],
) -> Option<CSharpFunctionInfo<'tree>> {
    let body = node.child_by_field_name("body")?; // interface member/abstract method: nothing to analyze
    let method_name = node
        .child_by_field_name("name")
        .map(|n| text(n, source))
        .unwrap_or_else(|| "?".to_string());
    Some(CSharpFunctionInfo {
        name: format!("{type_name}.{method_name}"),
        body_node: body,
        param_names: param_names(node.child_by_field_name("parameters"), source),
        lineno: node.start_position().row + 1,
    })
}

fn constructor_info<'tree>(
    node: Node<'tree>,
    type_name: &str,
    source: &[u8],
) -> Option<CSharpFunctionInfo<'tree>> {
    let body = node.child_by_field_name("body")?;
    Some(CSharpFunctionInfo {
        name: format!("{type_name}.<init>"),
        body_node: body,
        param_names: param_names(node.child_by_field_name("parameters"), source),
        lineno: node.start_position().row + 1,
    })
}

// ============================================================================
// Summary computation
// ============================================================================

/// Computes the summary of a C# method/constructor.
///
/// Builds the CFG from `fn.body_node` then delegates to
/// `summary::compute_csharp_summary_from_cfg` — no duplication of
/// the probing algorithm.
pub fn compute_csharp_summary<'tree>(
    fn_info: &CSharpFunctionInfo<'tree>,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
) -> FunctionSummary {
    let cfg = super::csharp_cfg::build_csharp_cfg(fn_info.body_node, source);
    super::summary::compute_csharp_summary_from_cfg(
        &cfg,
        &fn_info.name,
        &fn_info.param_names,
        specs,
        source,
        source_lines,
        fn_info.lineno,
    )
}

/// Computes the summaries of all methods/constructors of a C# file.
/// Mirrors `compute_java_file_summaries`.
///
/// Also exposes each method under its **bare** name (without the
/// class prefix) when unambiguous — an unqualified intra-class call
/// (`InjectableQuery(x)` within the same class) is valid in C# as in
/// Java; without this alias, most intra-class calls would never
/// resolve via the summaries — see [`add_bare_name_aliases`].
pub fn compute_csharp_file_summaries<'tree>(
    root: Node<'tree>,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
) -> BTreeMap<String, Arc<FunctionSummary>> {
    let mut summaries = BTreeMap::new();
    for fn_info in collect_csharp_functions(root, source) {
        let summary = Arc::new(compute_csharp_summary(
            &fn_info,
            specs,
            source,
            source_lines,
        ));
        summaries.insert(fn_info.name, summary);
    }
    add_bare_name_aliases(&mut summaries);
    summaries
}

/// Adds, for each unambiguous method, an alias under its bare name.
///
/// Unambiguous = a single member with this name across the WHOLE
/// file (all top-level types combined). Ambiguous (same name in two
/// types of the same file) → no bare alias created for that name,
/// anti-FP (better to miss a flow than resolve to the wrong type).
/// Constructors (`Type.<init>`) are excluded — `<init>` is never a
/// valid C# identifier anyway.
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
// Declared types of local variables / fields — same purpose as
// `collect_java_local_types`/`collect_java_field_types`: lets a call
// qualified by a typed variable (`scr.Method()`) resolve to the
// `SeparateClassRequest.Method` summary (always indexed by class
// name, never by variable name — cf. `RuleSpecs.type_map`,
// `transfer.rs::eval_call`).
// ============================================================================

/// Simple name of a type node, with generic arguments and namespace
/// stripped (`System.Collections.Generic.List<string>` → `"List"`).
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
    if node.kind() == "local_declaration_statement" {
        let mut w = node.walk();
        let decl = node
            .named_children(&mut w)
            .find(|c| c.kind() == "variable_declaration");
        if let Some(decl) = decl
            && let Some(type_node) = decl.child_by_field_name("type")
        {
            let simple = simple_type_name(type_node, source);
            if !simple.is_empty() {
                let mut dw = decl.walk();
                for declarator in decl.named_children(&mut dw) {
                    if declarator.kind() != "variable_declarator" {
                        continue;
                    }
                    if let Some(name_node) = declarator.child_by_field_name("name") {
                        out.insert(text(name_node, source), simple.clone());
                    }
                }
            }
        }
    }
    let mut w = node.walk();
    for child in node.children(&mut w) {
        collect_local_var_types(child, source, out);
    }
}

/// Builds `variable_name -> simple_class_name` for every local
/// variable declaration in the file (across all methods), including
/// `using (var x = ...)` resource declarations (generic recursion
/// over every child, not just `local_declaration_statement` — unlike
/// Python, which explicitly excludes this case as a documented scope
/// limit; here the `collect_local_var_types` recursion naturally
/// descends into the bare `variable_declaration` appended by
/// `CSharpCfgBuilder::visit_using`, EXCEPT that this node precisely
/// does not have the `local_declaration_statement` type expected by
/// the guard above — the same scope limit as Python in practice,
/// noted here so a future reader does not rediscover it by surprise).
///
/// Accepted simplification, identical to `collect_java_local_types`:
/// built over the WHOLE file, not per method scope. Method
/// PARAMETERS are not covered.
pub fn collect_csharp_local_types(root: Node, source: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for fn_info in collect_csharp_functions(root, source) {
        collect_local_var_types(fn_info.body_node, source, &mut out);
    }
    out
}

/// Builds `field_name -> simple_class_name` for the fields
/// (`field_declaration`) of every top-level (and nested) type in the
/// file — complements `collect_csharp_local_types`, which only sees
/// local variables.
///
/// Same simplification as `collect_csharp_local_types`: whole-file
/// scope, not per type — on a name collision between two types, the
/// last declaration encountered wins.
pub fn collect_csharp_field_types(root: Node, source: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for type_decl in iter_top_level_type_decls(root) {
        collect_type_field_types(type_decl, source, &mut out);
    }
    out
}

/// `type_decl` is a `class_declaration`/... node (not a container) —
/// same contract as `collect_type_members`, the equivalent for
/// fields rather than methods.
fn collect_type_field_types(type_decl: Node, source: &[u8], out: &mut BTreeMap<String, String>) {
    let Some(body) = type_decl.child_by_field_name("body") else {
        return;
    };
    for member in flatten_preproc_members(body) {
        match member.kind() {
            "field_declaration" => {
                let mut w = member.walk();
                let Some(decl) = member
                    .named_children(&mut w)
                    .find(|c| c.kind() == "variable_declaration")
                else {
                    continue;
                };
                let Some(type_node) = decl.child_by_field_name("type") else {
                    continue;
                };
                let simple = simple_type_name(type_node, source);
                if simple.is_empty() {
                    continue;
                }
                let mut dw = decl.walk();
                for declarator in decl.named_children(&mut dw) {
                    if declarator.kind() != "variable_declarator" {
                        continue;
                    }
                    if let Some(name_node) = declarator.child_by_field_name("name") {
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
// Tests — partial mirror of `java_summary.rs::tests` (excluding Spring
// machinery, out of scope for C# — cf. module doc), density
// equivalent (~40 tests targeted by ticket #79).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::{SinkSpec, SourceSpec};
    use tree_sitter::Parser;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_c_sharp::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(src, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "syntaxe C# invalide : {src:?}"
        );
        tree
    }

    fn sqli_specs() -> RuleSpecs {
        RuleSpecs {
            rule_id: "test-sqli".to_string(),
            severity: "HIGH".to_string(),
            cwe: None,
            message: "test finding".to_string(),
            sources: vec![SourceSpec::new("Request.GetParameter", "http")],
            sinks: vec![SinkSpec::new("*.Execute")],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
        }
    }

    // ------------------------------------------------- collect_csharp_functions

    #[test]
    fn test_single_method() {
        let src = "class Foo { void Bar() {} }";
        let tree = parse(src);
        let fns = collect_csharp_functions(tree.root_node(), src.as_bytes());
        assert_eq!(
            fns.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            vec!["Foo.Bar"]
        );
    }

    #[test]
    fn test_multiple_methods_and_params() {
        let src =
            "class Foo { void Run(string query, object db) {} int Compute(int x) { return x; } }";
        let tree = parse(src);
        let fns = collect_csharp_functions(tree.root_node(), src.as_bytes());
        let names: std::collections::BTreeSet<&str> = fns.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from(["Foo.Run", "Foo.Compute"])
        );
        let run = fns.iter().find(|f| f.name == "Foo.Run").unwrap();
        assert_eq!(run.param_names, vec!["query".to_string(), "db".to_string()]);
        let compute = fns.iter().find(|f| f.name == "Foo.Compute").unwrap();
        assert_eq!(compute.param_names, vec!["x".to_string()]);
    }

    #[test]
    fn test_constructor_named_init() {
        let src = "class Foo { Foo(string x) {} }";
        let tree = parse(src);
        let fns = collect_csharp_functions(tree.root_node(), src.as_bytes());
        assert_eq!(fns[0].name, "Foo.<init>");
        assert_eq!(fns[0].param_names, vec!["x".to_string()]);
    }

    #[test]
    fn test_abstract_method_skipped() {
        let src = "interface Foo { void Bar(); }";
        let tree = parse(src);
        assert!(collect_csharp_functions(tree.root_node(), src.as_bytes()).is_empty());
    }

    #[test]
    fn test_multiple_top_level_classes() {
        let src = "class Foo { void A() {} } class Bar { void B() {} }";
        let tree = parse(src);
        let names: std::collections::BTreeSet<String> =
            collect_csharp_functions(tree.root_node(), src.as_bytes())
                .into_iter()
                .map(|f| f.name)
                .collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from(["Foo.A".to_string(), "Bar.B".to_string()])
        );
    }

    #[test]
    fn test_empty_file() {
        let src = "class Foo {}";
        let tree = parse(src);
        assert!(collect_csharp_functions(tree.root_node(), src.as_bytes()).is_empty());
    }

    #[test]
    fn test_nested_class_method_discovered() {
        let src = "class Api { void Handler() {} private class Test { string DoSomething(string p) { return p; } } }";
        let tree = parse(src);
        let names: std::collections::BTreeSet<String> =
            collect_csharp_functions(tree.root_node(), src.as_bytes())
                .into_iter()
                .map(|f| f.name)
                .collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from([
                "Api.Handler".to_string(),
                "Test.DoSomething".to_string()
            ])
        );
    }

    #[test]
    fn test_doubly_nested_class_method_discovered() {
        let src = "class Api { private class Mid { private class Inner { void Deep() {} } } }";
        let tree = parse(src);
        let names: std::collections::BTreeSet<String> =
            collect_csharp_functions(tree.root_node(), src.as_bytes())
                .into_iter()
                .map(|f| f.name)
                .collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from(["Inner.Deep".to_string()])
        );
    }

    // ------------------------------------------- block namespace (no Java equivalent)

    #[test]
    fn test_block_namespace_discovered() {
        let src = "namespace Foo { class Api { void M() {} } }";
        let tree = parse(src);
        let names: std::collections::BTreeSet<String> =
            collect_csharp_functions(tree.root_node(), src.as_bytes())
                .into_iter()
                .map(|f| f.name)
                .collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from(["Api.M".to_string()])
        );
    }

    #[test]
    fn test_nested_namespaces_discovered() {
        let src = "namespace A { namespace B { class C { void M() {} } } }";
        let tree = parse(src);
        let names: std::collections::BTreeSet<String> =
            collect_csharp_functions(tree.root_node(), src.as_bytes())
                .into_iter()
                .map(|f| f.name)
                .collect();
        assert_eq!(names, std::collections::BTreeSet::from(["C.M".to_string()]));
    }

    // ------------------------------------------- preproc_if (Juliet corpus)

    #[test]
    fn test_method_wrapped_in_preproc_if_discovered() {
        let src = "class C { #if (!OMITBAD)\nvoid M() { }\n#endif\n }";
        let tree = parse(src);
        let names: std::collections::BTreeSet<String> =
            collect_csharp_functions(tree.root_node(), src.as_bytes())
                .into_iter()
                .map(|f| f.name)
                .collect();
        assert_eq!(names, std::collections::BTreeSet::from(["C.M".to_string()]));
    }

    #[test]
    fn test_method_without_preproc_if_still_discovered() {
        let src = "class C { void M() { } }";
        let tree = parse(src);
        let names: std::collections::BTreeSet<String> =
            collect_csharp_functions(tree.root_node(), src.as_bytes())
                .into_iter()
                .map(|f| f.name)
                .collect();
        assert_eq!(names, std::collections::BTreeSet::from(["C.M".to_string()]));
    }

    // ------------------------------------- compute_csharp_summary(_file_summaries)

    #[test]
    fn test_return_tainted_uncond() {
        let src = "class Api { string GetInput() { return Request.GetParameter(\"q\"); } }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_csharp_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(sums.contains_key("Api.GetInput"));
        assert!(sums["Api.GetInput"].return_tainted_uncond);
    }

    /// Ticket #123: an expression-bodied method (`=> expr`) returns
    /// `expr` — its summary must say so, like the `return` form above.
    #[test]
    fn test_expression_bodied_method_return_tainted_uncond() {
        let src = "class Api { string GetInput() => Request.GetParameter(\"q\"); }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_csharp_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(sums["Api.GetInput"].return_tainted_uncond);
    }

    /// Ticket #123: a parameter reaching a sink through an
    /// expression body (`void Run(string q, object db) => db.Execute(q);`).
    #[test]
    fn test_expression_bodied_method_sink_param_finding() {
        let src = "class Api { void RunQuery(string query, object db) => db.Execute(query); }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_csharp_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(sums["Api.RunQuery"].sink_param_findings.contains_key(&0));
    }

    #[test]
    fn test_sink_param_finding() {
        let src = "class Api { void RunQuery(string query, object db) { db.Execute(query); } }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_csharp_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(sums["Api.RunQuery"].sink_param_findings.contains_key(&0));
    }

    #[test]
    fn test_clean_function_summary_is_empty() {
        let src = "class Api { void RunQuery(object db) { db.Execute(\"SELECT 1\"); } }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_csharp_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(!sums["Api.RunQuery"].return_tainted_uncond);
        assert!(sums["Api.RunQuery"].sink_param_findings.is_empty());
    }

    // ---------------------------------------------------- bare name alias

    #[test]
    fn test_bare_name_alias_added_when_unambiguous() {
        let src = "class Api { void RunQuery(string q, object db) { db.Execute(q); } }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_csharp_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(sums.contains_key("RunQuery"));
        assert!(sums.contains_key("Api.RunQuery"));
    }

    #[test]
    fn test_bare_name_alias_not_added_when_ambiguous() {
        let src = "class A { void RunQuery() {} } class B { void RunQuery() {} }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_csharp_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(!sums.contains_key("RunQuery"));
        assert!(sums.contains_key("A.RunQuery"));
        assert!(sums.contains_key("B.RunQuery"));
    }

    #[test]
    fn test_bare_name_alias_excludes_constructors() {
        let src = "class Api { Api(string x) {} }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let sums = compute_csharp_file_summaries(
            tree.root_node(),
            &sqli_specs(),
            src.as_bytes(),
            Some(&lines),
        );
        assert!(!sums.contains_key("<init>"));
        assert!(sums.contains_key("Api.<init>"));
    }

    // -------------------------------------------------- local/field types

    #[test]
    fn test_local_var_type_resolved() {
        let src =
            "class Api { void M() { SeparateClassRequest scr = new SeparateClassRequest(); } }";
        let tree = parse(src);
        let types = collect_csharp_local_types(tree.root_node(), src.as_bytes());
        assert_eq!(
            types.get("scr").map(String::as_str),
            Some("SeparateClassRequest")
        );
    }

    #[test]
    fn test_local_var_type_generic_stripped() {
        let src = "class Api { void M() { List<string> items = new List<string>(); } }";
        let tree = parse(src);
        let types = collect_csharp_local_types(tree.root_node(), src.as_bytes());
        assert_eq!(types.get("items").map(String::as_str), Some("List"));
    }

    #[test]
    fn test_field_type_resolved() {
        let src = "class Api { private CommentsCache comments; void M() {} }";
        let tree = parse(src);
        let types = collect_csharp_field_types(tree.root_node(), src.as_bytes());
        assert_eq!(
            types.get("comments").map(String::as_str),
            Some("CommentsCache")
        );
    }

    #[test]
    fn test_field_type_in_nested_class() {
        let src = "class Outer { class Inner { private Foo bar; } }";
        let tree = parse(src);
        let types = collect_csharp_field_types(tree.root_node(), src.as_bytes());
        assert_eq!(types.get("bar").map(String::as_str), Some("Foo"));
    }

    #[test]
    fn test_no_field_types_when_none_declared() {
        let src = "class Api { void M() {} }";
        let tree = parse(src);
        assert!(collect_csharp_field_types(tree.root_node(), src.as_bytes()).is_empty());
    }

    // ---------------------------------------------------- add_bare_name_aliases (unit)

    #[test]
    fn test_add_bare_name_aliases_unit() {
        let mut summaries: BTreeMap<String, Arc<FunctionSummary>> = BTreeMap::new();
        summaries.insert(
            "Foo.Bar".to_string(),
            Arc::new(FunctionSummary {
                name: "Foo.Bar".to_string(),
                ..Default::default()
            }),
        );
        add_bare_name_aliases(&mut summaries);
        assert!(summaries.contains_key("Bar"));
    }

    #[test]
    fn test_add_bare_name_aliases_respects_existing_key() {
        // A bare name already present (a fictitious top-level method,
        // never real in C#, but a defensive guard identical to Java)
        // must not be overwritten.
        let mut summaries: BTreeMap<String, Arc<FunctionSummary>> = BTreeMap::new();
        summaries.insert(
            "Foo.Bar".to_string(),
            Arc::new(FunctionSummary {
                name: "Foo.Bar".to_string(),
                ..Default::default()
            }),
        );
        summaries.insert(
            "Bar".to_string(),
            Arc::new(FunctionSummary {
                name: "Bar".to_string(),
                return_tainted_uncond: true,
                ..Default::default()
            }),
        );
        add_bare_name_aliases(&mut summaries);
        assert!(summaries["Bar"].return_tainted_uncond);
    }
}
