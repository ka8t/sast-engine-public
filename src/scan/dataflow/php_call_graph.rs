//! Persistent PHP call graph — multi-hop interprocedural resolution.
//! Direct template of `js_call_graph.rs` for the shape
//! (nodes/edges/Tarjan SCC/fixpoint), **resolution algorithm entirely
//! specific to PHP** (`php_module_registry.rs` — two distinct
//! mechanisms: star-merge of `require`/`include`, global class-name
//! index for static-scope calls): no equivalent Python source exists
//! for this module (same observation as for JS, see
//! `js_call_graph.rs` doc) — new development, not a port.
//!
//! **Cycles/recursion**: decomposition into strongly connected
//! components (Tarjan) + bounded fixpoint
//! (`call_graph::MAX_SCC_FIXPOINT_ITER`), duplicated from
//! `call_graph.rs`/`js_call_graph.rs` — same deliberate choice as for
//! JS (no extraction into a shared helper for this effort).
//!
//! **Call resolution** (`outgoing_edges`, see `call_local_name` below
//! and the `php_module_registry.rs` doc for the details of the two
//! mechanisms):
//!   - Bare call `foo()` — same file, otherwise via a function made
//!     available by a literal `require`/`include` (star-merge).
//!   - `Klass::method()` (literal static scope) — resolved via the
//!     global class-name index, **with no notion of scope/
//!     namespace** (unlike Java, which limits itself to classes in
//!     the same package + explicit imports): sufficient to cover
//!     modern PHP code (Composer/PSR-4), which often has no explicit
//!     `require` between application classes.
//!   - `self::method()`/`static::method()` — resolved by bare name in
//!     the current file (same spirit as `this.method()` in JS).
//!   - `$obj->method()` — resolved **only** if `$obj` is literally
//!     `$this` (same file); no variable type tracking (no Java-style
//!     `type_map`), same limitation as JS for `obj.method()` on a
//!     non-imported receiver.
//!   - `parent::method()` — **not resolved in v1**: would require
//!     knowing which class encloses the calling method in order to
//!     find its superclass (Java does this via a qualified
//!     `JavaFunctionInfo` `Class.method` + a superclass map;
//!     `PhpFunctionInfo` does not keep this class-method association)
//!     — out of scope for this effort, documented rather than guessed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tree_sitter::Node;

pub use super::call_graph::{FileInput, MAX_SCC_FIXPOINT_ITER, NodeKey, SummariesByFile};
use super::php_module_registry::{
    build_class_name_index, collect_php_class_names, collect_php_requires, resolve_required_file,
};
use super::php_summary::{PhpFunctionInfo, collect_php_functions, compute_php_summary};
use super::transfer::{FunctionSummary, RuleSpecs};

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// Local call name of a PHP call node — three distinct node shapes
/// in PHP (unlike the unified `call_expression` in JS, see
/// `php_lowering.rs` doc):
///   - `function_call_expression` (`foo(...)`) → `foo`, only if the
///     callee is a literal `name` (not `$fn(...)`, a dynamic call).
///   - `member_call_expression` (`$obj->method(...)`) → `this.method`
///     only if `$obj` is literally `$this`; otherwise unresolved (no
///     variable type tracking).
///   - `scoped_call_expression` (`Klass::method(...)`/`self::.../
///     static::.../parent::...`) → `Klass.method` (scope = literal
///     class name) or `self.method`/`static.method` (relative scope
///     resolved by bare name in the current file); `None` for
///     `parent::...` (out of scope for v1, see module doc).
fn call_local_name(call_node: Node, source: &[u8]) -> Option<String> {
    match call_node.kind() {
        "function_call_expression" => {
            let func = call_node.child_by_field_name("function")?;
            if func.kind() != "name" {
                return None;
            }
            Some(text(func, source))
        }
        "member_call_expression" => {
            let obj = call_node.child_by_field_name("object")?;
            let name = call_node.child_by_field_name("name")?;
            if obj.kind() == "variable_name" && text(obj, source) == "$this" {
                Some(format!("this.{}", text(name, source)))
            } else {
                None
            }
        }
        "scoped_call_expression" => {
            let scope = call_node.child_by_field_name("scope")?;
            let name = call_node.child_by_field_name("name")?;
            match scope.kind() {
                "name" => Some(format!("{}.{}", text(scope, source), text(name, source))),
                "relative_scope" => match text(scope, source).as_str() {
                    "self" | "static" => {
                        Some(format!("{}.{}", text(scope, source), text(name, source)))
                    }
                    _ => None, // "parent" — not resolved in v1, see module doc.
                },
                _ => None,
            }
        }
        _ => None,
    }
}

const CALL_NODE_KINDS: [&str; 3] = [
    "function_call_expression",
    "member_call_expression",
    "scoped_call_expression",
];

fn walk_calls<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if CALL_NODE_KINDS.contains(&node.kind()) {
        out.push(node);
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_calls(child, out);
    }
}

/// Returns the outgoing edges of a PHP function. Resolves: a bare
/// call to a function in the same file, or one made available by a
/// literal `require`/`include`/static-scope
/// (`import_bindings`, see module doc for how the latter is built —
/// star-merge of `require` + global class index);
/// `self.`/`static.`/`this.` are resolved directly as same-file here
/// (never via `import_bindings`, which does not contain them).
fn outgoing_edges(
    fn_info: &PhpFunctionInfo,
    source: &[u8],
    filepath: &str,
    local_names: &BTreeSet<String>,
    import_bindings: &BTreeMap<String, NodeKey>,
) -> BTreeMap<String, NodeKey> {
    let mut edges = BTreeMap::new();
    let mut calls = Vec::new();
    walk_calls(fn_info.body_node, &mut calls);
    for call_node in calls {
        let Some(local_name) = call_local_name(call_node, source) else {
            continue;
        };
        if edges.contains_key(&local_name) {
            continue;
        }
        let same_file_target = ["this.", "self.", "static."]
            .iter()
            .find_map(|prefix| local_name.strip_prefix(prefix));
        if let Some(method) = same_file_target {
            if local_names.contains(method) {
                edges.insert(
                    local_name.clone(),
                    (filepath.to_string(), method.to_string()),
                );
            }
            continue;
        }
        if local_names.contains(&local_name) {
            edges.insert(local_name.clone(), (filepath.to_string(), local_name));
        } else if let Some(target) = import_bindings.get(&local_name) {
            edges.insert(local_name.clone(), target.clone());
        }
    }
    edges
}

/// Bindings brought in by a file's `require`/`include` (literal
/// string) — star-merge (mirrors `call_graph.rs::
/// resolve_import_bindings`, Python star-import branch): each
/// function of the required file becomes callable **without a
/// prefix**. On collision (two required files each defining a
/// function with the same name) → neither is kept (anti-FP).
fn resolve_require_bindings(
    filepath: &str,
    required_specifiers: &[String],
    known_files: &[String],
    file_function_names: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, NodeKey> {
    let mut seen: BTreeMap<String, NodeKey> = BTreeMap::new();
    let mut collided: BTreeSet<String> = BTreeSet::new();
    let empty_set: BTreeSet<String> = BTreeSet::new();
    for spec in required_specifiers {
        let Some(target) = resolve_required_file(filepath, spec, known_files) else {
            continue;
        };
        if target == filepath {
            continue;
        }
        for fname in file_function_names.get(&target).unwrap_or(&empty_set) {
            let key = (target.clone(), fname.clone());
            match seen.get(fname) {
                Some(existing) if *existing != key => {
                    collided.insert(fname.clone());
                }
                None => {
                    seen.insert(fname.clone(), key);
                }
                _ => {}
            }
        }
    }
    seen.into_iter()
        .filter(|(name, _)| !collided.contains(name))
        .collect()
}

// ============================================================================
// PhpCallGraph
// ============================================================================

/// Call graph of a set of PHP files analyzed together — same
/// contract as `call_graph::CallGraph`/`js_call_graph::JsCallGraph`
/// (see their doc for field details, identical here).
#[derive(Default)]
pub struct PhpCallGraph<'tree> {
    pub nodes: BTreeMap<NodeKey, PhpFunctionInfo<'tree>>,
    pub edges: BTreeMap<NodeKey, BTreeMap<String, NodeKey>>,
    pub import_bindings: BTreeMap<String, BTreeMap<String, NodeKey>>,
    source_by_file: BTreeMap<String, &'tree [u8]>,
}

impl<'tree> PhpCallGraph<'tree> {
    /// Builds the complete graph from a set of already-parsed PHP
    /// files.
    ///
    /// Static-scope bindings (`Klass.method`, via the global
    /// class-name index) are computed **once for the whole corpus**
    /// (file-independent — no scope/namespace notion is tracked, see
    /// module doc), then merged into `import_bindings` of EACH file,
    /// alongside the `require` bindings specific to that file — no
    /// key collision is possible (`require` keys are bare function
    /// names, without a `.`, class keys always contain a `.`).
    pub fn build(files: &[FileInput<'tree>]) -> Self {
        let mut graph = PhpCallGraph::default();
        let mut file_function_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut requires_by_file: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut class_names_by_file: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for f in files {
            let functions = collect_php_functions(f.root, f.source);
            file_function_names.insert(
                f.filepath.clone(),
                functions.iter().map(|fi| fi.name.clone()).collect(),
            );
            for fi in functions {
                graph
                    .nodes
                    .insert((f.filepath.clone(), fi.name.clone()), fi);
            }
            requires_by_file.insert(f.filepath.clone(), collect_php_requires(f.root, f.source));
            class_names_by_file.insert(
                f.filepath.clone(),
                collect_php_class_names(f.root, f.source),
            );
            graph.source_by_file.insert(f.filepath.clone(), f.source);
        }

        let known_files: Vec<String> = file_function_names.keys().cloned().collect();
        let class_index = build_class_name_index(&class_names_by_file);
        let empty_set: BTreeSet<String> = BTreeSet::new();
        let mut global_class_bindings: BTreeMap<String, NodeKey> = BTreeMap::new();
        for (cname, target) in &class_index {
            let Some(target_fp) = target else { continue };
            for method in file_function_names.get(target_fp).unwrap_or(&empty_set) {
                global_class_bindings.insert(
                    format!("{cname}.{method}"),
                    (target_fp.clone(), method.clone()),
                );
            }
        }

        for filepath in &known_files {
            let requires = requires_by_file.get(filepath).cloned().unwrap_or_default();
            let mut bindings =
                resolve_require_bindings(filepath, &requires, &known_files, &file_function_names);
            bindings.extend(global_class_bindings.clone());
            let local_names = file_function_names
                .get(filepath)
                .cloned()
                .unwrap_or_default();
            let source = graph.source_by_file[filepath];
            let fn_keys: Vec<NodeKey> = graph
                .nodes
                .keys()
                .filter(|(fp, _)| fp == filepath)
                .cloned()
                .collect();
            for key in fn_keys {
                let edges = outgoing_edges(
                    &graph.nodes[&key],
                    source,
                    filepath,
                    &local_names,
                    &bindings,
                );
                graph.edges.insert(key, edges);
            }
            graph.import_bindings.insert(filepath.clone(), bindings);
        }
        graph
    }

    /// Decomposition into strongly connected components (Tarjan) —
    /// identical to `call_graph::CallGraph`/`js_call_graph::JsCallGraph`.
    fn strongly_connected_components(&self) -> Vec<Vec<NodeKey>> {
        let mut state = TarjanState::default();
        let node_keys: Vec<NodeKey> = self.nodes.keys().cloned().collect();
        for node in &node_keys {
            if !state.indices.contains_key(node) {
                self.tarjan_visit(node, &mut state);
            }
        }
        state.sccs
    }

    fn tarjan_visit(&self, node: &NodeKey, state: &mut TarjanState) {
        state.indices.insert(node.clone(), state.counter);
        state.lowlinks.insert(node.clone(), state.counter);
        state.counter += 1;
        state.stack.push(node.clone());
        state.on_stack.insert(node.clone());

        if let Some(node_edges) = self.edges.get(node) {
            for target in node_edges.values() {
                if !self.nodes.contains_key(target) {
                    continue;
                }
                if !state.indices.contains_key(target) {
                    self.tarjan_visit(target, state);
                    let target_low = state.lowlinks[target];
                    if target_low < state.lowlinks[node] {
                        state.lowlinks.insert(node.clone(), target_low);
                    }
                } else if state.on_stack.contains(target) {
                    let target_idx = state.indices[target];
                    if target_idx < state.lowlinks[node] {
                        state.lowlinks.insert(node.clone(), target_idx);
                    }
                }
            }
        }

        if state.lowlinks[node] == state.indices[node] {
            let mut component = Vec::new();
            loop {
                let w = state
                    .stack
                    .pop()
                    .expect("pile Tarjan non vide (racine SCC atteinte)");
                state.on_stack.remove(&w);
                let is_root = w == *node;
                component.push(w);
                if is_root {
                    break;
                }
            }
            state.sccs.push(component);
        }
    }

    fn build_seed(
        &self,
        node: &NodeKey,
        resolved: &BTreeMap<NodeKey, Arc<FunctionSummary>>,
        scc_current: &BTreeMap<NodeKey, Arc<FunctionSummary>>,
    ) -> BTreeMap<String, Arc<FunctionSummary>> {
        let mut seed = BTreeMap::new();
        if let Some(node_edges) = self.edges.get(node) {
            for (local_name, target) in node_edges {
                if let Some(s) = resolved.get(target) {
                    seed.insert(local_name.clone(), s.clone());
                } else if let Some(s) = scc_current.get(target) {
                    seed.insert(local_name.clone(), s.clone());
                }
            }
        }
        seed
    }

    fn compute_one(
        &self,
        node: &NodeKey,
        seed: BTreeMap<String, Arc<FunctionSummary>>,
        base_specs: &RuleSpecs,
        source_lines_by_file: &BTreeMap<String, Vec<String>>,
    ) -> Option<Arc<FunctionSummary>> {
        let (filepath, _name) = node;
        let fn_info = self.nodes.get(node)?;
        let specs = if seed.is_empty() {
            base_specs.clone()
        } else {
            RuleSpecs {
                summaries: seed,
                ..base_specs.clone()
            }
        };
        let source = *self.source_by_file.get(filepath)?;
        let lines = source_lines_by_file.get(filepath).map(|v| v.as_slice());
        Some(Arc::new(compute_php_summary(
            fn_info, &specs, source, lines,
        )))
    }

    /// Computes the summaries of all functions in the graph — same
    /// algorithm and same `(own, extra)` return contract as the
    /// other call graphs (see their doc).
    pub fn resolve_summaries(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&BTreeMap<String, Vec<String>>>,
    ) -> (SummariesByFile, SummariesByFile) {
        let resolved = self.resolve_summaries_incremental(base_specs, source_lines_by_file, None);
        (resolved.own, resolved.extra)
    }

    /// `resolve_summaries`, reusing the summaries of a previous scan where
    /// they cannot have changed: see
    /// `call_graph::CallGraph::resolve_summaries_incremental` (same
    /// algorithm, shared through `call_graph::resolve_incremental`).
    pub fn resolve_summaries_incremental(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&BTreeMap<String, Vec<String>>>,
        reuse: Option<&super::call_graph::SummaryReuse>,
    ) -> super::call_graph::ResolvedSummaries {
        let empty_lines = BTreeMap::new();
        let source_lines_by_file = source_lines_by_file.unwrap_or(&empty_lines);
        let sccs = self.strongly_connected_components();
        super::call_graph::resolve_incremental(
            sccs,
            &self.edges,
            &self.import_bindings,
            reuse,
            |node, resolved, current| {
                let seed = self.build_seed(node, resolved, current);
                self.compute_one(node, seed, base_specs, source_lines_by_file)
            },
        )
    }

    /// True when `file` reads a summary that changed in this scan.
    pub fn consumes_changed(
        &self,
        file: &str,
        changed: &std::collections::BTreeSet<NodeKey>,
    ) -> bool {
        super::call_graph::consumes_changed_in(&self.import_bindings, file, changed)
    }

    /// What, besides its own text, decides the analysis of `file`.
    pub fn dependency_fingerprint(&self, file: &str) -> String {
        super::call_graph::dependency_fingerprint_in(
            &self.edges,
            self.nodes.keys(),
            &self.import_bindings,
            file,
        )
    }
}

#[derive(Default)]
struct TarjanState {
    counter: usize,
    indices: BTreeMap<NodeKey, usize>,
    lowlinks: BTreeMap<NodeKey, usize>,
    on_stack: BTreeSet<NodeKey>,
    stack: Vec<NodeKey>,
    sccs: Vec<Vec<NodeKey>>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::SinkSpec;
    use tree_sitter::Parser;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn specs_with(sinks: Vec<SinkSpec>) -> RuleSpecs {
        RuleSpecs {
            rule_id: "test-rule".to_string(),
            severity: "HIGH".to_string(),
            cwe: None,
            message: "test finding".to_string(),
            sources: vec![],
            sinks,
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
        }
    }

    #[test]
    fn test_build_intra_file_edge_same_file_call() {
        let src = b"<?php\nfunction helper($x) {}\nfunction main() { helper(1); }\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = PhpCallGraph::build(&files);
        let edges = &graph.edges[&("m.php".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("m.php".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_build_cross_file_edge_via_require() {
        let src_a = b"<?php\nrequire './utils.php';\nfunction main() { helper(1); }\n".to_vec();
        let src_u = b"<?php\nfunction helper($x) {}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.php".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.php".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = PhpCallGraph::build(&files);
        let edges = &graph.edges[&("a.php".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("utils.php".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_static_call_resolved_via_global_class_index() {
        let src_a = b"<?php\nfunction main() { Utils::helper(1); }\n".to_vec();
        let src_u = b"<?php\nclass Utils {\n  function helper($x) {}\n}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.php".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.php".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = PhpCallGraph::build(&files);
        let edges = &graph.edges[&("a.php".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("Utils.helper"),
            Some(&("utils.php".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_ambiguous_class_name_not_resolved() {
        let src_a = b"<?php\nfunction main() { Utils::helper(1); }\n".to_vec();
        let src_u1 = b"<?php\nclass Utils {\n  function helper($x) {}\n}\n".to_vec();
        let src_u2 = b"<?php\nclass Utils {\n  function helper($x) {}\n}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u1 = parse(std::str::from_utf8(&src_u1).unwrap());
        let tree_u2 = parse(std::str::from_utf8(&src_u2).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.php".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils1.php".to_string(),
                root: tree_u1.root_node(),
                source: &src_u1,
            },
            FileInput {
                filepath: "utils2.php".to_string(),
                root: tree_u2.root_node(),
                source: &src_u2,
            },
        ];
        let graph = PhpCallGraph::build(&files);
        let edges = &graph.edges[&("a.php".to_string(), "main".to_string())];
        assert!(edges.get("Utils.helper").is_none());
    }

    #[test]
    fn test_self_and_static_resolved_same_file() {
        let src = b"<?php\nclass C {\n  function helper($x) {}\n  function main() { self::helper(1); static::helper(2); }\n}\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = PhpCallGraph::build(&files);
        let edges = &graph.edges[&("m.php".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("self.helper"),
            Some(&("m.php".to_string(), "helper".to_string()))
        );
        assert_eq!(
            edges.get("static.helper"),
            Some(&("m.php".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_parent_call_not_resolved() {
        let src = b"<?php\nclass C extends Base {\n  function main() { parent::helper(1); }\n}\n"
            .to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = PhpCallGraph::build(&files);
        let edges = &graph.edges[&("m.php".to_string(), "main".to_string())];
        assert!(
            edges.is_empty(),
            "parent:: non resolu en v1, cf. doc de module"
        );
    }

    #[test]
    fn test_this_method_call_resolved_same_file() {
        let src = b"<?php\nclass C {\n  function helper($x) {}\n  function main() { $this->helper(1); }\n}\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = PhpCallGraph::build(&files);
        let edges = &graph.edges[&("m.php".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("this.helper"),
            Some(&("m.php".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_instance_call_on_other_variable_not_resolved() {
        let src = b"<?php\nfunction main($obj) { $obj->helper(1); }\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = PhpCallGraph::build(&files);
        let edges = &graph.edges[&("m.php".to_string(), "main".to_string())];
        assert!(edges.is_empty());
    }

    #[test]
    fn test_resolve_summaries_multi_hop_sink_propagation() {
        let src_a =
            b"<?php\nrequire './utils.php';\nfunction main($userInput) { helper($userInput); }\n"
                .to_vec();
        let src_u = b"<?php\nfunction helper($cmd) { $db->query($cmd); }\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.php".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.php".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = PhpCallGraph::build(&files);
        let specs = specs_with(vec![SinkSpec::new("*.query")]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);

        let helper_summary = &own["utils.php"]["helper"];
        assert!(
            helper_summary.sink_param_findings.contains_key(&0),
            "helper: param 0 atteint db->query"
        );
        let main_summary = &own["a.php"]["main"];
        assert!(
            main_summary.sink_param_findings.contains_key(&0),
            "main: param 0 (userInput) atteint le sink via helper (multi-hop)"
        );
    }

    #[test]
    fn test_resolve_summaries_mutual_recursion_does_not_hang() {
        let src =
            b"<?php\nfunction f($x) { return g($x); }\nfunction g($y) { return f($y); }\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = PhpCallGraph::build(&files);
        let specs = specs_with(vec![]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);
        assert!(own["m.php"].contains_key("f"));
        assert!(own["m.php"].contains_key("g"));
    }
}
