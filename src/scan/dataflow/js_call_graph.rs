//! Persistent JavaScript/TypeScript call graph — multi-hop
//! interprocedural resolution. Direct template of `call_graph.rs`
//! (Python) for the shape (nodes/edges/SCC/fixed point), **entirely
//! original import-resolution algorithm** (`js_module_registry.rs`
//! — relative path, no Python-style suffix nor Java-style FQCN): no
//! equivalent Python source exists for this module (the reference
//! Python engine has no JS interprocedural analysis) — new development,
//! not a port.
//!
//! **Cycles/recursion**: decomposition into strongly connected
//! components (Tarjan) + bounded fixed point (`call_graph::
//! MAX_SCC_FIXPOINT_ITER`), duplicated from `call_graph.rs` rather than
//! extracted into a shared helper — a deliberate choice for this
//! effort (avoid touching `call_graph.rs`, tested and in production,
//! for a need that doesn't require it; extraction into a common helper
//! left as a future improvement if the Python/JS/PHP triplication
//! becomes bothersome). Not the naive DFS of `java_call_graph.rs`: Java
//! kept that only for fidelity to actual existing Python source code
//! (`java_call_graph.py`) — a constraint that doesn't apply here,
//! nothing to faithfully imitate.
//!
//! **Call resolution** (`outgoing_edges`): a bare call (`foo(...)`), a
//! non-computed member call on an identifier (`obj.method(...)`, `obj`
//! = resolved imported binding) or on `this` (`this.method(...)` →
//! resolved by name in the current file if a function/method of that
//! name is defined there, same spirit as the "bare name" fallback of
//! `java_call_graph.rs::add_bare_name_aliases`, simpler here: JS has no
//! class FQCN to disambiguate). A member call on a computed expression
//! (`obj[expr]()`) or a non-identifier receiver → never resolved
//! (anti-FP, same principle as everywhere else in the engine: better
//! to miss a flow than to invent one).
//!
//! **Over-approximation inherited from the Python template**
//! (`walk_calls` walks the entire subtree of a function, including the
//! bodies of **nested** functions): a call made from a nested JS
//! callback (`array.map(x => sink(x))`) therefore also appears in the
//! outgoing edges of the enclosing function, in addition to those of
//! the callback itself (which has its own node via
//! `collect_js_functions`). As on the Python side, this is not fixed
//! here — and it is actually welcome for JS: the `js_summary.rs` doc
//! already notes that most vulnerable JS code lives in callbacks passed
//! as arguments, a pattern even more dominant than in Python.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tree_sitter::Node;

pub use super::call_graph::{FileInput, MAX_SCC_FIXPOINT_ITER, NodeKey, SummariesByFile};
use super::js_module_registry::{JsImportInfo, collect_js_imports, resolve_target_file};
use super::js_summary::{JsFunctionInfo, collect_js_functions, compute_js_summary};
use super::transfer::{FunctionSummary, RuleSpecs};

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// Returns the bindings brought in by a file's imports, indexed by the
/// **local** call name as it appears in that file's code — mirror of
/// `call_graph.rs::resolve_import_bindings`, but simpler: resolution by
/// exact path ([`resolve_target_file`]) leaves no ambiguity to handle
/// (no suffix, no star to merge). An empty `orig_name` or `"*"`
/// (binding for the whole module — default import, plain
/// `require(mod)`, namespace import) produces one `"{local}.{fname}"`
/// edge per function of the target file, like Python's
/// `import mod as m`. A precise `orig_name` (named import /
/// `require` destructuring) produces a direct
/// `local -> (target, orig_name)` edge, only if `orig_name` actually
/// designates a known function of the target file (anti-FP guard
/// identical to Python: never invent a link to an export that doesn't
/// exist).
fn resolve_import_bindings(
    filepath: &str,
    imports: &[JsImportInfo],
    known_files: &[String],
    file_function_names: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, NodeKey> {
    let mut out = BTreeMap::new();
    let empty_set: BTreeSet<String> = BTreeSet::new();
    for imp in imports {
        let Some(target) = resolve_target_file(filepath, &imp.specifier, known_files) else {
            continue;
        };
        if imp.orig_name.is_empty() || imp.orig_name == "*" {
            for fname in file_function_names.get(&target).unwrap_or(&empty_set) {
                out.insert(
                    format!("{}.{}", imp.local_name, fname),
                    (target.clone(), fname.clone()),
                );
            }
        } else if file_function_names
            .get(&target)
            .is_some_and(|names| names.contains(&imp.orig_name))
        {
            out.insert(
                imp.local_name.clone(),
                (target.clone(), imp.orig_name.clone()),
            );
        }
    }
    out
}

/// Local call name of a `call_expression` node: `foo` for
/// `foo(...)`, `obj.method` for `obj.method(...)` (identifier
/// receiver), `this.method` for `this.method(...)` (resolved later by
/// [`outgoing_edges`] within the current file, not here — this is not
/// an import binding). `None` for forms not statically resolvable
/// (computed receiver/complex expression, method chaining) — stays
/// over-approximated as today (no edge, not an error).
fn call_local_name(call_node: Node, source: &[u8]) -> Option<String> {
    let func = call_node.child_by_field_name("function")?;
    match func.kind() {
        "identifier" => Some(text(func, source)),
        "member_expression" => {
            let obj = func.child_by_field_name("object")?;
            let prop = func.child_by_field_name("property")?;
            if prop.kind() != "property_identifier" {
                return None;
            }
            match obj.kind() {
                "identifier" => Some(format!("{}.{}", text(obj, source), text(prop, source))),
                "this" => Some(format!("this.{}", text(prop, source))),
                _ => None,
            }
        }
        _ => None,
    }
}

fn walk_calls<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if node.kind() == "call_expression" {
        out.push(node);
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_calls(child, out);
    }
}

/// Returns the outgoing edges of a JS function: local call name →
/// target node. Resolves three cases: a call to a function in the
/// **same file** (`local_names`), a call to an **imported** function
/// (`import_bindings`), a `this.method()` call resolved in the current
/// file (see module doc). Other forms remain unresolved.
fn outgoing_edges(
    fn_info: &JsFunctionInfo,
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
        if let Some(method) = local_name.strip_prefix("this.") {
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

// ============================================================================
// JsCallGraph
// ============================================================================

/// Call graph of a set of JS/TS files analyzed together — same
/// contract as `call_graph::CallGraph` (see its doc for the detail of
/// the fields, identical here).
#[derive(Default)]
pub struct JsCallGraph<'tree> {
    pub nodes: BTreeMap<NodeKey, JsFunctionInfo<'tree>>,
    pub edges: BTreeMap<NodeKey, BTreeMap<String, NodeKey>>,
    pub import_bindings: BTreeMap<String, BTreeMap<String, NodeKey>>,
    source_by_file: BTreeMap<String, &'tree [u8]>,
}

impl<'tree> JsCallGraph<'tree> {
    /// Builds the complete graph (nodes + edges + import bindings) from
    /// a set of already-parsed JS/TS files.
    pub fn build(files: &[FileInput<'tree>]) -> Self {
        let mut graph = JsCallGraph::default();
        let mut file_function_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut imports_by_file: BTreeMap<String, Vec<JsImportInfo>> = BTreeMap::new();

        for f in files {
            let functions = collect_js_functions(f.root, f.source);
            file_function_names.insert(
                f.filepath.clone(),
                functions.iter().map(|fi| fi.name.clone()).collect(),
            );
            for fi in functions {
                graph
                    .nodes
                    .insert((f.filepath.clone(), fi.name.clone()), fi);
            }
            imports_by_file.insert(f.filepath.clone(), collect_js_imports(f.root, f.source));
            graph.source_by_file.insert(f.filepath.clone(), f.source);
        }

        let known_files: Vec<String> = file_function_names.keys().cloned().collect();
        for filepath in &known_files {
            let imports = imports_by_file.get(filepath).cloned().unwrap_or_default();
            let bindings =
                resolve_import_bindings(filepath, &imports, &known_files, &file_function_names);
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
    /// identical to `call_graph::CallGraph::strongly_connected_components`.
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
        Some(Arc::new(compute_js_summary(fn_info, &specs, source, lines)))
    }

    /// Computes the summaries of every function in the graph — same
    /// algorithm and same `(own, extra)` return contract as
    /// `call_graph::CallGraph::resolve_summaries` (see its doc).
    pub fn resolve_summaries(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&BTreeMap<String, Vec<String>>>,
    ) -> (SummariesByFile, SummariesByFile) {
        let empty_lines = BTreeMap::new();
        let source_lines_by_file = source_lines_by_file.unwrap_or(&empty_lines);

        let sccs = self.strongly_connected_components();
        let mut resolved: BTreeMap<NodeKey, Arc<FunctionSummary>> = BTreeMap::new();
        let mut own: SummariesByFile = BTreeMap::new();

        for scc in sccs {
            let is_self_loop = scc.len() == 1
                && self
                    .edges
                    .get(&scc[0])
                    .map(|e| e.values().any(|t| t == &scc[0]))
                    .unwrap_or(false);

            if scc.len() == 1 && !is_self_loop {
                let node = &scc[0];
                let seed = self.build_seed(node, &resolved, &BTreeMap::new());
                if let Some(summary) =
                    self.compute_one(node, seed, base_specs, source_lines_by_file)
                {
                    resolved.insert(node.clone(), summary.clone());
                    own.entry(node.0.clone())
                        .or_default()
                        .insert(node.1.clone(), summary);
                }
                continue;
            }

            let mut current: BTreeMap<NodeKey, Arc<FunctionSummary>> = BTreeMap::new();
            for _ in 0..MAX_SCC_FIXPOINT_ITER {
                let mut next: BTreeMap<NodeKey, Arc<FunctionSummary>> = BTreeMap::new();
                for node in &scc {
                    let seed = self.build_seed(node, &resolved, &current);
                    if let Some(summary) =
                        self.compute_one(node, seed, base_specs, source_lines_by_file)
                    {
                        next.insert(node.clone(), summary);
                    }
                }
                let converged = next == current;
                current = next;
                if converged {
                    break;
                }
            }
            for node in &scc {
                if let Some(summary) = current.remove(node) {
                    resolved.insert(node.clone(), summary.clone());
                    own.entry(node.0.clone())
                        .or_default()
                        .insert(node.1.clone(), summary);
                }
            }
        }

        let mut extra: SummariesByFile = BTreeMap::new();
        for (filepath, bindings) in &self.import_bindings {
            for (local_name, target) in bindings {
                if let Some(s) = resolved.get(target) {
                    extra
                        .entry(filepath.clone())
                        .or_default()
                        .insert(local_name.clone(), s.clone());
                }
            }
        }

        (own, extra)
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
        let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
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
        let src = b"function helper(x) {}\nfunction main() { helper(1); }\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.js".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = JsCallGraph::build(&files);
        let edges = &graph.edges[&("m.js".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("m.js".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_build_cross_file_import_edge_named() {
        let src_a = b"import { helper } from './utils';\nfunction main() { helper(1); }\n".to_vec();
        let src_u = b"export function helper(x) {}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.js".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.js".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = JsCallGraph::build(&files);
        let edges = &graph.edges[&("a.js".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("utils.js".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_build_cross_file_require_whole_module_member_call() {
        let src_a =
            b"const utils = require('./utils');\nfunction main() { utils.helper(1); }\n".to_vec();
        let src_u = b"function helper(x) {}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.js".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.js".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = JsCallGraph::build(&files);
        let edges = &graph.edges[&("a.js".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("utils.helper"),
            Some(&("utils.js".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_this_method_call_resolved_same_file() {
        let src = b"class C {\n  helper(x) {}\n  main() { this.helper(1); }\n}\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.js".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = JsCallGraph::build(&files);
        let edges = &graph.edges[&("m.js".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("this.helper"),
            Some(&("m.js".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_bare_import_yields_no_edge() {
        let src_a = b"import x from 'lodash';\nfunction main() { x.helper(1); }\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let files = vec![FileInput {
            filepath: "a.js".to_string(),
            root: tree_a.root_node(),
            source: &src_a,
        }];
        let graph = JsCallGraph::build(&files);
        let edges = &graph.edges[&("a.js".to_string(), "main".to_string())];
        assert!(edges.get("x.helper").is_none());
    }

    #[test]
    fn test_resolve_summaries_multi_hop_sink_propagation() {
        // a.js: main(userInput) -> helper() (utils.js) -> db.query(cmd):
        // the sink must be resolved at the level of main() via helper's
        // summary (multi-hop cross-file resolution).
        let src_a = b"const { helper } = require('./utils');\nfunction main(userInput) { helper(userInput); }\n".to_vec();
        let src_u = b"function helper(cmd) { db.query(cmd); }\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.js".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.js".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = JsCallGraph::build(&files);
        let specs = specs_with(vec![SinkSpec::new("db.query")]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);

        let helper_summary = &own["utils.js"]["helper"];
        assert!(
            helper_summary.sink_param_findings.contains_key(&0),
            "helper: param 0 atteint db.query"
        );
        let main_summary = &own["a.js"]["main"];
        assert!(
            main_summary.sink_param_findings.contains_key(&0),
            "main: param 0 (userInput) atteint le sink via helper (multi-hop)"
        );
    }

    #[test]
    fn test_resolve_summaries_mutual_recursion_does_not_hang() {
        let src = b"function f(x) { return g(x); }\nfunction g(y) { return f(y); }\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.js".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = JsCallGraph::build(&files);
        let specs = specs_with(vec![]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);
        assert!(own["m.js"].contains_key("f"));
        assert!(own["m.js"].contains_key("g"));
    }

    #[test]
    fn test_extra_summaries_indexed_by_local_import_name() {
        let src_a = b"const utils = require('./utils');\n".to_vec();
        let src_u = b"function helper() {}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.js".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.js".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = JsCallGraph::build(&files);
        let specs = specs_with(vec![]);
        let (_own, extra) = graph.resolve_summaries(&specs, None);
        assert!(
            extra["a.js"].contains_key("utils.helper"),
            "import du module (pas appelé) doit quand même apparaître dans extra"
        );
    }
}
