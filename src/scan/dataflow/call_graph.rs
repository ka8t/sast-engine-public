//! Persistent (Python) call graph — multi-hop interprocedural
//! resolution. Port of `Audit/sca/dataflow/call_graph.py`.
//!
//! Replaces `ModuleRegistry`'s 1-hop resolution (import → already
//! computed summary, itself blind to its own calls) with a real graph
//! (nodes = functions, edges = resolved calls, including intra-file)
//! and a summary computation done in **topological order** (callees
//! before callers): when B (imported by A) itself calls a function of
//! C, that link is now resolved.
//!
//! Reuses the suffix-matching logic of `module_registry.py`
//! (`resolve_target_file`) — ported here as free functions, **without
//! the `ModuleRegistry` class**: `dataflow_adapter.py` (the prod entry
//! point) only uses `CallGraph`, never `ModuleRegistry` (confirmed via
//! grep on the Audit repo) — that class is dead code in production,
//! not ported.
//!
//! **Deviation vs Python (Decision #3, already settled in the plan)**:
//! `topological_order()` on the Python side is a naive DFS post-order
//! — a recursion cycle (A↔B) leaves the revisited link unresolved
//! (just an infinite-loop guard, not a real fixpoint). Here: breakdown
//! into strongly connected components (Tarjan), processed in the
//! topological order of the condensation (callees-before-callers,
//! guaranteed by construction); a non-trivial SCC (real cycle) is
//! resolved by a bounded fixpoint between its members
//! (`MAX_SCC_FIXPOINT_ITER` passes, same spirit as CFG loop widening)
//! instead of being given up on.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tree_sitter::Node;

use super::summary::{
    FunctionInfo, ImportInfo, collect_functions, collect_imports, compute_summary,
};
use super::transfer::{FunctionSummary, RuleSpecs};

/// (file path, function name).
pub type NodeKey = (String, String);

/// `{file: {name: FunctionSummary}}` — shape shared by `own` and
/// `extra` in the `resolve_summaries` result.
///
/// `Arc<FunctionSummary>`, not `FunctionSummary` directly — found by
/// profiling (`sample`) a large Java corpus (2000+ files, OWASP
/// BenchmarkJava, 2026-08-26): `FunctionSummary` embeds
/// `sink_param_findings: BTreeMap<usize, Finding>`, and `Finding` is a
/// heavy struct (several `String` + `Vec<FlowStep>`). The summary of a
/// "hub" function (called by hundreds of near-identical files, typical
/// of this corpus) was being deep-cloned on EVERY incoming edge — the
/// real dominant cost, not `resolve_summaries` itself (two previous
/// fixes on
/// `topological_order`/`per_file_key_targets`/`base_specs.clone()`
/// had only given a marginal gain). `Arc` makes `.clone()` O(1)
/// (reference-count bump) regardless of content — no read logic
/// changes (transparent auto-dereferencing).
pub type SummariesByFile = BTreeMap<String, BTreeMap<String, Arc<FunctionSummary>>>;

/// Fixpoint threshold on a non-trivial SCC (recursion cycle) — same
/// spirit as `worklist::MAX_LOOP_ITER`: a few passes are enough in
/// practice, bounded to avoid pathological cases.
pub const MAX_SCC_FIXPOINT_ITER: u32 = 3;

/// Writes the file and the code line on every step of a summary's
/// template findings that has none yet: a step already stamped comes
/// from a deeper callee and keeps its own file. Once a summary is used
/// in another file, its steps still say where they are, so the report
/// can show the real line of a query written two calls away.
fn stamp_steps(summary: &mut FunctionSummary, filepath: &str, lines: Option<&[String]>) {
    for template in summary.sink_param_findings.values_mut() {
        for step in &mut template.flow {
            if step.file.is_some() {
                continue;
            }
            step.file = Some(filepath.to_string());
            step.code = lines
                .and_then(|l| l.get(step.line.wrapping_sub(1)))
                .map(|l| l.trim().to_string());
        }
    }
}

fn path_parts(path: &str) -> Vec<String> {
    path.replace('\\', "/")
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .map(|s| s.to_string())
        .collect()
}

fn common_prefix_len(a: &[String], b: &[String]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

/// Returns the file from `known_files` whose path ends with `suffix`.
/// `anchored` (relative import) requires an exact end match; when not
/// anchored (absolute import), a directory prefix is tolerated but
/// only one candidate is accepted (otherwise ambiguous → None).
fn match_unique_suffix(
    suffix: &str,
    anchored: bool,
    importer: &str,
    known_files: &[String],
) -> Option<String> {
    let suffix_parts = path_parts(suffix);
    let candidates: Vec<&String> = known_files
        .iter()
        .filter(|fp| fp.as_str() != importer)
        .filter(|fp| {
            let fp_parts = path_parts(fp);
            fp_parts.len() >= suffix_parts.len()
                && fp_parts[fp_parts.len() - suffix_parts.len()..] == suffix_parts[..]
        })
        .collect();
    if candidates.len() == 1 {
        return Some(candidates[0].clone());
    }
    if anchored && !candidates.is_empty() {
        let imp_parts = path_parts(importer);
        let mut sorted = candidates;
        sorted.sort_by_key(|c| std::cmp::Reverse(common_prefix_len(&path_parts(c), &imp_parts)));
        return Some(sorted[0].clone());
    }
    None
}

/// Returns the path of the analyzed file targeted by an import, or
/// None. Relative (`level >= 1`): anchored to the importer's
/// directory (goes up `level - 1` levels), then follows the module
/// path. Absolute (`level == 0`): `mod/parts.py` suffix, resolved only
/// if it matches **exactly one** file in the set (ambiguity →
/// give up, anti-FP).
fn resolve_target_file(importer: &str, imp: &ImportInfo, known_files: &[String]) -> Option<String> {
    let mod_parts: Vec<String> = if imp.module.is_empty() {
        vec![]
    } else {
        imp.module.split('.').map(|s| s.to_string()).collect()
    };

    if imp.level >= 1 {
        let importer_parts = path_parts(importer);
        let dir_parts: Vec<String> = if importer_parts.is_empty() {
            vec![]
        } else {
            importer_parts[..importer_parts.len() - 1].to_vec()
        };
        let ascend = imp.level - 1;
        if ascend > dir_parts.len() {
            return None;
        }
        let base: Vec<String> = if ascend > 0 {
            dir_parts[..dir_parts.len() - ascend].to_vec()
        } else {
            dir_parts
        };
        let mut target_parts = base;
        target_parts.extend(mod_parts);
        if target_parts.is_empty() {
            return None;
        }
        let target_suffix = format!("{}.py", target_parts.join("/"));
        return match_unique_suffix(&target_suffix, true, importer, known_files);
    }

    if mod_parts.is_empty() {
        return None;
    }
    let target_suffix = format!("{}.py", mod_parts.join("/"));
    match_unique_suffix(&target_suffix, false, importer, known_files)
}

/// Returns the bindings brought in by a file's imports, indexed by
/// the **local** call name as it appears in that file's code. Mirrors
/// `_resolve_one_import`/`_apply_star_imports` (module_registry.py),
/// but returns `NodeKey` rather than `FunctionSummary` — summary
/// resolution does not happen yet at this stage (structural pre-pass
/// of the graph, independent of the specs).
fn resolve_import_bindings(
    filepath: &str,
    imports: &[ImportInfo],
    known_files: &[String],
    file_function_names: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, NodeKey> {
    let mut out: BTreeMap<String, NodeKey> = BTreeMap::new();
    let mut star_imports: Vec<&ImportInfo> = Vec::new();
    let empty_set: BTreeSet<String> = BTreeSet::new();

    for imp in imports {
        if imp.orig_name == "*" {
            star_imports.push(imp);
            continue;
        }
        if imp.orig_name.is_empty() {
            // `import mod [as m]` -> calls of the form `m.func(...)`.
            if let Some(target) = resolve_target_file(filepath, imp, known_files) {
                for fname in file_function_names.get(&target).unwrap_or(&empty_set) {
                    if !fname.contains('.') {
                        out.insert(
                            format!("{}.{}", imp.local_name, fname),
                            (target.clone(), fname.clone()),
                        );
                    }
                }
            }
            continue;
        }
        // `from mod import X`: X is either a function or a submodule.
        let target = resolve_target_file(filepath, imp, known_files);
        if let Some(t) = &target
            && file_function_names
                .get(t)
                .map(|s| s.contains(&imp.orig_name))
                .unwrap_or(false)
        {
            out.insert(imp.local_name.clone(), (t.clone(), imp.orig_name.clone()));
            continue;
        }
        let submod_module = if imp.module.is_empty() {
            imp.orig_name.clone()
        } else {
            format!("{}.{}", imp.module, imp.orig_name)
        };
        let submod_import = ImportInfo {
            local_name: imp.local_name.clone(),
            module: submod_module,
            orig_name: String::new(),
            level: imp.level,
        };
        if let Some(submod) = resolve_target_file(filepath, &submod_import, known_files) {
            for fname in file_function_names.get(&submod).unwrap_or(&empty_set) {
                if !fname.contains('.') {
                    out.insert(
                        format!("{}.{}", imp.local_name, fname),
                        (submod.clone(), fname.clone()),
                    );
                }
            }
        }
    }

    if !star_imports.is_empty() {
        let mut seen: BTreeMap<String, NodeKey> = BTreeMap::new();
        let mut collided: BTreeSet<String> = BTreeSet::new();
        for imp in &star_imports {
            let Some(target) = resolve_target_file(filepath, imp, known_files) else {
                continue;
            };
            for fname in file_function_names.get(&target).unwrap_or(&empty_set) {
                if fname.contains('.') {
                    continue;
                }
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
        for (name, key) in seen {
            if !collided.contains(&name) && !out.contains_key(&name) {
                out.insert(name, key);
            }
        }
    }
    out
}

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// Local call name of a `call` node: `foo` for `foo(...)`, `m.func`
/// for `m.func(...)`. `None` for forms not statically resolvable
/// (call on an expression, instance method with no type info — out of
/// scope, stays over-approximated as it does today).
fn call_local_name(call_node: Node, source: &[u8]) -> Option<String> {
    let func = call_node.child_by_field_name("function")?;
    match func.kind() {
        "identifier" => Some(text(func, source)),
        "attribute" => {
            let obj = func.child_by_field_name("object")?;
            if obj.kind() != "identifier" {
                return None;
            }
            let attr = func.child_by_field_name("attribute")?;
            Some(format!("{}.{}", text(obj, source), text(attr, source)))
        }
        _ => None,
    }
}

fn walk_calls<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if node.kind() == "call" {
        out.push(node);
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_calls(child, out);
    }
}

/// Returns a function's outgoing edges: local call name → target
/// node. Resolves two cases: a call to a function in the **same
/// file** (direct name in `local_names`), and a call to an
/// **imported** function (via `import_bindings`). Other call forms
/// remain unresolved — unchanged current behavior (SCA-9
/// over-approximation in `eval_call`).
fn outgoing_edges(
    fn_info: &FunctionInfo,
    source: &[u8],
    filepath: &str,
    local_names: &BTreeSet<String>,
    import_bindings: &BTreeMap<String, NodeKey>,
) -> BTreeMap<String, NodeKey> {
    let mut edges = BTreeMap::new();
    let mut calls = Vec::new();
    walk_calls(fn_info.def_node, &mut calls);
    for call_node in calls {
        let Some(local_name) = call_local_name(call_node, source) else {
            continue;
        };
        if edges.contains_key(&local_name) {
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
// CallGraph
// ============================================================================

/// An already-parsed Python file, ready to be integrated into the
/// graph.
pub struct FileInput<'tree> {
    pub filepath: String,
    pub root: Node<'tree>,
    pub source: &'tree [u8],
}

/// Call graph of a set of Python files analyzed together.
///
/// `nodes`: every known function/method, indexed by (file, name).
/// `edges`: for each node, its resolved outgoing calls (local call
/// name → target node) — a subset of the real calls (a call that
/// cannot be statically resolved is simply absent, not an error).
#[derive(Default)]
pub struct CallGraph<'tree> {
    pub nodes: BTreeMap<NodeKey, FunctionInfo<'tree>>,
    pub edges: BTreeMap<NodeKey, BTreeMap<String, NodeKey>>,
    /// All resolved imports of each file (local name → target node),
    /// whether they are called inside a function or at module level —
    /// used to rebuild `extra` (component 3), never restricted to a
    /// particular function.
    pub import_bindings: BTreeMap<String, BTreeMap<String, NodeKey>>,
    source_by_file: BTreeMap<String, &'tree [u8]>,
}

impl<'tree> CallGraph<'tree> {
    /// Builds the complete graph (nodes + edges + import bindings)
    /// from a set of already-parsed Python modules.
    pub fn build(files: &[FileInput<'tree>]) -> Self {
        let mut graph = CallGraph::default();
        let mut file_function_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut imports_by_file: BTreeMap<String, Vec<ImportInfo>> = BTreeMap::new();

        for f in files {
            let functions = collect_functions(f.root, f.source);
            file_function_names.insert(
                f.filepath.clone(),
                functions.iter().map(|fi| fi.name.clone()).collect(),
            );
            for fi in functions {
                graph
                    .nodes
                    .insert((f.filepath.clone(), fi.name.clone()), fi);
            }
            imports_by_file.insert(f.filepath.clone(), collect_imports(f.root, f.source));
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

    /// Breakdown into strongly connected components (Tarjan), returned
    /// in callees-before-callers order (guaranteed by construction: an
    /// SCC is only closed after those of all its successors).
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
                    continue; // target outside the graph (unresolved import)
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

    /// Builds a node's `specs.summaries` seed: already resolved
    /// summaries (outside the current SCC, or members of the SCC
    /// already stabilized) for its outgoing calls.
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
        let mut summary = compute_summary(fn_info, &specs, source, lines)?;
        stamp_steps(&mut summary, filepath, lines);
        Some(Arc::new(summary))
    }

    /// Computes the summaries of every function in the graph, in the
    /// topological order of the SCCs, seeding `specs.summaries` with
    /// the already-resolved summaries of the callees (same file or
    /// cross-file) — multi-hop resolution. A non-trivial SCC
    /// (recursion cycle) is resolved by a real bounded fixpoint between
    /// its members (Decision #3), not left unresolved.
    ///
    /// Returns `(own, extra)`:
    ///   - `own`: `{file: {function_name: FunctionSummary}}` —
    ///     functions defined in each file.
    ///   - `extra`: `{file: {local_import_name: FunctionSummary}}` —
    ///     all resolved imports of each file.
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

            // Real cycle (multi-node SCC, or direct self-recursion):
            // bounded fixpoint between the members.
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
        let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
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
    fn test_resolve_target_file_relative_single_dot() {
        let known = vec!["pkg/a.py".to_string(), "pkg/utils.py".to_string()];
        let imp = ImportInfo {
            local_name: "utils".to_string(),
            module: "utils".to_string(),
            orig_name: "utils".to_string(),
            level: 1,
        };
        assert_eq!(
            resolve_target_file("pkg/a.py", &imp, &known),
            Some("pkg/utils.py".to_string())
        );
    }

    #[test]
    fn test_resolve_target_file_absolute_ambiguous_gives_up() {
        let known = vec!["a/utils.py".to_string(), "b/utils.py".to_string()];
        let imp = ImportInfo {
            local_name: "utils".to_string(),
            module: "utils".to_string(),
            orig_name: "".to_string(),
            level: 0,
        };
        assert_eq!(
            resolve_target_file("main.py", &imp, &known),
            None,
            "ambiguïté -> anti-FP, abandon"
        );
    }

    #[test]
    fn test_build_intra_file_edge_same_file_call() {
        let (tree, src) = (
            parse("def helper(x):\n    pass\n\ndef main():\n    helper(1)\n"),
            b"def helper(x):\n    pass\n\ndef main():\n    helper(1)\n".to_vec(),
        );
        let files = vec![FileInput {
            filepath: "m.py".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = CallGraph::build(&files);
        let edges = &graph.edges[&("m.py".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("m.py".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_build_cross_file_import_edge() {
        let src_a = b"from utils import helper\n\ndef main():\n    helper(1)\n".to_vec();
        let src_u = b"def helper(x):\n    pass\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.py".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.py".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = CallGraph::build(&files);
        let edges = &graph.edges[&("a.py".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("utils.py".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_resolve_summaries_multi_hop_sink_propagation() {
        // a.py: main() -> helper() (utils.py) -> os.system(x): the sink
        // must be resolved at main()'s level via helper's summary.
        let src_a =
            b"from utils import helper\n\ndef main(user_input):\n    helper(user_input)\n".to_vec();
        let src_u = b"import os\n\ndef helper(cmd):\n    os.system(cmd)\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.py".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.py".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = CallGraph::build(&files);
        let specs = specs_with(vec![SinkSpec::new("os.system")]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);

        let helper_summary = &own["utils.py"]["helper"];
        assert!(
            helper_summary.sink_param_findings.contains_key(&0),
            "helper: param 0 atteint os.system"
        );

        // main() does NOT call os.system directly: without multi-hop
        // resolution, no sink would be seen here. With the graph,
        // helper's summary is seeded into specs.summaries when
        // computing main's summary -> the sink must appear.
        let main_summary = &own["a.py"]["main"];
        assert!(
            main_summary.sink_param_findings.contains_key(&0),
            "main: param 0 (user_input) atteint le sink via helper (multi-hop)"
        );

        // The path keeps the real sink, in its own file, and the call
        // to helper in a.py: the report shows both lines.
        let flow = &main_summary.sink_param_findings[&0].flow;
        let sink = flow.iter().rev().find(|s| s.kind == "sink").unwrap();
        assert_eq!((sink.file.as_deref(), sink.line), (Some("utils.py"), 4), "{flow:?}");
        assert!(
            flow.iter()
                .any(|s| s.kind == "propagation" && s.file.as_deref() == Some("a.py") && s.line == 4),
            "{flow:?}"
        );
    }

    #[test]
    fn test_resolve_summaries_mutual_recursion_does_not_hang_and_resolves() {
        // Direct cycle: f calls g, g calls f. An SCC fixpoint must
        // converge (no infinite loop) and resolve at least partially
        // the flow through the cycle.
        let src = b"def f(x):\n    return g(x)\n\ndef g(y):\n    return f(y)\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.py".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = CallGraph::build(&files);
        let specs = specs_with(vec![]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);
        assert!(own["m.py"].contains_key("f"));
        assert!(own["m.py"].contains_key("g"));
    }

    #[test]
    fn test_resolve_summaries_direct_self_recursion_terminates() {
        let src =
            b"def fact(n):\n    if n <= 1:\n        return 1\n    return fact(n - 1)\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.py".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = CallGraph::build(&files);
        let specs = specs_with(vec![]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);
        assert!(own["m.py"].contains_key("fact"));
    }

    #[test]
    fn test_extra_summaries_indexed_by_local_import_name() {
        let src_a = b"import utils\n".to_vec();
        let src_u = b"def helper():\n    pass\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.py".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.py".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = CallGraph::build(&files);
        let specs = specs_with(vec![]);
        let (_own, extra) = graph.resolve_summaries(&specs, None);
        assert!(
            extra["a.py"].contains_key("utils.helper"),
            "import module (pas appelé) doit quand même apparaître dans extra"
        );
    }

    #[test]
    fn test_topological_order_via_scc_is_callees_before_callers() {
        let src =
            b"def leaf():\n    pass\n\ndef mid():\n    leaf()\n\ndef top():\n    mid()\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.py".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = CallGraph::build(&files);
        let sccs = graph.strongly_connected_components();
        let flat: Vec<&NodeKey> = sccs.iter().flatten().collect();
        let pos = |name: &str| flat.iter().position(|(_, n)| n == name).unwrap();
        assert!(
            pos("leaf") < pos("mid"),
            "leaf (callee) doit précéder mid (caller)"
        );
        assert!(
            pos("mid") < pos("top"),
            "mid (callee) doit précéder top (caller)"
        );
    }
}
