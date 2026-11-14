//! Persistent call graph (Java) — multi-hop interprocedural
//! resolution. Faithful port of `Audit/sca/dataflow/java_call_graph.py`.
//!
//! Mirrors `call_graph.rs` (Python), same role: replace a
//! 1-hop resolution (import → already-computed summary, itself blind to
//! its own calls) with a real graph (nodes = methods/
//! constructors, edges = resolved calls, including intra-file) and
//! a summary computation in topological order (callees before callers).
//!
//! **Not a port of `_outgoing_edges`**: Java's call semantics
//! (enclosing class, `this`/`super`, package visibility, binding
//! via declared type) has nothing in common with Python's import
//! resolution — see `java_module_registry.rs` for the same distinction on the
//! import-resolution side.
//!
//! **`topological_order`/`resolve_summaries`, on the other hand, are duplicated
//! as-is in their structure** (post-order DFS, anti-FP cycles) —
//! NOT the SCC/Tarjan fixed point of `call_graph.rs` (Decision #3, a
//! deliberate correction on the Python side only): on the Java side, the
//! actual Python source (`java_call_graph.py`) never received this
//! correction — a choice already settled in the real code, not a
//! simplification introduced here. A node in a cycle is computed
//! last, with the summaries of the cycle's not-yet-resolved links
//! (better to miss a flow than invent a false one, the same
//! philosophy as `call_graph.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use tree_sitter::Node;

pub use super::call_graph::{FileInput, NodeKey, SummariesByFile};
use super::java_module_registry::{
    JavaImportInfo, build_fqcn_index, build_static_import_bindings, collect_java_class_names,
    collect_java_imports, collect_java_superclass, collect_package, resolve_visible_classes,
};
use super::java_summary::{
    JavaFunctionInfo, add_bare_name_aliases, collect_java_field_types, collect_java_functions,
    collect_java_local_types, compute_java_summary,
};
use super::transfer::{FunctionSummary, RuleSpecs};

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

fn simple_type_text(type_node: Node, source: &[u8]) -> String {
    let t = text(type_node, source);
    let before_generic = t.split('<').next().unwrap_or(&t).to_string();
    before_generic
        .rsplit('.')
        .next()
        .unwrap_or(&before_generic)
        .to_string()
}

/// Generic DFS over a tree-sitter subtree, returning all
/// `method_invocation` nodes encountered.
fn iter_method_invocations<'tree>(body: Node<'tree>) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if n.kind() == "method_invocation" {
            out.push(n);
        }
        let mut w = n.walk();
        stack.extend(n.children(&mut w));
    }
    out
}

/// Structural metadata for a Java file, computed once
/// (independent of the rule specs — like `call_graph.rs`).
struct FileInfo {
    package: String,
    class_names: Vec<String>,
    imports: Vec<JavaImportInfo>,
    superclass: BTreeMap<String, Option<String>>,
    /// Fields + locals merged (locals take priority).
    type_map: BTreeMap<String, String>,
}

/// Call graph for a set of Java files analyzed together.
///
/// `nodes`: every known method/constructor, indexed by
/// `(file, "ClassName.methodName")`.
/// `edges`: for each node, its resolved outgoing calls (local call
/// key — EXACTLY the form that `transfer.rs::eval_call`
/// computes via `canon_callee`/its fallback logic — → target node).
/// `import_bindings`: all cross-file/same-package bindings for a
/// file (visible classes + static imports), not restricted to
/// a particular function — used to rebuild `extra`
/// (the multi-hop equivalent of the 1-hop resolution).
#[derive(Default)]
pub struct JavaCallGraph<'tree> {
    pub nodes: BTreeMap<NodeKey, JavaFunctionInfo<'tree>>,
    pub edges: BTreeMap<NodeKey, BTreeMap<String, NodeKey>>,
    pub import_bindings: BTreeMap<String, BTreeMap<String, NodeKey>>,
    source_by_file: BTreeMap<String, &'tree [u8]>,
    /// Lazy caches, independent of `base_specs` — derived
    /// solely from the graph's structure (`nodes`/`edges`), so
    /// identical for every rule. `resolve_summaries` is
    /// now called once PER RULE in parallel
    /// (orchestrator.rs, ~20 Java taint rules): without this cache,
    /// `topological_order()` (full post-order DFS) and
    /// `per_file_key_targets` (full `edges` traversal) were
    /// recomputed entirely on EVERY call — pure waste
    /// (20 identical recomputations) that, at the scale of a large corpus
    /// (2000+ files, e.g. OWASP BenchmarkJava), amplified
    /// allocator contention across threads to the point of dominating
    /// wall-clock time (profiled via `sample`: `__psynch_cvwait` at the
    /// top, flagged by the maintainer on 2026-08-26 while comparing against the
    /// Python analyzer). `OnceLock`: thread-safe lazy computation, only one
    /// winner in case of a race between `rayon` threads.
    topo_order_cache: OnceLock<Vec<NodeKey>>,
    per_file_key_targets_cache: OnceLock<BTreeMap<String, BTreeMap<String, BTreeSet<NodeKey>>>>,
}

impl<'tree> JavaCallGraph<'tree> {
    /// Builds the complete graph (nodes + edges + import bindings)
    /// from a set of already-parsed Java files.
    pub fn build(files: &[FileInput<'tree>]) -> Self {
        let mut graph = JavaCallGraph::default();

        let mut file_info: BTreeMap<String, FileInfo> = BTreeMap::new();
        let mut class_names_by_file: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
        let mut file_function_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for f in files {
            let functions = collect_java_functions(f.root, f.source);
            let mut names = BTreeSet::new();
            for fn_info in functions {
                names.insert(fn_info.name.clone());
                graph
                    .nodes
                    .insert((f.filepath.clone(), fn_info.name.clone()), fn_info);
            }
            file_function_names.insert(f.filepath.clone(), names);
            graph.source_by_file.insert(f.filepath.clone(), f.source);

            let package = collect_package(f.root, f.source);
            let class_names = collect_java_class_names(f.root, f.source);
            class_names_by_file.insert(f.filepath.clone(), (package.clone(), class_names.clone()));

            // Locals take priority over fields (more precise scope) —
            // MUST stay in sync with the same merge done on the
            // scan executor side (same logical dict), see the doc of
            // `java_summary.rs::collect_java_field_types`.
            let mut type_map = collect_java_field_types(f.root, f.source);
            type_map.extend(collect_java_local_types(f.root, f.source));

            file_info.insert(
                f.filepath.clone(),
                FileInfo {
                    package,
                    class_names,
                    imports: collect_java_imports(f.root, f.source),
                    superclass: collect_java_superclass(f.root, f.source),
                    type_map,
                },
            );
        }

        let fqcn_index = build_fqcn_index(&class_names_by_file);

        let mut visible_by_file: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut static_by_file: BTreeMap<String, BTreeMap<String, NodeKey>> = BTreeMap::new();
        for f in files {
            let info = &file_info[&f.filepath];
            let visible = resolve_visible_classes(
                &f.filepath,
                &info.package,
                &info.imports,
                &class_names_by_file,
                &fqcn_index,
            );
            let statics = build_static_import_bindings(
                &f.filepath,
                &info.imports,
                &fqcn_index,
                &file_function_names,
            );
            graph.import_bindings.insert(
                f.filepath.clone(),
                build_import_bindings(&visible, &statics, &file_function_names),
            );
            visible_by_file.insert(f.filepath.clone(), visible);
            static_by_file.insert(f.filepath.clone(), statics);
        }

        for f in files {
            let info = &file_info[&f.filepath];
            let local_class_names: BTreeSet<String> = info.class_names.iter().cloned().collect();
            let visible = &visible_by_file[&f.filepath];
            let statics = &static_by_file[&f.filepath];
            let fn_keys: Vec<NodeKey> = graph
                .nodes
                .keys()
                .filter(|(fp, _)| fp == &f.filepath)
                .cloned()
                .collect();
            for key in fn_keys {
                let enclosing_class = key.1.rsplit_once('.').map(|(c, _)| c).unwrap_or("");
                let edges = outgoing_edges(
                    &graph.nodes[&key],
                    &f.filepath,
                    enclosing_class,
                    &local_class_names,
                    info,
                    visible,
                    statics,
                    &graph.nodes,
                    f.source,
                );
                graph.edges.insert(key, edges);
            }
        }

        graph
    }

    /// Memoized `topological_order()` — see the `topo_order_cache`
    /// field doc. Computed at most once per instance,
    /// regardless of the number of rules/calls to `resolve_summaries`.
    fn topo_order_cached(&self) -> &Vec<NodeKey> {
        self.topo_order_cache
            .get_or_init(|| self.topological_order())
    }

    /// Memoized `{caller file: {local key: {targets}}}` — see the doc
    /// of the `per_file_key_targets_cache` field. Derived solely from
    /// `self.edges` (graph structure, independent of the rule).
    fn per_file_key_targets_cached(
        &self,
    ) -> &BTreeMap<String, BTreeMap<String, BTreeSet<NodeKey>>> {
        self.per_file_key_targets_cache.get_or_init(|| {
            let mut per_file_key_targets: BTreeMap<String, BTreeMap<String, BTreeSet<NodeKey>>> =
                BTreeMap::new();
            for ((caller_file, _caller_name), edges) in &self.edges {
                for (local_key, target) in edges {
                    per_file_key_targets
                        .entry(caller_file.clone())
                        .or_default()
                        .entry(local_key.clone())
                        .or_default()
                        .insert(target.clone());
                }
            }
            per_file_key_targets
        })
    }

    /// Returns a callees-before-callers order (post-order DFS). A
    /// cycle leaves the revisited link unreordered: it will be computed
    /// without that particular callee being resolved yet (no
    /// invented flow).
    pub fn topological_order(&self) -> Vec<NodeKey> {
        let mut order = Vec::new();
        let mut visited: BTreeSet<NodeKey> = BTreeSet::new();
        let mut in_progress: BTreeSet<NodeKey> = BTreeSet::new();
        let node_keys: Vec<NodeKey> = self.nodes.keys().cloned().collect();
        for node in &node_keys {
            self.visit_topo(node, &mut visited, &mut in_progress, &mut order);
        }
        order
    }

    fn visit_topo(
        &self,
        node: &NodeKey,
        visited: &mut BTreeSet<NodeKey>,
        in_progress: &mut BTreeSet<NodeKey>,
        order: &mut Vec<NodeKey>,
    ) {
        if visited.contains(node) || !self.nodes.contains_key(node) || in_progress.contains(node) {
            return;
        }
        in_progress.insert(node.clone());
        if let Some(edges) = self.edges.get(node) {
            for target in edges.values().cloned().collect::<Vec<_>>() {
                self.visit_topo(&target, visited, in_progress, order);
            }
        }
        in_progress.remove(node);
        visited.insert(node.clone());
        order.push(node.clone());
    }

    /// Computes summaries for all methods in the graph, in topological
    /// order, seeding `specs.summaries` with already-resolved
    /// summaries (same file or cross-file) — multi-hop resolution.
    /// Returns `(own, extra)`, the same shapes as `CallGraph::
    /// resolve_summaries` (Python).
    pub fn resolve_summaries(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&BTreeMap<String, Vec<String>>>,
    ) -> (SummariesByFile, SummariesByFile) {
        let resolved = self.resolve_summaries_incremental(base_specs, source_lines_by_file, None);
        (resolved.own, resolved.extra)
    }

    /// `resolve_summaries`, reusing the summaries of a previous scan where
    /// they cannot have changed (scan cache, issue #183). Java resolves in
    /// a plain topological order, a method seeing only the callees already
    /// resolved before it; a method keeps its previous summary when its
    /// file is clean and none of those callees changed in this scan, which
    /// gives exactly the seed a full scan would give it.
    pub fn resolve_summaries_incremental(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&BTreeMap<String, Vec<String>>>,
        reuse: Option<&super::call_graph::SummaryReuse>,
    ) -> super::call_graph::ResolvedSummaries {
        let mut changed: std::collections::BTreeSet<NodeKey> = std::collections::BTreeSet::new();
        let mut recomputed = 0usize;
        let empty_lines = BTreeMap::new();
        let source_lines_by_file = source_lines_by_file.unwrap_or(&empty_lines);

        let mut resolved: BTreeMap<NodeKey, Arc<FunctionSummary>> = BTreeMap::new();
        let mut own: SummariesByFile = BTreeMap::new();

        // Cloned ONCE before the loop (`sources`/`sinks`/
        // `sanitizers`/`passthroughs`, each with their compiled
        // `Regex`) rather than per node — only `.summaries` varies
        // per node. `base_specs.summaries` is always empty on entry
        // here (built by `rule_json_to_specs`, never pre-seeded):
        // replacing `.summaries` with `seed` on every iteration, even
        // when `seed` is empty, gives exactly the same
        // result as the old `if seed.is_empty() {
        // base_specs.clone() } else { ... }` branch.
        let mut node_specs = base_specs.clone();
        for node in self.topo_order_cached() {
            let node = node.clone();
            let (filepath, name) = node.clone();
            let Some(fn_info) = self.nodes.get(&node) else {
                continue;
            };
            if let Some(reuse) = reuse
                && !reuse.dirty_files.contains(&filepath)
                && self
                    .edges
                    .get(&node)
                    .is_none_or(|e| e.values().all(|t| !changed.contains(t)))
                && let Some(previous) = reuse.previous.get(&node)
            {
                resolved.insert(node, previous.clone());
                own.entry(filepath).or_default().insert(name, previous.clone());
                continue;
            }
            let mut seed: BTreeMap<String, Arc<FunctionSummary>> = BTreeMap::new();
            if let Some(edges) = self.edges.get(&node) {
                for (local_name, target) in edges {
                    if let Some(s) = resolved.get(target) {
                        seed.insert(local_name.clone(), s.clone());
                    }
                }
            }
            node_specs.summaries = seed;
            let Some(&source) = self.source_by_file.get(&filepath) else {
                continue;
            };
            let lines = source_lines_by_file.get(&filepath).map(|v| v.as_slice());
            // `Arc::new` once per node — every subsequent `.clone()`
            // (below, and in callers' seeds) is then just a
            // reference-count bump, not a deep copy of `FunctionSummary`
            // (whose `sink_param_findings` can contain `Finding`
            // values that are expensive to clone). This is what dominated
            // the actual cost on a large corpus (high fan-in "hub"
            // nodes, e.g. OWASP BenchmarkJava) — see the `SummariesByFile` doc.
            let summary = Arc::new(compute_java_summary(fn_info, &node_specs, source, lines));
            recomputed += 1;
            if reuse.is_none_or(|r| r.previous.get(&node) != Some(&summary)) {
                changed.insert(node.clone());
            }
            resolved.insert(node, summary.clone());
            own.entry(filepath).or_default().insert(name, summary);
        }

        // `own[filepath]` must expose the same bare aliases as
        // `compute_java_file_summaries` (Java specificity: a call
        // `runQuery(x)` targets the SAME class without qualification) — without
        // this post-processing, a bare call site resolved as an edge
        // (used to seed the CALLER's summary during the
        // topological loop) stays invisible to the final `analyze()`
        // pass on the caller itself, which looks up `specs.summaries` with the
        // literal bare key produced by `canon_callee`. Bug found through
        // calibration on the Python side (F1 regression 99.9%→88.8% on OWASP
        // BenchmarkJava before this fix — see Audit/docs/ROADMAP.md § v2.0.0).
        for summaries in own.values_mut() {
            add_bare_name_aliases(summaries);
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

        // Call-site aliases (`this.foo`, `super.foo`, `Class.method`,
        // `recv.method` via type_map): the same need as the bare aliases
        // above, generalized to ALL key forms produced by
        // `outgoing_edges` — without this, a call `super.execute(...)`
        // correctly resolved as an EDGE (used to seed the
        // CALLER's summary during the topological loop) stays invisible to
        // the final `analyze()` pass on that same caller, which looks up
        // `specs.summaries["super.execute"]` literally — a key
        // absent from `own`/`extra` as long as it is built ONLY
        // from visible classes (`Class.method`, never
        // `super.method`, `this.method`, or `recv.method`). Bug found
        // on a real WebGoat case (`ProfileUpload.uploadFileHandler` →
        // `super.execute(...)`, cross-file) — see Audit/docs/ROADMAP.md § v2.0.0.
        //
        // Anti-ambiguity (same discipline as `add_bare_name_aliases`):
        // if two callers in the same file use the same local key
        // to target DIFFERENT destinations, seed nothing for
        // that key — a missed flow is better than an invented one.
        let per_file_key_targets = self.per_file_key_targets_cached();
        for (caller_file, key_targets) in per_file_key_targets {
            for (local_key, targets) in key_targets {
                if targets.len() != 1 {
                    continue;
                }
                let target = targets.iter().next().unwrap();
                let Some(s) = resolved.get(target) else {
                    continue;
                };
                let bucket = if &target.0 == caller_file {
                    &mut own
                } else {
                    &mut extra
                };
                bucket
                    .entry(caller_file.clone())
                    .or_default()
                    .entry(local_key.clone())
                    .or_insert_with(|| s.clone());
            }
        }

        super::call_graph::ResolvedSummaries {
            own,
            extra,
            all: resolved,
            changed,
            recomputed,
        }
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

/// Rebuilds, for a file, ALL cross-file/same-package
/// bindings in the form `{local_key: NodeKey}` — the same keys that
/// a 1-hop resolution would produce (dotted "Class.method" for a
/// visible class, bare name for a static import), but resolved
/// from the multi-hop graph.
fn build_import_bindings(
    visible_classes: &BTreeMap<String, String>,
    static_bindings: &BTreeMap<String, NodeKey>,
    file_function_names: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, NodeKey> {
    let mut out = BTreeMap::new();
    for (cname, target_file) in visible_classes {
        let prefix = format!("{cname}.");
        if let Some(names) = file_function_names.get(target_file) {
            for dotted in names {
                if dotted.starts_with(&prefix) {
                    out.insert(dotted.clone(), (target_file.clone(), dotted.clone()));
                }
            }
        }
    }
    for (bare_name, target) in static_bindings {
        out.insert(bare_name.clone(), target.clone());
    }
    out
}

/// Returns the file defining `class_name` as seen from `filepath` —
/// the file itself first, otherwise via visible classes (same
/// package or import). `None` if unknown (anti-FP, no invention).
fn resolve_class_target(
    class_name: &str,
    filepath: &str,
    local_class_names: &BTreeSet<String>,
    visible_classes: &BTreeMap<String, String>,
) -> Option<String> {
    if local_class_names.contains(class_name) {
        return Some(filepath.to_string());
    }
    visible_classes.get(class_name).cloned()
}

/// Returns the outgoing edges of a method/constructor — one call
/// site per local key (the first resolution encountered wins,
/// as on the Python side).
#[allow(clippy::too_many_arguments)]
fn outgoing_edges<'tree>(
    fn_info: &JavaFunctionInfo<'tree>,
    filepath: &str,
    enclosing_class: &str,
    local_class_names: &BTreeSet<String>,
    info: &FileInfo,
    visible_classes: &BTreeMap<String, String>,
    static_bindings: &BTreeMap<String, NodeKey>,
    all_nodes: &BTreeMap<NodeKey, JavaFunctionInfo<'tree>>,
    source: &[u8],
) -> BTreeMap<String, NodeKey> {
    let mut edges: BTreeMap<String, NodeKey> = BTreeMap::new();

    let try_same_class = |name: &str| -> Option<NodeKey> {
        let key = (filepath.to_string(), format!("{enclosing_class}.{name}"));
        if all_nodes.contains_key(&key) {
            Some(key)
        } else {
            None
        }
    };

    for call in iter_method_invocations(fn_info.body_node) {
        let Some(name_node) = call.child_by_field_name("name") else {
            continue;
        };
        let name = text(name_node, source);
        let obj = call.child_by_field_name("object");

        let Some(obj) = obj else {
            // Bare call: same class first, then static import.
            if edges.contains_key(&name) {
                continue;
            }
            let target = try_same_class(&name).or_else(|| static_bindings.get(&name).cloned());
            if let Some(t) = target {
                edges.insert(name, t);
            }
            continue;
        };

        match obj.kind() {
            "this" => {
                let local_key = format!("this.{name}");
                if edges.contains_key(&local_key) {
                    continue;
                }
                if let Some(t) = try_same_class(&name) {
                    edges.insert(local_key, t);
                }
            }
            "super" => {
                let local_key = format!("super.{name}");
                if edges.contains_key(&local_key) {
                    continue;
                }
                if let Some(Some(super_name)) = info.superclass.get(enclosing_class)
                    && let Some(target_file) = resolve_class_target(
                        super_name,
                        filepath,
                        local_class_names,
                        visible_classes,
                    )
                {
                    let target = (target_file, format!("{super_name}.{name}"));
                    if all_nodes.contains_key(&target) {
                        edges.insert(local_key, target);
                    }
                }
            }
            "object_creation_expression" => {
                let ctor_type_text = obj
                    .child_by_field_name("type")
                    .map(|t| simple_type_text(t, source));
                let Some(ctor_type_text) = ctor_type_text.filter(|s| !s.is_empty()) else {
                    continue;
                };
                let local_key = format!("{ctor_type_text}.{name}");
                if edges.contains_key(&local_key) {
                    continue;
                }
                if let Some(target_file) = resolve_class_target(
                    &ctor_type_text,
                    filepath,
                    local_class_names,
                    visible_classes,
                ) {
                    let target = (target_file, local_key.clone());
                    if all_nodes.contains_key(&target) {
                        edges.insert(local_key, target);
                    }
                }
            }
            "identifier" => {
                let recv = text(obj, source);
                let local_key = format!("{recv}.{name}");
                if edges.contains_key(&local_key) {
                    continue;
                }
                // 1. `recv` is itself the name of a visible class
                //    (qualified static call, e.g. `Helper.doThing()`).
                let mut target_file =
                    resolve_class_target(&recv, filepath, local_class_names, visible_classes);
                let mut resolved_class = recv.clone();
                if target_file.is_none() {
                    // 2. `recv` is a variable/field with a known declared type.
                    if let Some(declared_type) = info.type_map.get(&recv) {
                        target_file = resolve_class_target(
                            declared_type,
                            filepath,
                            local_class_names,
                            visible_classes,
                        );
                        resolved_class = declared_type.clone();
                    }
                }
                if let Some(tf) = target_file {
                    let target = (tf, format!("{resolved_class}.{name}"));
                    if all_nodes.contains_key(&target) {
                        edges.insert(local_key, target);
                    }
                }
            }
            _ => {
                // Multi-level chain (`a.b.method()`) or a form not
                // handled in v1 — left unresolved (anti-FP), see the
                // module's non-goals.
            }
        }
    }

    edges
}

// ============================================================================
// Tests — mirror of `Audit/tests/dataflow/test_java_call_graph.py`.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::{SinkSpec, SourceSpec};
    use tree_sitter::Parser;

    fn parse_java(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    /// Parses a set of Java `(path, source)` files and exposes
    /// the `JavaCallGraph` built on top of them to `f` — avoids letting
    /// a borrowed graph escape the scope of the trees it
    /// depends on.
    fn with_graph<R>(files: &[(&str, &str)], f: impl FnOnce(&JavaCallGraph) -> R) -> R {
        let trees: Vec<(String, String, tree_sitter::Tree)> = files
            .iter()
            .map(|(path, src)| {
                let tree = parse_java(src);
                assert!(
                    !tree.root_node().has_error(),
                    "syntaxe Java invalide dans {path} : {src:?}"
                );
                (path.to_string(), src.to_string(), tree)
            })
            .collect();
        let file_inputs: Vec<FileInput> = trees
            .iter()
            .map(|(path, src, tree)| FileInput {
                filepath: path.clone(),
                root: tree.root_node(),
                source: src.as_bytes(),
            })
            .collect();
        let graph = JavaCallGraph::build(&file_inputs);
        f(&graph)
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

    fn key(fp: &str, name: &str) -> NodeKey {
        (fp.to_string(), name.to_string())
    }

    // -------------------------------------------------------- build: edges

    #[test]
    fn test_bare_call_same_class() {
        with_graph(
            &[("A.java", "class A { void foo() { bar(); } void bar() {} }")],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "A.foo")],
                    BTreeMap::from([("bar".to_string(), key("A.java", "A.bar"))])
                );
            },
        );
    }

    #[test]
    fn test_this_call_same_class() {
        with_graph(
            &[(
                "A.java",
                "class A { void foo() { this.bar(); } void bar() {} }",
            )],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "A.foo")],
                    BTreeMap::from([("this.bar".to_string(), key("A.java", "A.bar"))])
                );
            },
        );
    }

    #[test]
    fn test_super_call_same_file() {
        with_graph(
            &[(
                "A.java",
                "class Base { void bar() {} } class Impl extends Base { void foo() { super.bar(); } }",
            )],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "Impl.foo")],
                    BTreeMap::from([("super.bar".to_string(), key("A.java", "Base.bar"))])
                );
            },
        );
    }

    #[test]
    fn test_super_call_cross_file() {
        with_graph(
            &[
                ("Base.java", "package p; class Base { void bar() {} }"),
                (
                    "Impl.java",
                    "package p; class Impl extends Base { void foo() { super.bar(); } }",
                ),
            ],
            |graph| {
                assert_eq!(
                    graph.edges[&key("Impl.java", "Impl.foo")],
                    BTreeMap::from([("super.bar".to_string(), key("Base.java", "Base.bar"))])
                );
            },
        );
    }

    #[test]
    fn test_cross_file_edge_via_explicit_import() {
        with_graph(
            &[
                (
                    "Helper.java",
                    "package com.acme.util; class Helper { void run() {} }",
                ),
                (
                    "Api.java",
                    "package com.acme.service;\nimport com.acme.util.Helper;\nclass Api { void foo() { Helper h = new Helper(); h.run(); } }",
                ),
            ],
            |graph| {
                assert_eq!(
                    graph.edges[&key("Api.java", "Api.foo")],
                    BTreeMap::from([("h.run".to_string(), key("Helper.java", "Helper.run"))])
                );
            },
        );
    }

    #[test]
    fn test_cross_file_edge_same_package_no_import() {
        with_graph(
            &[
                ("Helper.java", "package p; class Helper { void run() {} }"),
                (
                    "Api.java",
                    "package p; class Api { void foo() { Helper.run(); } }",
                ),
            ],
            |graph| {
                assert_eq!(
                    graph.edges[&key("Api.java", "Api.foo")],
                    BTreeMap::from([("Helper.run".to_string(), key("Helper.java", "Helper.run"))])
                );
            },
        );
    }

    #[test]
    fn test_field_typed_receiver_edge() {
        with_graph(
            &[(
                "A.java",
                "class A { private final Helper helper; void foo() { helper.run(); } } class Helper { void run() {} }",
            )],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "A.foo")],
                    BTreeMap::from([("helper.run".to_string(), key("A.java", "Helper.run"))])
                );
            },
        );
    }

    #[test]
    fn test_local_var_typed_receiver_edge() {
        with_graph(
            &[(
                "A.java",
                "class A { void foo() { Helper h = new Helper(); h.run(); } } class Helper { void run() {} }",
            )],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "A.foo")],
                    BTreeMap::from([("h.run".to_string(), key("A.java", "Helper.run"))])
                );
            },
        );
    }

    #[test]
    fn test_chained_constructor_call_edge() {
        with_graph(
            &[(
                "A.java",
                "class A { void foo() { new Helper().run(); } } class Helper { void run() {} }",
            )],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "A.foo")],
                    BTreeMap::from([("Helper.run".to_string(), key("A.java", "Helper.run"))])
                );
            },
        );
    }

    #[test]
    fn test_static_import_bare_call_edge() {
        with_graph(
            &[
                (
                    "Const.java",
                    "package p; class Const { static void log() {} }",
                ),
                (
                    "Api.java",
                    "package q;\nimport static p.Const.log;\nclass Api { void foo() { log(); } }",
                ),
            ],
            |graph| {
                assert_eq!(
                    graph.edges[&key("Api.java", "Api.foo")],
                    BTreeMap::from([("log".to_string(), key("Const.java", "Const.log"))])
                );
            },
        );
    }

    #[test]
    fn test_unresolvable_receiver_has_no_edge() {
        with_graph(
            &[("A.java", "class A { void foo(Object o) { o.toString(); } }")],
            |graph| {
                assert_eq!(graph.edges[&key("A.java", "A.foo")], BTreeMap::new());
            },
        );
    }

    #[test]
    fn test_multi_level_chain_not_resolved() {
        with_graph(
            &[(
                "A.java",
                "class A { void foo() { this.helper.run(); } Helper helper; } class Helper { void run() {} }",
            )],
            |graph| {
                assert_eq!(graph.edges[&key("A.java", "A.foo")], BTreeMap::new());
            },
        );
    }

    #[test]
    fn test_unknown_class_import_no_edge() {
        with_graph(
            &[(
                "Api.java",
                "package q; class Api { void foo() { Missing.run(); } }",
            )],
            |graph| {
                assert_eq!(graph.edges[&key("Api.java", "Api.foo")], BTreeMap::new());
            },
        );
    }

    // ---------------------------------------------------- topological_order

    #[test]
    fn test_callee_before_caller() {
        with_graph(
            &[("A.java", "class A { void foo() { bar(); } void bar() {} }")],
            |graph| {
                let order = graph.topological_order();
                let bar_idx = order.iter().position(|k| k == &key("A.java", "A.bar"));
                let foo_idx = order.iter().position(|k| k == &key("A.java", "A.foo"));
                assert!(bar_idx < foo_idx);
            },
        );
    }

    #[test]
    fn test_self_recursive_cycle_terminates() {
        with_graph(
            &[("A.java", "class A { void fact() { fact(); } }")],
            |graph| {
                let order = graph.topological_order();
                assert_eq!(order, vec![key("A.java", "A.fact")]);
            },
        );
    }

    // ------------------------------------------------- resolve_summaries

    #[test]
    fn test_transitive_source_reaches_caller_two_hops() {
        let c_src =
            "package p; class C { String getTainted(String v) { return v.getParameter(\"x\"); } }";
        let b_src = "package p; class B { C c = new C(); String wrapper(String v) { return c.getTainted(v); } }";
        let a_src = "package p; class A { B b = new B(); void entry(String v) { String x = b.wrapper(v); stmt.execute(x); } }";
        with_graph(
            &[("C.java", c_src), ("B.java", b_src), ("A.java", a_src)],
            |graph| {
                let lines = BTreeMap::from([
                    (
                        "C.java".to_string(),
                        c_src.lines().map(str::to_string).collect(),
                    ),
                    (
                        "B.java".to_string(),
                        b_src.lines().map(str::to_string).collect(),
                    ),
                    (
                        "A.java".to_string(),
                        a_src.lines().map(str::to_string).collect(),
                    ),
                ]);
                let (own, _extra) = graph.resolve_summaries(&sqli_specs(), Some(&lines));
                assert!(own["C.java"]["C.getTainted"].return_tainted_uncond);
                assert!(
                    own["B.java"]["B.wrapper"].return_tainted_uncond,
                    "le taint inconditionnel de C.getTainted doit se propager à B.wrapper via le graphe multi-sauts"
                );
            },
        );
    }

    #[test]
    fn test_intra_file_sibling_resolution() {
        let src = "class A { String bar(String v) { return v.getParameter(\"x\"); } String foo(String v) { return bar(v); } }";
        with_graph(&[("A.java", src)], |graph| {
            let lines = BTreeMap::from([(
                "A.java".to_string(),
                src.lines().map(str::to_string).collect(),
            )]);
            let (own, _extra) = graph.resolve_summaries(&sqli_specs(), Some(&lines));
            assert!(own["A.java"]["A.bar"].return_tainted_uncond);
            assert!(own["A.java"]["A.foo"].return_tainted_uncond);
        });
    }

    #[test]
    fn test_cycle_resolves_without_crashing() {
        let src = "class A { void foo(int n) { bar(n); } void bar(int n) { foo(n); } }";
        with_graph(&[("A.java", src)], |graph| {
            let lines = BTreeMap::from([(
                "A.java".to_string(),
                src.lines().map(str::to_string).collect(),
            )]);
            let (own, _extra) = graph.resolve_summaries(&sqli_specs(), Some(&lines));
            let keys: std::collections::BTreeSet<&String> = own["A.java"].keys().collect();
            assert_eq!(
                keys,
                std::collections::BTreeSet::from([
                    &"A.foo".to_string(),
                    &"A.bar".to_string(),
                    &"foo".to_string(),
                    &"bar".to_string(),
                ])
            );
        });
    }

    #[test]
    fn test_extra_summaries_cover_visible_class_bindings() {
        let helper_src =
            "package p; class Helper { String run(String v) { return v.getParameter(\"x\"); } }";
        let api_src = "package p; class Api { void foo() {} }";
        with_graph(
            &[("Helper.java", helper_src), ("Api.java", api_src)],
            |graph| {
                let lines = BTreeMap::from([
                    (
                        "Helper.java".to_string(),
                        helper_src.lines().map(str::to_string).collect(),
                    ),
                    (
                        "Api.java".to_string(),
                        api_src.lines().map(str::to_string).collect(),
                    ),
                ]);
                let (_own, extra) = graph.resolve_summaries(&sqli_specs(), Some(&lines));
                assert!(
                    extra
                        .get("Api.java")
                        .is_some_and(|m| m.contains_key("Helper.run"))
                );
            },
        );
    }
}
