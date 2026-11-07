//! Worklist algorithm — port of
//! `Audit/sca/dataflow/worklist.py`.
//!
//! **Scope of this component**: the constant-propagation pre-pass that
//! computes the CFG's dead edges (`compute_dead_edges`, port of
//! `_compute_dead_edges`), the per-node CFG→IR lowering
//! (`lower_node_to_ir`, Python — the Java equivalent lives in
//! `java_lowering::lower_node_to_ir`), **and** the main taint fixpoint
//! (`analyze`, §6).
//!
//! **Multi-language genericity (2026-08-25)**: on the Python side,
//! `worklist.py::analyze(cfg, specs, language=...)` dispatches CFG→IR
//! lowering at runtime via a `language: str` parameter. Rust has no
//! such dynamic-typing escape hatch — the same contract is ported via
//! generic parameters resolved at compile time
//! (`analyze_generic`/`compute_dead_edges_generic`, parameterized by
//! `lower_all`/`lower_expr`), with `analyze` (Python, unchanged for
//! every existing caller) and `analyze_java` as concrete
//! instantiations.

use std::collections::{BTreeMap, HashSet, VecDeque};

use tree_sitter::Node;

use super::cfg::{Cfg, EdgeLabel, NodeKind};
use super::const_eval::{
    ConstState, apply_list_mutation, const_state_equal, empty_const_state, eval_const,
    invalidate_var, is_truthy, join_const_states, simplify_stmt, update_const_on_assign,
};
use super::ir::{IrStmt, Rhs, canon_rhs};
use super::lattice::{State, empty_state, state_equal, state_join, state_widen};
use super::lowering::{lower_expr_standalone, lower_for_target_assign, lower_stmts};
use super::transfer::{Finding, RuleSpecs, transfer_stmts};

/// Spec §4.3: widening threshold for loops.
pub const MAX_LOOP_ITER: u32 = 3;

/// Guard against infinite loops. In practice widening ensures
/// convergence within a few iterations, but we cap it to avoid
/// pathological cases.
pub const MAX_WORKLIST_ITER: u32 = 10_000;

// ============================================================================
// Lowering a CFG node to IR
// ============================================================================

/// Lowers the statements/condition of a CFG node to IR — Python-only
/// scope (Decision #10; on the Python side this function also
/// dispatches to Java/C#, not relevant here).
pub fn lower_node_to_ir<'tree>(cfg: &Cfg<'tree>, node_id: usize, source: &[u8]) -> Vec<IrStmt> {
    let node = &cfg.nodes[&node_id];
    match node.kind {
        NodeKind::Basic | NodeKind::Finally | NodeKind::RaiseSite => {
            if node.statements.is_empty() {
                Vec::new()
            } else {
                lower_stmts(source, &node.statements)
            }
        }
        NodeKind::Branch | NodeKind::Loop => {
            let Some(cond) = node.condition else {
                return Vec::new();
            };
            // For loop: emits the synthetic assignment `target :=
            // iter` (without it, taint from `iter` does not propagate
            // to `target`, cf. "for/break bug" on the Python side).
            if node.kind == NodeKind::Loop
                && let Some(target) = node.for_target
            {
                return lower_for_target_assign(source, target, cond);
            }
            let (_, stmts) = lower_expr_standalone(source, cond);
            stmts
        }
        _ => Vec::new(),
    }
}

/// Lowers all nodes of a CFG to IR, in a single pass.
pub fn lower_all_nodes<'tree>(cfg: &Cfg<'tree>, source: &[u8]) -> BTreeMap<usize, Vec<IrStmt>> {
    cfg.nodes
        .keys()
        .map(|&nid| (nid, lower_node_to_ir(cfg, nid, source)))
        .collect()
}

// ============================================================================
// §9 — Constant propagation and dead-edge marking
// ============================================================================

/// Propagates `const_state` through a sequence of IR statements and,
/// along the way, simplifies evaluable `IfExp` nodes (§9).
///
/// For each statement:
///   1. `simplify_stmt(stmt, cs)` recursively rewrites `IfExp` nodes
///      whose condition is known in `cs`, or returns `stmt`
///      unchanged.
///   2. The simplified statement updates `cs`:
///      - `Assign` → updates the target's value if the new RHS is
///        evaluable.
///      - `Call` on a known receiver → invalidates (or simulates,
///        §9.quater) the receiver's value.
///      - Others → no effect on `cs`.
fn simplify_and_apply_stmts(
    stmts: &[IrStmt],
    const_state: &ConstState,
) -> (Vec<IrStmt>, ConstState) {
    let mut cs = const_state.clone();
    let mut new_stmts = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        let simplified = simplify_stmt(stmt, &cs);
        match &simplified {
            IrStmt::Assign { lhs, rhs, .. } => {
                cs = update_const_on_assign(&cs, lhs, rhs);
            }
            IrStmt::Call {
                callee: Rhs::AttrRef { base, attr },
                args,
                ..
            } => {
                let base_key = canon_rhs(base);
                if !base_key.is_empty() && !base_key.starts_with('<') && cs.contains_key(&base_key)
                {
                    // §9.quater — first tries to simulate the
                    // operation on a list tracked as Tuple. Otherwise,
                    // conservative invalidation.
                    match apply_list_mutation(&cs, &base_key, attr, args) {
                        Some(simulated) => cs = simulated,
                        None => cs = invalidate_var(&cs, &base_key),
                    }
                }
            }
            _ => {}
        }
        new_stmts.push(simplified);
    }
    (new_stmts, cs)
}

/// Attempts to evaluate the condition of a `Branch`/`Loop` node at
/// compile time.
///
/// Two possible sources depending on how the node was built:
///   - `node.condition` (tree-sitter node carried by the CFG):
///     standard if/while case.
///   - An IR `Branch` emitted explicitly (`match`/`case` case, which
///     inserts a Branch into the linear flow of a Basic block).
///
/// `eval_const` (const_eval.rs) is 100% language-neutral — only the
/// lowering of `node.condition` differs by language, injected via
/// `lower_expr` (generic — cf. `compute_dead_edges_generic`).
fn eval_branch_condition<'tree, FExpr>(
    node: &super::cfg::CfgNode<'tree>,
    stmts: &[IrStmt],
    const_state: &ConstState,
    source: &'tree [u8],
    lower_expr: FExpr,
) -> Option<bool>
where
    FExpr: Fn(&'tree [u8], Node<'tree>) -> (Rhs, Vec<IrStmt>),
{
    if let Some(cond) = node.condition {
        // **Java** — `switch_case_label` present: `cond` carries the
        // switch subject (not a boolean), the real condition is
        // `subject == label` (cf. `CfgNode::switch_case_label`).
        // Without this special case, `is_truthy(subject)` would
        // evaluate any non-null/non-empty value as "always true" —
        // incorrect pruning (all switch FALSE edges dead) as soon as
        // the subject becomes resolvable (e.g. via
        // `eval_string_method_call`). Always `None` on the Python side
        // (no Python `CfgNode` carries this field), so no effect there.
        let rhs = if let Some(label) = node.switch_case_label {
            let (subject_rhs, _) = lower_expr(source, cond);
            let (label_rhs, _) = lower_expr(source, label);
            Rhs::Cmp {
                op: "==".to_string(),
                left: Box::new(subject_rhs),
                right: Box::new(label_rhs),
            }
        } else {
            let (rhs, _) = lower_expr(source, cond);
            rhs
        };
        let v = eval_const(&rhs, const_state)?;
        return Some(is_truthy(&v));
    }
    for stmt in stmts {
        if let IrStmt::Branch { condition, .. } = stmt {
            let v = eval_const(condition, const_state)?;
            return Some(is_truthy(&v));
        }
    }
    None
}

/// Computes the set of `(src, dst)` edges made dead by constant
/// propagation (§9).
///
/// Algorithm: a separate fixpoint on `ConstState`. On each visit to a
/// `BRANCH` node, its condition is evaluated in the computed
/// `const_out`; if known, the opposite edge (TRUE or FALSE) is marked
/// dead. Dead edges are excluded from the computation of
/// `const_in[succ]`.
///
/// `LOOP` nodes are never pruned (the loop condition can change
/// between runtime iterations — over-cautious by design).
///
/// Updates `node_ir` in place with the simplified version (evaluated
/// `IfExp` nodes are replaced by the branch taken) — the future main
/// taint engine will reuse this modified `node_ir`.
pub fn compute_dead_edges<'tree>(
    cfg: &Cfg<'tree>,
    node_ir: &mut BTreeMap<usize, Vec<IrStmt>>,
    source: &'tree [u8],
) -> HashSet<(usize, usize)> {
    compute_dead_edges_generic(cfg, node_ir, source, lower_expr_standalone)
}

/// Generic variant of [`compute_dead_edges`], parameterized by the
/// lowering of a standalone condition (`lower_expr`) — Rust mirror of
/// the `language: str` parameter of `worklist.py::analyze`/
/// `compute_dead_edges` (runtime dispatch on the Python side; resolved
/// here at compile time via monomorphization). Used by
/// `compute_dead_edges` (Python, above) and by the future Java entry
/// point (§ `dataflow/mod.rs`).
pub fn compute_dead_edges_generic<'tree, FExpr>(
    cfg: &Cfg<'tree>,
    node_ir: &mut BTreeMap<usize, Vec<IrStmt>>,
    source: &'tree [u8],
    lower_expr: FExpr,
) -> HashSet<(usize, usize)>
where
    FExpr: Fn(&'tree [u8], Node<'tree>) -> (Rhs, Vec<IrStmt>) + Copy,
{
    let mut const_in: BTreeMap<usize, ConstState> = cfg
        .nodes
        .keys()
        .map(|&nid| (nid, empty_const_state()))
        .collect();
    let mut const_out: BTreeMap<usize, ConstState> = cfg
        .nodes
        .keys()
        .map(|&nid| (nid, empty_const_state()))
        .collect();
    let mut dead_edges: HashSet<(usize, usize)> = HashSet::new();
    let mut iter_count: BTreeMap<usize, u32> = cfg.nodes.keys().map(|&nid| (nid, 0)).collect();

    let mut worklist: VecDeque<usize> = VecDeque::from([cfg.entry]);
    let mut in_worklist: HashSet<usize> = HashSet::from([cfg.entry]);

    let mut iterations: u32 = 0;
    while let Some(n) = worklist.pop_front() {
        if iterations > MAX_WORKLIST_ITER {
            break;
        }
        iterations += 1;
        in_worklist.remove(&n);

        // Recomputes const_in[n], ignoring known dead edges.
        if n != cfg.entry {
            let preds = cfg.predecessor_ids(n);
            let live_preds: Vec<usize> = preds
                .into_iter()
                .filter(|p| !dead_edges.contains(&(*p, n)))
                .collect();
            if !live_preds.is_empty() {
                let mut new_in: Option<ConstState> = None;
                for p in &live_preds {
                    new_in = Some(match new_in {
                        None => const_out[p].clone(),
                        Some(acc) => join_const_states(&acc, &const_out[p]),
                    });
                }
                const_in.insert(n, new_in.unwrap_or_else(empty_const_state));
            }
            // If no live pred: const_in[n] stays as-is (the node
            // becomes orphaned, pruned later by the taint engine).
        }

        let (new_stmts, mut new_out) = simplify_and_apply_stmts(&node_ir[&n], &const_in[&n]);
        node_ir.insert(n, new_stmts);
        *iter_count.get_mut(&n).unwrap() += 1;

        let node = &cfg.nodes[&n];

        // Simple widening: on a LOOP node, after MAX_LOOP_ITER passes
        // that don't converge, empties the const_state (over-caution).
        if iter_count[&n] > MAX_LOOP_ITER
            && node.kind == NodeKind::Loop
            && !const_state_equal(&new_out, &const_out[&n])
        {
            new_out = empty_const_state();
        }

        let mut new_dead_from_n: HashSet<(usize, usize)> = HashSet::new();
        if node.kind == NodeKind::Branch
            && let Some(cond_val) =
                eval_branch_condition(node, &node_ir[&n], &new_out, source, lower_expr)
        {
            let dead_label = if cond_val {
                EdgeLabel::False
            } else {
                EdgeLabel::True
            };
            for edge in cfg.successors(n) {
                if edge.label == dead_label {
                    new_dead_from_n.insert((n, edge.dst));
                }
            }
        }

        let prev_dead_from_n: HashSet<(usize, usize)> =
            dead_edges.iter().copied().filter(|e| e.0 == n).collect();
        let dead_changed = new_dead_from_n != prev_dead_from_n;
        let first_pass = iter_count[&n] == 1;

        if first_pass || !const_state_equal(&new_out, &const_out[&n]) || dead_changed {
            const_out.insert(n, new_out);
            if dead_changed {
                dead_edges.retain(|e| e.0 != n);
                dead_edges.extend(new_dead_from_n);
            }
            for succ_id in cfg.successor_ids(n) {
                if dead_edges.contains(&(n, succ_id)) {
                    continue;
                }
                if !in_worklist.contains(&succ_id) {
                    worklist.push_back(succ_id);
                    in_worklist.insert(succ_id);
                }
            }
        }
    }

    dead_edges
}

// ============================================================================
// Worklist algorithm (§6) — main taint fixpoint
// ============================================================================

/// Result of the dataflow analysis — σ_in, σ_out and the emitted findings.
pub struct AnalysisResult {
    pub state_in: BTreeMap<usize, State>,
    pub state_out: BTreeMap<usize, State>,
    pub findings: Vec<Finding>,
    pub iterations: u32,
}

/// Runs the dataflow analysis on a CFG with a taint rule (§6).
///
/// `initial_state`: entry state (default: empty = clean everywhere —
/// used for the future interprocedural analysis, a function parameter
/// already tainted by the caller). `source_lines`: enables §10bis
/// hybrid matching (cf. `transfer::transfer_stmt`).
pub fn analyze<'tree>(
    cfg: &Cfg<'tree>,
    source: &'tree [u8],
    specs: &RuleSpecs,
    initial_state: Option<&State>,
    source_lines: Option<&[String]>,
) -> AnalysisResult {
    analyze_generic(
        cfg,
        source,
        specs,
        initial_state,
        source_lines,
        lower_all_nodes,
        lower_expr_standalone,
    )
}

/// Java equivalent of [`analyze`] — same fixpoint algorithm, Java
/// lowering (`java_lowering::lower_all_nodes`/
/// `lower_expr_standalone`).
pub fn analyze_java<'tree>(
    cfg: &Cfg<'tree>,
    source: &'tree [u8],
    specs: &RuleSpecs,
    initial_state: Option<&State>,
    source_lines: Option<&[String]>,
) -> AnalysisResult {
    analyze_generic(
        cfg,
        source,
        specs,
        initial_state,
        source_lines,
        super::java_lowering::lower_all_nodes,
        super::java_lowering::lower_expr_standalone,
    )
}

/// JavaScript equivalent of [`analyze`] — same fixpoint algorithm, JS
/// lowering (`js_lowering::lower_all_nodes`/
/// `lower_expr_standalone`).
pub fn analyze_js<'tree>(
    cfg: &Cfg<'tree>,
    source: &'tree [u8],
    specs: &RuleSpecs,
    initial_state: Option<&State>,
    source_lines: Option<&[String]>,
) -> AnalysisResult {
    analyze_generic(
        cfg,
        source,
        specs,
        initial_state,
        source_lines,
        super::js_lowering::lower_all_nodes,
        super::js_lowering::lower_expr_standalone,
    )
}

/// PHP equivalent of [`analyze`] — same fixpoint algorithm, PHP
/// lowering (`php_lowering::lower_all_nodes`/
/// `lower_expr_standalone`).
pub fn analyze_php<'tree>(
    cfg: &Cfg<'tree>,
    source: &'tree [u8],
    specs: &RuleSpecs,
    initial_state: Option<&State>,
    source_lines: Option<&[String]>,
) -> AnalysisResult {
    analyze_generic(
        cfg,
        source,
        specs,
        initial_state,
        source_lines,
        super::php_lowering::lower_all_nodes,
        super::php_lowering::lower_expr_standalone,
    )
}

/// C# equivalent of [`analyze`] — same fixpoint algorithm, C#
/// lowering (`csharp_lowering::lower_all_nodes`/
/// `lower_expr_standalone`), ticket #79/spec #77.
pub fn analyze_csharp<'tree>(
    cfg: &Cfg<'tree>,
    source: &'tree [u8],
    specs: &RuleSpecs,
    initial_state: Option<&State>,
    source_lines: Option<&[String]>,
) -> AnalysisResult {
    analyze_generic(
        cfg,
        source,
        specs,
        initial_state,
        source_lines,
        super::csharp_lowering::lower_all_nodes,
        super::csharp_lowering::lower_expr_standalone,
    )
}

/// Generic variant of [`analyze`], parameterized by CFG→IR lowering
/// (`lower_all`) and the lowering of a standalone condition
/// (`lower_expr`, for `compute_dead_edges_generic`) — Rust mirror of
/// the `language: str` parameter of `worklist.py::analyze` (runtime
/// dispatch on the Python side; resolved here at compile time).
pub fn analyze_generic<'tree, FAll, FExpr>(
    cfg: &Cfg<'tree>,
    source: &'tree [u8],
    specs: &RuleSpecs,
    initial_state: Option<&State>,
    source_lines: Option<&[String]>,
    lower_all: FAll,
    lower_expr: FExpr,
) -> AnalysisResult
where
    FAll: Fn(&Cfg<'tree>, &'tree [u8]) -> BTreeMap<usize, Vec<IrStmt>>,
    FExpr: Fn(&'tree [u8], Node<'tree>) -> (Rhs, Vec<IrStmt>) + Copy,
{
    // Lowers everything at once, upfront.
    let mut node_ir = lower_all(cfg, source);

    // §9 — pre-pass: constant propagation to identify dead edges
    // (branches whose condition is known at compile time). Excluded
    // from the σ_in[n] computation below.
    let dead_edges = compute_dead_edges_generic(cfg, &mut node_ir, source, lower_expr);

    // Initialization: state_in[entry] = initial_state, others = empty.
    let mut state_in: BTreeMap<usize, State> =
        cfg.nodes.keys().map(|&nid| (nid, empty_state())).collect();
    let mut state_out: BTreeMap<usize, State> =
        cfg.nodes.keys().map(|&nid| (nid, empty_state())).collect();
    state_in.insert(
        cfg.entry,
        initial_state.cloned().unwrap_or_else(empty_state),
    );

    // Findings are accumulated over the whole analysis, deduplicated at the end.
    let mut raw_findings: Vec<Finding> = Vec::new();

    // Per-node iteration counter (for widening on loops).
    let mut iter_count: BTreeMap<usize, u32> = cfg.nodes.keys().map(|&nid| (nid, 0)).collect();

    // Identifies loop heads for widening.
    let loop_heads: HashSet<usize> = cfg
        .nodes
        .iter()
        .filter(|(_, node)| node.kind == NodeKind::Loop)
        .map(|(&nid, _)| nid)
        .collect();

    let mut worklist: VecDeque<usize> = VecDeque::from([cfg.entry]);
    let mut in_worklist: HashSet<usize> = HashSet::from([cfg.entry]);

    let mut iterations: u32 = 0;
    while let Some(n) = worklist.pop_front() {
        if iterations > MAX_WORKLIST_ITER {
            // Pathological case: stop (widening should have converged).
            break;
        }
        iterations += 1;
        in_worklist.remove(&n);

        // Recomputes state_in[n] = ⊔ state_out[p] for p ∈ pred(n). §9 —
        // ignores preds whose edge to n has been marked dead.
        if n != cfg.entry {
            let preds = cfg.predecessor_ids(n);
            let live_preds: Vec<usize> = preds
                .into_iter()
                .filter(|p| !dead_edges.contains(&(*p, n)))
                .collect();
            if !live_preds.is_empty() {
                let mut new_in = empty_state();
                for p in &live_preds {
                    new_in = state_join(&new_in, &state_out[p]);
                }
                state_in.insert(n, new_in);
            }
        }

        // Applies the node's transfer function. §9 — findings are
        // collected PER ITERATION to allow final deduplication.
        let mut local_findings: Vec<Finding> = Vec::new();
        let mut new_out = transfer_stmts(
            &node_ir[&n],
            &state_in[&n],
            specs,
            &mut local_findings,
            source_lines,
        );

        *iter_count.get_mut(&n).unwrap() += 1;
        if iter_count[&n] > MAX_LOOP_ITER && loop_heads.contains(&n) {
            new_out = state_widen(&state_out[&n], &new_out, iter_count[&n], MAX_LOOP_ITER);
        }

        // Propagates on change OR on the first pass over this node.
        // §9 — does not push successors past a dead edge.
        let first_pass = iter_count[&n] == 1;
        if first_pass || !state_equal(&new_out, &state_out[&n]) {
            state_out.insert(n, new_out);
            for succ_id in cfg.successor_ids(n) {
                if dead_edges.contains(&(n, succ_id)) {
                    continue;
                }
                if !in_worklist.contains(&succ_id) {
                    worklist.push_back(succ_id);
                    in_worklist.insert(succ_id);
                }
            }
        }

        raw_findings.extend(local_findings);
    }

    // Deduplication — key (rule_id, line, source_line). `sink_text`
    // excluded: varies between pointed and §10bis hybrid matching.
    let mut seen: HashSet<(String, usize, Option<usize>)> = HashSet::new();
    let mut deduped: Vec<Finding> = Vec::new();
    for f in raw_findings {
        let key = (f.rule_id.clone(), f.line, f.source_line);
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);
        deduped.push(f);
    }

    AnalysisResult {
        state_in,
        state_out,
        findings: deduped,
        iterations,
    }
}

/// Public helper: analyzes a Python source fragment directly.
/// Convenient for tests (`analyze_module_source(src, specs)`). In
/// production, use `analyze(cfg, source, specs, ...)` with an already-
/// built CFG.
pub fn analyze_module_source(source: &str, specs: &RuleSpecs) -> AnalysisResult {
    let mut parser = tree_sitter::Parser::new();
    let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
    parser
        .set_language(&lang)
        .expect("langage tree-sitter-python valide");
    let tree = parser
        .parse(source, None)
        .expect("parse tree-sitter réussi");
    let src_bytes = source.as_bytes();
    let cfg = super::cfg::build_cfg(&tree, src_bytes);
    analyze(&cfg, src_bytes, specs, None, None)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::cfg::build_cfg;
    use crate::scan::dataflow::ir::{ConstValue, Lhs};
    use crate::scan::dataflow::lattice::{SourceInfo, Taint, state_set};
    use crate::scan::dataflow::transfer::{SanitizerSpec, SinkSpec, SourceSpec};
    use tree_sitter::Parser;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn build(src: &str) -> (tree_sitter::Tree, Vec<u8>) {
        (parse(src), src.as_bytes().to_vec())
    }

    #[test]
    fn test_lower_node_to_ir_basic_block() {
        let (tree, src) = build("x = 1\ny = 2\n");
        let cfg = build_cfg(&tree, &src);
        let basic_id = cfg
            .nodes
            .iter()
            .find(|(_, n)| n.kind == NodeKind::Basic)
            .map(|(id, _)| *id)
            .unwrap();
        let ir = lower_node_to_ir(&cfg, basic_id, &src);
        assert_eq!(ir.len(), 2);
        assert!(matches!(ir[0], IrStmt::Assign { .. }));
    }

    #[test]
    fn test_lower_node_to_ir_branch_condition_produces_assign_temp() {
        let (tree, src) = build("if a < b:\n    x = 1\n");
        let cfg = build_cfg(&tree, &src);
        let branch_id = cfg
            .nodes
            .iter()
            .find(|(_, n)| n.kind == NodeKind::Branch)
            .map(|(id, _)| *id)
            .unwrap();
        let ir = lower_node_to_ir(&cfg, branch_id, &src);
        // `a < b` compound -> an intermediate Assign(__t0 := Cmp(...)).
        assert_eq!(ir.len(), 1);
        assert!(matches!(ir[0], IrStmt::Assign { .. }));
    }

    #[test]
    fn test_lower_node_to_ir_for_loop_emits_synthetic_assign() {
        let (tree, src) = build("for item in items:\n    x = item\n");
        let cfg = build_cfg(&tree, &src);
        let loop_id = cfg
            .nodes
            .iter()
            .find(|(_, n)| n.kind == NodeKind::Loop)
            .map(|(id, _)| *id)
            .unwrap();
        let ir = lower_node_to_ir(&cfg, loop_id, &src);
        assert_eq!(ir.len(), 1);
        match &ir[0] {
            IrStmt::Assign { lhs, rhs, .. } => {
                assert_eq!(*lhs, Lhs::VarLhs("item".to_string()));
                assert_eq!(*rhs, Rhs::VarRef("items".to_string()));
            }
            _ => panic!("attendu Assign(item := items)"),
        }
    }

    #[test]
    fn test_lower_node_to_ir_entry_exit_empty() {
        let (tree, src) = build("x = 1\n");
        let cfg = build_cfg(&tree, &src);
        assert!(lower_node_to_ir(&cfg, cfg.entry, &src).is_empty());
        assert!(lower_node_to_ir(&cfg, cfg.exit, &src).is_empty());
    }

    #[test]
    fn test_dead_edges_condition_always_true_kills_false_edge() {
        let (tree, src) = build("if 7 * 42 > 200:\n    a()\nelse:\n    b()\n");
        let cfg = build_cfg(&tree, &src);
        let mut node_ir = lower_all_nodes(&cfg, &src);
        let dead = compute_dead_edges(&cfg, &mut node_ir, &src);

        let branch_id = cfg
            .nodes
            .iter()
            .find(|(_, n)| n.kind == NodeKind::Branch)
            .map(|(id, _)| *id)
            .unwrap();
        let false_edge = cfg
            .successors(branch_id)
            .into_iter()
            .find(|e| e.label == EdgeLabel::False)
            .unwrap();
        let true_edge = cfg
            .successors(branch_id)
            .into_iter()
            .find(|e| e.label == EdgeLabel::True)
            .unwrap();
        assert!(dead.contains(&(branch_id, false_edge.dst)));
        assert!(!dead.contains(&(branch_id, true_edge.dst)));
    }

    #[test]
    fn test_dead_edges_condition_always_false_kills_true_edge() {
        let (tree, src) = build("if 1 > 200:\n    a()\nelse:\n    b()\n");
        let cfg = build_cfg(&tree, &src);
        let mut node_ir = lower_all_nodes(&cfg, &src);
        let dead = compute_dead_edges(&cfg, &mut node_ir, &src);

        let branch_id = cfg
            .nodes
            .iter()
            .find(|(_, n)| n.kind == NodeKind::Branch)
            .map(|(id, _)| *id)
            .unwrap();
        let true_edge = cfg
            .successors(branch_id)
            .into_iter()
            .find(|e| e.label == EdgeLabel::True)
            .unwrap();
        assert!(dead.contains(&(branch_id, true_edge.dst)));
    }

    #[test]
    fn test_dead_edges_unknown_condition_none_dead() {
        let (tree, src) = build("if param:\n    a()\nelse:\n    b()\n");
        let cfg = build_cfg(&tree, &src);
        let mut node_ir = lower_all_nodes(&cfg, &src);
        let dead = compute_dead_edges(&cfg, &mut node_ir, &src);
        assert!(dead.is_empty());
    }

    #[test]
    fn test_dead_edges_propagates_through_basic_block() {
        // x = 5 in a Basic block before the Branch -> x > 3 known true
        // by the time it reaches the Branch (const_in propagated from
        // the previous Basic block's const_out).
        let (tree, src) = build("x = 5\nif x > 3:\n    a()\nelse:\n    b()\n");
        let cfg = build_cfg(&tree, &src);
        let mut node_ir = lower_all_nodes(&cfg, &src);
        let dead = compute_dead_edges(&cfg, &mut node_ir, &src);

        let branch_id = cfg
            .nodes
            .iter()
            .find(|(_, n)| n.kind == NodeKind::Branch)
            .map(|(id, _)| *id)
            .unwrap();
        let false_edge = cfg
            .successors(branch_id)
            .into_iter()
            .find(|e| e.label == EdgeLabel::False)
            .unwrap();
        assert!(dead.contains(&(branch_id, false_edge.dst)));
    }

    #[test]
    fn test_dead_edges_loop_condition_never_cut() {
        // Even if the loop condition is always syntactically true, a
        // LOOP is never cut (over-caution, the condition can change
        // between runtime iterations).
        let (tree, src) = build("while 1 < 2:\n    x = 1\n");
        let cfg = build_cfg(&tree, &src);
        let mut node_ir = lower_all_nodes(&cfg, &src);
        let dead = compute_dead_edges(&cfg, &mut node_ir, &src);
        // No edge originating from a LOOP node must be marked dead.
        for &(src_id, _) in &dead {
            assert_ne!(cfg.nodes[&src_id].kind, NodeKind::Loop);
        }
    }

    #[test]
    fn test_dead_edges_terminates_on_while_true_loop() {
        // Anti-infinite-loop guard: the fixpoint must terminate even
        // on a loop whose condition remains always known-true.
        let (tree, src) = build("while True:\n    x = 1\n    y = x\n");
        let cfg = build_cfg(&tree, &src);
        let mut node_ir = lower_all_nodes(&cfg, &src);
        // Must not loop indefinitely (the test itself times out otherwise).
        let _dead = compute_dead_edges(&cfg, &mut node_ir, &src);
    }

    #[test]
    fn test_simplify_and_apply_stmts_tracks_assign() {
        let stmts = vec![IrStmt::Assign {
            lhs: Lhs::VarLhs("x".to_string()),
            rhs: Rhs::Const(ConstValue::Int(42)),
            lineno: 1,
        }];
        let (new_stmts, cs) = simplify_and_apply_stmts(&stmts, &empty_const_state());
        assert_eq!(new_stmts.len(), 1);
        assert_eq!(
            cs.get("x"),
            Some(&super::super::const_eval::EvalConst::Const(
                ConstValue::Int(42)
            ))
        );
    }

    #[test]
    fn test_lower_all_nodes_covers_every_node() {
        let (tree, src) = build("if a:\n    x = 1\nelse:\n    x = 2\n");
        let cfg = build_cfg(&tree, &src);
        let node_ir = lower_all_nodes(&cfg, &src);
        assert_eq!(node_ir.len(), cfg.nodes.len());
    }

    // ------------------------------------------------------------------
    // §6 — analyze(): main taint fixpoint
    // ------------------------------------------------------------------

    fn specs_with(sources: Vec<SourceSpec>, sinks: Vec<SinkSpec>) -> RuleSpecs {
        RuleSpecs {
            rule_id: "test-rule".to_string(),
            severity: "HIGH".to_string(),
            cwe: None,
            message: "test finding".to_string(),
            sources,
            sinks,
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
        }
    }

    #[test]
    fn test_analyze_simple_source_to_sink_flow() {
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let result = analyze_module_source("x = input()\nos.system(x)\n", &specs);
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn test_analyze_no_finding_when_source_absent() {
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let result = analyze_module_source("x = 'safe'\nos.system(x)\n", &specs);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_analyze_no_finding_when_sanitized() {
        let mut specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        specs.sanitizers.push(SanitizerSpec::new("shlex.quote"));
        let result =
            analyze_module_source("x = input()\ny = shlex.quote(x)\nos.system(y)\n", &specs);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_analyze_branch_merge_propagates_taint() {
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let src = "if cond:\n    x = input()\nelse:\n    x = 'safe'\nos.system(x)\n";
        let result = analyze_module_source(src, &specs);
        assert_eq!(
            result.findings.len(),
            1,
            "state_join doit propager la taint depuis la branche if"
        );
    }

    #[test]
    fn test_analyze_dead_branch_never_visited() {
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let src = "if 1 > 200:\n    os.system(input())\n";
        let result = analyze_module_source(src, &specs);
        assert!(
            result.findings.is_empty(),
            "la branche toujours-fausse ne doit jamais être visitée"
        );
    }

    #[test]
    fn test_analyze_loop_terminates_and_dedups_repeated_finding() {
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let src = "x = input()\nwhile cond:\n    os.system(x)\n    x = x\n";
        let result = analyze_module_source(src, &specs);
        assert_eq!(
            result.findings.len(),
            1,
            "même finding ré-émis à chaque passe du point fixe -> dédupliqué à 1"
        );
        assert!(
            result.iterations < 1000,
            "doit converger rapidement, pas boucler jusqu'à MAX_WORKLIST_ITER"
        );
    }

    #[test]
    fn test_analyze_direct_with_initial_state_propagates_taint() {
        let specs = specs_with(vec![], vec![SinkSpec::new("os.system")]);
        let (tree, src) = build("os.system(x)\n");
        let cfg = build_cfg(&tree, &src);
        let mut initial = empty_state();
        initial = state_set(
            &initial,
            "x",
            Taint::tainted(
                ["cli".to_string()],
                SourceInfo {
                    line: 0,
                    expr: "param x".to_string(),
                    kind: "cli".to_string(),
                },
            ),
        );
        let result = analyze(&cfg, &src, &specs, Some(&initial), None);
        assert_eq!(
            result.findings.len(),
            1,
            "un état initial tainté (paramètre de fonction) doit se propager"
        );
    }

    #[test]
    fn test_analyze_state_in_out_populated_for_every_node() {
        let specs = specs_with(vec![], vec![]);
        let (tree, src) = build("x = 1\ny = 2\n");
        let cfg = build_cfg(&tree, &src);
        let result = analyze(&cfg, &src, &specs, None, None);
        assert_eq!(result.state_in.len(), cfg.nodes.len());
        assert_eq!(result.state_out.len(), cfg.nodes.len());
    }

    // ------------------------------------------------------------------
    // analyze_java() — same fixpoint, Java lowering (verifies the
    // generic wiring end-to-end, cf. `analyze_generic`).
    // ------------------------------------------------------------------

    fn parse_java(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn find_first<'t>(node: tree_sitter::Node<'t>, kind: &str) -> Option<tree_sitter::Node<'t>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut w = node.walk();
        for child in node.children(&mut w) {
            if let Some(found) = find_first(child, kind) {
                return Some(found);
            }
        }
        None
    }

    fn build_java(method_body_src: &str) -> (tree_sitter::Tree, String) {
        let src = format!("class Foo {{ void t() {{ {method_body_src} }} }}");
        let tree = parse_java(&src);
        assert!(!tree.root_node().has_error());
        (tree, src)
    }

    #[test]
    fn test_analyze_java_simple_source_to_sink_flow() {
        let specs = specs_with(
            vec![SourceSpec::new("request.getParameter", "http")],
            vec![SinkSpec::new("logger.leak")],
        );
        let (tree, src) = build_java("String x = request.getParameter(\"cmd\"); logger.leak(x);");
        let method = find_first(tree.root_node(), "method_declaration").unwrap();
        let body = method.child_by_field_name("body").unwrap();
        let cfg = super::super::java_cfg::build_java_cfg(body, src.as_bytes());
        let result = analyze_java(&cfg, src.as_bytes(), &specs, None, None);
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn test_analyze_java_no_finding_when_source_absent() {
        let specs = specs_with(
            vec![SourceSpec::new("request.getParameter", "http")],
            vec![SinkSpec::new("logger.leak")],
        );
        let (tree, src) = build_java("String x = \"safe\"; logger.leak(x);");
        let method = find_first(tree.root_node(), "method_declaration").unwrap();
        let body = method.child_by_field_name("body").unwrap();
        let cfg = super::super::java_cfg::build_java_cfg(body, src.as_bytes());
        let result = analyze_java(&cfg, src.as_bytes(), &specs, None, None);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_analyze_java_branch_merge_propagates_taint() {
        let specs = specs_with(
            vec![SourceSpec::new("request.getParameter", "http")],
            vec![SinkSpec::new("logger.leak")],
        );
        let (tree, src) = build_java(
            "String x; if (cond) { x = request.getParameter(\"cmd\"); } else { x = request.getParameter(\"cmd\"); } logger.leak(x);",
        );
        let method = find_first(tree.root_node(), "method_declaration").unwrap();
        let body = method.child_by_field_name("body").unwrap();
        let cfg = super::super::java_cfg::build_java_cfg(body, src.as_bytes());
        let result = analyze_java(&cfg, src.as_bytes(), &specs, None, None);
        assert_eq!(result.findings.len(), 1);
    }

    // ------------------------------------------------------------------
    // analyze_csharp() — same fixpoint, C# lowering (ticket #79) —
    // verifies the generic wiring end-to-end, mirroring the 3
    // analyze_java() tests above.
    // ------------------------------------------------------------------

    fn parse_csharp(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_c_sharp::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn build_csharp(method_body_src: &str) -> (tree_sitter::Tree, String) {
        let src = format!("class Foo {{ void t() {{ {method_body_src} }} }}");
        let tree = parse_csharp(&src);
        assert!(!tree.root_node().has_error());
        (tree, src)
    }

    // CALL-shaped source (`Request.GetParameter("cmd")`), not an
    // indexer (`Request.QueryString["cmd"]`, the real shape of the 18
    // C# taint rules from ticket #80) — deliberately, to test here the
    // generic `analyze_generic`/`eval_rhs` wiring the same way as
    // `test_analyze_java_*` above (source_lines=None, pure structural
    // matching). An indexer source with a literal key (`SubscriptRef`
    // with `key: Const`) is NOT recognized by `eval_rhs`'s structural
    // path (it never re-evaluates `base` in that case, cf.
    // `transfer.rs::eval_rhs::Rhs::SubscriptRef`) — caught in a real
    // scan by the §10bis textual fallback
    // (`aux_match_line`/`arg_regex_source`, active whenever
    // `source_lines` is `Some`, ALWAYS the case in the real
    // `orchestrator.rs` pipeline). Exercised and verified at that
    // realistic level by `csharp_taint_scan.rs` (ticket #79) and the
    // ticket #80 end-to-end tests, not here.
    #[test]
    fn test_analyze_csharp_simple_source_to_sink_flow() {
        let specs = specs_with(
            vec![SourceSpec::new("Request.GetParameter", "http")],
            vec![SinkSpec::new("Logger.Leak")],
        );
        let (tree, src) = build_csharp("string x = Request.GetParameter(\"cmd\"); Logger.Leak(x);");
        let method = find_first(tree.root_node(), "method_declaration").unwrap();
        let body = method.child_by_field_name("body").unwrap();
        let cfg = super::super::csharp_cfg::build_csharp_cfg(body, src.as_bytes());
        let result = analyze_csharp(&cfg, src.as_bytes(), &specs, None, None);
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn test_analyze_csharp_no_finding_when_source_absent() {
        let specs = specs_with(
            vec![SourceSpec::new("Request.QueryString", "http")],
            vec![SinkSpec::new("Logger.Leak")],
        );
        let (tree, src) = build_csharp("string x = \"safe\"; Logger.Leak(x);");
        let method = find_first(tree.root_node(), "method_declaration").unwrap();
        let body = method.child_by_field_name("body").unwrap();
        let cfg = super::super::csharp_cfg::build_csharp_cfg(body, src.as_bytes());
        let result = analyze_csharp(&cfg, src.as_bytes(), &specs, None, None);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_analyze_csharp_branch_merge_propagates_taint() {
        let specs = specs_with(
            vec![SourceSpec::new("Request.GetParameter", "http")],
            vec![SinkSpec::new("Logger.Leak")],
        );
        let (tree, src) = build_csharp(
            "string x; if (cond) { x = Request.GetParameter(\"cmd\"); } else { x = Request.GetParameter(\"cmd\"); } Logger.Leak(x);",
        );
        let method = find_first(tree.root_node(), "method_declaration").unwrap();
        let body = method.child_by_field_name("body").unwrap();
        let cfg = super::super::csharp_cfg::build_csharp_cfg(body, src.as_bytes());
        let result = analyze_csharp(&cfg, src.as_bytes(), &specs, None, None);
        assert_eq!(result.findings.len(), 1);
    }
}
