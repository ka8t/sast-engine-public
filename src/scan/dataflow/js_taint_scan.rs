//! Taint scan for a single JavaScript file — direct template of
//! `java_taint_scan.rs` (one CFG per function — JS has no executable
//! statement outside a function body for what `js_summary::
//! collect_js_functions` collects, see its doc for the detail of what
//! is/isn't covered).
//!
//! **Scope of this component**: a single file, `specs.summaries`
//! supplied by the caller — since 08/30, the orchestrator actually
//! populates it via `js_call_graph.rs::JsCallGraph::resolve_summaries`
//! (multi-file interprocedural resolution) before calling this
//! function; this file's tests keep supplying it empty or precomputed
//! by hand, exactly as before — same split as
//! `taint_scan.rs`/`java_taint_scan.rs`.
//!
//! **Difference from Java**: no initial-state seed (`init_state`) —
//! Java seeds Spring route parameters (`@RequestParam`/..., or the
//! implicit binding of a mapped handler) right at method entry via
//! `JavaFunctionInfo::route_param_names`. JS v1 has no framework-aware
//! equivalent (implicit Express/Fastify binding, Phase 3 deferred) —
//! each function is analyzed with an empty entry state, taint only
//! comes from `source` rules explicitly matched in the function body
//! (e.g. `req.query.q`, `req.body.x`).

use tree_sitter::Node;

use super::js_cfg::build_js_cfg;
use super::js_summary::collect_js_functions;
use super::lattice::empty_state;
use super::transfer::{Finding, RuleSpecs};
use super::worklist::analyze_js;

/// Runs a taint rule on an already-parsed JS file.
///
/// Analyzes the file at **module top-level** (mirror of
/// `taint_scan.rs::run_taint_rule` on the Python side, wired in on
/// 08/30), THEN each function/method collected by `collect_js_functions`
/// as an independent CFG, with an empty entry state (see module doc).
/// **08/30 fix**: before this module-level pass, any JS code written
/// outside a function (simple scripts, top-level code of an unwrapped
/// configuration/route file) was invisible — found while validating the
/// engine against real code. No double counting with the functions:
/// `build_js_cfg(root, ...)` treats every `function_declaration` it encounters as an opaque
/// statement (see `js_cfg.rs` doc), without descending into its body.
/// Final global deduplication by `(rule_id, line, source_line)`.
pub fn run_taint_rule_js<'tree>(
    root: Node<'tree>,
    source: &'tree [u8],
    specs: &RuleSpecs,
    source_lines: Option<&[String]>,
) -> Vec<Finding> {
    let mut all_findings: Vec<Finding> = Vec::new();

    let module_cfg = build_js_cfg(root, source);
    let module_result = analyze_js(
        &module_cfg,
        source,
        specs,
        Some(&empty_state()),
        source_lines,
    );
    all_findings.extend(module_result.findings);

    for fn_info in collect_js_functions(root, source) {
        let cfg = build_js_cfg(fn_info.body_node, source);
        let result = analyze_js(&cfg, source, specs, Some(&empty_state()), source_lines);
        all_findings.extend(result.findings);
    }

    let mut seen: std::collections::HashSet<(String, usize, Option<usize>)> =
        std::collections::HashSet::new();
    all_findings.retain(|f| seen.insert((f.rule_id.clone(), f.line, f.source_line)));
    all_findings
}

// ============================================================================
// Tests — same categories of behavior as `java_taint_scan.rs`
// (constant folding, sanitizer, isolated multi-functions, precomputed
// summaries), adapted to JS syntax/common Express patterns.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::{FunctionSummary, SanitizerSpec, SinkSpec, SourceSpec};
    use std::collections::BTreeMap;
    use tree_sitter::Parser;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(src, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "syntaxe JS invalide : {src:?}"
        );
        tree
    }

    fn sqli_specs() -> RuleSpecs {
        RuleSpecs {
            rule_id: "taint_sqli_js".to_string(),
            severity: "HIGH".to_string(),
            cwe: Some("CWE-89".to_string()),
            message: "test finding".to_string(),
            sources: vec![SourceSpec::new("*.query.*", "http")],
            sinks: vec![SinkSpec::new("*.query")],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
        }
    }

    fn run(src: &str, specs: &RuleSpecs) -> Vec<Finding> {
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        run_taint_rule_js(tree.root_node(), src.as_bytes(), specs, Some(&lines))
    }

    #[test]
    fn test_source_to_sink_detected() {
        let src = "function handler(req, db) { const q = req.query.q; db.query(q); }";
        let findings = run(src, &sqli_specs());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "taint_sqli_js");
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
    }

    #[test]
    fn test_clean_no_finding() {
        let src = "function handler(db) { db.query('SELECT 1'); }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_no_source_no_finding() {
        let src = "function handler(q, db) { db.query(q); }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_sanitized_no_finding() {
        let src = "function handler(req, db) { const q = sanitize(req.query.q); db.query(q); }";
        let mut specs = sqli_specs();
        specs.sanitizers.push(SanitizerSpec::new("sanitize"));
        assert!(run(src, &specs).is_empty());
    }

    #[test]
    fn test_flow_trace_present() {
        let src = "function handler(req, db) { const q = req.query.q; db.query(q); }";
        let findings = run(src, &sqli_specs());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].flow.len() >= 2);
        assert_eq!(findings[0].flow[0].kind, "source");
        assert_eq!(findings[0].flow[findings[0].flow.len() - 1].kind, "sink");
    }

    #[test]
    fn test_multiple_functions_isolated() {
        let src = "function clean(db) { db.query('SELECT 1'); } function vuln(req, db) { const q = req.query.q; db.query(q); }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_express_style_arrow_callback_detected() {
        // Dominant Express pattern: an anonymous callback passed
        // directly to app.get() — see `js_summary.rs` doc (recursive
        // discovery).
        let src = "app.get('/x', (req, res) => { const q = req.query.q; db.query(q); });";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_template_string_interpolation_propagates_taint() {
        let src = "function handler(req, db) { const q = `SELECT * FROM t WHERE id=${req.query.q}`; db.query(q); }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_conditional_constant_folding() {
        let src = "function handler(req, db) { const p = req.query.q; let bar; if (1 > 2) { bar = p; } else { bar = 'safe'; } db.query(bar); }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_non_constant_condition_stays_conservative() {
        let src = "function handler(req, db) { const p = req.query.q; let bar; if (req.headers.x) { bar = p; } else { bar = 'safe'; } db.query(bar); }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_cross_function_summary_via_precomputed() {
        // Mirror of the equivalent Java test: the real wiring of
        // summaries (call graph) lives in
        // `js_call_graph.rs`/`orchestrator.rs` (wired in on 08/30,
        // tested there end to end) — here we only verify, at this
        // lower level, that `analyze_js` correctly consults
        // `specs.summaries` once supplied directly.
        let src = "function handler(req, db) { const q = req.query.q; runQuery(q, db); }";
        let mut specs = sqli_specs();
        specs.summaries.insert(
            "runQuery".to_string(),
            FunctionSummary {
                name: "runQuery".to_string(),
                param_names: vec!["query".to_string(), "db".to_string()],
                return_tainted_uncond: false,
                return_kind: None,
                return_taint_params: Default::default(),
                sink_param_findings: {
                    let mut m = BTreeMap::new();
                    m.insert(
                        0,
                        Finding {
                            rule_id: "taint_sqli_js".to_string(),
                            severity: "HIGH".to_string(),
                            line: 0,
                            column: 0,
                            sink_text: "db.query(query)".to_string(),
                            source_line: Some(0),
                            message: "test".to_string(),
                            cwe: Some("CWE-89".to_string()),
                            flow: vec![
                                crate::scan::dataflow::transfer::FlowStep {
                                    line: 0,
                                    kind: "source".to_string(),
                                    text: String::new(),
                                },
                                crate::scan::dataflow::transfer::FlowStep {
                                    line: 0,
                                    kind: "sink".to_string(),
                                    text: String::new(),
                                },
                            ],
                            source_kind: "http".to_string(),
                        },
                    );
                    m
                },
            }
            .into(),
        );
        assert_eq!(run(src, &specs).len(), 1);
    }

    #[test]
    fn test_dedup_same_rule_line_source_line() {
        let src = "function handler(req, db) { const q = req.query.q; db.query(q); }";
        let findings1 = run(src, &sqli_specs());
        let findings2 = run(src, &sqli_specs());
        assert_eq!(findings1.len(), findings2.len());
        assert_eq!(findings1.len(), 1);
    }
}
