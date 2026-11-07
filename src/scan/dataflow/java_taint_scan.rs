//! Taint scan for a single Java file — faithful port of the
//! central flow of `Audit/sca/executors/dataflow_taint_java.py::
//! run_taint_rule_java` (one CFG per method/constructor — Java has
//! no executable statement outside a method body, unlike
//! Python which has an extra "module level" pass).
//!
//! **Scope of this module**: a single file, `specs.summaries`/
//! `specs.type_map` supplied by the caller — same split as
//! `taint_scan.rs` (Python): this module does NOT itself build the
//! summaries (role of `java_call_graph::JavaCallGraph::resolve_summaries`,
//! wiring left to the orchestrator), unlike
//! `dataflow_taint_java.py::run_taint_rule_java` which computes them
//! internally (`compute_java_file_summaries`/`extra_summaries`) — a split
//! already established on the Rust side for Python (`orchestrator.rs` does this work
//! once per batch of files, not per rule call).
#![allow(dead_code)]

use tree_sitter::Node;

use super::java_cfg::build_java_cfg;
use super::java_summary::collect_java_functions;
use super::lattice::{SourceInfo, Taint, empty_state, state_set};
use super::transfer::{Finding, RuleSpecs};
use super::worklist::analyze_java;

/// Runs a taint rule on an already-parsed Java file.
///
/// Each method/constructor is analyzed as an independent CFG.
/// A Spring route parameter (`@RequestParam`/... or implicit on
/// a mapped handler `@GetMapping`/...) has its entry state seeded
/// tainted `http` — Java equivalent of `route_source_params`
/// (`taint_scan.rs`, Python), computed once by
/// `java_summary::collect_java_functions` (`JavaFunctionInfo::
/// route_param_names`). Final global deduplication by
/// `(rule_id, line, source_line)`.
pub fn run_taint_rule_java<'tree>(
    root: Node<'tree>,
    source: &'tree [u8],
    specs: &RuleSpecs,
    source_lines: Option<&[String]>,
) -> Vec<Finding> {
    let mut all_findings: Vec<Finding> = Vec::new();

    for fn_info in collect_java_functions(root, source) {
        let cfg = build_java_cfg(fn_info.body_node, source);

        let init_state = if fn_info.route_param_names.is_empty() {
            None
        } else {
            let mut state = empty_state();
            for pname in &fn_info.route_param_names {
                state = state_set(
                    &state,
                    pname,
                    Taint::tainted(
                        ["http".to_string()],
                        SourceInfo {
                            line: fn_info.lineno,
                            expr: format!("{}({pname})", fn_info.name),
                            kind: "http".to_string(),
                        },
                    ),
                );
            }
            Some(state)
        };

        let result = analyze_java(&cfg, source, specs, init_state.as_ref(), source_lines);
        all_findings.extend(result.findings);
    }

    let mut seen: std::collections::HashSet<(String, usize, Option<usize>)> =
        std::collections::HashSet::new();
    all_findings.retain(|f| seen.insert((f.rule_id.clone(), f.line, f.source_line)));
    all_findings
}

// ============================================================================
// Tests — mirror the behavior cases (not rule_json/mode, covered
// elsewhere by `dispatch.rs`) of
// `Audit/tests/dataflow/test_dataflow_taint_java_executor.py`: constant
// folding (branches + switch), list simulation, interprocedural
// (summaries supplied + type_map), chained constructor call, Map put/get,
// explicit/implicit Spring route parameters — the requested quality bar
// (parity with or better than the Python engine) is about THIS
// behavior, not the rule_json/dispatch layer.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::{FunctionSummary, SanitizerSpec, SinkSpec, SourceSpec};
    use std::collections::BTreeMap;
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
            rule_id: "taint_sqli".to_string(),
            severity: "HIGH".to_string(),
            cwe: Some("CWE-89".to_string()),
            message: "test finding".to_string(),
            sources: vec![SourceSpec::new("*.getParameter", "http")],
            sinks: vec![SinkSpec::new("*.execute")],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
        }
    }

    fn run(src: &str, specs: &RuleSpecs) -> Vec<Finding> {
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        run_taint_rule_java(tree.root_node(), src.as_bytes(), specs, Some(&lines))
    }

    // ------------------------------------------------------------------
    // Basic: simple flow, clean, no source
    // ------------------------------------------------------------------

    #[test]
    fn test_source_to_sink_detected() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); db.execute(q); } }";
        let findings = run(src, &sqli_specs());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "taint_sqli");
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
    }

    #[test]
    fn test_clean_no_finding() {
        let src = "class Api { void handler(Statement db) { db.execute(\"SELECT 1\"); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_no_source_no_finding() {
        let src = "class Api { void handler(String q, Statement db) { db.execute(q); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_sanitized_no_finding() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = sanitize(req.getParameter(\"q\")); db.execute(q); } }";
        let mut specs = sqli_specs();
        specs.sanitizers.push(SanitizerSpec::new("sanitize"));
        assert!(run(src, &specs).is_empty());
    }

    #[test]
    fn test_flow_trace_present() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); db.execute(q); } }";
        let findings = run(src, &sqli_specs());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].flow.len() >= 2);
        assert_eq!(findings[0].flow[0].kind, "source");
        assert_eq!(findings[0].flow[findings[0].flow.len() - 1].kind, "sink");
    }

    #[test]
    fn test_multiple_methods_isolated() {
        let src = "class Api { void clean(Statement db) { db.execute(\"SELECT 1\"); } void vuln(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); db.execute(q); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    // ------------------------------------------------------------------
    // Constant folding (branches + switch) — OWASP BenchmarkJava calibration
    // ------------------------------------------------------------------

    #[test]
    fn test_arithmetic_constant_condition_eliminates_dead_branch() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; int num = 86; if ((7 * 42) - num > 200) { bar = \"always_this_branch\"; } else { bar = param; } db.execute(bar); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_constant_condition_still_detects_when_reachable() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; int num = 86; if ((7 * 42) - num > 200) { bar = param; } else { bar = \"never_this_branch\"; } db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_non_constant_condition_still_conservative() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; if (req.getHeader(\"x-flag\") != null) { bar = param; } else { bar = \"safe\"; } db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_switch_charat_const_eliminates_dead_case() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; String guess = \"ABC\"; char switchTarget = guess.charAt(1); switch (switchTarget) { case 'A': bar = param; break; case 'B': bar = \"bob\"; break; default: bar = \"bobs_uncle\"; break; } db.execute(bar); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_switch_charat_const_still_detects_active_case() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; String guess = \"ABC\"; char switchTarget = guess.charAt(1); switch (switchTarget) { case 'A': bar = \"safe\"; break; case 'B': bar = param; break; default: bar = \"bobs_uncle\"; break; } db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_switch_on_non_constant_stays_conservative() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; char switchTarget = req.getHeader(\"x-flag\").charAt(0); switch (switchTarget) { case 'A': bar = param; break; default: bar = \"safe\"; break; } db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    // ------------------------------------------------------------------
    // Positional list simulation
    // ------------------------------------------------------------------

    #[test]
    fn test_list_shuffle_pattern_resolves_clean() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar = \"alsosafe\"; if (param != null) { java.util.List<String> valuesList = new java.util.ArrayList<String>(); valuesList.add(\"safe\"); valuesList.add(param); valuesList.add(\"moresafe\"); valuesList.remove(0); bar = valuesList.get(1); } db.execute(bar); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_list_get_at_tainted_index_still_detected() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); java.util.List<String> valuesList = new java.util.ArrayList<String>(); valuesList.add(\"safe\"); valuesList.add(param); String bar = valuesList.get(1); db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_list_with_dynamic_content_stays_conservative() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); java.util.List<String> valuesList = new java.util.ArrayList<String>(); valuesList.add(param); String bar = valuesList.get(0); db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    // ------------------------------------------------------------------
    // Interprocedural resolution (summaries already supplied) — the
    // actual wiring of summaries is the role of the orchestrator/
    // `JavaCallGraph`, not of this module; here we just verify that
    // `analyze_java` correctly consults `specs.summaries`/
    // `specs.type_map` once supplied (same contract as the Python
    // test `extra_summaries`).
    // ------------------------------------------------------------------

    #[test]
    fn test_cross_method_summary_via_precomputed() {
        // The actual computation/wiring of intra-file summaries is the role
        // of the orchestrator (via `JavaCallGraph::resolve_summaries`,
        // already tested in `java_call_graph.rs`) — here we directly
        // supply the summary under its bare alias ("runQuery", added
        // by `add_bare_name_aliases` for an unqualified intra-class
        // call) and verify that `analyze_java` consults it
        // correctly.
        let src = "class Api { void runQuery(String query, Statement db) { db.execute(query); } void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); runQuery(q, db); } }";
        let mut specs = sqli_specs();
        let mut summary = FunctionSummary {
            name: "Api.runQuery".to_string(),
            param_names: vec!["query".to_string(), "db".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "taint_sqli".to_string(),
                severity: "HIGH".to_string(),
                line: 1,
                column: 0,
                sink_text: "sink".to_string(),
                source_line: None,
                message: String::new(),
                cwe: None,
                flow: vec![],
                source_kind: "unknown".to_string(),
            },
        );
        specs
            .summaries
            .insert("runQuery".to_string(), summary.into());
        assert!(!run(src, &specs).is_empty());
    }

    #[test]
    fn test_extra_summaries_cross_file_via_qualified_call() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); QueryRunner.runQuery(q, db); } }";
        let mut specs = sqli_specs();
        let mut summary = FunctionSummary {
            name: "QueryRunner.runQuery".to_string(),
            param_names: vec!["query".to_string(), "db".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "taint_sqli".to_string(),
                severity: "HIGH".to_string(),
                line: 1,
                column: 0,
                sink_text: "sink".to_string(),
                source_line: None,
                message: String::new(),
                cwe: None,
                flow: vec![],
                source_kind: "unknown".to_string(),
            },
        );
        specs
            .summaries
            .insert("QueryRunner.runQuery".to_string(), summary.into());
        assert!(!run(src, &specs).is_empty());
    }

    #[test]
    fn test_extra_summaries_via_typed_local_variable() {
        // Round 5 (calibration): `qr.runQuery(...)` where `qr` is a
        // typed LOCAL variable — requires RuleSpecs.type_map to
        // resolve to `QueryRunner.runQuery` despite the callee_name
        // "qr.runQuery".
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); QueryRunner qr = new QueryRunner(); qr.runQuery(q, db); } }";
        let mut specs = sqli_specs();
        specs
            .type_map
            .insert("qr".to_string(), "QueryRunner".to_string());
        let mut summary = FunctionSummary {
            name: "QueryRunner.runQuery".to_string(),
            param_names: vec!["query".to_string(), "db".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "taint_sqli".to_string(),
                severity: "HIGH".to_string(),
                line: 1,
                column: 0,
                sink_text: "sink".to_string(),
                source_line: None,
                message: String::new(),
                cwe: None,
                flow: vec![],
                source_kind: "unknown".to_string(),
            },
        );
        specs
            .summaries
            .insert("QueryRunner.runQuery".to_string(), summary.into());
        assert!(!run(src, &specs).is_empty());
    }

    #[test]
    fn test_typed_local_variable_no_summary_stays_conservative() {
        let src = "class Api { void handler(Statement db) { QueryRunner qr = new QueryRunner(); qr.doSomethingUnrelated(); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    // ------------------------------------------------------------------
    // Nested class + chained constructor call (round 6+7)
    // ------------------------------------------------------------------

    #[test]
    fn test_nested_class_constant_fold_suppresses_taint() {
        // The actual computation of the Test.doSomething summary (constant fold:
        // the return is always "always_this", never the parameter) is
        // the role of `compute_java_summary` (already tested in
        // `java_summary.rs`) — here we directly supply the already
        // computed summary (return_tainted_uncond=false, return_taint_params empty,
        // default values of `FunctionSummary`) and verify that
        // `eval_call` (Round 6, chained constructor call resolution)
        // does respect this narrowing rather than over-approximating.
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); String bar = new Test().doSomething(q); db.execute(bar); } private class Test { String doSomething(String param) { return \"always_this\"; } } }";
        let mut specs = sqli_specs();
        specs.summaries.insert(
            "Test.doSomething".to_string(),
            FunctionSummary {
                name: "Test.doSomething".to_string(),
                param_names: vec!["param".to_string()],
                ..Default::default()
            }
            .into(),
        );
        assert!(run(src, &specs).is_empty());
    }

    #[test]
    fn test_nested_class_passthrough_still_detected() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); String bar = new Test().doSomething(q); db.execute(bar); } private class Test { String doSomething(String param) { return param; } } }";
        assert!(!run(src, &sqli_specs()).is_empty());
    }

    // ------------------------------------------------------------------
    // Map put/get roundtrip (round 7)
    // ------------------------------------------------------------------

    #[test]
    fn test_map_put_get_roundtrip_propagates_taint() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>(); map.put(\"k\", q); String bar = (String) map.get(\"k\"); db.execute(bar); } }";
        assert!(!run(src, &sqli_specs()).is_empty());
    }

    // ------------------------------------------------------------------
    // Spring route parameters — explicit and implicit
    // ------------------------------------------------------------------

    #[test]
    fn test_request_param_seeded_reaches_sink() {
        let src =
            "class Api { void handler(@RequestParam String q, Statement db) { db.execute(q); } }";
        assert!(!run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_unannotated_param_not_seeded() {
        let src = "class Api { void handler(String q, Statement db) { db.execute(q); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_route_param_propagates_through_local_assignment() {
        let src = "class Api { void handler(@RequestParam String account, Statement db) { String q = \"SELECT * FROM t WHERE a = \" + account; db.execute(q); } }";
        assert!(!run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_container_type_param_not_seeded_even_if_annotated() {
        let src = "class Api { void handler(@RequestParam HttpServletRequest req, Statement db) { db.execute(req.toString()); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_unannotated_param_on_mapped_handler_reaches_sink() {
        let src = "class Api { @PostMapping(\"/x\") void handler(String query, Statement db) { db.execute(query); } }";
        assert!(!run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_unannotated_param_not_mapped_handler_no_finding() {
        let src = "class Api { void handler(String query, Statement db) { db.execute(query); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_container_type_not_seeded_even_on_mapped_handler() {
        let src = "class Api { @GetMapping(\"/x\") void handler(HttpServletRequest request, Statement db) { db.execute(request.toString()); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }
}
