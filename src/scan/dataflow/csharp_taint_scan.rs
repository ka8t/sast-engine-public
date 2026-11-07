//! Single-file taint scan for C# — mirrors
//! `java_taint_scan.rs`, a faithful port of the central flow of
//! `Audit/sca/executors/dataflow_taint_csharp.py::run_taint_rule_csharp`
//! (one CFG per method/constructor — C# has no executable statement
//! outside a method body).
//!
//! **Scope of this component**: single file only, `specs.summaries`/
//! `specs.type_map` supplied by the caller — same split as
//! `java_taint_scan.rs`: this module does NOT build the summaries
//! itself (wiring left to a future `csharp_call_graph.rs`,
//! explicitly out of scope for ticket #79/spec #77).
//!
//! **Difference from `java_taint_scan.rs`**: no seeding of
//! ASP.NET Core route parameters (the Java/Spring equivalent of
//! `route_param_names`) — explicitly out of scope for ticket #77 (the
//! Juliet Test Suite C# 1.3, the calibration target for ticket #81,
//! does not use ASP.NET Core, and Python itself never built this
//! detection on the C# side). `initial_state` is therefore always `None`
//! here, unlike `run_taint_rule_java`.
#![allow(dead_code)]

use tree_sitter::Node;

use super::csharp_cfg::build_csharp_cfg;
use super::csharp_summary::collect_csharp_functions;
use super::transfer::{Finding, RuleSpecs};
use super::worklist::analyze_csharp;

/// Runs a taint rule on an already-parsed C# file.
///
/// Each method/constructor is analyzed as an independent CFG.
/// Final global deduplication by `(rule_id, line, source_line)`.
pub fn run_taint_rule_csharp<'tree>(
    root: Node<'tree>,
    source: &'tree [u8],
    specs: &RuleSpecs,
    source_lines: Option<&[String]>,
) -> Vec<Finding> {
    let mut all_findings: Vec<Finding> = Vec::new();

    for fn_info in collect_csharp_functions(root, source) {
        let cfg = build_csharp_cfg(fn_info.body_node, source);
        let result = analyze_csharp(&cfg, source, specs, None, source_lines);
        all_findings.extend(result.findings);
    }

    let mut seen: std::collections::HashSet<(String, usize, Option<usize>)> =
        std::collections::HashSet::new();
    all_findings.retain(|f| seen.insert((f.rule_id.clone(), f.line, f.source_line)));
    all_findings
}

// ============================================================================
// Tests — mirrors the structural behavior cases of
// `java_taint_scan.rs::tests` (constant folding, interprocedural
// resolution via supplied summaries, nested class), excluding
// the Spring route parameter machinery (out of scope for C#, see the
// module doc).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::{FunctionSummary, SanitizerSpec, SinkSpec, SourceSpec};
    use std::collections::BTreeMap;
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
            rule_id: "taint_sqli".to_string(),
            severity: "HIGH".to_string(),
            cwe: Some("CWE-89".to_string()),
            message: "test finding".to_string(),
            sources: vec![SourceSpec::new("Request.GetParameter", "http")],
            sinks: vec![SinkSpec::new("*.Execute")],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
        }
    }

    fn run(src: &str, specs: &RuleSpecs) -> Vec<Finding> {
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        run_taint_rule_csharp(tree.root_node(), src.as_bytes(), specs, Some(&lines))
    }

    // ------------------------------------------------------------------
    // Basic: simple flow, clean, without a source
    // ------------------------------------------------------------------

    #[test]
    fn test_source_to_sink_detected() {
        let src = "class Api { void Handler(object db) { string q = Request.GetParameter(\"q\"); db.Execute(q); } }";
        let findings = run(src, &sqli_specs());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "taint_sqli");
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
    }

    /// Ticket #123: source and sink inside an expression-bodied method
    /// (`=> expr`) — was silently skipped (the bare expression lowered to
    /// a `Noop`) and tripped the CFG builder's `debug_assert`.
    #[test]
    fn test_expression_bodied_method_source_to_sink_detected() {
        let src =
            "class Api { void Handler(object db) => db.Execute(Request.GetParameter(\"q\")); }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    /// Ticket #123: the tainted value flows out of an expression-bodied
    /// helper into a sink of another method of the same file.
    #[test]
    fn test_expression_bodied_helper_return_reaches_sink() {
        let src = "class Api { string Input() => Request.GetParameter(\"q\"); void Handler(object db) { db.Execute(Input()); } }";
        let tree = parse(src);
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let mut specs = sqli_specs();
        specs.summaries = crate::scan::dataflow::csharp_summary::compute_csharp_file_summaries(
            tree.root_node(),
            &specs,
            src.as_bytes(),
            Some(&lines),
        );
        assert_eq!(
            run_taint_rule_csharp(tree.root_node(), src.as_bytes(), &specs, Some(&lines)).len(),
            1
        );
    }

    #[test]
    fn test_expression_bodied_clean_method_no_finding() {
        let src = "class Api { void Handler(object db) => db.Execute(\"SELECT 1\"); int Twice(int a) => a * 2; }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_clean_no_finding() {
        let src = "class Api { void Handler(object db) { db.Execute(\"SELECT 1\"); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_no_source_no_finding() {
        let src = "class Api { void Handler(string q, object db) { db.Execute(q); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_sanitized_no_finding() {
        let src = "class Api { void Handler(object db) { string q = Sanitize(Request.GetParameter(\"q\")); db.Execute(q); } }";
        let mut specs = sqli_specs();
        specs.sanitizers.push(SanitizerSpec::new("Sanitize"));
        assert!(run(src, &specs).is_empty());
    }

    #[test]
    fn test_flow_trace_present() {
        let src = "class Api { void Handler(object db) { string q = Request.GetParameter(\"q\"); db.Execute(q); } }";
        let findings = run(src, &sqli_specs());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].flow.len() >= 2);
        assert_eq!(findings[0].flow[0].kind, "source");
        assert_eq!(findings[0].flow[findings[0].flow.len() - 1].kind, "sink");
    }

    #[test]
    fn test_multiple_methods_isolated() {
        let src = "class Api { void Clean(object db) { db.Execute(\"SELECT 1\"); } void Vuln(object db) { string q = Request.GetParameter(\"q\"); db.Execute(q); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    // ------------------------------------------------------------------
    // Constant folding (branches + switch) — same generic engine as
    // Java, exercised here via the C# front-end.
    // ------------------------------------------------------------------

    #[test]
    fn test_constant_condition_eliminates_dead_branch() {
        let src = "class Api { void Handler(object db) { string param = Request.GetParameter(\"q\"); string bar; int num = 86; if ((7 * 42) - num > 200) { bar = \"always_this_branch\"; } else { bar = param; } db.Execute(bar); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_constant_condition_still_detects_when_reachable() {
        let src = "class Api { void Handler(object db) { string param = Request.GetParameter(\"q\"); string bar; int num = 86; if ((7 * 42) - num > 200) { bar = param; } else { bar = \"never_this_branch\"; } db.Execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_switch_const_eliminates_dead_case() {
        let src = "class Api { void Handler(object db) { string param = Request.GetParameter(\"q\"); string bar; int flag = 1; switch (flag) { case 0: bar = param; break; case 1: bar = \"safe\"; break; default: bar = \"safe2\"; break; } db.Execute(bar); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_switch_const_still_detects_active_case() {
        let src = "class Api { void Handler(object db) { string param = Request.GetParameter(\"q\"); string bar; int flag = 1; switch (flag) { case 0: bar = \"safe\"; break; case 1: bar = param; break; default: bar = \"safe2\"; break; } db.Execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    // ------------------------------------------------------------------
    // Interprocedural resolution (summaries already supplied) — the
    // actual wiring of summaries is the role of a future
    // `csharp_call_graph.rs` (out of scope for #79); here we just verify
    // that `analyze_csharp` correctly consults `specs.summaries`/
    // `specs.type_map` once supplied, same contract as
    // `java_taint_scan.rs`.
    // ------------------------------------------------------------------

    #[test]
    fn test_cross_method_summary_via_precomputed() {
        let src = "class Api { void RunQuery(string query, object db) { db.Execute(query); } void Handler(object db) { string q = Request.GetParameter(\"q\"); RunQuery(q, db); } }";
        let mut specs = sqli_specs();
        let mut summary = FunctionSummary {
            name: "Api.RunQuery".to_string(),
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
            .insert("RunQuery".to_string(), summary.into());
        assert!(!run(src, &specs).is_empty());
    }

    #[test]
    fn test_extra_summaries_via_typed_local_variable() {
        let src = "class Api { void Handler(object db) { string q = Request.GetParameter(\"q\"); QueryRunner qr = new QueryRunner(); qr.RunQuery(q, db); } }";
        let mut specs = sqli_specs();
        specs
            .type_map
            .insert("qr".to_string(), "QueryRunner".to_string());
        let mut summary = FunctionSummary {
            name: "QueryRunner.RunQuery".to_string(),
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
            .insert("QueryRunner.RunQuery".to_string(), summary.into());
        assert!(!run(src, &specs).is_empty());
    }

    #[test]
    fn test_typed_local_variable_no_summary_stays_conservative() {
        let src = "class Api { void Handler(object db) { QueryRunner qr = new QueryRunner(); qr.DoSomethingUnrelated(); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    // ------------------------------------------------------------------
    // Nested class + chained constructor call
    // ------------------------------------------------------------------

    // No equivalent, for ticket #79/#80, of the chained constructor
    // call resolution in `java_lowering.rs::lower_method_invocation`
    // (`new Test().DoSomething(q)` → `AttrRef{base: CallRef{...} inlined,
    // attr}`, which lets `eval_call` recover "Test" via
    // `callee.base.callee`): `csharp_to_ir.py` (the Python reference)
    // does NOT have this optimization — the C#'s `_lower_expr` goes
    // through the generic `object_creation_expression` path, which emits
    // an Assign+temporary (`__t0 := CallRef{...}`) before the `AttrRef`,
    // so `callee.base` is an opaque `VarRef`, never an inspectable
    // `CallRef`.
    // Deliberately PORTED AS-IS deviation (not a Rust regression) — no
    // C# taint `.sca` from tickets #80/#81, nor the Juliet Test Suite
    // C# 1.3, exercises this exact pattern so far; to be reevaluated
    // only if a future corpus justifies it, consistent with ADR-0023
    // (mirroring Python, not reinventing it). Direct consequence,
    // verified right below: the call stays unresolved and therefore
    // ALWAYS conservative (a finding is emitted even when a "safe"
    // summary is supplied for `Test.DoSomething` — never consulted).

    #[test]
    fn test_nested_class_passthrough_still_detected() {
        let src = "class Api { void Handler(object db) { string q = Request.GetParameter(\"q\"); string bar = new Test().DoSomething(q); db.Execute(bar); } private class Test { string DoSomething(string param) { return param; } } }";
        assert!(!run(src, &sqli_specs()).is_empty());
    }

    // ------------------------------------------------------------------
    // No ASP.NET Core seeding (accepted deviation from Java) —
    // an unannotated parameter is NEVER tainted at entry, regardless of
    // its name or the presence of attributes on the method, see the
    // module doc.
    // ------------------------------------------------------------------

    #[test]
    fn test_no_route_param_seeding_even_with_attribute() {
        let src = "class Api { [HttpGet] void Handler(string q, object db) { db.Execute(q); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }
}
