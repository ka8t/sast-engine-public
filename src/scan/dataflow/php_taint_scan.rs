//! Taint scan for a single PHP file — direct template of
//! `js_taint_scan.rs` (one CFG per function/method/closure —
//! `php_summary::collect_php_functions`, see its doc for the details
//! of what is/is not covered, notably the total exclusion of arrow
//! functions).
//!
//! **Scope of this piece**: a single file, `specs.summaries` supplied
//! by the caller — since 08/30, the orchestrator actually populates
//! it via `php_call_graph.rs::PhpCallGraph::resolve_summaries`
//! (multi-file interprocedural resolution) before calling this
//! function; this file's tests still supply it empty or precomputed
//! by hand, exactly as before — same split as `js_taint_scan.rs`.
//!
//! **No initial-state seed** — PHP has no equivalent of Java's
//! implicit Spring binding; superglobals (`$_GET`/`$_POST`/
//! `$_REQUEST`/`$_COOKIE`) are ordinary variables detected via the
//! `source` rules of the `.sca` catalog (e.g. `\$_GET\s*\[`), not via
//! a separate seed mechanism.
//!
//! **Two calibration pitfalls found while writing the tests below,
//! specific to PHP, not to this module**:
//!   - `$_GET['q']` is a `SubscriptRef` (key access) — `eval_rhs`
//!     (`transfer.rs`) does NOT test `source` patterns against the
//!     base of a CONSTANT key access (§9.bis): only the hybrid
//!     raw-line matching (§10bis, `raw_regex`) detects this pattern.
//!     A real `.sca` rule loaded via `rule_loader::rule_json_to_specs`
//!     always populates `raw_regex` automatically — only
//!     `SourceSpec::new()` alone (low-level construction, unit tests)
//!     does not.
//!   - `resolve_spec` (`transfer.rs`) checks `sources` BEFORE
//!     `sinks`: an IDENTICAL glob pattern used for both (e.g.
//!     `*.query` for both a source and a sink) ALWAYS resolves the
//!     call as a source, never as a sink — the sink is silently
//!     masked. Found while calibrating this module (`*.query` reused
//!     by mistake for both `$request->query` and `$db->query(...)`),
//!     not an engine bug.

use tree_sitter::Node;

use super::lattice::empty_state;
use super::php_cfg::build_php_cfg;
use super::php_summary::collect_php_functions;
use super::transfer::{Finding, RuleSpecs};
use super::worklist::analyze_php;

/// Runs a taint rule on an already-parsed PHP file.
///
/// Analyzes the file at the **top-level module** scope (mirrors
/// `taint_scan.rs::run_taint_rule` on the Python side, wired on
/// 08/30), THEN each function/method/closure collected by
/// `collect_php_functions` as an independent CFG, with an empty entry
/// state. **08/30 fix**: before this module-level pass, all classic
/// procedural PHP code written outside a function (a dominant pattern
/// in a lot of real-world PHP code) was invisible — found while
/// validating the engine on DVWA (0 PHP findings on a corpus full of
/// deliberate vulnerabilities, all in top-level code). No double-counting with
/// the functions (see `php_cfg.rs` doc). Final global deduplication
/// by `(rule_id, line, source_line)`.
pub fn run_taint_rule_php<'tree>(
    root: Node<'tree>,
    source: &'tree [u8],
    specs: &RuleSpecs,
    source_lines: Option<&[String]>,
) -> Vec<Finding> {
    let mut all_findings: Vec<Finding> = Vec::new();

    let module_cfg = build_php_cfg(root, source);
    let module_result = analyze_php(
        &module_cfg,
        source,
        specs,
        Some(&empty_state()),
        source_lines,
    );
    all_findings.extend(module_result.findings);

    for fn_info in collect_php_functions(root, source) {
        let cfg = build_php_cfg(fn_info.body_node, source);
        let result = analyze_php(&cfg, source, specs, Some(&empty_state()), source_lines);
        all_findings.extend(result.findings);
    }

    let mut seen: std::collections::HashSet<(String, usize, Option<usize>)> =
        std::collections::HashSet::new();
    all_findings.retain(|f| seen.insert((f.rule_id.clone(), f.line, f.source_line)));
    drop_sinks_on_sanitizer_lines(all_findings, specs, source, source_lines)
}

/// Drops a finding whose sink line matches one of the rule's sanitizers.
///
/// The Audit analyzes PHP with its lexical engine only (ADR-0007), where
/// "a sanitizer matched on the same line neutralizes the sink"
/// (`lexical_taint.py`, `sanitizer_match_on_line`): a hardening flag
/// passed to the sink itself, as in
/// `simplexml_load_string($_POST['xml'], 'SimpleXMLElement', LIBXML_NONET)`
/// for `sanitizer LIBXML_NONET`, makes the call safe. This native engine
/// evaluates the call before the line's sanitizer and reported it (ticket
/// #178). Kept to PHP, the language whose reference behavior is the
/// lexical one: the Python dataflow engine, reference for Python, has no
/// such rule.
fn drop_sinks_on_sanitizer_lines(
    findings: Vec<Finding>,
    specs: &RuleSpecs,
    source: &[u8],
    source_lines: Option<&[String]>,
) -> Vec<Finding> {
    if specs.sanitizers.iter().all(|s| s.raw_regex.is_none()) {
        return findings;
    }
    let owned: Vec<String>;
    let lines: &[String] = match source_lines {
        Some(lines) => lines,
        None => {
            owned = String::from_utf8_lossy(source)
                .lines()
                .map(String::from)
                .collect();
            &owned
        }
    };
    findings
        .into_iter()
        .filter(|f| {
            let Some(text) = f.line.checked_sub(1).and_then(|i| lines.get(i)) else {
                return true;
            };
            !specs.sanitizers.iter().any(|san| {
                san.raw_regex
                    .as_ref()
                    .is_some_and(|re| re.is_match(text).unwrap_or(false))
            })
        })
        .collect()
}

// ============================================================================
// Tests — same behavior categories as `js_taint_scan.rs`,
// adapted to PHP syntax.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::{SanitizerSpec, SinkSpec, SourceSpec};
    use std::collections::BTreeMap;
    use tree_sitter::Parser;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(src, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "syntaxe PHP invalide : {src:?}"
        );
        tree
    }

    fn sqli_specs() -> RuleSpecs {
        RuleSpecs {
            rule_id: "taint_sqli_php".to_string(),
            severity: "HIGH".to_string(),
            cwe: Some("CWE-89".to_string()),
            message: "test finding".to_string(),
            // `$_GET['q']` is a subscript access (SubscriptRef), not
            // an AttrRef — `eval_rhs` does not test `source` patterns
            // against the base of a CONSTANT key access (§9.bis, see
            // module doc): detection therefore goes through the
            // hybrid raw-line matching (§10bis, `raw_regex`), exactly
            // like a real `.sca` rule loaded via
            // `rule_loader::rule_json_to_specs` (which always
            // populates `raw_regex` from the same pattern) —
            // `SourceSpec::new` alone does not, hence the explicit
            // `.with_raw_regex` here to stay faithful to real
            // behavior.
            sources: vec![
                SourceSpec::new("\\$_GET\\[", "http")
                    .with_raw_regex(fancy_regex::Regex::new(r"\$_GET\[").unwrap()),
            ],
            // canon_callee canonicalizes EVERY method access into the
            // dotted form `base.attr`, whatever the source syntax
            // (`->` in PHP, `.` in JS/Java) — the sink's glob pattern
            // must therefore target `*.query`, not `->query`.
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
        run_taint_rule_php(tree.root_node(), src.as_bytes(), specs, Some(&lines))
    }

    #[test]
    fn test_source_to_sink_detected() {
        let src = "<?php\nfunction handler($db) { $q = $_GET['q']; $db->query($q); }\n";
        let findings = run(src, &sqli_specs());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "taint_sqli_php");
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
    }

    #[test]
    fn test_clean_no_finding() {
        let src = "<?php\nfunction handler($db) { $db->query('SELECT 1'); }\n";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_no_source_no_finding() {
        let src = "<?php\nfunction handler($q, $db) { $db->query($q); }\n";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    /// Ticket #178: a sanitizer on the sink's own line (a hardening flag
    /// passed to the sink) neutralizes it, as in the Audit's lexical
    /// engine; the same sink without the flag is still reported.
    fn test_sanitizer_on_sink_line_neutralizes_the_sink() {
        let mut specs = sqli_specs();
        specs.sanitizers.push(
            SanitizerSpec::new("SAFE_FLAG")
                .with_raw_regex(fancy_regex::Regex::new(r"SAFE_FLAG").unwrap()),
        );
        let flagged = "<?php\n$db->query($_GET['q'], SAFE_FLAG);\n";
        let plain = "<?php\n$db->query($_GET['q']);\n";
        let run_src = |src: &str| {
            let tree = parse(src);
            run_taint_rule_php(tree.root_node(), src.as_bytes(), &specs, None)
        };
        assert!(run_src(flagged).is_empty());
        assert!(!run_src(plain).is_empty());
    }

    #[test]
    fn test_sanitized_no_finding() {
        let src = "<?php\nfunction handler($db) { $q = sanitize($_GET['q']); $db->query($q); }\n";
        let mut specs = sqli_specs();
        // Same remark as for the source (§10bis, hybrid raw-line
        // matching): a real `.sca` rule always populates `raw_regex`,
        // made explicit here to stay faithful.
        specs.sanitizers.push(
            SanitizerSpec::new("sanitize")
                .with_raw_regex(fancy_regex::Regex::new(r"sanitize\s*\(").unwrap()),
        );
        assert!(run(src, &specs).is_empty());
    }

    #[test]
    fn test_flow_trace_present() {
        let src = "<?php\nfunction handler($db) { $q = $_GET['q']; $db->query($q); }\n";
        let findings = run(src, &sqli_specs());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].flow.len() >= 2);
        assert_eq!(findings[0].flow[0].kind, "source");
        assert_eq!(findings[0].flow[findings[0].flow.len() - 1].kind, "sink");
    }

    #[test]
    fn test_multiple_functions_isolated() {
        let src = "<?php\nfunction clean($db) { $db->query('SELECT 1'); }\nfunction vuln($db) { $q = $_GET['q']; $db->query($q); }\n";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_anonymous_closure_callback_detected() {
        // Dominant PHP pattern: closure passed directly as an
        // argument (framework handler) — see php_summary.rs doc.
        let src = "<?php\napp_get('/x', function($db) { $q = $_GET['q']; $db->query($q); });\n";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_encapsed_string_interpolation_propagates_taint() {
        let src = r#"<?php
function handler($db) { $q = "SELECT * FROM t WHERE id={$_GET['q']}"; $db->query($q); }
"#;
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    /// Specs with an AttrRef source (`$request->query`, Symfony
    /// style) rather than the `$_GET[...]` subscript — isolates the
    /// constant-folding test from the hybrid raw-line matching
    /// (§10bis, see `test_sanitized_no_finding`/`sqli_specs`): these
    /// two mechanisms are independent in the engine (language-neutral,
    /// already validated on the Python/Java/JS side) and should not
    /// be mixed in a single test for readability. Source and sink use
    /// DIFFERENT patterns (`*.query` vs `*.execute`) — `resolve_spec`
    /// (`transfer.rs`) checks sources BEFORE sinks, so the same
    /// pattern for both would always resolve the sink as a source
    /// (a test bug found while calibrating: `*.query` used for both
    /// completely masked the sink).
    fn attrref_sqli_specs() -> RuleSpecs {
        RuleSpecs {
            rule_id: "taint_sqli_php".to_string(),
            severity: "HIGH".to_string(),
            cwe: Some("CWE-89".to_string()),
            message: "test finding".to_string(),
            sources: vec![SourceSpec::new("*.query", "http")],
            sinks: vec![SinkSpec::new("*.execute")],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
        }
    }

    #[test]
    fn test_conditional_constant_folding() {
        let src = "<?php\nfunction handler($request, $db) { $p = $request->query; $bar = null; if (1 > 2) { $bar = $p; } else { $bar = 'safe'; } $db->execute($bar); }\n";
        assert!(run(src, &attrref_sqli_specs()).is_empty());
    }

    #[test]
    fn test_non_constant_condition_stays_conservative() {
        let src = "<?php\nfunction handler($request, $db) { $p = $request->query; $bar = null; if ($request->flag) { $bar = $p; } else { $bar = 'safe'; } $db->execute($bar); }\n";
        assert_eq!(run(src, &attrref_sqli_specs()).len(), 1);
    }

    #[test]
    fn test_dedup_same_rule_line_source_line() {
        let src = "<?php\nfunction handler($db) { $q = $_GET['q']; $db->query($q); }\n";
        let findings1 = run(src, &sqli_specs());
        let findings2 = run(src, &sqli_specs());
        assert_eq!(findings1.len(), findings2.len());
        assert_eq!(findings1.len(), 1);
    }
}
