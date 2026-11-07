//! Compiles a DSL rule (compiled JSON) into `RuleSpecs` — faithful
//! port of `Audit/sca/executors/dataflow_taint.py::
//! rule_json_to_specs`/`regex_to_dotted_patterns` and satellite
//! functions. Python-only scope (Decision #10).
//!
//! Bridge between the JSON produced by `parser::compile_sca_to_json`
//! (already 100% aligned with Python, field names verified) and
//! `RuleSpecs`: each DSL source/sink/sanitizer/passthrough carries a
//! single **regex** pattern; this module derives from it a **dotted**
//! glob (`compiled`, for fast `eval_call` matching) in addition to
//! keeping the raw regex (`raw_regex`, §10bis) — a single JSON entry
//! can produce 0 to N specs (one per expanded `(a|b|c)` alternative).
#![allow(dead_code)]

use std::sync::LazyLock;

use fancy_regex::Regex;
use serde_json::Value;

use super::transfer::{PassthroughSpec, RuleSpecs, SanitizerSpec, SinkSpec, SourceSpec};

fn safe_compile_regex(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

// ============================================================================
// regex → dotted patterns (heuristic, §7.1)
// ============================================================================

/// Opening markers of a lookaround assertion `(?=`, `(?!`, `(?<=`,
/// `(?<!` — anchored at the current position (mirrors
/// `re.Pattern.match(string, pos)` on the Python side).
static LOOKAROUND_OPEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\(\?<?[=!]").expect("regex statique valide"));

/// Regex noise to strip to obtain a readable "dotted" name.
static REGEX_NOISE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\\s\*|\\b|\\s\+|\\\(|\\\)|\\\[|\\\]|\(\?\:").expect("regex statique valide")
});

static WORD_WILDCARD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\w[+*]?").expect("regex statique valide"));
static DOT_WILDCARD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.[+*]").expect("regex statique valide"));
static MULTI_STAR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\*+").expect("regex statique valide"));

/// Entirely strips lookaround groups `(?=...)`, `(?!...)`,
/// `(?<=...)`, `(?<!...)` (including balanced parentheses), not just
/// the opening marker — a lookaround carries a constraint with no
/// equivalent in the "dotted" model (neither negation nor context),
/// an accepted over-approximation. **Historical bug documented on
/// the Python side** (`taint_xss.sca`) if only the opening marker is
/// stripped: the orphaned closing parenthesis and the content (often
/// an `a|b` alternation) get misinterpreted downstream by
/// `expand_alternations`, producing corrupted patterns (e.g.
/// `(?<!System\.(?:out|err))\.print\s*\(` → `<!System.out).print`,
/// `err).print` — zero XSS sink recognized).
fn strip_lookaround_groups(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::new();
    let mut i = 0usize;
    while i < chars.len() {
        let rest: String = chars[i..].iter().collect();
        if let Ok(Some(m)) = LOOKAROUND_OPEN_RE.find(&rest) {
            let mut depth = 1i32;
            let mut j = i + m.end();
            while j < chars.len() && depth > 0 {
                match chars[j] {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            i = j;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Expands `(a|b|c)` alternation groups into multiple patterns.
/// Limited to the simplest groups (no deep nesting). Finds the FIRST
/// `(...)` group containing a `|` and expands on its alternatives,
/// recursive on the result.
fn expand_alternations(pattern: &str) -> Vec<String> {
    let chars: Vec<char> = pattern.chars().collect();
    let Some(open) = chars.iter().position(|&c| c == '(') else {
        return vec![pattern.to_string()];
    };
    let mut depth = 0i32;
    let mut close: Option<usize> = None;
    for (i, &c) in chars.iter().enumerate().skip(open) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        // Unbalanced parenthesis: leave as-is.
        return vec![pattern.to_string()];
    };
    let inside: String = chars[open + 1..close].iter().collect();
    let before: String = chars[..open].iter().collect();
    let after: String = chars[close + 1..].iter().collect();
    if !inside.contains('|') {
        // No alternation in this group: "(x)" -> "x", recurse on the rest.
        return expand_alternations(&format!("{before}{inside}{after}"));
    }
    let mut out = Vec::new();
    for alt in inside.split('|') {
        out.extend(expand_alternations(&format!("{before}{alt}{after}")));
    }
    out
}

/// Final cleanup pass on a "dotted" pattern.
fn finalize_dotted(pattern: &str) -> String {
    let p = WORD_WILDCARD_RE.replace_all(pattern, "*").into_owned();
    let p = DOT_WILDCARD_RE.replace_all(&p, "*").into_owned();
    let p = p.replace('?', "");
    let p = MULTI_STAR_RE.replace_all(&p, "*").into_owned();
    let p = p.trim().to_string();
    if p.is_empty() || p.chars().all(|c| c == '.' || c == '*') {
        return String::new();
    }
    if p.starts_with('.') {
        format!("**{p}")
    } else {
        p
    }
}

/// "Best-effort" conversion of a DSL regex into a list of "dotted"
/// patterns. Returns an empty list if the regex is too opaque.
pub fn regex_to_dotted_patterns(regex_str: &str) -> Vec<String> {
    if regex_str.is_empty() {
        return Vec::new();
    }
    let stripped = strip_lookaround_groups(regex_str);
    let clean = REGEX_NOISE_RE.replace_all(&stripped, "").into_owned();
    let clean = clean.replace(r"\.", ".");
    // PHP (`->method`/`\->method`) and the static double-colon
    // (`::method`) are normalized to `.` — same semantic role as dot
    // access in Python/Java/JS (member resolution), but absent from
    // the Python source (the original `regex_to_dotted_patterns` only
    // handles `\.` since Audit has no PHP AST engine). AuditRust
    // addition, beyond Python parity — without it, NO PHP rule
    // targeting a method call (`sink \->query\s*\(`, the natural form
    // in real PHP syntax) derives a usable "dotted" pattern, and
    // `resolve_spec`/`eval_call` never matches the sink (only the
    // `raw_regex` confirmation filter, built from the SAME
    // unmodified `regex_str`, still validates against the real
    // `->`/`::` syntax of the source file).
    let clean = clean.replace(r"\->", ".").replace("->", ".");
    let clean = clean.replace(r"\::", ".").replace("::", ".");
    let clean = clean.trim_start_matches('^').trim_end_matches('$');
    let clean = clean.split('=').next().unwrap_or("").trim().to_string();
    expand_alternations(&clean)
        .into_iter()
        .filter_map(|p| {
            let f = finalize_dotted(&p);
            if f.is_empty() { None } else { Some(f) }
        })
        .collect()
}

// ============================================================================
// Compiled JSON → RuleSpecs
// ============================================================================

fn json_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("")
}

/// `pub(crate)`: reused by the orchestrator (Step 5) to populate the
/// `ReportFinding` of the regex/file_contains executors, which do not
/// themselves carry the rule's i18n message.
///
/// `lang`: target language (`"fr"`/`"es"`/`"de"`/...) — tried first,
/// then falls back to `"en"`, then to the first language available in
/// the block. Deviation fixed (2026-08-26): the previous version
/// completely ignored `lang` and always preferred `"en"` — a
/// `--lang fr` scan still produced an English `message` regardless.
pub(crate) fn extract_message(rule_json: &Value, lang: &str) -> String {
    match rule_json.get("message") {
        Some(Value::Object(map)) => {
            let target = map
                .get(lang)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let en = || {
                map.get("en")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
            };
            target
                .or_else(en)
                .map(|s| s.to_string())
                .or_else(|| {
                    map.values()
                        .next()
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_default()
        }
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => String::new(),
    }
}

/// `pub(crate)`: reused by the orchestrator (Step 5).
pub(crate) fn extract_cwe(rule_json: &Value) -> Option<String> {
    let metadata = rule_json.get("metadata")?;
    match metadata.get("cwe") {
        Some(Value::Array(arr)) => arr.first().and_then(|v| v.as_str()).map(|s| s.to_string()),
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Converts a compiled SCA rule (JSON) into dataflow engine
/// `RuleSpecs`. "Best-effort" conversion: each regex pattern
/// generates 1..N dotted patterns. `None` if the rule doesn't have at
/// least one convertible source AND sink.
pub fn rule_json_to_specs(rule_json: &Value, lang: &str) -> Option<RuleSpecs> {
    let empty: Vec<Value> = Vec::new();
    let mut sources = Vec::new();
    for s in rule_json
        .get("sources")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
    {
        let regex = json_str(s, "pattern");
        let kind = if json_str(s, "kind").is_empty() {
            "unknown"
        } else {
            json_str(s, "kind")
        };
        let compiled = safe_compile_regex(regex);
        for dotted in regex_to_dotted_patterns(regex) {
            let mut spec = SourceSpec::new(dotted, kind);
            spec.raw_regex = compiled.clone();
            sources.push(spec);
        }
    }

    let mut sinks = Vec::new();
    for s in rule_json
        .get("sinks")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
    {
        let regex = json_str(s, "pattern");
        // The .sca DSL produces `arg_index: 0` (int) by default on
        // each sink. `args: [...]` (list of indices) is also accepted
        // for backward compatibility; takes priority if present.
        let args: Vec<usize> = if let Some(arr) = s.get("args").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as usize))
                .collect()
        } else if let Some(idx) = s.get("arg_index").and_then(|v| v.as_u64()) {
            vec![idx as usize]
        } else {
            Vec::new()
        };
        let kinds: Vec<String> = s
            .get("kinds")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let compiled = safe_compile_regex(regex);
        for dotted in regex_to_dotted_patterns(regex) {
            let mut spec = SinkSpec::new(dotted)
                .with_args(args.clone())
                .with_kinds(kinds.clone());
            spec.raw_regex = compiled.clone();
            sinks.push(spec);
        }
    }

    let mut sanitizers = Vec::new();
    for s in rule_json
        .get("sanitizers")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
    {
        let regex = json_str(s, "pattern");
        let compiled = safe_compile_regex(regex);
        for dotted in regex_to_dotted_patterns(regex) {
            let mut spec = SanitizerSpec::new(dotted);
            spec.raw_regex = compiled.clone();
            sanitizers.push(spec);
        }
    }

    let mut passthroughs = Vec::new();
    for s in rule_json
        .get("passthroughs")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
    {
        let regex = json_str(s, "pattern");
        let compiled = safe_compile_regex(regex);
        for dotted in regex_to_dotted_patterns(regex) {
            let mut spec = PassthroughSpec::new(dotted);
            spec.raw_regex = compiled.clone();
            passthroughs.push(spec);
        }
    }

    if sources.is_empty() || sinks.is_empty() {
        return None;
    }

    let rule_id = rule_json
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| rule_json.get("rule_id").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    let severity = rule_json
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("MEDIUM")
        .to_string();

    Some(RuleSpecs {
        rule_id,
        severity,
        cwe: extract_cwe(rule_json),
        message: extract_message(rule_json, lang),
        sources,
        sinks,
        sanitizers,
        passthroughs,
        summaries: Default::default(),
        type_map: Default::default(),
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_empty_regex_produces_no_patterns() {
        assert_eq!(regex_to_dotted_patterns(""), Vec::<String>::new());
    }

    #[test]
    fn test_simple_escaped_dot_pattern() {
        assert_eq!(
            regex_to_dotted_patterns(r"os\.system"),
            vec!["os.system".to_string()]
        );
    }

    #[test]
    fn test_alternation_expands_into_multiple_patterns() {
        let out = regex_to_dotted_patterns(r"os\.(system|popen)");
        assert_eq!(out, vec!["os.system".to_string(), "os.popen".to_string()]);
    }

    #[test]
    fn test_anchors_stripped() {
        assert_eq!(
            regex_to_dotted_patterns(r"^os\.system$"),
            vec!["os.system".to_string()]
        );
    }

    #[test]
    fn test_equals_sign_truncates_pattern() {
        assert_eq!(regex_to_dotted_patterns("foo=bar"), vec!["foo".to_string()]);
    }

    #[test]
    fn test_php_arrow_normalized_to_dot() {
        // `->` (PHP method access) must derive a "dotted" pattern
        // usable by `eval_call`/`resolve_spec`, exactly like `\.` in
        // Python/Java/JS — without this no PHP rule targeting a
        // method call (`sink ->query\(`) ever matches via the AST
        // path (cf. `php_taint_scan.rs`, 25/08 calibration).
        assert_eq!(
            regex_to_dotted_patterns(r"->query\("),
            vec!["**.query".to_string()]
        );
    }

    #[test]
    fn test_php_escaped_arrow_normalized_to_dot() {
        assert_eq!(
            regex_to_dotted_patterns(r"\->execute\("),
            vec!["**.execute".to_string()]
        );
    }

    #[test]
    fn test_static_double_colon_normalized_to_dot() {
        assert_eq!(
            regex_to_dotted_patterns(r"Foo::bar\("),
            vec!["Foo.bar".to_string()]
        );
    }

    #[test]
    fn test_raw_regex_unaffected_by_arrow_normalization() {
        // The `->`→`.` normalization must affect ONLY the "dotted"
        // derivation — `raw_regex` (hybrid matching §10bis,
        // confirmation against the real source text) must keep
        // matching the real PHP `->` syntax, never `.`.
        let compiled = safe_compile_regex(r"->query\(").expect("regex valide");
        assert!(compiled.is_match("$db->query(").unwrap_or(false));
        assert!(!compiled.is_match("$db.query(").unwrap_or(false));
    }

    #[test]
    fn test_word_wildcard_becomes_star() {
        assert_eq!(
            regex_to_dotted_patterns(r"\w+\.execute"),
            vec!["*.execute".to_string()]
        );
    }

    #[test]
    fn test_dot_only_result_filtered_out() {
        assert_eq!(regex_to_dotted_patterns(r"\."), Vec::<String>::new());
    }

    #[test]
    fn test_lookaround_stripped_entirely_regression_taint_xss() {
        // Regression case documented on the Python side
        // (taint_xss.sca): the negative lookbehind must be stripped
        // IN ITS ENTIRETY, not just its opening marker, otherwise the
        // orphaned parenthesis and the inner alternation (out|err)
        // corrupt the result.
        let out = regex_to_dotted_patterns(r"(?<!System\.(?:out|err))\.print\s*\(");
        assert_eq!(
            out,
            vec!["**.print".to_string()],
            "le lookbehind entier doit disparaître, laissant .print -> **.print"
        );
    }

    #[test]
    fn test_non_capturing_group_marker_stripped_but_content_kept() {
        // `(?:` is stripped by the noise filter (non-capturing
        // group), but its content must remain -- unlike the
        // lookaround, which disappears entirely along with its
        // content.
        let out = regex_to_dotted_patterns(r"(?:foo)\.bar");
        assert_eq!(
            out,
            vec!["foo).bar".to_string()],
            "seul le marqueur '(?:' est retiré, la parenthèse fermante et 'foo' restent"
        );
    }

    #[test]
    fn test_rule_json_to_specs_basic() {
        let rule = json!({
            "id": "sql_injection",
            "severity": "HIGH",
            "message": {"en": "SQL injection risk", "fr": "Risque d'injection SQL"},
            "metadata": {"cwe": ["CWE-89"]},
            "sources": [{"pattern": r"request\.GET", "kind": "http"}],
            "sinks": [{"pattern": r"cursor\.execute", "arg_index": 0}],
        });
        let specs = rule_json_to_specs(&rule, "en").expect("sources et sinks présents -> Some");
        assert_eq!(specs.rule_id, "sql_injection");
        assert_eq!(specs.severity, "HIGH");
        assert_eq!(specs.message, "SQL injection risk");
        assert_eq!(specs.cwe.as_deref(), Some("CWE-89"));
        assert_eq!(specs.sources.len(), 1);
        assert_eq!(specs.sources[0].pattern, "request.GET");
        assert_eq!(specs.sources[0].kind, "http");
        assert!(specs.sources[0].raw_regex.is_some());
        assert_eq!(specs.sinks.len(), 1);
        assert_eq!(specs.sinks[0].args, vec![0]);
    }

    #[test]
    fn test_rule_json_to_specs_message_falls_back_when_en_absent() {
        let rule = json!({
            "id": "r",
            "message": {"fr": "seulement en français"},
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": "eval"}],
        });
        let specs = rule_json_to_specs(&rule, "en").unwrap();
        assert_eq!(specs.message, "seulement en français");
    }

    #[test]
    fn test_rule_json_to_specs_none_without_sources() {
        let rule = json!({"id": "r", "sinks": [{"pattern": "eval"}]});
        assert!(rule_json_to_specs(&rule, "en").is_none());
    }

    #[test]
    fn test_rule_json_to_specs_none_without_sinks() {
        let rule = json!({"id": "r", "sources": [{"pattern": "input"}]});
        assert!(rule_json_to_specs(&rule, "en").is_none());
    }

    #[test]
    fn test_rule_json_to_specs_sink_args_list_takes_priority_over_arg_index() {
        let rule = json!({
            "id": "r",
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": "run", "arg_index": 0, "args": [1, 2]}],
        });
        let specs = rule_json_to_specs(&rule, "en").unwrap();
        assert_eq!(specs.sinks[0].args, vec![1, 2]);
    }

    #[test]
    fn test_rule_json_to_specs_sink_kinds_filter() {
        let rule = json!({
            "id": "r",
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": "run", "kinds": ["http", "network"]}],
        });
        let specs = rule_json_to_specs(&rule, "en").unwrap();
        assert_eq!(
            specs.sinks[0].kinds,
            vec!["http".to_string(), "network".to_string()]
        );
    }

    #[test]
    fn test_rule_json_to_specs_expands_alternation_into_multiple_specs() {
        let rule = json!({
            "id": "r",
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": r"os\.(system|popen)"}],
        });
        let specs = rule_json_to_specs(&rule, "en").unwrap();
        assert_eq!(
            specs.sinks.len(),
            2,
            "une entrée sink JSON avec alternation -> 2 SinkSpec"
        );
    }

    #[test]
    fn test_rule_json_to_specs_invalid_regex_yields_no_raw_regex_but_no_crash() {
        // "(" is an invalid regex (unclosed parenthesis) -- no panic,
        // raw_regex stays None (mirrors _safe_compile_regex which
        // catches re.error and returns None); the "unbalanced
        // parenthesis, leave as-is" fallback of expand_alternations
        // still produces a literal "(" dotted pattern (same behavior
        // as the Python side).
        let rule = json!({
            "id": "r",
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": "("}],
        });
        let specs = rule_json_to_specs(&rule, "en")
            .expect("sources et sinks non vides -> Some malgré le regex invalide");
        assert_eq!(specs.sinks.len(), 1);
        assert!(
            specs.sinks[0].raw_regex.is_none(),
            "regex invalide -> raw_regex None, pas de panique"
        );
    }
}
