//! Transfer functions of the dataflow engine — port of
//! `Audit/sca/dataflow/transfer.py`.
//!
//! **Scope of this component**: the pure semantic core (spec
//! resolution, `eval_rhs`/`eval_call`, applying sink/sanitizer/
//! passthrough, per-statement transfer functions, indexed
//! object/list/receiver mutation methods), the hybrid regex matching
//! layer over the source text
//! (`aux_match_line`/`discard_sinks_failing_raw_regex`, §7/§10bis)
//! **and** interprocedural resolution via function summary ("Part 2"
//! on the Python side, §5.2): `FunctionSummary` and
//! `RuleSpecs.summaries` live here rather than in `summary.rs` —
//! Python types this field as `Any` precisely to break the
//! `transfer.py ↔ summary.py` import cycle; Rust has no such
//! weak-typing escape hatch, so `FunctionSummary` (which references
//! `Finding`, already defined here) is co-located with
//! `RuleSpecs`/`Finding` rather than in `summary.rs`, which re-exports
//! it to stay close to the Python structure. `specs.type_map` (Java
//! resolution, always empty on the Python side) ported on 2026-08-25
//! with the Python+Java extension — Round 5/6 (resolving
//! `scr.method()`/`new X().method()`) in `eval_call` below.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

use fancy_regex::Regex;

use super::ir::{
    IrStmt, Lhs, Rhs, canon_callee, canon_lhs, canon_rhs, canon_subscript_key, pretty_rhs,
};
use super::lattice::{SourceInfo, State, Taint, join, state_get, state_set};

// ============================================================================
// §10bis — Static regexes for hybrid matching over the source text
// ============================================================================

/// Terminator of a sanitizer-guard: the line following
/// `if not <san>(x): ...` must contain one of these calls for the
/// block to be considered a guard (the downstream sink is no longer
/// reached if the predicate fails).
static GUARD_TERMINATOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:abort|raise|return|exit|sys\.exit|os\._exit)\b")
        .expect("regex statique valide")
});

/// Terminators of a guard written on one line in a brace language,
/// `if (!ALLOWED.Contains(cmd)) return Forbid();` — the list of the
/// Audit's lexical engine (`lexical_taint.py::
/// _GUARD_TERMINATOR_RE_MULTILANG`), which is the reference behavior for
/// C#, PHP and JavaScript (ADR-0003, ADR-0007). Ticket #178.
static GUARD_TERMINATOR_SAMELINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:return|throw|raise|break|continue|exit|die|abort|halt|Forbid|Halt|sendError|sendRedirect|RedirectToAction|Response\.End)\b",
    )
    .expect("regex statique valide")
});

/// `!` negation (Java/C#/JS style, e.g. `if (!isValid(x))`) —
/// alternative to Python's `not`/`in`. Excludes `!=` (not a negation
/// of a sanitizer call).
static NEGATION_BANG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"!(?!=)").expect("regex statique valide"));

/// Reassignment to a literal inside a guard
/// `if (!check(x)) x = "literal";` (same physical line as the if).
/// The PHP `$` is part of the captured name: the PHP engine keeps it in
/// its variable names (`$next`). The Audit's pattern allowed `\$?` before
/// the group; the first port had lost it, so a PHP guard
/// `if (!filter_var($next, ...)) { $next = '/'; }` left `$next` tainted
/// (ticket #157).
static GUARD_REASSIGN_SAMELINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\)\s*\{?\s*(\$?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:["'][^"']*["']|[+-]?[0-9]+|null|None|undefined|true|false)"#,
    )
    .expect("regex statique valide")
});

/// Same idiom, but as a whole following line (multi-line guard body).
/// Anchored at the start of the line (standalone statement, not a
/// continuation of `)`). Same `$` as `GUARD_REASSIGN_SAMELINE_RE`.
static GUARD_REASSIGN_NEXTLINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\s*(\$?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:["'][^"']*["']|[+-]?[0-9]+|null|None|undefined|true|false)\s*;"#,
    )
    .expect("regex statique valide")
});

/// String literals (single/double quote), to strip them from the
/// text before a substring search (variable name). Pattern identical
/// to `lexical_taint.py::_STRING_LIT_STRIP_RE` — unambiguous
/// partition (each repetition of `(?:\\.[^"\\]*)*` starts on a
/// literal backslash excluded from the previous group), no
/// exponential backtracking despite the appearance of nested
/// quantifiers.
static STRING_LIT_STRIP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'"#)
        .expect("regex statique valide")
});

/// `\b\w+\b`-style identifiers (ASCII) — used to extract the
/// identifiers mentioned on a guard line (§10bis).
static IDENTIFIER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_][A-Za-z0-9_]*\b").expect("regex statique valide"));

/// Strips "flat" string literals from `text`, but leaves intact
/// those that interpolate (contain `{`/`}`) — a Python f-string
/// (`f'Hello {bar}'`) or a JS template carries a REAL variable
/// reference inside the quotes, not a textual coincidence: stripping
/// it would break legitimate XSS detection on
/// `return f'...{bar}...'`. A "flat" literal (e.g. SQL text) is
/// indeed stripped.
fn strip_plain_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in STRING_LIT_STRIP_RE.find_iter(text) {
        let Ok(m) = m else { break };
        out.push_str(&text[last..m.start()]);
        let matched = m.as_str();
        if matched.contains('{') || matched.contains('}') {
            out.push_str(matched);
        } else {
            out.push(' ');
        }
        last = m.end();
    }
    out.push_str(&text[last..]);
    out
}

fn extract_identifiers(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for m in IDENTIFIER_RE.find_iter(text).flatten() {
        out.insert(m.as_str().to_string());
    }
    out
}

/// Checks the 10 preceding lines for `<id> = ...<var_name>...` where
/// `<id>` is a guard identifier. Covers the pattern
/// `url = urlparse(bar); if url.netloc in [...]: return; redirect(bar)`.
///
/// **No regex here, deliberately**: this function is called in the
/// hot loop of the taint fixpoint (once per generic `if`/`elif` line,
/// on every worklist iteration). The old version compiled a dynamic
/// regex (`Regex::new`) per `(gid, var_name)` pair × up to 10 lines
/// back — profiled (`sample`) on a real 34k-line scan (`Audit/sca`):
/// regex compilation (fancy-regex parse + regex-automata NFA/DFA
/// builder) dominated total CPU time. Replaced by string operations
/// bit-for-bit equivalent to the old pattern
/// `^\s*{gid}\s*=.*\b{var_name}\b`: `trim_start`/`strip_prefix` for
/// the literal anchor, `extract_identifiers` (static regex already
/// compiled once via `LazyLock`) for the `\b...\b` test.
fn backward_aliased_var(
    var_name: &str,
    guard_ids: &BTreeSet<String>,
    lineno: usize,
    source_lines: &[String],
) -> bool {
    for back in 1..=10i64 {
        let idx_back = lineno as i64 - 1 - back;
        if idx_back < 0 {
            return false;
        }
        let prev = &source_lines[idx_back as usize];
        let trimmed = prev.trim_start();
        for gid in guard_ids {
            let Some(after_gid) = trimmed.strip_prefix(gid.as_str()) else {
                continue;
            };
            let Some(after_eq) = after_gid.trim_start().strip_prefix('=') else {
                continue;
            };
            if extract_identifiers(after_eq).contains(var_name) {
                return true;
            }
        }
    }
    false
}

/// Cleans up tainted variables involved in a guard
/// `if EXPR: …return`. Step 1: directly cleans the tainted variables
/// mentioned on the guard line. Step 2: backward aliasing — for each
/// identifier in the guard, scans the 10 preceding lines for an
/// assignment `<id> = ...<var>...`.
fn apply_guard_cleanup(
    state: &State,
    line_text: &str,
    lineno: usize,
    source_lines: &[String],
) -> State {
    let mut state = state.clone();
    let keys: Vec<String> = state.keys().cloned().collect();
    for var_name in &keys {
        if line_text.contains(var_name.as_str()) && state_get(&state, var_name).is_tainted() {
            state = state_set(&state, var_name, Taint::Clean);
        }
    }
    let guard_ids = extract_identifiers(line_text);
    let keys2: Vec<String> = state.keys().cloned().collect();
    for var_name in &keys2 {
        if !state_get(&state, var_name).is_tainted() {
            continue;
        }
        if backward_aliased_var(var_name, &guard_ids, lineno, source_lines) {
            state = state_set(&state, var_name, Taint::Clean);
        }
    }
    state
}

fn kind_str_compatible(kind: &str, sink_kinds: &[String]) -> bool {
    sink_kinds.is_empty() || sink_kinds.iter().any(|k| k == kind)
}

fn stmt_lineno(stmt: &IrStmt) -> usize {
    match stmt {
        IrStmt::Assign { lineno, .. }
        | IrStmt::Call { lineno, .. }
        | IrStmt::Return { lineno, .. }
        | IrStmt::Raise { lineno, .. }
        | IrStmt::Branch { lineno, .. }
        | IrStmt::Noop { lineno } => *lineno,
    }
}

/// Revalidates in place the findings added since index `before`
/// against the `raw_regex` of their originating `SinkSpec` — sink
/// resolution via dotted glob (`**.println` matches ANY receiver) is
/// not revalidated by default: a DSL pattern written with a negative
/// lookbehind to exclude a specific receiver (e.g.
/// `(?<!System\.(?:out|err))\.println\s*\(`) must therefore be
/// revalidated here, otherwise the exclusion has no effect on this
/// path (bug found via the `taint_xss_console_clean` regression —
/// `System.out.println` was wrongly flagged as an XSS sink via the
/// `**.println` glob, even though `raw_regex` explicitly excluded
/// it).
///
/// Only removes a finding if at least one spec whose glob matches its
/// `sink_text` exists AND none of those specs validates `raw_regex`
/// against the relevant text — a spec with no `raw_regex` is never
/// filtered out. Relevant text: `sink_text` THEN the source line, in
/// that order (both forms of sink DSL depend on it).
fn discard_sinks_failing_raw_regex(
    findings: &mut Vec<Finding>,
    before: usize,
    specs: &RuleSpecs,
    source_lines: &[String],
) {
    if before >= findings.len() {
        return;
    }
    let mut kept: Vec<Finding> = findings[..before].to_vec();
    for f in &findings[before..] {
        let candidates: Vec<&SinkSpec> = specs
            .sinks
            .iter()
            .filter(|s| match_pattern(&f.sink_text, &s.compiled))
            .collect();
        if candidates.is_empty() {
            kept.push(f.clone());
            continue;
        }
        let line_text = if f.line > 0 && f.line <= source_lines.len() {
            source_lines[f.line - 1].as_str()
        } else {
            ""
        };
        let passes = candidates.iter().any(|c| match &c.raw_regex {
            None => true,
            Some(rx) => {
                rx.is_match(&f.sink_text).unwrap_or(false)
                    || rx.is_match(line_text).unwrap_or(false)
            }
        });
        if passes {
            kept.push(f.clone());
        }
    }
    *findings = kept;
}

/// Auxiliary regex matching against the raw source line (§10bis).
/// For each sink/sanitizer/source spec carrying a `raw_regex`, tests
/// against the statement's source line; on a match, triggers the
/// corresponding behavior.
fn aux_match_line(
    stmt: &IrStmt,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    source_lines: &[String],
) -> State {
    let lineno = stmt_lineno(stmt);
    if lineno == 0 || lineno > source_lines.len() {
        return state.clone();
    }
    let line_text = source_lines[lineno - 1].clone();
    let lhs_key: Option<String> = if let IrStmt::Assign { lhs, .. } = stmt {
        Some(canon_lhs(lhs))
    } else {
        None
    };
    let mut state = state.clone();

    // Generic guard (before the sanitizers loop) — `if EXPR: body`
    // with a terminator (return/raise/abort) in the body and
    // `not`/`in` in the condition. Cleans any tainted variable
    // mentioned on the line. Covers `if '\'' in bar: return` and
    // `if not bar.startswith(...): return` without depending on a
    // specific sanitizer.
    let stripped_full = line_text.trim_start();
    if (stripped_full.starts_with("if ") || stripped_full.starts_with("elif "))
        && (line_text.contains(" not ") || line_text.contains(" in "))
    {
        let if_indent = line_text.len() - stripped_full.len();
        for off in 0..8usize {
            let idx = lineno + off;
            if idx >= source_lines.len() {
                break;
            }
            let nxt = &source_lines[idx];
            if nxt.trim().is_empty() {
                continue;
            }
            let nxt_indent = nxt.len() - nxt.trim_start().len();
            if nxt_indent <= if_indent {
                break;
            }
            if GUARD_TERMINATOR_RE.is_match(nxt).unwrap_or(false) {
                return apply_guard_cleanup(&state, &line_text, lineno, source_lines);
            }
        }
    }

    // Sanitizers — kills the LHS taint if the line matches.
    for san in &specs.sanitizers {
        let Some(rx) = &san.raw_regex else { continue };
        if !rx.is_match(&line_text).unwrap_or(false) {
            continue;
        }
        // "sanitizer-guard" case (predicate, §10bis):
        // `if not <sanitizer>(x): abort/raise/return/break/sys.exit`.
        let stripped = line_text.trim_start();
        let if_indent = line_text.len() - stripped.len();
        // A brace-language guard can end on its own line:
        // `if (!ALLOWED.Contains(cmd)) return Forbid();`. The Python
        // dataflow engine only looks at the following, more indented
        // lines (its own syntax); the Audit read C#/PHP/JS guards with its
        // lexical engine, which also tests the guard line (ticket #178).
        let brace_if = stripped.starts_with("if (") || stripped.starts_with("if(");
        let mut terminator_nearby = brace_if
            && GUARD_TERMINATOR_SAMELINE_RE
                .is_match(&line_text)
                .unwrap_or(false);
        let mut reassign_var: Option<String> = None;
        if let Ok(Some(caps)) = GUARD_REASSIGN_SAMELINE_RE.captures(&line_text) {
            reassign_var = caps.get(1).map(|m| m.as_str().to_string());
        }
        for off in 0..8usize {
            if terminator_nearby {
                break;
            }
            let idx = lineno + off;
            if idx >= source_lines.len() {
                break;
            }
            let nxt = &source_lines[idx];
            if nxt.trim().is_empty() {
                continue;
            }
            let nxt_indent = nxt.len() - nxt.trim_start().len();
            if nxt_indent <= if_indent {
                break; // exited the if block
            }
            if GUARD_TERMINATOR_RE.is_match(nxt).unwrap_or(false) {
                terminator_nearby = true;
                break;
            }
            if reassign_var.is_none()
                && let Ok(Some(caps)) = GUARD_REASSIGN_NEXTLINE_RE.captures(nxt)
            {
                reassign_var = caps.get(1).map(|m| m.as_str().to_string());
            }
        }
        let has_negation = line_text.contains(" not ")
            || line_text.contains(" in ")
            || NEGATION_BANG_RE.is_match(&line_text).unwrap_or(false);
        let is_guard = (stripped.starts_with("if ")
            || stripped.starts_with("if(")
            || stripped.starts_with("elif "))
            && has_negation
            && (terminator_nearby || reassign_var.is_some());
        if is_guard {
            if terminator_nearby {
                let line_text_no_lit = strip_plain_string_literals(&line_text);
                let keys: Vec<String> = state.keys().cloned().collect();
                for var_name in &keys {
                    if line_text_no_lit.contains(var_name.as_str())
                        && state_get(&state, var_name).is_tainted()
                    {
                        state = state_set(&state, var_name, Taint::Clean);
                    }
                }
            } else if let Some(rv) = &reassign_var {
                state = state_set(&state, rv, Taint::Clean);
            }
            return state;
        }
        if let Some(key) = &lhs_key {
            state = state_set(&state, key, Taint::Clean);
        }
        return state; // first sanitizer match is enough
    }

    // Does a user assignment line ALSO contain a sink?
    // (`result = eval(request.args.get(...))`). Excludes lowering
    // temporaries `__t{N}` — otherwise a
    // `return f"...request.args..."` (lowered to `__t0 = f"..."`)
    // would reopen detection on a LITERAL (false positive).
    let assign_line_has_sink = lhs_key
        .as_deref()
        .map(|k| !k.starts_with("__t"))
        .unwrap_or(false)
        && specs.sinks.iter().any(|s| {
            s.raw_regex
                .as_ref()
                .map(|rx| rx.is_match(&line_text).unwrap_or(false))
                .unwrap_or(false)
        });

    // Sources — marks the LHS as tainted.
    for src in &specs.sources {
        let Some(rx) = &src.raw_regex else { continue };
        if !rx.is_match(&line_text).unwrap_or(false) {
            continue;
        }
        if let Some(key) = &lhs_key {
            state = state_set(
                &state,
                key,
                Taint::tainted(
                    [src.kind.clone()],
                    SourceInfo {
                        line: lineno,
                        expr: line_text.trim().to_string(),
                        kind: src.kind.clone(),
                    },
                ),
            );
            if assign_line_has_sink {
                break; // let the sinks loop detect the inline flow
            }
            return state;
        }
        // Part 4 — only for a Call statement (direct call): a source
        // passed as an argument can feed a sink on the same line. For
        // a Return/Branch, a LITERAL source in the text must not open
        // sink detection.
        if matches!(stmt, IrStmt::Call { .. }) {
            break;
        }
        return state;
    }

    // Sinks — emits a finding if a taint is visible on the line.
    for sink in &specs.sinks {
        let Some(rx) = &sink.raw_regex else { continue };
        if !rx.is_match(&line_text).unwrap_or(false) {
            continue;
        }
        // Multi-line call: if the line opens unbalanced parentheses,
        // extends the search text to the continuation lines (until
        // balanced, capped at 25 lines).
        let mut scan_text = line_text.clone();
        let mut paren_depth =
            line_text.matches('(').count() as i64 - line_text.matches(')').count() as i64;
        if paren_depth > 0 {
            let mut span = vec![line_text.clone()];
            let mut j = lineno; // source_lines[lineno-1] == line_text ; next = index lineno
            let j_end = (lineno + 25).min(source_lines.len());
            while j < j_end && paren_depth > 0 {
                let cont = &source_lines[j];
                span.push(cont.clone());
                paren_depth += cont.matches('(').count() as i64 - cont.matches(')').count() as i64;
                j += 1;
            }
            scan_text = span.join("\n");
            // A sanitizer written in the continuation clears the sink, as
            // it does on a one-line call (the sanitizers loop above returns
            // before this loop). Deliberate deviation from Python
            // (`transfer.py`), which searched the tainted variable over the
            // whole call but the sanitizer on its first line only: every
            // SQLAlchemy `db.execute(\n select(...).where(x == p))` was an
            // injection (my-ia, 2026-11-14).
            let continuation = &span[1..].join("\n");
            if specs.sanitizers.iter().any(|san| {
                san.raw_regex
                    .as_ref()
                    .is_some_and(|rx| rx.is_match(continuation).unwrap_or(false))
            }) {
                continue;
            }
        }
        let scan_text_no_lit = strip_plain_string_literals(&scan_text);
        let mut hit = false;
        for (var_name, var_taint) in state.iter() {
            if scan_text_no_lit.contains(var_name.as_str()) && var_taint.is_tainted() {
                if !kinds_compatible(var_taint, &sink.kinds) {
                    continue;
                }
                let mut source_line = None;
                let mut source_kind = "unknown".to_string();
                let mut flow = Vec::new();
                if let Taint::Tainted { source, .. } = var_taint {
                    source_line = Some(source.line);
                    source_kind = if source.kind.is_empty() {
                        "unknown".to_string()
                    } else {
                        source.kind.clone()
                    };
                    flow.push(FlowStep {
                        line: source.line,
                        kind: "source".to_string(),
                        text: source.expr.clone(),
                        file: None,
                        code: None,
                    });
                }
                flow.push(FlowStep {
                    line: lineno,
                    kind: "sink".to_string(),
                    text: line_text.trim().to_string(),
                    file: None,
                    code: None,
                });
                findings.push(Finding {
                    rule_id: specs.rule_id.clone(),
                    severity: specs.severity.clone(),
                    line: lineno,
                    column: 0,
                    sink_text: line_text.trim().to_string(),
                    source_line,
                    message: specs.message.clone(),
                    cwe: specs.cwe.clone(),
                    flow,
                    source_kind,
                });
                hit = true;
                break; // one finding per sink line is enough
            }
        }

        // Part 4 — source written DIRECTLY on the sink line, with no
        // intermediate variable.
        if !hit {
            for src in &specs.sources {
                let Some(rx) = &src.raw_regex else { continue };
                if !rx.is_match(&line_text).unwrap_or(false) {
                    continue;
                }
                if !kind_str_compatible(&src.kind, &sink.kinds) {
                    continue;
                }
                findings.push(Finding {
                    rule_id: specs.rule_id.clone(),
                    severity: specs.severity.clone(),
                    line: lineno,
                    column: 0,
                    sink_text: line_text.trim().to_string(),
                    source_line: Some(lineno),
                    message: specs.message.clone(),
                    cwe: specs.cwe.clone(),
                    flow: vec![
                        FlowStep {
                            line: lineno,
                            kind: "source".to_string(),
                            text: line_text.trim().to_string(),
                            file: None,
                            code: None,
                        },
                        FlowStep {
                            line: lineno,
                            kind: "sink".to_string(),
                            text: line_text.trim().to_string(),
                            file: None,
                            code: None,
                        },
                    ],
                    source_kind: src.kind.clone(),
                });
                break; // one source is enough
            }
        }
    }

    state
}

// ============================================================================
// Spec format
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecKind {
    Source,
    Sink,
    Sanitizer,
    Passthrough,
    Unknown,
}

/// Compiles an SCA glob pattern into an anchored regex (§7.1).
///
/// Supported syntax:
///   - `foo`        : exact match
///   - `foo.bar`    : exact with dots
///   - `foo.*`      : a direct child of foo (1 segment)
///   - `*.execute`  : any execute method (1 segment before)
///   - `**.execute` : any execute method at any depth
///
/// `*` does not cross dots; `**` does.
pub fn compile_glob_pattern(pattern: &str) -> Regex {
    if !pattern.contains('*') {
        return Regex::new(&format!("^{}$", regex::escape(pattern))).expect("regex literal valide");
    }
    let mut out = String::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '*' && i + 1 < chars.len() && chars[i + 1] == '*' {
            out.push_str(".*");
            i += 2;
        } else if c == '*' {
            out.push_str("[^.]*");
            i += 1;
        } else {
            out.push_str(&regex::escape(&c.to_string()));
            i += 1;
        }
    }
    Regex::new(&format!("^{out}$")).expect("regex glob valide")
}

/// Matches a dotted name against a pre-compiled glob regex (§7.1).
/// A fancy-regex error (backtracking limit exceeded) is treated as a
/// non-match — a conservative choice, with no equivalent failure mode
/// in Python's standard `re`.
pub fn match_pattern(callee_name: &str, compiled: &Regex) -> bool {
    compiled.is_match(callee_name).unwrap_or(false)
}

#[derive(Debug, Clone)]
pub struct SourceSpec {
    pub pattern: String,
    pub kind: String,
    /// Phase 7 — regex over the raw source line (§10bis, next component).
    pub raw_regex: Option<Regex>,
    compiled: Regex,
}

impl SourceSpec {
    pub fn new(pattern: impl Into<String>, kind: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let compiled = compile_glob_pattern(&pattern);
        SourceSpec {
            pattern,
            kind: kind.into(),
            raw_regex: None,
            compiled,
        }
    }

    pub fn with_raw_regex(mut self, re: Regex) -> Self {
        self.raw_regex = Some(re);
        self
    }
}

#[derive(Debug, Clone)]
pub struct SinkSpec {
    pub pattern: String,
    /// Empty = all arguments.
    pub args: Vec<usize>,
    /// Empty = all kinds.
    pub kinds: Vec<String>,
    pub raw_regex: Option<Regex>,
    compiled: Regex,
}

impl SinkSpec {
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let compiled = compile_glob_pattern(&pattern);
        SinkSpec {
            pattern,
            args: Vec::new(),
            kinds: Vec::new(),
            raw_regex: None,
            compiled,
        }
    }

    pub fn with_args(mut self, args: Vec<usize>) -> Self {
        self.args = args;
        self
    }

    pub fn with_kinds(mut self, kinds: Vec<String>) -> Self {
        self.kinds = kinds;
        self
    }

    pub fn with_raw_regex(mut self, re: Regex) -> Self {
        self.raw_regex = Some(re);
        self
    }
}

#[derive(Debug, Clone)]
pub struct SanitizerSpec {
    pub pattern: String,
    pub args: Vec<usize>,
    pub raw_regex: Option<Regex>,
    compiled: Regex,
}

impl SanitizerSpec {
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let compiled = compile_glob_pattern(&pattern);
        SanitizerSpec {
            pattern,
            args: Vec::new(),
            raw_regex: None,
            compiled,
        }
    }

    pub fn with_raw_regex(mut self, re: Regex) -> Self {
        self.raw_regex = Some(re);
        self
    }
}

/// Target of a passthrough's propagation: the return value, or a
/// mutated argument (positional index).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgOut {
    Return,
    Index(usize),
}

#[derive(Debug, Clone)]
pub struct PassthroughSpec {
    pub pattern: String,
    /// Empty = all arguments.
    pub args_in: Vec<usize>,
    pub arg_out: ArgOut,
    pub raw_regex: Option<Regex>,
    compiled: Regex,
}

impl PassthroughSpec {
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let compiled = compile_glob_pattern(&pattern);
        PassthroughSpec {
            pattern,
            args_in: Vec::new(),
            arg_out: ArgOut::Return,
            raw_regex: None,
            compiled,
        }
    }

    pub fn with_args_in(mut self, args_in: Vec<usize>) -> Self {
        self.args_in = args_in;
        self
    }
}

/// The complete set of specs for a taint rule.
#[derive(Debug, Clone, Default)]
pub struct RuleSpecs {
    pub rule_id: String,
    pub severity: String,
    pub cwe: Option<String>,
    pub message: String,
    pub sources: Vec<SourceSpec>,
    pub sinks: Vec<SinkSpec>,
    pub sanitizers: Vec<SanitizerSpec>,
    pub passthroughs: Vec<PassthroughSpec>,
    /// Part 2 — interprocedural function summaries, indexed by callee
    /// name. Populated by `call_graph.rs::resolve_summaries` before
    /// the main analysis; consulted in `eval_call` to propagate taint
    /// across calls.
    pub summaries: BTreeMap<String, Arc<FunctionSummary>>,
    /// **Java only** — `variable_name/field -> simple_class_name`
    /// (merge of `collect_java_field_types`/`collect_java_local_types`,
    /// locals take priority). Always empty on the Python side (no
    /// declared typed variable to resolve). Lets `eval_call` resolve
    /// `scr.method()` where `scr` is a local variable/field of known
    /// type, falling back to `"{type}.{attr}"` when the variable name
    /// alone matches no summary (a summary key is always indexed by
    /// CLASS name, never by variable name) — Round 5, cf.
    /// `Audit/sca/dataflow/transfer.py`.
    pub type_map: BTreeMap<String, String>,
}

/// "Summary sheet" of a function's taint behavior — describes how
/// taint flows through its calls.
/// `PartialEq`: used by `call_graph.rs` to detect fixpoint
/// convergence per SCC (correction vs Python, Decision #3).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FunctionSummary {
    pub name: String,
    /// Positional parameters (excluding self/cls).
    pub param_names: Vec<String>,
    /// True if an internal source reaches the `return` regardless of
    /// arguments (e.g. `return request.GET[...]`).
    pub return_tainted_uncond: bool,
    /// Nature of the unconditional return taint (http…).
    pub return_kind: Option<String>,
    /// Index of parameters whose taint reaches the return.
    pub return_taint_params: BTreeSet<usize>,
    /// For each parameter index reaching a sink, a template finding
    /// to re-emit at the call site.
    pub sink_param_findings: BTreeMap<usize, Finding>,
}

// ============================================================================
// Finding
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct FlowStep {
    pub line: usize,
    /// "source" | "propagation" | "sink".
    pub kind: String,
    pub text: String,
    /// File of the step, relative to the scanned root, when it differs
    /// from the finding's own file: set on the steps of a cross-file
    /// function summary (`call_graph::compute_one`). `None` means the
    /// finding's file.
    pub file: Option<String>,
    /// The source line of the step (trimmed), stamped with `file` so
    /// that the report can show the code of another file without
    /// reading it again. `None`: read from the finding's file.
    pub code: Option<String>,
}

/// A reported taint finding, conforming to CONTRACT-SCA-AUDITAI.md §3.2.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub line: usize,
    pub column: usize,
    pub sink_text: String,
    pub source_line: Option<usize>,
    pub message: String,
    pub cwe: Option<String>,
    pub flow: Vec<FlowStep>,
    pub source_kind: String,
}

// ============================================================================
// Spec resolution
// ============================================================================

/// Result of `resolve_spec` — the variant encodes the `SpecKind`
/// directly (no separate `(kind, spec)` tuple like on the Python side).
pub enum ResolvedSpec<'a> {
    Source(&'a SourceSpec),
    Sink(&'a SinkSpec),
    Sanitizer(&'a SanitizerSpec),
    Passthrough(&'a PassthroughSpec),
    Unknown,
}

/// Resolves a callee name against a rule's specs.
/// Priority (§5.2): SOURCE > SINK > SANITIZER > PASSTHROUGH > UNKNOWN.
pub fn resolve_spec<'a>(callee_name: &str, specs: &'a RuleSpecs) -> ResolvedSpec<'a> {
    for s in &specs.sources {
        if match_pattern(callee_name, &s.compiled) {
            return ResolvedSpec::Source(s);
        }
    }
    for s in &specs.sinks {
        if match_pattern(callee_name, &s.compiled) {
            return ResolvedSpec::Sink(s);
        }
    }
    for s in &specs.sanitizers {
        if match_pattern(callee_name, &s.compiled) {
            return ResolvedSpec::Sanitizer(s);
        }
    }
    for s in &specs.passthroughs {
        if match_pattern(callee_name, &s.compiled) {
            return ResolvedSpec::Passthrough(s);
        }
    }
    ResolvedSpec::Unknown
}

fn check_source_match(name: &str, specs: &RuleSpecs, lineno: usize) -> Option<Taint> {
    for s in &specs.sources {
        if match_pattern(name, &s.compiled) {
            return Some(Taint::tainted(
                [s.kind.clone()],
                SourceInfo {
                    line: lineno,
                    expr: name.to_string(),
                    kind: s.kind.clone(),
                },
            ));
        }
    }
    None
}

fn kinds_compatible(t: &Taint, sink_kinds: &[String]) -> bool {
    if sink_kinds.is_empty() {
        return true;
    }
    match t {
        Taint::Top => true,
        Taint::Tainted { kinds, .. } => kinds.iter().any(|k| sink_kinds.contains(k)),
        Taint::Clean => false,
    }
}

/// Canonical representation of an access key, for state keys
/// (literal `obj['k']` vs dynamic `obj[*]`) — same convention as
/// `ir::canon_subscript_key`.
fn key_repr(rhs: &Rhs) -> String {
    canon_subscript_key(rhs)
}

// ============================================================================
// RHS evaluation (§5.1)
// ============================================================================

pub fn eval_rhs(
    rhs: &Rhs,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    lineno: usize,
) -> Taint {
    match rhs {
        Rhs::Const(_) => Taint::Clean,
        Rhs::VarRef(name) => {
            if let Some(t) = check_source_match(name, specs, lineno) {
                return t;
            }
            // §9.bis — aggregates indexed sub-entries: if `obj['k']`
            // is tainted, reading `obj` as a whole must pick up that
            // taint.
            let mut base = state_get(state, name);
            let prefix = format!("{name}[");
            for (key, t) in state.iter() {
                if key.starts_with(&prefix) {
                    base = join(&base, t);
                }
            }
            base
        }
        Rhs::AttrRef { base, .. } => {
            let attr_name = canon_callee(rhs);
            if let Some(t) = check_source_match(&attr_name, specs, lineno) {
                return t;
            }
            let attr_key = canon_rhs(rhs);
            join(
                &state_get(state, &attr_key),
                &eval_rhs(base, state, specs, findings, lineno),
            )
        }
        Rhs::SubscriptRef { base, key } => {
            let sub_key = canon_rhs(rhs);
            let base_key = canon_rhs(base);
            let sub_taint = state_get(state, &sub_key);
            if matches!(key.as_ref(), Rhs::Const(_)) {
                if state.contains_key(&sub_key) {
                    return sub_taint;
                }
                let wildcard_taint = state_get(state, &format!("{base_key}[*]"));
                let base_direct = state_get(state, &base_key);
                return join(&wildcard_taint, &base_direct);
            }
            join(
                &join(&sub_taint, &state_get(state, &base_key)),
                &join(
                    &eval_rhs(base, state, specs, findings, lineno),
                    &eval_rhs(key, state, specs, findings, lineno),
                ),
            )
        }
        Rhs::BinOp { left, right, .. } => join(
            &eval_rhs(left, state, specs, findings, lineno),
            &eval_rhs(right, state, specs, findings, lineno),
        ),
        Rhs::UnaryOp { operand, .. } => eval_rhs(operand, state, specs, findings, lineno),
        Rhs::Cmp { left, right, .. } => {
            eval_rhs(left, state, specs, findings, lineno);
            eval_rhs(right, state, specs, findings, lineno);
            Taint::Clean
        }
        Rhs::Bool { operands, .. } => operands.iter().fold(Taint::Clean, |acc, op| {
            join(&acc, &eval_rhs(op, state, specs, findings, lineno))
        }),
        Rhs::TupleRef(elements) | Rhs::ListRef(elements) | Rhs::SetRef(elements) => {
            elements.iter().fold(Taint::Clean, |acc, e| {
                join(&acc, &eval_rhs(e, state, specs, findings, lineno))
            })
        }
        Rhs::DictRef(items) => items.iter().fold(Taint::Clean, |acc, (k, v)| {
            let acc = join(&acc, &eval_rhs(k, state, specs, findings, lineno));
            join(&acc, &eval_rhs(v, state, specs, findings, lineno))
        }),
        Rhs::Star { inner, .. } => eval_rhs(inner, state, specs, findings, lineno),
        Rhs::IfExp { cond, then, orelse } => {
            // §9 — conservative semantics: evaluates the condition for
            // its effects, then joins both branches. Simplification
            // when cond is Const-evaluable is done upstream by
            // `_compute_dead_edges` (const_eval.rs).
            eval_rhs(cond, state, specs, findings, lineno);
            join(
                &eval_rhs(then, state, specs, findings, lineno),
                &eval_rhs(orelse, state, specs, findings, lineno),
            )
        }
        Rhs::LambdaRef { .. } => Taint::Clean,
        Rhs::CallRef {
            callee,
            args,
            kwargs,
        } => eval_call(callee, args, kwargs, state, specs, findings, lineno),
    }
}

// ============================================================================
// Call evaluation (§5.2)
// ============================================================================

/// Detects a source via regex over the TEXT of a single call argument
/// (§7, part 4). Lets a source passed directly as an argument
/// (`run_query(request.GET["q"])`) be tainted with no intermediate
/// variable. Only consulted when `eval_rhs` has already returned
/// CLEAN for that argument.
fn arg_regex_source(arg: &Rhs, specs: &RuleSpecs, lineno: usize) -> Option<Taint> {
    let mut expr: Option<String> = None;
    for src in &specs.sources {
        let Some(rx) = &src.raw_regex else { continue };
        let e = expr.get_or_insert_with(|| pretty_rhs(arg));
        if rx.is_match(e).unwrap_or(false) {
            return Some(Taint::tainted(
                [src.kind.clone()],
                SourceInfo {
                    line: lineno,
                    expr: e.clone(),
                    kind: src.kind.clone(),
                },
            ));
        }
    }
    None
}

pub fn eval_call(
    callee: &Rhs,
    args: &[Rhs],
    kwargs: &[(String, Rhs)],
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    lineno: usize,
) -> Taint {
    let arg_taints: Vec<Taint> = args
        .iter()
        .map(|arg| {
            let t = eval_rhs(arg, state, specs, findings, lineno);
            if t.is_clean() {
                arg_regex_source(arg, specs, lineno).unwrap_or(t)
            } else {
                t
            }
        })
        .collect();
    let kw_taints: BTreeMap<String, Taint> = kwargs
        .iter()
        .map(|(name, val)| {
            let t = eval_rhs(val, state, specs, findings, lineno);
            let t = if t.is_clean() {
                arg_regex_source(val, specs, lineno).unwrap_or(t)
            } else {
                t
            };
            (name.clone(), t)
        })
        .collect();

    let callee_name = canon_callee(callee);
    // The receiver is also evaluated for its effects AND its taint
    // (e.g. `request.args` in `request.args.get(...)`) — propagates
    // to the result.
    let callee_taint = eval_rhs(callee, state, specs, findings, lineno);

    match resolve_spec(&callee_name, specs) {
        ResolvedSpec::Source(spec) => Taint::tainted(
            [spec.kind.clone()],
            SourceInfo {
                line: lineno,
                expr: callee_name,
                kind: spec.kind.clone(),
            },
        ),
        ResolvedSpec::Sink(spec) => {
            check_sink(
                spec,
                &callee_name,
                &arg_taints,
                &kw_taints,
                specs,
                findings,
                lineno,
            );
            Taint::Clean
        }
        ResolvedSpec::Sanitizer(_) => Taint::Clean,
        ResolvedSpec::Passthrough(spec) => {
            let passthrough_result = eval_passthrough(spec, &arg_taints, &kw_taints);
            join(&passthrough_result, &callee_taint)
        }
        ResolvedSpec::Unknown => {
            // Part 2 — call to a summarized user function
            // (interprocedural). Additive: emits sinks reached across
            // the call, and taints the return if the function has an
            // unconditional internal source.
            let mut callee_name = callee_name;
            let mut summary = specs.summaries.get(&callee_name);

            // Round 5 (Java) — `scr.method()` where `scr` is a local
            // variable/field of known type: the direct lookup by
            // variable name always fails (no summary is ever indexed
            // by variable name) — retry via the declared class name.
            // `specs.type_map` is always empty on the Python side (cf.
            // `RuleSpecs` doc), so it has no effect there.
            if summary.is_none()
                && !specs.type_map.is_empty()
                && let Rhs::AttrRef { base, attr } = callee
                && let Rhs::VarRef(var_name) = base.as_ref()
                && let Some(declared_type) = specs.type_map.get(var_name)
            {
                callee_name = format!("{declared_type}.{attr}");
                summary = specs.summaries.get(&callee_name);
            }
            // Round 6 (Java) — chained call `new ClassName(...).method(...)`:
            // `java_lowering.rs::lower_method_invocation` inlines the
            // constructor's `CallRef` as the base of the `AttrRef`
            // precisely to enable this resolution. No language guard
            // needed: this form is only produced by Java lowering,
            // with no effect on Python (never built by `lowering.rs`).
            if summary.is_none()
                && let Rhs::AttrRef { base, attr } = callee
                && let Rhs::CallRef {
                    callee: ctor_callee,
                    ..
                } = base.as_ref()
                && let Rhs::VarRef(ctor_type_name) = ctor_callee.as_ref()
            {
                callee_name = format!("{ctor_type_name}.{attr}");
                summary = specs.summaries.get(&callee_name);
            }

            if let Some(s) = summary {
                findings.extend(apply_summary_at_call(
                    s,
                    &callee_name,
                    &arg_taints,
                    specs,
                    lineno,
                ));
            }

            // §9.bis — precise indexed read, short-circuits the
            // generic over-approximation below.
            if let Some(t) = try_indexed_read(callee, args, state, &arg_taints) {
                return t;
            }

            // UNKNOWN with no summary: over-approximation (SCA-9
            // choice). With a summary: precise positional narrowing
            // via `return_taint_params` (the receiver and kwargs
            // remain over-approximated — not modeled by the probe).
            let mut result = callee_taint;
            if let Some(s) = summary {
                for (i, t) in arg_taints.iter().enumerate() {
                    if s.return_taint_params.contains(&i) {
                        result = join(&result, t);
                    }
                }
            } else {
                for t in &arg_taints {
                    result = join(&result, t);
                }
            }
            for t in kw_taints.values() {
                result = join(&result, t);
            }
            // Part 2 — unconditional internal source: the return is
            // tainted even with no tainted argument.
            if let Some(s) = summary
                && s.return_tainted_uncond
            {
                let kind = s.return_kind.clone().unwrap_or_else(|| "http".to_string());
                result = join(
                    &result,
                    &Taint::tainted(
                        [kind.clone()],
                        SourceInfo {
                            line: lineno,
                            expr: format!("{callee_name}()"),
                            kind,
                        },
                    ),
                );
            }
            result
        }
    }
}

/// Builds "sink reached through a call" findings from a callee's
/// summary. A tainted argument passed to a parameter that the summary
/// marks as reaching a sink triggers a finding at the call site, with
/// a flow that crosses the call boundary.
fn apply_summary_at_call(
    summary: &FunctionSummary,
    callee_name: &str,
    arg_taints: &[Taint],
    specs: &RuleSpecs,
    lineno: usize,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (&param_idx, template) in &summary.sink_param_findings {
        let Some(arg_t) = arg_taints.get(param_idx) else {
            continue;
        };
        if !arg_t.is_tainted() {
            continue;
        }
        let mut source_line = None;
        let mut source_kind = "unknown".to_string();
        let mut flow = Vec::new();
        if let Taint::Tainted { source, .. } = arg_t {
            source_line = Some(source.line);
            source_kind = if source.kind.is_empty() {
                "unknown".to_string()
            } else {
                source.kind.clone()
            };
            flow.push(FlowStep {
                line: source.line,
                kind: "source".to_string(),
                text: source.expr.clone(),
                file: None,
                code: None,
            });
        }
        // Explicit interprocedural step (contains "→").
        flow.push(FlowStep {
            line: lineno,
            kind: "propagation".to_string(),
            text: format!("{callee_name}(...) → {}", template.sink_text),
            file: None,
            code: None,
        });
        // The callee's own path (its propagations and its real sink, with
        // their file once `call_graph` stamped them), not just its name:
        // the report must show where the query is actually written
        // (my-ia: `_reponse(...) → get_usage(...)` named the call, never
        // the `db.execute` of `quotas.py`). Its source step is the
        // callee's parameter, replaced by the caller's real source above.
        let inner: Vec<FlowStep> = template
            .flow
            .iter()
            .filter(|s| s.kind != "source")
            .cloned()
            .collect();
        if inner.iter().any(|s| s.kind == "sink") {
            flow.extend(inner);
        } else {
            flow.push(FlowStep {
                line: template.line,
                kind: "sink".to_string(),
                text: template.sink_text.clone(),
                file: None,
                code: None,
            });
        }
        out.push(Finding {
            rule_id: specs.rule_id.clone(),
            severity: specs.severity.clone(),
            line: lineno,
            column: 0,
            sink_text: format!("{callee_name}(...)"),
            source_line,
            message: specs.message.clone(),
            cwe: specs.cwe.clone(),
            flow,
            source_kind,
        });
    }
    out
}

fn check_sink(
    spec: &SinkSpec,
    callee_name: &str,
    arg_taints: &[Taint],
    _kw_taints: &BTreeMap<String, Taint>,
    rule_specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    lineno: usize,
) {
    let indices: Vec<usize> = if spec.args.is_empty() {
        (0..arg_taints.len()).collect()
    } else {
        spec.args.clone()
    };
    for idx in indices {
        let Some(t) = arg_taints.get(idx) else {
            continue;
        };
        if t.is_clean() {
            continue;
        }
        if !kinds_compatible(t, &spec.kinds) {
            continue;
        }
        let mut source_line = None;
        let mut source_kind = "unknown".to_string();
        let mut flow = Vec::new();
        if let Taint::Tainted { source, .. } = t {
            source_line = Some(source.line);
            source_kind = if source.kind.is_empty() {
                "unknown".to_string()
            } else {
                source.kind.clone()
            };
            flow.push(FlowStep {
                line: source.line,
                kind: "source".to_string(),
                text: source.expr.clone(),
                file: None,
                code: None,
            });
        }
        flow.push(FlowStep {
            line: lineno,
            kind: "sink".to_string(),
            text: callee_name.to_string(),
            file: None,
            code: None,
        });
        findings.push(Finding {
            rule_id: rule_specs.rule_id.clone(),
            severity: rule_specs.severity.clone(),
            line: lineno,
            column: 0,
            sink_text: callee_name.to_string(),
            source_line,
            message: rule_specs.message.clone(),
            cwe: rule_specs.cwe.clone(),
            flow,
            source_kind,
        });
        // One finding per tainted argument: no early return, every
        // distinct vector must be flagged.
    }
}

fn eval_passthrough(
    spec: &PassthroughSpec,
    arg_taints: &[Taint],
    kw_taints: &BTreeMap<String, Taint>,
) -> Taint {
    let _ = kw_taints; // signature aligned with Python, kwargs not consulted here (§7.2)
    let indices: Vec<usize> = if spec.args_in.is_empty() {
        (0..arg_taints.len()).collect()
    } else {
        spec.args_in.clone()
    };
    let mut result = Taint::Clean;
    for idx in indices {
        if let Some(t) = arg_taints.get(idx) {
            result = join(&result, t);
        }
    }
    result
}

// ============================================================================
// Indexed read/write (object mutation, §9.bis)
// ============================================================================

const INDEXED_WRITE_METHODS: &[&str] = &["set", "setdefault", "__setitem__", "put"];
const BULK_UPDATE_METHODS: &[&str] = &["update"];
const ELEMENT_WRITE_METHODS: &[&str] = &["append", "extend", "insert", "add"];
const RECEIVER_WRITE_METHODS: &[&str] = &["write", "writelines"];
const INDEXED_READ_METHODS: &[&str] = &["get", "__getitem__", "setdefault", "pop"];

fn is_mutation_method(m: &str) -> bool {
    INDEXED_WRITE_METHODS.contains(&m)
        || BULK_UPDATE_METHODS.contains(&m)
        || ELEMENT_WRITE_METHODS.contains(&m)
        || RECEIVER_WRITE_METHODS.contains(&m)
}

/// Indexed read for dict/configparser-style methods
/// (`get`/`__getitem__`/`setdefault`/`pop`). Returns `None` if the
/// signature doesn't support a precise indexed read (the caller then
/// falls back to the UNKNOWN over-approximation); `Some(Taint::Clean)`
/// is a valid precise result (a known, untainted read).
fn try_indexed_read(
    callee: &Rhs,
    args: &[Rhs],
    state: &State,
    arg_taints: &[Taint],
) -> Option<Taint> {
    let Rhs::AttrRef { base, attr } = callee else {
        return None;
    };
    if !INDEXED_READ_METHODS.contains(&attr.as_str()) {
        return None;
    }
    let base_key = canon_rhs(base);
    if base_key.is_empty()
        || base_key == "<unknown>"
        || base_key == "<call>"
        || base_key.starts_with('<')
    {
        return None;
    }
    let first_arg = args.first()?;

    let k0 = key_repr(first_arg);
    let one_level = format!("{base_key}[{k0}]");
    let wildcard = format!("{base_key}[*]");
    let base_direct = state_get(state, &base_key);
    let wildcard_taint = state_get(state, &wildcard);

    // configparser-style (section, option) on get/__getitem__.
    if args.len() >= 2 && (attr == "get" || attr == "__getitem__") {
        let k1 = key_repr(&args[1]);
        let two_level = format!("{base_key}[{k0}][{k1}]");
        let two_level_wild = format!("{base_key}[{k0}][*]");
        if state.contains_key(&two_level) || state.contains_key(&two_level_wild) {
            let t = join(
                &state_get(state, &two_level),
                &state_get(state, &two_level_wild),
            );
            return Some(join(&join(&t, &base_direct), &wildcard_taint));
        }
    }

    let mut result = state_get(state, &one_level);
    result = join(&result, &wildcard_taint);
    result = join(&result, &base_direct);
    if args.len() >= 2
        && (attr == "get" || attr == "pop" || attr == "setdefault")
        && let Some(t) = arg_taints.get(1)
    {
        result = join(&result, t);
    }
    Some(result)
}

// ============================================================================
// Per-statement transfer functions (§5)
// ============================================================================

/// Canonical target to match against sink patterns for an assignable
/// lhs (`SubscriptLhs`/`AttrLhs` only — `VarLhs`/`TupleLhs`/`StarLhs`
/// are never sinks).
fn lhs_sink_target(lhs: &Lhs) -> Option<String> {
    match lhs {
        Lhs::SubscriptLhs { base, .. } => Some(canon_rhs(base)),
        Lhs::AttrLhs { .. } => Some(canon_lhs(lhs)),
        _ => None,
    }
}

fn transfer_assign(
    stmt_lhs: &Lhs,
    stmt_rhs: &Rhs,
    lineno: usize,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
) -> State {
    let rhs_taint = eval_rhs(stmt_rhs, state, specs, findings, lineno);
    if rhs_taint.is_tainted()
        && let Some(target_name) = lhs_sink_target(stmt_lhs)
    {
        for sink in &specs.sinks {
            if !match_pattern(&target_name, &sink.compiled) {
                continue;
            }
            if !kinds_compatible(&rhs_taint, &sink.kinds) {
                continue;
            }
            let mut source_line = None;
            let mut source_kind = "unknown".to_string();
            let mut flow = Vec::new();
            if let Taint::Tainted { source, .. } = &rhs_taint {
                source_line = Some(source.line);
                source_kind = if source.kind.is_empty() {
                    "unknown".to_string()
                } else {
                    source.kind.clone()
                };
                flow.push(FlowStep {
                    line: source.line,
                    kind: "source".to_string(),
                    text: source.expr.clone(),
                    file: None,
                    code: None,
                });
            }
            flow.push(FlowStep {
                line: lineno,
                kind: "sink".to_string(),
                text: target_name.clone(),
                file: None,
                code: None,
            });
            findings.push(Finding {
                rule_id: specs.rule_id.clone(),
                severity: specs.severity.clone(),
                line: lineno,
                column: 0,
                sink_text: target_name.clone(),
                source_line,
                message: specs.message.clone(),
                cwe: specs.cwe.clone(),
                flow,
                source_kind,
            });
            break; // one finding per assignment is enough
        }
    }
    assign_lhs(stmt_lhs, rhs_taint, state)
}

fn assign_lhs(lhs: &Lhs, taint: Taint, state: &State) -> State {
    match lhs {
        Lhs::VarLhs(name) => state_set(state, name, taint),
        Lhs::AttrLhs { .. } | Lhs::SubscriptLhs { .. } => state_set(state, &canon_lhs(lhs), taint),
        Lhs::TupleLhs(elements) => {
            let mut new_state = state.clone();
            for elt in elements {
                new_state = assign_lhs(elt, taint.clone(), &new_state);
            }
            new_state
        }
        Lhs::StarLhs(inner) => assign_lhs(inner, taint, state),
    }
}

fn compute_indexed_write_key(
    callee_attr: &str,
    call_args: &[Rhs],
    base_key: &str,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    lineno: usize,
) -> Option<(String, Taint)> {
    if !INDEXED_WRITE_METHODS.contains(&callee_attr) {
        return None;
    }
    if call_args.len() == 2 {
        let kstr = key_repr(&call_args[0]);
        let val_taint = eval_rhs(&call_args[1], state, specs, findings, lineno);
        return Some((format!("{base_key}[{kstr}]"), val_taint));
    }
    if call_args.len() == 3 && callee_attr == "set" {
        let k0 = key_repr(&call_args[0]);
        let k1 = key_repr(&call_args[1]);
        let val_taint = eval_rhs(&call_args[2], state, specs, findings, lineno);
        return Some((format!("{base_key}[{k0}][{k1}]"), val_taint));
    }
    None
}

/// A call used as a statement (return value ignored). Models object
/// mutation — `obj.<method>(...tainted...)` — depending on the
/// method's category.
pub fn transfer_call_stmt(
    callee: &Rhs,
    call_args: &[Rhs],
    kwargs: &[(String, Rhs)],
    lineno: usize,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
) -> State {
    eval_call(callee, call_args, kwargs, state, specs, findings, lineno);

    let Rhs::AttrRef { base, attr } = callee else {
        return state.clone();
    };
    if !is_mutation_method(attr) {
        return state.clone();
    }
    let base_key = canon_rhs(base);
    if base_key.is_empty()
        || base_key == "<unknown>"
        || base_key == "<call>"
        || base_key.starts_with('<')
    {
        return state.clone();
    }

    if INDEXED_WRITE_METHODS.contains(&attr.as_str()) {
        let Some((slot, val_taint)) =
            compute_indexed_write_key(attr, call_args, &base_key, state, specs, findings, lineno)
        else {
            return state.clone();
        };
        if val_taint.is_tainted() {
            let existing = state_get(state, &slot);
            return state_set(state, &slot, join(&existing, &val_taint));
        }
        return state.clone();
    }

    if BULK_UPDATE_METHODS.contains(&attr.as_str()) {
        return apply_bulk_update(call_args, kwargs, &base_key, state, specs, findings, lineno);
    }

    if ELEMENT_WRITE_METHODS.contains(&attr.as_str()) {
        return apply_element_write(call_args, kwargs, &base_key, state, specs, findings, lineno);
    }

    if RECEIVER_WRITE_METHODS.contains(&attr.as_str()) {
        return apply_receiver_write(call_args, kwargs, &base_key, state, specs, findings, lineno);
    }

    state.clone()
}

fn apply_bulk_update(
    call_args: &[Rhs],
    kwargs: &[(String, Rhs)],
    base_key: &str,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    lineno: usize,
) -> State {
    let mut new_state = state.clone();
    let mut items: Vec<(String, Rhs)> = Vec::new();
    if let Some(first) = call_args.first() {
        if let Rhs::DictRef(entries) = first {
            for (k, v) in entries {
                items.push((key_repr(k), v.clone()));
            }
        } else {
            let arg_taint = eval_rhs(first, &new_state, specs, findings, lineno);
            if arg_taint.is_tainted() {
                let wkey = format!("{base_key}[*]");
                let existing = state_get(&new_state, &wkey);
                new_state = state_set(&new_state, &wkey, join(&existing, &arg_taint));
            }
        }
    }
    for (kname, v) in kwargs {
        items.push((format!("'{kname}'"), v.clone()));
    }
    for (kstr, v) in &items {
        let slot = format!("{base_key}[{kstr}]");
        let vtaint = eval_rhs(v, &new_state, specs, findings, lineno);
        if vtaint.is_tainted() {
            let existing = state_get(&new_state, &slot);
            new_state = state_set(&new_state, &slot, join(&existing, &vtaint));
        }
    }
    new_state
}

fn apply_element_write(
    call_args: &[Rhs],
    kwargs: &[(String, Rhs)],
    base_key: &str,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    lineno: usize,
) -> State {
    let mut arg_taint = Taint::Clean;
    for arg in call_args {
        arg_taint = join(&arg_taint, &eval_rhs(arg, state, specs, findings, lineno));
    }
    for (_, val) in kwargs {
        arg_taint = join(&arg_taint, &eval_rhs(val, state, specs, findings, lineno));
    }
    if arg_taint.is_tainted() {
        let wkey = format!("{base_key}[*]");
        let existing = state_get(state, &wkey);
        return state_set(state, &wkey, join(&existing, &arg_taint));
    }
    state.clone()
}

fn apply_receiver_write(
    call_args: &[Rhs],
    kwargs: &[(String, Rhs)],
    base_key: &str,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    lineno: usize,
) -> State {
    let mut arg_taint = Taint::Clean;
    for arg in call_args {
        arg_taint = join(&arg_taint, &eval_rhs(arg, state, specs, findings, lineno));
    }
    for (_, val) in kwargs {
        arg_taint = join(&arg_taint, &eval_rhs(val, state, specs, findings, lineno));
    }
    if arg_taint.is_tainted() {
        let existing = state_get(state, base_key);
        return state_set(state, base_key, join(&existing, &arg_taint));
    }
    state.clone()
}

fn transfer_return(
    value: Option<&Rhs>,
    lineno: usize,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
) -> State {
    if let Some(v) = value {
        eval_rhs(v, state, specs, findings, lineno);
    }
    state.clone()
}

fn transfer_raise(
    value: Option<&Rhs>,
    lineno: usize,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
) -> State {
    if let Some(v) = value {
        eval_rhs(v, state, specs, findings, lineno);
    }
    state.clone()
}

/// Applies the transfer function of a single IR statement.
///
/// `source_lines`: if provided, enables hybrid regex matching against
/// the source line (§10bis) — lets sinks/sanitizers/sources also be
/// detected via the original DSL regexes, in addition to the pointed
/// matching, and enables `raw_regex` revalidation of sinks resolved by
/// glob (`discard_sinks_failing_raw_regex`).
pub fn transfer_stmt(
    stmt: &IrStmt,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    source_lines: Option<&[String]>,
) -> State {
    let before = findings.len();
    let new_state = match stmt {
        IrStmt::Assign { lhs, rhs, lineno } => {
            transfer_assign(lhs, rhs, *lineno, state, specs, findings)
        }
        IrStmt::Call {
            callee,
            args,
            kwargs,
            lineno,
        } => transfer_call_stmt(callee, args, kwargs, *lineno, state, specs, findings),
        IrStmt::Return { value, lineno } => {
            transfer_return(value.as_ref(), *lineno, state, specs, findings)
        }
        IrStmt::Raise { value, lineno } => {
            transfer_raise(value.as_ref(), *lineno, state, specs, findings)
        }
        IrStmt::Branch { condition, lineno } => {
            eval_rhs(condition, state, specs, findings, *lineno);
            state.clone()
        }
        IrStmt::Noop { .. } => return state.clone(),
    };
    if let Some(lines) = source_lines {
        discard_sinks_failing_raw_regex(findings, before, specs, lines);
        return aux_match_line(stmt, &new_state, specs, findings, lines);
    }
    new_state
}

/// Sequentially applies the transfer functions of a list of statements
/// (processes an entire basic block). See `transfer_stmt` for
/// `source_lines`.
pub fn transfer_stmts(
    stmts: &[IrStmt],
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    source_lines: Option<&[String]>,
) -> State {
    let mut state = state.clone();
    for stmt in stmts {
        state = transfer_stmt(stmt, &state, specs, findings, source_lines);
    }
    state
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::ir::ConstValue;
    use crate::scan::dataflow::lattice::empty_state;

    fn varref(name: &str) -> Rhs {
        Rhs::VarRef(name.to_string())
    }

    fn call(callee: Rhs, args: Vec<Rhs>) -> Rhs {
        Rhs::CallRef {
            callee: Box::new(callee),
            args,
            kwargs: vec![],
        }
    }

    fn attr(base: Rhs, name: &str) -> Rhs {
        Rhs::AttrRef {
            base: Box::new(base),
            attr: name.to_string(),
        }
    }

    fn specs_with(sources: Vec<SourceSpec>, sinks: Vec<SinkSpec>) -> RuleSpecs {
        RuleSpecs {
            rule_id: "test-rule".to_string(),
            severity: "HIGH".to_string(),
            cwe: Some("CWE-89".to_string()),
            message: "test finding".to_string(),
            sources,
            sinks,
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
        }
    }

    fn dummy_finding(sink_text: &str, line: usize) -> Finding {
        Finding {
            rule_id: "test-rule".to_string(),
            severity: "HIGH".to_string(),
            line,
            column: 0,
            sink_text: sink_text.to_string(),
            source_line: None,
            message: "test finding".to_string(),
            cwe: None,
            flow: vec![],
            source_kind: "unknown".to_string(),
        }
    }

    fn tainted(kind: &str, line: usize) -> Taint {
        Taint::tainted(
            [kind.to_string()],
            SourceInfo {
                line,
                expr: "x".to_string(),
                kind: kind.to_string(),
            },
        )
    }

    #[test]
    fn test_compile_glob_pattern_exact() {
        let re = compile_glob_pattern("os.system");
        assert!(match_pattern("os.system", &re));
        assert!(!match_pattern("os.system2", &re));
    }

    #[test]
    fn test_compile_glob_pattern_single_star() {
        let re = compile_glob_pattern("*.execute");
        assert!(match_pattern("cursor.execute", &re));
        assert!(!match_pattern("db.cursor.execute", &re));
    }

    #[test]
    fn test_compile_glob_pattern_double_star() {
        let re = compile_glob_pattern("**.execute");
        assert!(match_pattern("db.cursor.execute", &re));
        // ** requires >=1 segment before a dot; here there is no dot at all.
        assert!(!match_pattern("execute", &re));
    }

    #[test]
    fn test_eval_rhs_const_is_clean() {
        let specs = specs_with(vec![], vec![]);
        let mut findings = Vec::new();
        let t = eval_rhs(
            &Rhs::Const(ConstValue::Int(1)),
            &empty_state(),
            &specs,
            &mut findings,
            1,
        );
        assert!(t.is_clean());
    }

    #[test]
    fn test_eval_rhs_varref_source_match() {
        let specs = specs_with(vec![SourceSpec::new("request", "http")], vec![]);
        let mut findings = Vec::new();
        let t = eval_rhs(&varref("request"), &empty_state(), &specs, &mut findings, 5);
        assert!(t.is_tainted());
    }

    #[test]
    fn test_eval_rhs_attrref_source_match() {
        let specs = specs_with(vec![SourceSpec::new("request.GET", "http")], vec![]);
        let mut findings = Vec::new();
        let expr = attr(varref("request"), "GET");
        let t = eval_rhs(&expr, &empty_state(), &specs, &mut findings, 3);
        assert!(t.is_tainted());
    }

    #[test]
    fn test_eval_call_source_via_call() {
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        let expr = call(varref("input"), vec![]);
        let t = eval_rhs(&expr, &empty_state(), &specs, &mut findings, 1);
        assert!(t.is_tainted());
    }

    #[test]
    fn test_sink_emits_finding_when_arg_tainted() {
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let mut findings = Vec::new();
        let src = call(varref("input"), vec![]);
        let sink_call = call(attr(varref("os"), "system"), vec![src]);
        let t = eval_rhs(&sink_call, &empty_state(), &specs, &mut findings, 10);
        assert!(t.is_clean(), "le retour d'un sink reste clean par défaut");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 10);
        assert_eq!(findings[0].sink_text, "os.system");
    }

    #[test]
    fn test_sink_no_finding_when_arg_clean() {
        let specs = specs_with(vec![], vec![SinkSpec::new("os.system")]);
        let mut findings = Vec::new();
        let sink_call = call(
            attr(varref("os"), "system"),
            vec![Rhs::Const(ConstValue::Str("ls".to_string()))],
        );
        eval_rhs(&sink_call, &empty_state(), &specs, &mut findings, 1);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_sanitizer_clears_return_taint() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        specs.sanitizers.push(SanitizerSpec::new("shlex.quote"));
        let mut findings = Vec::new();
        let src = call(varref("input"), vec![]);
        let sanitized = call(attr(varref("shlex"), "quote"), vec![src]);
        let t = eval_rhs(&sanitized, &empty_state(), &specs, &mut findings, 1);
        assert!(t.is_clean());
    }

    #[test]
    fn test_passthrough_propagates_arg_taint() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        specs.passthroughs.push(PassthroughSpec::new("str"));
        let mut findings = Vec::new();
        let src = call(varref("input"), vec![]);
        let wrapped = call(varref("str"), vec![src]);
        let t = eval_rhs(&wrapped, &empty_state(), &specs, &mut findings, 1);
        assert!(t.is_tainted());
    }

    #[test]
    fn test_kinds_compatible_filters_sink() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        specs
            .sinks
            .push(SinkSpec::new("os.system").with_kinds(vec!["http".to_string()]));
        let mut findings = Vec::new();
        let src = call(varref("input"), vec![]); // kind = cli
        let sink_call = call(attr(varref("os"), "system"), vec![src]);
        eval_rhs(&sink_call, &empty_state(), &specs, &mut findings, 1);
        assert!(
            findings.is_empty(),
            "kind cli ne doit pas matcher un sink filtré sur http"
        );
    }

    #[test]
    fn test_transfer_assign_updates_state() {
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        let stmt = IrStmt::Assign {
            lhs: Lhs::VarLhs("x".to_string()),
            rhs: call(varref("input"), vec![]),
            lineno: 1,
        };
        let new_state = transfer_stmt(&stmt, &empty_state(), &specs, &mut findings, None);
        assert!(state_get(&new_state, "x").is_tainted());
    }

    #[test]
    fn test_transfer_assign_subscript_lhs_sink() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        specs.sinks.push(SinkSpec::new("response.headers"));
        let mut findings = Vec::new();
        let stmt = IrStmt::Assign {
            lhs: Lhs::SubscriptLhs {
                base: Box::new(attr(varref("response"), "headers")),
                key: Box::new(Rhs::Const(ConstValue::Str("X".to_string()))),
            },
            rhs: call(varref("input"), vec![]),
            lineno: 7,
        };
        transfer_stmt(&stmt, &empty_state(), &specs, &mut findings, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].sink_text, "response.headers");
    }

    #[test]
    fn test_element_write_taints_wildcard_slot() {
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        // lst.append(input())
        let stmt = IrStmt::Call {
            callee: attr(varref("lst"), "append"),
            args: vec![call(varref("input"), vec![])],
            kwargs: vec![],
            lineno: 1,
        };
        let new_state = transfer_stmt(&stmt, &empty_state(), &specs, &mut findings, None);
        assert!(state_get(&new_state, "lst[*]").is_tainted());
    }

    #[test]
    fn test_indexed_write_const_key() {
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        // d.__setitem__('k', input())  (obj[key] = value is normally
        // already desugared by SubscriptLhs, but a direct __setitem__
        // call is also a real form: configparser.set)
        let stmt = IrStmt::Call {
            callee: attr(varref("d"), "__setitem__"),
            args: vec![
                Rhs::Const(ConstValue::Str("k".to_string())),
                call(varref("input"), vec![]),
            ],
            kwargs: vec![],
            lineno: 1,
        };
        let new_state = transfer_stmt(&stmt, &empty_state(), &specs, &mut findings, None);
        assert!(state_get(&new_state, "d['k']").is_tainted());
    }

    #[test]
    fn test_indexed_read_picks_up_prior_write() {
        let specs = specs_with(vec![], vec![]);
        let mut state = empty_state();
        state = state_set(
            &state,
            "d['k']",
            Taint::tainted(
                ["cli".to_string()],
                SourceInfo {
                    line: 1,
                    expr: "x".to_string(),
                    kind: "cli".to_string(),
                },
            ),
        );
        let mut findings = Vec::new();
        // d.get('k')
        let expr = call(
            attr(varref("d"), "get"),
            vec![Rhs::Const(ConstValue::Str("k".to_string()))],
        );
        let t = eval_rhs(&expr, &state, &specs, &mut findings, 1);
        assert!(t.is_tainted());
    }

    #[test]
    fn test_transfer_return_evaluates_effects() {
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let mut findings = Vec::new();
        let sink_call = call(
            attr(varref("os"), "system"),
            vec![call(varref("input"), vec![])],
        );
        let stmt = IrStmt::Return {
            value: Some(sink_call),
            lineno: 4,
        };
        transfer_stmt(&stmt, &empty_state(), &specs, &mut findings, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_transfer_stmts_sequences_state() {
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        let stmts = vec![
            IrStmt::Assign {
                lhs: Lhs::VarLhs("x".to_string()),
                rhs: call(varref("input"), vec![]),
                lineno: 1,
            },
            IrStmt::Assign {
                lhs: Lhs::VarLhs("y".to_string()),
                rhs: varref("x"),
                lineno: 2,
            },
        ];
        let out = transfer_stmts(&stmts, &empty_state(), &specs, &mut findings, None);
        assert!(
            state_get(&out, "y").is_tainted(),
            "la taint doit se propager de x à y"
        );
    }

    #[test]
    fn test_noop_leaves_state_unchanged() {
        let specs = specs_with(vec![], vec![]);
        let mut findings = Vec::new();
        let state = empty_state();
        let out = transfer_stmt(
            &IrStmt::Noop { lineno: 1 },
            &state,
            &specs,
            &mut findings,
            None,
        );
        assert_eq!(out, state);
    }

    // ------------------------------------------------------------------
    // §10bis — hybrid regex matching on the source text
    // ------------------------------------------------------------------

    #[test]
    fn test_strip_plain_string_literals_removes_flat_literal() {
        assert_eq!(strip_plain_string_literals("\"select ip from users\""), " ");
    }

    #[test]
    fn test_strip_plain_string_literals_keeps_interpolated() {
        let out = strip_plain_string_literals("return f'...{bar}...'");
        assert!(
            out.contains("{bar}"),
            "un littéral interpolé ne doit pas être retiré"
        );
    }

    #[test]
    fn test_discard_sinks_failing_raw_regex_drops_excluded_receiver() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sinks.push(
            SinkSpec::new("**.println")
                .with_raw_regex(Regex::new(r"(?<!System\.(?:out|err))\.println\s*\(").unwrap()),
        );
        let source_lines = vec!["System.out.println(tainted);".to_string()];
        let mut findings = vec![dummy_finding("System.out.println", 1)];
        discard_sinks_failing_raw_regex(&mut findings, 0, &specs, &source_lines);
        assert!(
            findings.is_empty(),
            "System.out.println doit être exclu par le lookbehind négatif"
        );
    }

    #[test]
    fn test_discard_sinks_failing_raw_regex_keeps_matching_receiver() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sinks.push(
            SinkSpec::new("**.println")
                .with_raw_regex(Regex::new(r"(?<!System\.(?:out|err))\.println\s*\(").unwrap()),
        );
        let source_lines = vec!["foo.println(tainted);".to_string()];
        let mut findings = vec![dummy_finding("foo.println", 1)];
        discard_sinks_failing_raw_regex(&mut findings, 0, &specs, &source_lines);
        assert_eq!(findings.len(), 1, "foo.println ne doit pas être exclu");
    }

    #[test]
    fn test_discard_sinks_failing_raw_regex_no_candidate_keeps_finding() {
        let specs = specs_with(vec![], vec![SinkSpec::new("os.system")]);
        let source_lines = vec!["cursor.execute(tainted)".to_string()];
        let mut findings = vec![dummy_finding("cursor.execute", 1)];
        discard_sinks_failing_raw_regex(&mut findings, 0, &specs, &source_lines);
        assert_eq!(
            findings.len(),
            1,
            "aucune spec candidate ne matche sink_text -> jamais filtré"
        );
    }

    #[test]
    fn test_aux_match_line_guard_sanitizer_clears_taint_on_terminator() {
        let mut specs = specs_with(vec![], vec![]);
        specs
            .sanitizers
            .push(SanitizerSpec::new("is_safe").with_raw_regex(Regex::new(r"is_safe\(").unwrap()));
        let source_lines = vec!["if not is_safe(bar):".to_string(), "    return".to_string()];
        let mut state = empty_state();
        state = state_set(&state, "bar", tainted("cli", 1));
        let stmt = IrStmt::Branch {
            condition: Rhs::Const(ConstValue::Bool(true)),
            lineno: 1,
        };
        let mut findings = Vec::new();
        let new_state = aux_match_line(&stmt, &state, &specs, &mut findings, &source_lines);
        assert!(!state_get(&new_state, "bar").is_tainted());
    }

    /// Ticket #157: a PHP guard that reassigns the variable to a literal
    /// on the next line clears it; the name keeps its `$`.
    #[test]
    fn test_aux_match_line_php_guard_reassign_clears_dollar_variable() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sanitizers.push(
            SanitizerSpec::new("filter_var")
                .with_raw_regex(Regex::new(r"filter_var.*FILTER_VALIDATE_URL").unwrap()),
        );
        let source_lines = vec![
            "if (!filter_var($next, FILTER_VALIDATE_URL)) {".to_string(),
            "    $next = '/';".to_string(),
            "}".to_string(),
        ];
        let mut state = empty_state();
        state = state_set(&state, "$next", tainted("http", 1));
        let stmt = IrStmt::Branch {
            condition: Rhs::Const(ConstValue::Bool(true)),
            lineno: 1,
        };
        let mut findings = Vec::new();
        let new_state = aux_match_line(&stmt, &state, &specs, &mut findings, &source_lines);
        assert!(!state_get(&new_state, "$next").is_tainted());
    }

    #[test]
    fn test_aux_match_line_generic_guard_clears_without_sanitizer_spec() {
        let specs = specs_with(vec![], vec![]);
        let source_lines = vec![
            "if not bar.startswith('safe'):".to_string(),
            "    return".to_string(),
        ];
        let mut state = empty_state();
        state = state_set(&state, "bar", tainted("cli", 1));
        let stmt = IrStmt::Branch {
            condition: Rhs::Const(ConstValue::Bool(true)),
            lineno: 1,
        };
        let mut findings = Vec::new();
        let new_state = aux_match_line(&stmt, &state, &specs, &mut findings, &source_lines);
        assert!(!state_get(&new_state, "bar").is_tainted());
    }

    #[test]
    fn test_aux_match_line_backward_aliasing_via_guard() {
        // url = urlparse(bar); if url.netloc in [...]: return; redirect(bar)
        let specs = specs_with(vec![], vec![]);
        let source_lines = vec![
            "url = urlparse(bar)".to_string(),
            "if url.netloc in allowed_hosts:".to_string(),
            "    return".to_string(),
        ];
        let mut state = empty_state();
        state = state_set(&state, "bar", tainted("http", 1));
        let stmt = IrStmt::Branch {
            condition: Rhs::Const(ConstValue::Bool(true)),
            lineno: 2,
        };
        let mut findings = Vec::new();
        let new_state = aux_match_line(&stmt, &state, &specs, &mut findings, &source_lines);
        assert!(
            !state_get(&new_state, "bar").is_tainted(),
            "aliasing arrière doit nettoyer bar via url"
        );
    }

    #[test]
    fn test_aux_match_line_source_taints_lhs() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sources.push(
            SourceSpec::new("request.GET", "http")
                .with_raw_regex(Regex::new(r"request\.GET").unwrap()),
        );
        let source_lines = vec!["x = request.GET['q']".to_string()];
        let stmt = IrStmt::Assign {
            lhs: Lhs::VarLhs("x".to_string()),
            rhs: Rhs::Const(ConstValue::Int(0)),
            lineno: 1,
        };
        let mut findings = Vec::new();
        let new_state = aux_match_line(&stmt, &empty_state(), &specs, &mut findings, &source_lines);
        assert!(state_get(&new_state, "x").is_tainted());
    }

    #[test]
    fn test_aux_match_line_sink_emits_finding_from_state() {
        let mut specs = specs_with(vec![], vec![]);
        specs
            .sinks
            .push(SinkSpec::new("os.system").with_raw_regex(Regex::new(r"os\.system\(").unwrap()));
        let source_lines = vec!["os.system(cmd)".to_string()];
        let mut state = empty_state();
        state = state_set(&state, "cmd", tainted("cli", 1));
        let stmt = IrStmt::Call {
            callee: Rhs::VarRef("noop".to_string()),
            args: vec![],
            kwargs: vec![],
            lineno: 1,
        };
        let mut findings = Vec::new();
        aux_match_line(&stmt, &state, &specs, &mut findings, &source_lines);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].sink_text, "os.system(cmd)");
    }

    #[test]
    fn test_aux_match_line_multiline_sink_extends_scan_text() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sinks.push(
            SinkSpec::new("cursor.execute").with_raw_regex(Regex::new(r"\.execute\s*\(").unwrap()),
        );
        let source_lines = vec![
            "cursor.execute(".to_string(),
            "    query + tainted_var".to_string(),
            ")".to_string(),
        ];
        let mut state = empty_state();
        state = state_set(&state, "tainted_var", tainted("cli", 2));
        let stmt = IrStmt::Call {
            callee: Rhs::VarRef("noop".to_string()),
            args: vec![],
            kwargs: vec![],
            lineno: 1,
        };
        let mut findings = Vec::new();
        aux_match_line(&stmt, &state, &specs, &mut findings, &source_lines);
        assert_eq!(
            findings.len(),
            1,
            "la taint sur la ligne de continuation doit être détectée"
        );
    }

    #[test]
    fn test_aux_match_line_multiline_sink_cleared_by_sanitizer_in_continuation() {
        // `db.execute(select(...).where(... == status))` on one line is
        // cleared by the `select(` sanitizer; the same call split over
        // several lines must be too (my-ia, SQLAlchemy queries).
        let mut specs = specs_with(vec![], vec![]);
        specs.sinks.push(
            SinkSpec::new("db.execute").with_raw_regex(Regex::new(r"\.execute\s*\(").unwrap()),
        );
        specs.sanitizers.push(
            SanitizerSpec::new("select").with_raw_regex(Regex::new(r"\bselect\s*\(").unwrap()),
        );
        let source_lines = vec![
            "return await db.execute(".to_string(),
            "    select(Call)".to_string(),
            "    .where(Call.status == status)".to_string(),
            ")".to_string(),
        ];
        let mut state = empty_state();
        state = state_set(&state, "status", tainted("http", 1));
        let stmt = IrStmt::Call {
            callee: Rhs::VarRef("noop".to_string()),
            args: vec![],
            kwargs: vec![],
            lineno: 1,
        };
        let mut findings = Vec::new();
        aux_match_line(&stmt, &state, &specs, &mut findings, &source_lines);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn test_aux_match_line_no_finding_when_sink_line_has_no_tainted_var() {
        let mut specs = specs_with(vec![], vec![]);
        specs
            .sinks
            .push(SinkSpec::new("os.system").with_raw_regex(Regex::new(r"os\.system\(").unwrap()));
        let source_lines = vec!["os.system(cmd)".to_string()];
        let stmt = IrStmt::Call {
            callee: Rhs::VarRef("noop".to_string()),
            args: vec![],
            kwargs: vec![],
            lineno: 1,
        };
        let mut findings = Vec::new();
        aux_match_line(&stmt, &empty_state(), &specs, &mut findings, &source_lines);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_transfer_stmt_applies_hybrid_layer_only_when_source_lines_given() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sources.push(
            SourceSpec::new("os.environ", "env")
                .with_raw_regex(Regex::new(r"os\.environ").unwrap()),
        );
        let source_lines = vec!["x = os.environ['SECRET']".to_string()];
        let stmt = IrStmt::Assign {
            lhs: Lhs::VarLhs("x".to_string()),
            rhs: Rhs::Const(ConstValue::Int(0)),
            lineno: 1,
        };

        let mut findings = Vec::new();
        let state_none = transfer_stmt(&stmt, &empty_state(), &specs, &mut findings, None);
        assert!(
            !state_get(&state_none, "x").is_tainted(),
            "sans source_lines, seul le cœur IR (RHS=Const) doit s'appliquer"
        );

        let mut findings2 = Vec::new();
        let state_some = transfer_stmt(
            &stmt,
            &empty_state(),
            &specs,
            &mut findings2,
            Some(&source_lines),
        );
        assert!(
            state_get(&state_some, "x").is_tainted(),
            "avec source_lines, le matching hybride doit détecter la source"
        );
    }

    // ------------------------------------------------------------------
    // Part 2 — interprocedural resolution via function summary
    // ------------------------------------------------------------------

    #[test]
    fn test_eval_call_summary_emits_sink_finding_for_tainted_arg() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut summary = FunctionSummary {
            name: "helper".to_string(),
            param_names: vec!["x".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "test-rule".to_string(),
                severity: "HIGH".to_string(),
                line: 42,
                column: 0,
                sink_text: "os.system".to_string(),
                source_line: None,
                message: String::new(),
                cwe: None,
                flow: vec![],
                source_kind: "unknown".to_string(),
            },
        );
        specs.summaries.insert("helper".to_string(), summary.into());

        let mut findings = Vec::new();
        let src = call(varref("input"), vec![]);
        let call_expr = call(varref("helper"), vec![src]);
        eval_rhs(&call_expr, &empty_state(), &specs, &mut findings, 7);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].line, 7,
            "le finding est émis au site d'appel, pas dans le résumé"
        );
        assert_eq!(findings[0].sink_text, "helper(...)");
        assert!(
            findings[0]
                .flow
                .iter()
                .any(|f| f.kind == "propagation" && f.text.contains('→'))
        );
    }

    #[test]
    fn test_eval_call_summary_no_finding_when_arg_clean() {
        let mut specs = specs_with(vec![], vec![]);
        let mut summary = FunctionSummary {
            name: "helper".to_string(),
            param_names: vec!["x".to_string()],
            ..Default::default()
        };
        summary
            .sink_param_findings
            .insert(0, dummy_finding("os.system", 42));
        specs.summaries.insert("helper".to_string(), summary.into());

        let mut findings = Vec::new();
        let call_expr = call(
            varref("helper"),
            vec![Rhs::Const(ConstValue::Str("safe".to_string()))],
        );
        eval_rhs(&call_expr, &empty_state(), &specs, &mut findings, 7);

        assert!(
            findings.is_empty(),
            "argument clean -> pas de finding via résumé"
        );
    }

    #[test]
    fn test_eval_call_summary_return_tainted_uncond() {
        let mut specs = specs_with(vec![], vec![]);
        let summary = FunctionSummary {
            name: "get_secret".to_string(),
            return_tainted_uncond: true,
            return_kind: Some("http".to_string()),
            ..Default::default()
        };
        specs
            .summaries
            .insert("get_secret".to_string(), summary.into());

        let mut findings = Vec::new();
        let call_expr = call(varref("get_secret"), vec![]);
        let t = eval_rhs(&call_expr, &empty_state(), &specs, &mut findings, 1);
        assert!(
            t.is_tainted(),
            "source interne inconditionnelle -> retour tainté même sans argument tainté"
        );
    }

    #[test]
    fn test_eval_call_summary_return_taint_params_narrows_positional() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut summary = FunctionSummary {
            name: "identity_first".to_string(),
            param_names: vec!["a".to_string(), "b".to_string()],
            ..Default::default()
        };
        // Only parameter 0 reaches the return (e.g. `def identity_first(a, b): return a`).
        summary.return_taint_params.insert(0);
        specs
            .summaries
            .insert("identity_first".to_string(), summary.into());

        let mut findings = Vec::new();
        // identity_first(input(), input()) -- only arg 0 should taint the
        // return, but since both are identically a source here, we vary: arg1 clean.
        let call_expr = call(
            varref("identity_first"),
            vec![
                call(varref("input"), vec![]),
                Rhs::Const(ConstValue::Str("safe".to_string())),
            ],
        );
        let t = eval_rhs(&call_expr, &empty_state(), &specs, &mut findings, 1);
        assert!(
            t.is_tainted(),
            "l'arg 0 (tainté) atteint le retour d'après le résumé"
        );
    }

    #[test]
    fn test_eval_call_no_summary_falls_back_to_over_approximation() {
        // With no summary for "unknown_fn", historical UNKNOWN behavior
        // (SCA-9 choice): join of all arguments.
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        let call_expr = call(varref("unknown_fn"), vec![call(varref("input"), vec![])]);
        let t = eval_rhs(&call_expr, &empty_state(), &specs, &mut findings, 1);
        assert!(t.is_tainted());
    }

    // ------------------------------------------------------------------
    // Round 5/6 (Java) — resolution via type_map / chained constructor call
    // ------------------------------------------------------------------

    #[test]
    fn test_eval_call_round5_resolves_via_type_map() {
        // `scr.method(input())` where `scr` is a local variable of a
        // known type (`type_map["scr"] = "Helper"`) — the direct lookup
        // by "scr.method" always fails (never indexed by variable
        // name), must fall back to "Helper.method".
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        specs
            .type_map
            .insert("scr".to_string(), "Helper".to_string());
        let mut summary = FunctionSummary {
            name: "Helper.method".to_string(),
            param_names: vec!["x".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "test-rule".to_string(),
                severity: "HIGH".to_string(),
                line: 42,
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
            .insert("Helper.method".to_string(), summary.into());

        let mut findings = Vec::new();
        let call_expr = call(
            attr(varref("scr"), "method"),
            vec![call(varref("input"), vec![])],
        );
        eval_rhs(&call_expr, &empty_state(), &specs, &mut findings, 7);
        assert_eq!(
            findings.len(),
            1,
            "scr.method() doit se résoudre via type_map vers Helper.method"
        );
    }

    #[test]
    fn test_eval_call_round6_resolves_chained_constructor_call() {
        // `new Test().method(input())` — java_lowering.rs inlines the
        // constructor's CallRef as the AttrRef's base; eval_call must
        // recognize this form and resolve "Test.method" without needing
        // type_map (no language guard, see the comment in eval_call —
        // this form is never produced on the Python side).
        let specs_base = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut specs = specs_base;
        let mut summary = FunctionSummary {
            name: "Test.method".to_string(),
            param_names: vec!["x".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "test-rule".to_string(),
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
            .insert("Test.method".to_string(), summary.into());

        let mut findings = Vec::new();
        let ctor_call = call(varref("Test"), vec![]);
        let call_expr = call(
            attr(ctor_call, "method"),
            vec![call(varref("input"), vec![])],
        );
        eval_rhs(&call_expr, &empty_state(), &specs, &mut findings, 3);
        assert_eq!(
            findings.len(),
            1,
            "new Test().method() doit se résoudre vers Test.method via le chaînage constructeur"
        );
    }
}
