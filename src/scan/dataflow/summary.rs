//! Function summaries for interprocedural analysis — port of
//! `Audit/sca/dataflow/summary.py`.
//! Python-only scope (Decision #10).
//!
//! Phase 6 approach: each function definition is treated as a
//! standalone sub-module and an intra-procedural analysis is run on
//! it (`compute_summary`/`compute_summary_from_cfg`, parameter-by-
//! parameter probing). `FunctionSummary` lives in `transfer.rs`
//! (co-located with `RuleSpecs`/`Finding` — see `transfer.rs`'s
//! docstring for why: Python types this field as `Any` precisely to
//! break an import cycle that Rust cannot work around the same way);
//! this module re-exports it to stay close to the Python structure.
//!
//! Limitations inherited from Python (minimal Phase 6, not fixed here
//! — `call_graph.rs` lifts the "no cross-file" limitation and replaces
//! the recursion with a real SCC fixpoint, cf. Decision #3):
//! intra-file recursion handled by a trivial fixpoint (2 passes).

use std::collections::BTreeMap;

use tree_sitter::Node;

use super::cfg::build_cfg_from_block;
use super::ir::IrStmt;
use super::lattice::{SourceInfo, State, Taint, empty_state, join, state_set};
pub use super::transfer::FunctionSummary;
use super::transfer::{Finding, RuleSpecs, eval_rhs, transfer_stmt};
use super::worklist::{analyze, lower_node_to_ir};

// ============================================================================
// Collecting functions (§8.1)
// ============================================================================

/// Metadata for a function defined in the module.
pub struct FunctionInfo<'tree> {
    /// Name (for global functions) or dotted name (Class.method).
    pub name: String,
    /// tree-sitter `function_definition` node.
    pub def_node: Node<'tree>,
    /// `block` node of the function body — always present in
    /// practice (the grammar requires it), `None` only in case of a
    /// malformed tree (tree-sitter error recovery).
    pub body_node: Option<Node<'tree>>,
    /// `decorator` nodes carried by the function (via an enclosing
    /// `decorated_definition`), empty if not decorated.
    pub decorators: Vec<Node<'tree>>,
    /// "positional-or-keyword" parameters (name, type annotation node
    /// if any) — excludes posonly (before `/`), kwonly (after
    /// `*`/`*args`), `*args`/`**kwargs` themselves. Includes self/cls
    /// if a method (filtered at use time, like on the Python side).
    pub params: Vec<(String, Option<Node<'tree>>)>,
    /// True if a class method (1st parameter self/cls).
    pub is_method: bool,
    pub lineno: usize,
}

impl<'tree> FunctionInfo<'tree> {
    pub fn param_names(&self) -> Vec<String> {
        self.params.iter().map(|(n, _)| n.clone()).collect()
    }
}

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// Unwraps the `type` (wrapper) node of an annotation to the real
/// expression — cf. tree-sitter-python grammar: `typed_parameter`'s
/// `type:` field points to a `type` node which wraps
/// `identifier`/`subscript`, not the expression directly.
fn unwrap_type_node(t: Node) -> Node {
    if t.kind() == "type" {
        let mut w = t.walk();
        t.named_children(&mut w).next().unwrap_or(t)
    } else {
        t
    }
}

/// Collects the "positional-or-keyword" parameters of a `parameters`
/// node — equivalent of `node.args.args` on the Python AST side
/// (excludes `posonlyargs`/`kwonlyargs`/vararg/kwarg, unlike a plain
/// walk over all named children).
fn collect_pos_or_kw_params<'tree>(
    params_node: Node<'tree>,
    source: &[u8],
) -> Vec<(String, Option<Node<'tree>>)> {
    let mut all: Vec<(String, Option<Node<'tree>>, usize)> = Vec::new();
    let mut posonly_end: Option<usize> = None;
    let mut kwonly_start: Option<usize> = None;
    let mut cursor = params_node.walk();
    for (idx, child) in params_node.named_children(&mut cursor).enumerate() {
        match child.kind() {
            "identifier" => all.push((text(child, source), None, idx)),
            "default_parameter" | "typed_default_parameter" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let ann = child.child_by_field_name("type").map(unwrap_type_node);
                    all.push((text(name_node, source), ann, idx));
                }
            }
            "typed_parameter" => {
                let mut w = child.walk();
                if let Some(name_node) = child.named_children(&mut w).next() {
                    let ann = child.child_by_field_name("type").map(unwrap_type_node);
                    all.push((text(name_node, source), ann, idx));
                }
            }
            "positional_separator" => posonly_end = Some(idx),
            "list_splat_pattern" | "keyword_separator" if kwonly_start.is_none() => {
                kwonly_start = Some(idx);
            }
            _ => {}
        }
    }
    all.into_iter()
        .filter(|(_, _, i)| posonly_end.is_none_or(|b| *i > b))
        .filter(|(_, _, i)| kwonly_start.is_none_or(|b| *i < b))
        .map(|(n, ann, _)| (n, ann))
        .collect()
}

/// Recursively walks `node` to collect function/method definitions
/// (§8.1). Nested functions (def inside def) are also collected
/// (dotted name) — mirrors `_walk` on the Python side.
fn walk_functions<'tree>(
    node: Node<'tree>,
    source: &[u8],
    prefix: &str,
    is_method: bool,
    pending_decorators: &[Node<'tree>],
    out: &mut Vec<FunctionInfo<'tree>>,
) {
    match node.kind() {
        "function_definition" => {
            let name = node
                .child_by_field_name("name")
                .map(|n| text(n, source))
                .unwrap_or_default();
            let full_name = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}{name}")
            };
            let params = node
                .child_by_field_name("parameters")
                .map(|p| collect_pos_or_kw_params(p, source))
                .unwrap_or_default();
            let body = node.child_by_field_name("body");
            out.push(FunctionInfo {
                name: full_name.clone(),
                def_node: node,
                body_node: body,
                decorators: pending_decorators.to_vec(),
                params,
                is_method,
                lineno: node.start_position().row + 1,
            });
            // Continue into the body for nested functions.
            if let Some(body) = body {
                let mut w = body.walk();
                for child in body.named_children(&mut w) {
                    walk_functions(child, source, &format!("{full_name}."), false, &[], out);
                }
            }
        }
        "class_definition" => {
            let name = node
                .child_by_field_name("name")
                .map(|n| text(n, source))
                .unwrap_or_default();
            let class_prefix = format!("{prefix}{name}.");
            if let Some(body) = node.child_by_field_name("body") {
                let mut w = body.walk();
                for child in body.named_children(&mut w) {
                    walk_functions(child, source, &class_prefix, true, &[], out);
                }
            }
        }
        "decorated_definition" => {
            let decorators: Vec<Node<'tree>> = {
                let mut w = node.walk();
                node.named_children(&mut w)
                    .filter(|c| c.kind() == "decorator")
                    .collect()
            };
            if let Some(def) = node.child_by_field_name("definition") {
                walk_functions(def, source, prefix, is_method, &decorators, out);
            }
        }
        _ => {
            let mut w = node.walk();
            for child in node.named_children(&mut w) {
                walk_functions(child, source, prefix, is_method, &[], out);
            }
        }
    }
}

/// Lists all function/method definitions of a module (tree-sitter
/// root node).
pub fn collect_functions<'tree>(root: Node<'tree>, source: &[u8]) -> Vec<FunctionInfo<'tree>> {
    let mut out = Vec::new();
    let mut w = root.walk();
    for child in root.named_children(&mut w) {
        walk_functions(child, source, "", false, &[], &mut out);
    }
    out
}

// ============================================================================
// Imports (components 3 + 5)
// ============================================================================

/// A name imported into a module — describes the link created by an
/// `import`/`from … import …`, to connect a `local_name(...)` call to
/// the `orig_name` function defined in the source module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportInfo {
    /// Name bound in the importing module (alias included).
    pub local_name: String,
    /// Dotted path of the source module (e.g. `mypkg.utils`, `utils`).
    pub module: String,
    /// Original name in the source module; `""` for a plain `import
    /// module` (the binding is then the module itself).
    pub orig_name: String,
    /// Relative import level (0 = absolute, 1 = `.`, 2 = `..`).
    pub level: usize,
}

fn collect_import_statement(node: Node, source: &[u8]) -> Vec<ImportInfo> {
    let mut out = Vec::new();
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        match child.kind() {
            "aliased_import" => {
                let path = child
                    .child_by_field_name("name")
                    .map(|n| text(n, source))
                    .unwrap_or_default();
                let local = child
                    .child_by_field_name("alias")
                    .map(|n| text(n, source))
                    .unwrap_or_else(|| path.clone());
                out.push(ImportInfo {
                    local_name: local,
                    module: path,
                    orig_name: String::new(),
                    level: 0,
                });
            }
            "dotted_name" => {
                let path = text(child, source);
                out.push(ImportInfo {
                    local_name: path.clone(),
                    module: path,
                    orig_name: String::new(),
                    level: 0,
                });
            }
            _ => {}
        }
    }
    out
}

fn relative_import_module_and_level(relative: Node, source: &[u8]) -> (String, usize) {
    let mut level = 0usize;
    let mut module = String::new();
    let mut w = relative.walk();
    for child in relative.named_children(&mut w) {
        match child.kind() {
            "import_prefix" => level = text(child, source).matches('.').count(),
            "dotted_name" => module = text(child, source),
            _ => {}
        }
    }
    (module, level)
}

fn collect_import_from_statement(node: Node, source: &[u8]) -> Vec<ImportInfo> {
    let mut out = Vec::new();
    let module_name_node = node.child_by_field_name("module_name");
    let (module, level) = match module_name_node {
        Some(n) if n.kind() == "relative_import" => relative_import_module_and_level(n, source),
        Some(n) => (text(n, source), 0),
        None => (String::new(), 0),
    };
    let module_name_id = module_name_node.map(|n| n.id());
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        if module_name_id == Some(child.id()) {
            continue;
        }
        match child.kind() {
            "wildcard_import" => out.push(ImportInfo {
                local_name: "*".to_string(),
                module: module.clone(),
                orig_name: "*".to_string(),
                level,
            }),
            "dotted_name" => {
                let name = text(child, source);
                out.push(ImportInfo {
                    local_name: name.clone(),
                    module: module.clone(),
                    orig_name: name,
                    level,
                });
            }
            "aliased_import" => {
                let orig = child
                    .child_by_field_name("name")
                    .map(|n| text(n, source))
                    .unwrap_or_default();
                let alias = child
                    .child_by_field_name("alias")
                    .map(|n| text(n, source))
                    .unwrap_or_else(|| orig.clone());
                out.push(ImportInfo {
                    local_name: alias,
                    module: module.clone(),
                    orig_name: orig,
                    level,
                });
            }
            _ => {}
        }
    }
    out
}

/// Lists the imports of a module (components 3 + 5), including those
/// nested inside a function (lazy imports, anti-cycle, component 5D)
/// — the entire tree is walked, not just top-level statements.
pub fn collect_imports(root: Node, source: &[u8]) -> Vec<ImportInfo> {
    let mut out = Vec::new();
    walk_imports(root, source, &mut out);
    out
}

fn walk_imports(node: Node, source: &[u8], out: &mut Vec<ImportInfo>) {
    match node.kind() {
        "import_statement" => out.extend(collect_import_statement(node, source)),
        "import_from_statement" => out.extend(collect_import_from_statement(node, source)),
        _ => {}
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_imports(child, source, out);
    }
}

// ============================================================================
// Web route handler detection (FastAPI/Flask/Starlette)
// ============================================================================

const ROUTE_DECORATOR_ATTRS: &[&str] = &[
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "websocket",
];

/// Annotations of a route parameter that make it an HTTP source.
///
/// Deliberate deviation from Python (`_USER_PARAM_SCALARS` of
/// `sca/dataflow/summary.py`, which also lists `int`, `float`, `bool` and
/// `UUID`): FastAPI converts those before the handler runs and answers
/// 422 to anything else, so the value cannot carry a payload into a
/// query, a command or a page. Keeping them raised every SQLAlchemy call
/// taking an `id: UUID` as an injection (my-ia report, 2026-11-14).
const USER_PARAM_SCALARS: &[&str] = &["str", "bytes"];

/// True if the function is a web route handler (recognized
/// decorator). Detects `@app.get(...)`, `@router.post(...)`,
/// `@blueprint.route(...)` etc. — a decorator that is a call on an
/// HTTP method attribute.
pub fn is_route_handler(fn_info: &FunctionInfo, source: &[u8]) -> bool {
    for deco in &fn_info.decorators {
        let mut w = deco.walk();
        let Some(expr) = deco.named_children(&mut w).next() else {
            continue;
        };
        let target = if expr.kind() == "call" {
            expr.child_by_field_name("function")
        } else {
            Some(expr)
        };
        if let Some(t) = target
            && t.kind() == "attribute"
            && let Some(attr_node) = t.child_by_field_name("attribute")
            && ROUTE_DECORATOR_ATTRS.contains(&text(attr_node, source).as_str())
        {
            return true;
        }
    }
    false
}

fn annotation_scalar_name(ann: Node, source: &[u8]) -> Option<String> {
    match ann.kind() {
        "identifier" => Some(text(ann, source)),
        "subscript" => ann
            .child_by_field_name("value")
            .filter(|v| v.kind() == "identifier")
            .map(|v| text(v, source)),
        _ => None,
    }
}

/// True when the parameter's default is a FastAPI validator
/// (`Query`, `Path`, `Header`, `Cookie`, `Form`) whose `pattern=` (or the
/// older `regex=`) only accepts a list of plain words:
/// `Query("json", pattern="^(json|md|docx)$")`. FastAPI answers 422 to
/// any other value, so the parameter cannot carry a payload.
///
/// Deliberate deviation from Python (`route_source_params` of
/// `sca/dataflow/summary.py` ignores the default): the six `taint_xss`
/// of the my-ia exports all came from such a parameter (2026-11-14).
/// Any other pattern (`^.*$`, a character class) keeps the parameter a
/// source: only a list of words is provably harmless.
fn bounded_by_literal_allowlist(ann: Node, source: &[u8]) -> bool {
    // `ann` is the unwrapped annotation: its parent is the `type`
    // wrapper, whose parent is the `typed_default_parameter`.
    let Some(param) = ann
        .parent()
        .and_then(|t| if t.kind() == "type" { t.parent() } else { Some(t) })
        .filter(|p| p.kind() == "typed_default_parameter")
    else {
        return false;
    };
    let Some(call) = param.child_by_field_name("value").filter(|v| v.kind() == "call") else {
        return false;
    };
    let callee = call
        .child_by_field_name("function")
        .map(|f| text(f, source))
        .unwrap_or_default();
    let callee = callee.rsplit('.').next().unwrap_or("");
    if !["Query", "Path", "Header", "Cookie", "Form"].contains(&callee) {
        return false;
    }
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut w = args.walk();
    args.named_children(&mut w).any(|arg| {
        arg.kind() == "keyword_argument"
            && arg
                .child_by_field_name("name")
                .is_some_and(|n| matches!(text(n, source).as_str(), "pattern" | "regex"))
            && arg
                .child_by_field_name("value")
                .filter(|v| v.kind() == "string")
                .is_some_and(|v| is_word_list_pattern(&text(v, source)))
    })
}

/// True for an anchored regex listing plain words: `^json$`,
/// `^(json|md|docx)$` (quotes and an `r` prefix accepted).
fn is_word_list_pattern(literal: &str) -> bool {
    let s = literal.trim_start_matches(['r', 'R']);
    let s = s.trim_matches(|c| c == '"' || c == '\'');
    let Some(inner) = s.strip_prefix('^').and_then(|s| s.strip_suffix('$')) else {
        return false;
    };
    let inner = inner
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(inner);
    let inner = inner.strip_prefix("?:").unwrap_or(inner);
    inner.split('|').all(|w| {
        !w.is_empty() && w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    })
}

/// Returns the parameters of a route handler to treat as HTTP
/// sources. Conservative: only parameters annotated with a
/// user-facing scalar type (`str`, `int`…) are kept — these are
/// FastAPI path/query parameters. Injected dependencies (`db`,
/// `session`, `request`, unannotated or `Depends(...)`) are ignored.
pub fn route_source_params(fn_info: &FunctionInfo, source: &[u8]) -> Vec<String> {
    if !is_route_handler(fn_info, source) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (name, ann) in &fn_info.params {
        if name == "self" || name == "cls" {
            continue;
        }
        let Some(ann) = ann else { continue };
        if let Some(ann_name) = annotation_scalar_name(*ann, source)
            && USER_PARAM_SCALARS.contains(&ann_name.as_str())
            && !bounded_by_literal_allowlist(*ann, source)
        {
            out.push(name.clone());
        }
    }
    out
}

// ============================================================================
// Function summaries — interprocedural propagation (component 2)
// ============================================================================

/// Anti-FP — source kinds that do NOT propagate through an
/// unconditional interprocedural return. A CLI/stdin/env input
/// propagated between calls triggers too many false sinks (e.g.
/// `input()` → `re.search` mistaken for an LDAP sink); these sources
/// stay detected intra-procedurally but do not cross a `return`.
const INTERPROC_BLOCKED_RETURN_KINDS: &[&str] = &["stdin", "cli", "env"];

/// The source kinds a rule accepts (`kind=` of its `source` lines),
/// `http` when it declares none.
pub(crate) fn rule_source_kinds(specs: &RuleSpecs) -> Vec<String> {
    let mut kinds: Vec<String> = specs
        .sources
        .iter()
        .map(|s| s.kind.clone())
        .filter(|k| !k.is_empty())
        .collect();
    kinds.sort();
    kinds.dedup();
    if kinds.is_empty() {
        vec!["http".to_string()]
    } else {
        kinds
    }
}

/// Taint of a source detected only by a line regex on the `return`
/// (e.g. `return request.GET[...]`); CLEAN if none matches.
fn return_line_source_taint(
    lineno: usize,
    source_lines: Option<&[String]>,
    specs: &RuleSpecs,
) -> Taint {
    let Some(lines) = source_lines else {
        return Taint::Clean;
    };
    if lineno == 0 || lineno > lines.len() {
        return Taint::Clean;
    }
    let line_text = &lines[lineno - 1];
    for src in &specs.sources {
        if let Some(rx) = &src.raw_regex
            && rx.is_match(line_text).unwrap_or(false)
        {
            return Taint::tainted(
                [src.kind.clone()],
                SourceInfo {
                    line: lineno,
                    expr: line_text.trim().to_string(),
                    kind: src.kind.clone(),
                },
            );
        }
    }
    Taint::Clean
}

/// Taint of a function's return value = join of the taints evaluated
/// at each `Return` statement, in the dataflow state computed at that
/// point. Replays the statements of each node from its `state_in`
/// (to account for assignments preceding the return in the same
/// node).
fn return_taint<'tree>(
    cfg: &super::cfg::Cfg<'tree>,
    result: &super::worklist::AnalysisResult,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
) -> Taint {
    return_taint_generic(cfg, result, specs, source, source_lines, lower_node_to_ir)
}

/// Generic variant of [`return_taint`], parameterized by the
/// per-node CFG→IR lowering (`lower_node_to_ir`) — Rust mirror of the
/// `language: str` parameter of `summary.py::return_taint`. Used by
/// `return_taint` (Python) and by `compute_summary_from_cfg_generic`
/// (Python AND Java, cf. `java_summary.rs`).
pub(crate) fn return_taint_generic<'tree, FNode>(
    cfg: &super::cfg::Cfg<'tree>,
    result: &super::worklist::AnalysisResult,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
    lower_node_to_ir: FNode,
) -> Taint
where
    FNode: Fn(&super::cfg::Cfg<'tree>, usize, &'tree [u8]) -> Vec<IrStmt> + Copy,
{
    let mut total = Taint::Clean;
    for &nid in cfg.nodes.keys() {
        let ir = lower_node_to_ir(cfg, nid, source);
        let mut state: State = result
            .state_in
            .get(&nid)
            .cloned()
            .unwrap_or_else(empty_state);
        let mut scratch: Vec<Finding> = Vec::new();
        for stmt in &ir {
            if let IrStmt::Return { value, lineno } = stmt {
                if let Some(v) = value {
                    total = join(&total, &eval_rhs(v, &state, specs, &mut scratch, *lineno));
                }
                total = join(
                    &total,
                    &return_line_source_taint(*lineno, source_lines, specs),
                );
            } else {
                state = transfer_stmt(stmt, &state, specs, &mut scratch, source_lines);
            }
        }
    }
    total
}

/// Language-neutral core of summary computation (probing
/// sub-analyses).
///
/// Method:
///   - "all parameters clean" pass: a tainted return ⇒ an internal
///     source reaches the return (`return_tainted_uncond`).
///   - one pass per parameter, with only that parameter seeded
///     tainted: a new sink triggered ⇒ the parameter reaches a sink;
///     a tainted return ⇒ the parameter contributes to the return
///     value.
pub fn compute_summary_from_cfg<'tree>(
    cfg: &super::cfg::Cfg<'tree>,
    name: &str,
    params: &[String],
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
    fn_lineno: usize,
) -> FunctionSummary {
    compute_summary_from_cfg_generic(
        cfg,
        name,
        params,
        specs,
        source,
        source_lines,
        fn_lineno,
        analyze,
        lower_node_to_ir,
    )
}

/// Java equivalent of [`compute_summary_from_cfg`] — same probing
/// algorithm, `analyze_java`/`java_lowering::lower_node_to_ir`.
/// Used by `java_summary.rs::compute_java_summary`.
pub(crate) fn compute_java_summary_from_cfg<'tree>(
    cfg: &super::cfg::Cfg<'tree>,
    name: &str,
    params: &[String],
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
    fn_lineno: usize,
) -> FunctionSummary {
    compute_summary_from_cfg_generic(
        cfg,
        name,
        params,
        specs,
        source,
        source_lines,
        fn_lineno,
        super::worklist::analyze_java,
        super::java_lowering::lower_node_to_ir,
    )
}

/// JavaScript equivalent of [`compute_summary_from_cfg`] — same
/// probing algorithm, `analyze_js`/`js_lowering::lower_node_to_ir`.
/// Used by `js_summary.rs::compute_js_summary`.
pub(crate) fn compute_js_summary_from_cfg<'tree>(
    cfg: &super::cfg::Cfg<'tree>,
    name: &str,
    params: &[String],
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
    fn_lineno: usize,
) -> FunctionSummary {
    compute_summary_from_cfg_generic(
        cfg,
        name,
        params,
        specs,
        source,
        source_lines,
        fn_lineno,
        super::worklist::analyze_js,
        super::js_lowering::lower_node_to_ir,
    )
}

/// PHP equivalent of [`compute_summary_from_cfg`] — same probing
/// algorithm, `analyze_php`/`php_lowering::lower_node_to_ir`. Used by
/// `php_summary.rs::compute_php_summary`.
pub(crate) fn compute_php_summary_from_cfg<'tree>(
    cfg: &super::cfg::Cfg<'tree>,
    name: &str,
    params: &[String],
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
    fn_lineno: usize,
) -> FunctionSummary {
    compute_summary_from_cfg_generic(
        cfg,
        name,
        params,
        specs,
        source,
        source_lines,
        fn_lineno,
        super::worklist::analyze_php,
        super::php_lowering::lower_node_to_ir,
    )
}

/// C# equivalent of [`compute_summary_from_cfg`] — same probing
/// algorithm, `analyze_csharp`/`csharp_lowering::lower_node_to_ir`.
/// Used by `csharp_summary.rs::compute_csharp_summary` (ticket
/// #79/spec #77).
pub(crate) fn compute_csharp_summary_from_cfg<'tree>(
    cfg: &super::cfg::Cfg<'tree>,
    name: &str,
    params: &[String],
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
    fn_lineno: usize,
) -> FunctionSummary {
    compute_summary_from_cfg_generic(
        cfg,
        name,
        params,
        specs,
        source,
        source_lines,
        fn_lineno,
        super::worklist::analyze_csharp,
        super::csharp_lowering::lower_node_to_ir,
    )
}

/// Generic variant of [`compute_summary_from_cfg`], parameterized by
/// the taint fixpoint (`analyze_fn`) and the per-node CFG→IR lowering
/// (`lower_node_to_ir`) — Rust mirror of the `language: str` parameter
/// of `summary.py::compute_summary_from_cfg` (runtime dispatch on the
/// Python side; resolved at compile time here). It is this genericity
/// that lets `java_summary.rs::compute_java_summary` reuse the probing
/// algorithm WITHOUT DUPLICATION, exactly like
/// `sca/dataflow/java_summary.py::compute_java_summary` delegates to
/// the shared `compute_summary_from_cfg` on the Python side.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_summary_from_cfg_generic<'tree, FAnalyze, FNode>(
    cfg: &super::cfg::Cfg<'tree>,
    name: &str,
    params: &[String],
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&[String]>,
    fn_lineno: usize,
    analyze_fn: FAnalyze,
    lower_node_to_ir: FNode,
) -> FunctionSummary
where
    FAnalyze: Fn(
        &super::cfg::Cfg<'tree>,
        &'tree [u8],
        &RuleSpecs,
        Option<&State>,
        Option<&[String]>,
    ) -> super::worklist::AnalysisResult,
    FNode: Fn(&super::cfg::Cfg<'tree>, usize, &'tree [u8]) -> Vec<IrStmt> + Copy,
{
    let probe_kinds = rule_source_kinds(specs);

    let base = analyze_fn(cfg, source, specs, None, source_lines);
    let base_keys: std::collections::HashSet<(String, usize, Option<usize>)> = base
        .findings
        .iter()
        .map(|f| (f.rule_id.clone(), f.line, f.source_line))
        .collect();
    let ret_base = return_taint_generic(cfg, &base, specs, source, source_lines, lower_node_to_ir);
    let mut uncond = ret_base.is_tainted();
    let mut ret_kind: Option<String> = None;
    if let Taint::Tainted { source: src, .. } = &ret_base {
        ret_kind = Some(src.kind.clone());
    }
    if let Some(k) = &ret_kind
        && INTERPROC_BLOCKED_RETURN_KINDS.contains(&k.as_str())
    {
        uncond = false;
    }

    let mut return_params = std::collections::BTreeSet::new();
    let mut sink_findings = BTreeMap::new();
    let first_kind = probe_kinds
        .first()
        .cloned()
        .unwrap_or_else(|| "http".to_string());
    for (i, pname) in params.iter().enumerate() {
        let init = state_set(
            &empty_state(),
            pname,
            Taint::tainted(
                probe_kinds.clone(),
                SourceInfo {
                    line: fn_lineno,
                    expr: format!("param:{pname}"),
                    kind: first_kind.clone(),
                },
            ),
        );
        let res = analyze_fn(cfg, source, specs, Some(&init), source_lines);
        if let Some(f) = res
            .findings
            .iter()
            .find(|f| !base_keys.contains(&(f.rule_id.clone(), f.line, f.source_line)))
        {
            sink_findings.insert(i, f.clone());
        }
        let ret_i = return_taint_generic(cfg, &res, specs, source, source_lines, lower_node_to_ir);
        if ret_i.is_tainted() && !uncond {
            return_params.insert(i);
        }
    }

    FunctionSummary {
        name: name.to_string(),
        param_names: params.to_vec(),
        return_tainted_uncond: uncond,
        return_kind: ret_kind,
        return_taint_params: return_params,
        sink_param_findings: sink_findings,
    }
}

/// Computes the summary of a Python function (probing
/// sub-analyses). Builds the CFG from `fn_info.body_node` then
/// delegates to `compute_summary_from_cfg`. `None` if the body is
/// absent (malformed tree — robustness, cf. `compute_file_summaries`).
pub fn compute_summary(
    fn_info: &FunctionInfo,
    specs: &RuleSpecs,
    source: &[u8],
    source_lines: Option<&[String]>,
) -> Option<FunctionSummary> {
    let body = fn_info.body_node?;
    let params: Vec<String> = fn_info
        .params
        .iter()
        .map(|(n, _)| n.clone())
        .filter(|n| n != "self" && n != "cls")
        .collect();
    let cfg = build_cfg_from_block(source, body);
    Some(compute_summary_from_cfg(
        &cfg,
        &fn_info.name,
        &params,
        specs,
        source,
        source_lines,
        fn_info.lineno,
    ))
}

/// Computes the summaries of all functions in a module. A function
/// whose sub-analysis fails (body absent) is simply omitted —
/// robustness, does not interrupt the others.
pub fn compute_file_summaries(
    root: Node,
    source: &[u8],
    specs: &RuleSpecs,
    source_lines: Option<&[String]>,
) -> BTreeMap<String, FunctionSummary> {
    let mut out = BTreeMap::new();
    for fn_info in collect_functions(root, source) {
        if let Some(summary) = compute_summary(&fn_info, specs, source, source_lines) {
            out.insert(fn_info.name.clone(), summary);
        }
    }
    out
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::{SinkSpec, SourceSpec};
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
    fn test_collect_functions_top_level() {
        let (tree, src) = build("def foo(a, b):\n    return a\n\ndef bar():\n    pass\n");
        let fns = collect_functions(tree.root_node(), &src);
        assert_eq!(
            fns.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            vec!["foo", "bar"]
        );
        assert_eq!(fns[0].param_names(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn test_collect_functions_nested_dotted_name() {
        let (tree, src) = build("def outer():\n    def inner():\n        pass\n    return inner\n");
        let fns = collect_functions(tree.root_node(), &src);
        let names: Vec<&str> = fns.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"outer"));
        assert!(names.contains(&"outer.inner"));
    }

    #[test]
    fn test_collect_functions_class_methods_dotted_and_is_method() {
        let (tree, src) = build("class Foo:\n    def method(self, y):\n        pass\n");
        let fns = collect_functions(tree.root_node(), &src);
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "Foo.method");
        assert!(fns[0].is_method);
        assert_eq!(
            fns[0].param_names(),
            vec!["self".to_string(), "y".to_string()]
        );
    }

    #[test]
    fn test_collect_functions_excludes_posonly_kwonly_vararg_kwarg() {
        let (tree, src) = build("def f(a, b=1, /, c, *args, d, e=2, **kw):\n    pass\n");
        let fns = collect_functions(tree.root_node(), &src);
        assert_eq!(fns[0].param_names(), vec!["c".to_string()]);
    }

    #[test]
    fn test_collect_imports_absolute_and_aliased() {
        let (tree, src) = build("import os\nimport pkg.utils as u\nfrom foo import bar as baz\n");
        let imports = collect_imports(tree.root_node(), &src);
        assert!(
            imports
                .iter()
                .any(|i| i.local_name == "os" && i.module == "os" && i.level == 0)
        );
        assert!(
            imports
                .iter()
                .any(|i| i.local_name == "u" && i.module == "pkg.utils")
        );
        assert!(
            imports
                .iter()
                .any(|i| i.local_name == "baz" && i.orig_name == "bar" && i.module == "foo")
        );
    }

    #[test]
    fn test_collect_imports_relative_level_and_wildcard() {
        let (tree, src) = build("from . import utils\nfrom ..pkg import x\nfrom mod import *\n");
        let imports = collect_imports(tree.root_node(), &src);
        assert!(
            imports
                .iter()
                .any(|i| i.local_name == "utils" && i.level == 1 && i.module.is_empty())
        );
        assert!(
            imports
                .iter()
                .any(|i| i.local_name == "x" && i.level == 2 && i.module == "pkg")
        );
        assert!(
            imports
                .iter()
                .any(|i| i.orig_name == "*" && i.module == "mod")
        );
    }

    #[test]
    fn test_collect_imports_nested_in_function_lazy_import() {
        let (tree, src) = build("def f():\n    import json\n    return json\n");
        let imports = collect_imports(tree.root_node(), &src);
        assert!(imports.iter().any(|i| i.local_name == "json"));
    }

    #[test]
    fn test_is_route_handler_detects_fastapi_decorator() {
        let (tree, src) = build("@app.get('/x')\ndef handler(item_id: str):\n    return item_id\n");
        let fns = collect_functions(tree.root_node(), &src);
        assert!(is_route_handler(&fns[0], &src));
    }

    #[test]
    fn test_is_route_handler_false_for_plain_function() {
        let (tree, src) = build("def handler(item_id):\n    return item_id\n");
        let fns = collect_functions(tree.root_node(), &src);
        assert!(!is_route_handler(&fns[0], &src));
    }

    #[test]
    fn test_route_source_params_only_scalar_annotated() {
        let (tree, src) = build(
            "@router.post('/x')\ndef handler(self, item_id: str, db: Session, q: int = 0):\n    pass\n",
        );
        let fns = collect_functions(tree.root_node(), &src);
        let params = route_source_params(&fns[0], &src);
        // `q: int` is converted by FastAPI: not a source (see USER_PARAM_SCALARS).
        assert_eq!(params, vec!["item_id".to_string()]);
    }

    #[test]
    fn test_route_source_params_skip_a_literal_allowlist_pattern() {
        // FastAPI answers 422 to any value outside the list: `format`
        // can only be `json`, `md` or `docx` (my-ia exports, 2026-11-14).
        // A pattern that accepts free text stays a source.
        let (tree, src) = build(
            "@router.get('/x')\ndef handler(\n    format: str = Query(\"json\", pattern=\"^(json|md|docx)$\"),\n    lang: str = Query('fr', regex='^fr$'),\n    q: str = Query(None, pattern='^.*$'),\n    name: str = Query(None),\n):\n    pass\n",
        );
        let fns = collect_functions(tree.root_node(), &src);
        let params = route_source_params(&fns[0], &src);
        assert_eq!(params, vec!["q".to_string(), "name".to_string()]);
    }

    #[test]
    fn test_route_source_params_empty_for_non_route() {
        let (tree, src) = build("def handler(item_id: str):\n    pass\n");
        let fns = collect_functions(tree.root_node(), &src);
        assert!(route_source_params(&fns[0], &src).is_empty());
    }

    #[test]
    fn test_compute_summary_sink_param_finding() {
        let specs = specs_with(vec![], vec![SinkSpec::new("os.system")]);
        let (tree, src) = build("def run(cmd):\n    os.system(cmd)\n");
        let fns = collect_functions(tree.root_node(), &src);
        let summary = compute_summary(&fns[0], &specs, &src, None).unwrap();
        assert!(
            summary.sink_param_findings.contains_key(&0),
            "le paramètre 0 (cmd) atteint le sink"
        );
    }

    #[test]
    fn test_compute_summary_return_taint_params() {
        let specs = specs_with(vec![], vec![]);
        let (tree, src) = build("def identity(x):\n    return x\n");
        let fns = collect_functions(tree.root_node(), &src);
        let summary = compute_summary(&fns[0], &specs, &src, None).unwrap();
        assert!(summary.return_taint_params.contains(&0));
        assert!(!summary.return_tainted_uncond);
    }

    #[test]
    fn test_compute_summary_return_tainted_uncond() {
        let specs = specs_with(vec![SourceSpec::new("get_secret", "http")], vec![]);
        let (tree, src) = build("def leak(x):\n    return get_secret()\n");
        let fns = collect_functions(tree.root_node(), &src);
        let summary = compute_summary(&fns[0], &specs, &src, None).unwrap();
        assert!(
            summary.return_tainted_uncond,
            "source interne indépendante de l'argument"
        );
        assert_eq!(summary.return_kind.as_deref(), Some("http"));
    }

    #[test]
    fn test_compute_summary_blocks_cli_kind_from_uncond_return() {
        // Anti-FP: an internal stdin/cli/env source does NOT make the
        // return unconditionally tainted at the interprocedural level.
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let (tree, src) = build("def get_input(x):\n    return input()\n");
        let fns = collect_functions(tree.root_node(), &src);
        let summary = compute_summary(&fns[0], &specs, &src, None).unwrap();
        assert!(!summary.return_tainted_uncond);
    }

    #[test]
    fn test_compute_summary_clean_function_has_no_effects() {
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let (tree, src) = build("def noop(x):\n    y = 1\n    return y\n");
        let fns = collect_functions(tree.root_node(), &src);
        let summary = compute_summary(&fns[0], &specs, &src, None).unwrap();
        assert!(summary.sink_param_findings.is_empty());
        assert!(summary.return_taint_params.is_empty());
        assert!(!summary.return_tainted_uncond);
    }

    #[test]
    fn test_compute_file_summaries_covers_every_function() {
        let specs = specs_with(vec![], vec![]);
        let (tree, src) = build("def a():\n    pass\n\ndef b():\n    pass\n");
        let summaries = compute_file_summaries(tree.root_node(), &src, &specs, None);
        assert_eq!(summaries.len(), 2);
        assert!(summaries.contains_key("a"));
        assert!(summaries.contains_key("b"));
    }
}
