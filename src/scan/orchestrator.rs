//! Scan orchestrator (Step 5) — assembles the already-built building
//! blocks (DSL parser, regex/file_contains/taint executors, file
//! discovery, suppression, LOC counter) into a complete pipeline.
//! Scope: Python + Java (Decision #10, extended on 2026-08-25).
//!
//! **Multi-language**: each discovered file carries its language
//! detected by extension (`.py`→Python, `.java`→Java). The
//! regex/file_contains mode (Phase B) is language-agnostic — a rule
//! only applies to files of ITS declared language
//! (`rule_json["language"]`).
//!
//! **Multi-file taint wired for all 4 languages** (2026-08-25 for
//! Python/Java, 2026-08-30 for JS/TS then PHP): resolved
//! **interprocedurally, one batch per language** —
//! `dataflow::call_graph::CallGraph` over Python files,
//! `dataflow::java_call_graph::JavaCallGraph` over Java files,
//! `dataflow::js_call_graph::JsCallGraph` over JS/TS files,
//! `dataflow::php_call_graph::PhpCallGraph` over PHP files,
//! each built once and then `resolve_summaries` per taint rule of
//! its language (a rule's sources/sinks determine the function
//! summaries, so resolution is repeated per rule, not graph
//! construction). Mirrors `dataflow_adapter.py` (Python) and the
//! spirit of `dataflow_taint_java.py` (Java, but without its internal
//! summary computation — here done once by the orchestrator via
//! `JavaCallGraph`, same split as on the Python side).
//! **JS/TS and PHP have no Python equivalent to mirror** (the
//! reference Python engine has no interprocedural analysis for these
//! two languages, cf. doc of `dataflow::js_call_graph`/`dataflow::
//! php_call_graph`) — fresh development for both, pipeline pattern
//! reused by analogy, call-resolution mechanisms specific to each
//! language. The `type_map` (var/field → declared class, Round 5,
//! Java only) is recomputed per Java file, independently of the
//! graph — MUST stay in sync with the merge done in
//! `JavaCallGraph::build` (same logical dict), cf. doc of
//! `java_summary::collect_java_field_types`.
//!
//! `ast` mode and `hook` rules remain out of scope (cf. `engine::dispatch`).
#![allow(dead_code)]

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use tree_sitter::{Parser as TsParser, Tree};

use crate::project::suppress::{Suppressions, is_inline_ignored};
use crate::report::exports::sarif::{ReportFinding, TaintFlow};
use crate::scan::counters::{count_java_loc, count_js_loc, count_python_loc};
use crate::scan::dataflow::call_graph::{CallGraph, FileInput};
use crate::scan::dataflow::csharp_summary::{
    collect_csharp_field_types, collect_csharp_local_types, compute_csharp_file_summaries,
};
use crate::scan::dataflow::csharp_taint_scan::run_taint_rule_csharp;
use crate::scan::dataflow::java_call_graph::JavaCallGraph;
use crate::scan::dataflow::java_summary::{collect_java_field_types, collect_java_local_types};
use crate::scan::dataflow::java_taint_scan::run_taint_rule_java;
use crate::scan::dataflow::js_call_graph::JsCallGraph;
use crate::scan::dataflow::js_taint_scan::run_taint_rule_js;
use crate::scan::dataflow::php_call_graph::PhpCallGraph;
use crate::scan::dataflow::php_taint_scan::run_taint_rule_php;
use crate::scan::dataflow::rule_loader::{extract_cwe, extract_message, rule_json_to_specs};
use crate::scan::dataflow::taint_scan::run_taint_rule;
use crate::scan::discovery::{FileDiscoveryConfig, find_files};
use crate::scan::engine::dispatch::{DispatchOutcome, dispatch_rule};
use crate::scan::parser::compile_sca_to_json;

/// Source language of a discovered file, detected by extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceLanguage {
    Python,
    Java,
    JavaScript,
    /// `.ts` only (not yet `.tsx`/JSX, cf. doc of
    /// `js_lowering.rs`) — parsed with `tree-sitter-typescript`, but
    /// fully reuses the JS front-end (`js_lowering`/`js_cfg`/
    /// `js_summary`/`js_taint_scan`, same node kinds for the whole
    /// plain-JS subset) and the same rule catalog
    /// (`rule_tag()` deliberately returns "javascript" — an
    /// Express/Node.js source/sink rule doesn't depend on any type
    /// annotation, duplicating the `.sca` files would add nothing).
    TypeScript,
    Php,
    /// C# (`.cs`) — detection/parsing/`match` mode (prefactor ticket
    /// #69/spec #68) AND native intra-procedural taint engine (tickets
    /// #78-79/spec #77: dedicated CFG, intra-file interprocedural
    /// summaries). **No C# call graph**
    /// (`csharp_call_graph.rs` not built, explicitly out of scope for
    /// ticket #77, consistent with the JS/PHP sequencing in this
    /// repo — a call graph is a later follow-up effort):
    /// unlike Java/JS/PHP, a `.sca` rule with `language csharp`
    /// in `taint` mode resolves calls ONLY within the same file,
    /// never to a summary computed in another file of the project.
    CSharp,
    /// HTML (`.html`/`.htm`).
    Html,
    /// YAML (`.yml`/`.yaml`) — main target: CI/CD pipelines
    /// (GitHub Actions, GitLab CI), mirrors the "yaml" subset of the
    /// Python catalog (`*.yml` files under `.github/workflows/`
    /// notably).
    Yaml,
    /// `Dockerfile` — recognized by EXACT FILE NAME (case-insensitive),
    /// not by extension (no standard extension for this format):
    /// goes through [`SourceLanguage::from_path`], never through
    /// [`SourceLanguage::from_extension`] alone.
    Dockerfile,
}

impl SourceLanguage {
    /// Recognized Dockerfile file names, case-insensitive comparison —
    /// exact mirror of `Audit/sca/rule_engine.py::
    /// _find_dockerfile_files` (`filename.lower() in (...)`,
    /// `rule_engine.py:1286`): NOT just the literal `Dockerfile`,
    /// the `.dev`/`.prod` variants are also recognized on the Python
    /// side. Fix from 2026-09-01 (found in review of ticket #69):
    /// the first version only matched the exact case
    /// "Dockerfile" and ignored the 2 variants. Constant shared
    /// between `from_path` (language detection, Phase A) and
    /// `run_scan` (building `FileDiscoveryConfig::filenames`,
    /// discovery) so that a single list is authoritative — two
    /// independent lists could have silently diverged.
    pub(crate) const DOCKERFILE_FILENAMES: [&'static str; 3] =
        ["Dockerfile", "Dockerfile.dev", "Dockerfile.prod"];

    /// Value expected in `rule_json["language"]` for this language.
    fn rule_tag(self) -> &'static str {
        match self {
            SourceLanguage::Python => "python",
            SourceLanguage::Java => "java",
            SourceLanguage::JavaScript | SourceLanguage::TypeScript => "javascript",
            SourceLanguage::Php => "php",
            SourceLanguage::CSharp => "csharp",
            SourceLanguage::Html => "html",
            SourceLanguage::Yaml => "yaml",
            SourceLanguage::Dockerfile => "dockerfile",
        }
    }

    /// Detects the language by EXTENSION alone. `None` for a format
    /// without a standard extension (`Dockerfile`) — use
    /// [`SourceLanguage::from_path`] for a real file on disk,
    /// this function stays correct in isolation everywhere an
    /// extension is already known otherwise.
    pub(crate) fn from_extension(path: &Path) -> Option<Self> {
        let ext = path.extension().and_then(|e| e.to_str())?;
        Self::EXTENSIONS
            .iter()
            .find(|(e, _)| *e == ext)
            .map(|(_, lang)| *lang)
    }

    /// Recognized file extensions (without the dot) and their language —
    /// the SOLE authoritative list, shared by [`SourceLanguage::from_extension`]
    /// (Phase A detection) and `run_scan` (building
    /// `FileDiscoveryConfig::extensions`), same single-source principle
    /// as [`SourceLanguage::DOCKERFILE_FILENAMES`].
    ///
    /// Mirrors `Audit/sca/runner.py` (`_py_exts`/`_js_exts`/`_html_exts`/
    /// `_java_exts`/`_csharp_exts`/`_php_exts`/`_yaml_exts`). Fix from
    /// 2026-11-04 (Python/Rust differential scan on `Audit/tests/fixtures`):
    /// the Rust lists only held `html`/`htm` for HTML, no `tsx`, no `inc`
    /// — `.vue`/`.svelte`/`.jsp`/`.cshtml`/… templates were never scanned
    /// (e.g. `xss_vue_vhtml`/`xss_svelte_html` never fired). All template
    /// formats go through the HTML grammar exactly like the Python side
    /// applies `language html` rules to them; tree-sitter is error-tolerant
    /// and the HTML rules are line-oriented regexes, so a partial parse of
    /// template syntax never hides a match. Deliberate superset: `cjs`
    /// (CommonJS, absent from Python's list) is kept from the initial port.
    pub(crate) const EXTENSIONS: [(&'static str, SourceLanguage); 33] = [
        ("py", SourceLanguage::Python),
        ("java", SourceLanguage::Java),
        ("js", SourceLanguage::JavaScript),
        ("jsx", SourceLanguage::JavaScript),
        ("mjs", SourceLanguage::JavaScript),
        ("cjs", SourceLanguage::JavaScript),
        ("ts", SourceLanguage::TypeScript),
        // Parsed with the TSX grammar, not the plain TypeScript one (JSX
        // syntax is a parse error for the latter) — see `ts_grammar_for`.
        ("tsx", SourceLanguage::TypeScript),
        ("php", SourceLanguage::Php),
        ("inc", SourceLanguage::Php),
        ("cs", SourceLanguage::CSharp),
        ("html", SourceLanguage::Html),
        ("htm", SourceLanguage::Html),
        ("xhtml", SourceLanguage::Html),
        ("shtml", SourceLanguage::Html),
        ("vue", SourceLanguage::Html),
        ("svelte", SourceLanguage::Html),
        ("ejs", SourceLanguage::Html),
        ("hbs", SourceLanguage::Html),
        ("njk", SourceLanguage::Html),
        ("jinja", SourceLanguage::Html),
        ("jinja2", SourceLanguage::Html),
        ("twig", SourceLanguage::Html),
        ("liquid", SourceLanguage::Html),
        ("mustache", SourceLanguage::Html),
        ("phtml", SourceLanguage::Html),
        ("erb", SourceLanguage::Html),
        ("jsp", SourceLanguage::Html),
        ("asp", SourceLanguage::Html),
        ("aspx", SourceLanguage::Html),
        ("cshtml", SourceLanguage::Html),
        ("yml", SourceLanguage::Yaml),
        ("yaml", SourceLanguage::Yaml),
    ];

    /// Detects the language of a real file on disk: EXACT NAME first
    /// (formats without a standard extension), then extension
    /// ([`SourceLanguage::from_extension`]) — ticket #69/spec #68.
    /// Mechanism deliberately reusable for a future extension-less
    /// format (only one case today: `Dockerfile`).
    /// Entry point to use everywhere a real file path is inspected
    /// (file discovery, scan Phase A).
    pub(crate) fn from_path(path: &Path) -> Option<Self> {
        if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && Self::DOCKERFILE_FILENAMES
                .iter()
                .any(|d| name.eq_ignore_ascii_case(d))
        {
            return Some(SourceLanguage::Dockerfile);
        }
        Self::from_extension(path)
    }
}

/// Tree-sitter grammar for a [`SourceLanguage::TypeScript`] file: TSX for
/// `.tsx` (JSX elements are a parse error in the plain TypeScript
/// grammar, which would degrade the AST the JS taint engine walks), plain
/// TypeScript otherwise. The TSX grammar is a superset sharing the same
/// node kinds, so downstream lowering needs no change.
fn ts_grammar_for(path: &Path) -> tree_sitter::Language {
    if path.extension().and_then(|e| e.to_str()) == Some("tsx") {
        tree_sitter_typescript::LANGUAGE_TSX.into()
    } else {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    }
}

/// Configuration of a scan.
pub struct ScanConfig {
    /// Root of the project to scan.
    pub root: PathBuf,
    /// Starting points for file discovery, relative to
    /// `root` — mirrors `paths.include` (`audit.config.json` on the
    /// Audit side, `sca/config.py`/`projects.py::_auto_detect_project`).
    /// `["."]` (default value, `ScanConfig::default()`) = the whole
    /// directory is scanned, unchanged historical behavior. A
    /// restricted value (e.g. `["sca/", "tests/"]`) avoids walking
    /// into directories that are never relevant (`.venv/`, `videos/`…)
    /// even if they aren't explicitly excluded by
    /// `exclude_patterns` — cf. `project_config.rs`.
    pub include_paths: Vec<String>,
    /// Directory holding the `.sca` rule files. Ignored if
    /// `use_embedded_rules` is active.
    pub rules_dir: PathBuf,
    /// Compiles the builtin catalog embedded in the binary
    /// (`embedded_rules::EMBEDDED_RULES`) entirely in memory, without
    /// going through `rules_dir` or disk — cf.
    /// `embedded_rules::compile_embedded_rules`. `false` by default
    /// (unchanged behavior: rules read from `rules_dir`, used by
    /// `--rules <DIR>` and by all existing tests).
    pub use_embedded_rules: bool,
    /// Custom rules directory, loaded IN ADDITION to the builtin
    /// catalog (never as a replacement) — ticket #84/spec #82, mirrors
    /// `_load_custom_rules`/`{SCRIPT_DIR}/custom-rules/` on the
    /// Python side (`rule_engine.py:714-731`). `None` (default): unchanged
    /// behavior, no custom rule consulted. **Ignored if
    /// `use_embedded_rules` is false**: `--rules <DIR>` (explicit
    /// full replacement) stays priority and exclusive, consistent with the
    /// acceptance criterion of the ticket — a user who explicitly requests
    /// an isolated test catalog must never see their custom rules
    /// silently slip in.
    pub custom_rules_dir: Option<PathBuf>,
    /// Directory of Ed25519-signed rule update packs,
    /// loaded IN ADDITION to the builtin catalog and the custom rules
    /// (never as a replacement) — ticket #85/spec #82, hardened mirror
    /// of `_load_update_packs`/`{SCRIPT_DIR}/rules-updates/` on the
    /// Python side (`rule_engine.py:357-420`). `None` (default):
    /// unchanged behavior, no pack consulted. **Ignored if
    /// `use_embedded_rules` is false**, same rule as
    /// `custom_rules_dir` above: `--rules <DIR>` stays exclusive.
    /// See `rule_packs.rs` for verification details and the safe
    /// fallback if no publisher public key was injected at build time.
    pub rule_updates_dir: Option<PathBuf>,
    /// Path to `.sca-suppress.json`, if it exists.
    pub suppress_file: Option<PathBuf>,
    /// Exclusion patterns (glob/directory/extension, cf. `discovery`).
    pub exclude_patterns: Vec<String>,
    /// Runs the audited project's test suite (opt-in, executes
    /// arbitrary project code — cf. `testing.rs`).
    pub with_tests: bool,
    /// Explicit test command; if absent and `with_tests`, tries
    /// auto-detection (`testing::auto_detect_test_command`).
    pub test_command: Option<String>,
    /// Detects unpinned dependencies and, when `advisories_dir` holds a
    /// database, dependencies with a published vulnerability (opt-in,
    /// offline — cf. `dependencies.rs`, `advisories.rs`).
    pub with_deps: bool,
    /// Offline advisory database written by `tools/sast-advisories`
    /// (ADR-0035), read during the dependencies phase. `None` or a
    /// missing directory: no vulnerability matching.
    pub advisories_dir: Option<PathBuf>,
    /// PostgreSQL schema audit (opt-in — network connection to the
    /// audited project's database, cf. `database::live`).
    pub database: Option<crate::project::database::live::DbConfig>,
    /// History directory (JSON export / baseline) — `None`
    /// disables export and baseline comparison.
    pub datas_dir: Option<PathBuf>,
    /// Naming prefix for history files (`{prefix}-DATA-*.json`).
    pub brand_prefix: String,
    /// `%Y-%m-%d-%H-%M` timestamp shared with the HTML report
    /// (`ReportContext::timestamp`), so that `{prefix}-DATA-*.json`
    /// and `{prefix}-REPORT-*.html` from the same scan carry exactly
    /// the same name — mirrors `self.timestamp` on the Audit side, computed
    /// once at the top of `AuditRunner.__init__`. Empty = computes
    /// its own timestamp (used by callers who don't export an
    /// HTML report, e.g. tests).
    pub timestamp: String,
    /// Fast mode — forces disabling the slow optional phases
    /// (`with_tests`/`with_deps`/`database`) even if they are
    /// otherwise requested, regardless of CLI argument order
    /// (mirrors `AuditRunner.quick_mode`, `runner.py::
    /// _compute_phase_total`/`run` — Python affects ONLY these 3 phases,
    /// never the rules themselves).
    pub quick_mode: bool,
    /// Restricts execution to rules of A SINGLE category
    /// (case-insensitive comparison against `rule_json["category"]`,
    /// e.g. "security") — mirrors `--only-category`/`AuditRunner.
    /// only_category`. `None` = all categories.
    pub only_category: Option<String>,
    /// Enables/disables EACH category independently (key =
    /// `rule_json["category"]` lowercased, e.g. "security"/"arch") —
    /// mirrors `AuditRunner.enabled_categories` (`runner.py:104-112`,
    /// fed by `audit.config.json::categories.<name>.enabled`,
    /// default `True` if the category isn't mentioned). Ticket
    /// #41/spec #27. **Distinct from `only_category` above, never
    /// combined with it**: `runner.py::should_run` (`runner.py:574-578`)
    /// uses one OR the other, never a translation from one to
    /// the other — if `only_category` is set, this map is
    /// entirely ignored (ticket #41 wrongly proposed
    /// "translating" the file into `only_category`, which would have given
    /// a wrong result as soon as disabling doesn't narrow
    /// the set down to exactly one category; confirmed by rereading
    /// `runner.py` directly, decision settled with the maintainer). Empty map
    /// = current behavior unchanged (all categories active).
    pub category_overrides: BTreeMap<String, bool>,
    /// Rule identifiers (`rule_json["id"]`) to never run —
    /// mirrors `--disable-rule`/`AuditRunner.disabled_rules`.
    pub disabled_rules: Vec<String>,
    /// Severities to keep in the final findings (e.g.
    /// `["HIGH", "CRITICAL"]`) — mirrors `--severity`. `None` = all
    /// severities. **Deliberate difference vs Python**: the source
    /// variant (`cli.py`) validates and stores `severity_levels` in
    /// `_cli_options` but never actually uses it afterward to
    /// filter findings (verified — no reference in
    /// `runner.py`); here the filter is actually applied, consistent
    /// with the expected behavior of such a flag.
    pub severity_levels: Option<Vec<String>>,
    /// Language (`en`/`fr`/`es`/`de`) used to resolve the i18n
    /// text of rules (`risk`/`solution`/`benefit`/`message`) right when
    /// findings are built — mirrors `self.lang` on the Audit side
    /// (`AuditRunner`, set once at initialization, before any
    /// finding is created). Deviation found by the maintainer (2026-08-26): this
    /// resolution used to happen without a known language and
    /// always fell back to English, regardless of `--lang` —
    /// rule text (risk/solution/benefit) systematically in
    /// English in an HTML/JSON report that should be in French. `"en"` by
    /// default (unchanged historical behavior if unspecified).
    pub lang: String,
    /// Optional callback invoked right after each phase (same
    /// label/duration as `ScanReport.phase_timings`), for LIVE progress
    /// display on the caller's side — `run_scan` stays free of
    /// direct I/O (no `eprintln!` here), the caller (`main.rs`)
    /// decides the format. A plain function pointer (not
    /// `Box<dyn Fn>`): sufficient for the only current need
    /// (`eprintln!` with no captured state) and trivially `Send + Sync`
    /// for the parallelized sections (`rayon`). `None` by default:
    /// no behavior change for existing callers
    /// (tests, `--quiet`).
    pub on_phase_complete: Option<fn(&str, std::time::Duration)>,
    /// `script` locale (console messages), for translating the phase
    /// labels emitted to `on_phase_complete` — ticket #48. `None`
    /// preserves exactly the historical behavior (hardcoded
    /// French labels): only `main.rs` builds and provides
    /// a real locale for a user scan; the ~1030 unit tests
    /// of this module that build `ScanConfig::default()`
    /// without worrying about it are not affected.
    ///
    /// **Deliberate deviation from this module's established convention**:
    /// until now, `run_scan` never did an i18n lookup
    /// itself — it only carries `lang: String` as
    /// data, leaving it to the caller (e.g. `report/html.rs::
    /// generate_html`) to load its own locale and translate. This
    /// wasn't possible here: the Phase A label is
    /// built dynamically (per-language detail, ticket #46)
    /// *during* the phase itself, before anything makes
    /// it back up to `main.rs` — deferring translation to the caller
    /// would have required making it also carry this label-building
    /// logic, duplicating part of `run_scan`.
    pub script_locale: Option<serde_json::Value>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::new(),
            include_paths: vec![".".to_string()],
            rules_dir: PathBuf::new(),
            use_embedded_rules: false,
            custom_rules_dir: None,
            rule_updates_dir: None,
            suppress_file: None,
            exclude_patterns: Vec::new(),
            with_tests: false,
            test_command: None,
            with_deps: false,
            advisories_dir: None,
            database: None,
            datas_dir: None,
            brand_prefix: "SCA".to_string(),
            timestamp: String::new(),
            quick_mode: false,
            only_category: None,
            category_overrides: BTreeMap::new(),
            disabled_rules: Vec::new(),
            severity_levels: None,
            lang: "en".to_string(),
            on_phase_complete: None,
            script_locale: None,
        }
    }
}

/// Resolves the text of a phase label — translated via
/// `config.script_locale` if provided (ticket #48), otherwise the
/// historical French text as-is (`config.script_locale == None`,
/// behavior of all callers who don't care about it,
/// notably this module's unit tests).
fn phase_label(config: &ScanConfig, key: &str, french_fallback: &str) -> String {
    match &config.script_locale {
        Some(locale) => crate::i18n::t(locale, key),
        None => french_fallback.to_string(),
    }
}

/// Result of a scan.
pub struct ScanReport {
    pub findings: Vec<ReportFinding>,
    pub files_scanned: usize,
    pub total_loc: usize,
    /// `.sca` files whose parsing/compilation failed (path,
    /// error message) — does not interrupt the scan, mirrors the
    /// robustness of `compute_file_summaries` on the Python side (a broken
    /// rule doesn't stop the others).
    pub rule_errors: Vec<(PathBuf, String)>,
    /// Catalog of compiled rules, indexed by id — needed by the
    /// HTML report (`report::html::generate_html`, `fix_before`/
    /// `fix_after` of `report::findings_html::generate_fix_suggestion`).
    pub rule_catalog: BTreeMap<String, serde_json::Value>,
    /// Results of the audited project's tests, if `with_tests` was active.
    pub test_results: Option<crate::project::testing::TestResults>,
    /// Dependency statistics, if `with_deps` was active.
    pub dependency_stats: Option<DependencyStats>,
    /// Extracted schema, if `database` was configured and the connection succeeded.
    pub database_schema: Option<crate::project::database::schema::DatabaseSchema>,
    /// Schema statistics (compared against the baseline if available).
    pub database_stats: Option<crate::project::database::schema::SchemaStats>,
    /// Comparison against the most recent baseline found in `datas_dir`.
    pub comparison: Option<crate::report::comparison::ComparisonResult>,
    /// Path of the JSON export written for this scan, if `datas_dir` was configured.
    pub export_path: Option<PathBuf>,
    /// Languages actually encountered among the scanned files
    /// (`SourceLanguage::rule_tag()`, e.g. "python"/"java"), sorted and
    /// deduplicated — feeds the "audit settings" section of the
    /// HTML report.
    pub languages: Vec<String>,
    /// Duration of each scan phase, in execution order —
    /// internal performance diagnostic. Added on 2026-08-26 to
    /// verify, backed by measurements rather than assumed, where
    /// time is actually spent (rule loading/compilation vs
    /// parsing vs regex vs per-language taint) — cf. memory of the
    /// ongoing perf effort. `String` (not `&'static str`) since
    /// ticket #46: Phase A's label now carries the
    /// per-language file count, computed at call time
    /// and therefore not `'static`.
    pub phase_timings: Vec<(String, std::time::Duration)>,
}

#[derive(Debug, Clone, Default)]
pub struct DependencyStats {
    pub total_scanned: usize,
    pub unpinned: usize,
    pub ok: usize,
    /// Dependencies with at least one published vulnerability
    /// (`vulnerable_dependency` findings, ADR-0035).
    pub vulnerable: usize,
}

/// `vulnerable_dependency` findings for the dependencies of `deps` hit
/// by the offline advisory database in `dir` (ADR-0035) — one finding
/// per dependency, listing every distinct vulnerability, so a package
/// with ten CVEs does not bury the report under ten lines. The severity
/// is the highest among them. Unreadable database files are reported on
/// stderr and skipped: the rest of the scan does not depend on them.
fn vulnerable_dependency_findings(
    dir: &Path,
    deps: &[crate::project::dependencies::Dependency],
) -> Vec<ReportFinding> {
    use crate::project::advisories;

    let ecosystems: std::collections::BTreeSet<String> =
        deps.iter().map(|d| d.ecosystem.clone()).collect();
    let (db, errors) = advisories::load(dir, &ecosystems);
    for error in errors {
        eprintln!("[sast-engine] advisory database skipped: {error}");
    }
    let rank = |s: &str| match s {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        _ => 1,
    };
    advisories::find_vulnerable(deps, &db)
        .into_iter()
        .map(|hit| {
            let dep = &hit.dependency;
            let severity = hit
                .advisories
                .iter()
                .map(|a| advisories::engine_severity(a))
                .max_by_key(|s| rank(s))
                .unwrap_or("MEDIUM");
            // The 10 most severe with their summary (the list arrives
            // sorted), the rest by identifier only: an old Django pin
            // matches 45 advisories.
            const DETAILED: usize = 10;
            let mut listed: Vec<String> = hit
                .advisories
                .iter()
                .take(DETAILED)
                .map(|a| {
                    format!(
                        "{} ({}): {}",
                        a.display_id(),
                        advisories::engine_severity(a),
                        a.summary
                    )
                })
                .collect();
            if hit.advisories.len() > DETAILED {
                let rest: Vec<&str> = hit.advisories[DETAILED..]
                    .iter()
                    .map(|a| a.display_id())
                    .collect();
                listed.push(format!("also {}", rest.join(", ")));
            }
            let mut cwe: Vec<String> = hit.advisories.iter().flat_map(|a| a.cwe.clone()).collect();
            cwe.sort();
            cwe.dedup();
            if cwe.is_empty() {
                // CWE-1395: Dependency on Vulnerable Third-Party Component.
                cwe.push("CWE-1395".to_string());
            }
            let solution = match &hit.fixed_version {
                Some(fixed) => format!("Upgrade {} to {fixed} or later.", dep.name),
                None => format!(
                    "No published version fixes every vulnerability: replace or remove {}.",
                    dep.name
                ),
            };
            ReportFinding {
                rule_key: "vulnerable_dependency".to_string(),
                rule_name: "Vulnerable dependency".to_string(),
                category: "DEPENDENCIES".to_string(),
                severity: severity.to_string(),
                risk: format!(
                    "{} {} is affected by {} published vulnerabilit{}: {}",
                    dep.name,
                    hit.version,
                    hit.advisories.len(),
                    if hit.advisories.len() == 1 {
                        "y"
                    } else {
                        "ies"
                    },
                    listed.join("; ")
                ),
                file: dep.file.to_string_lossy().to_string(),
                line: dep.line,
                solution: Some(solution),
                cwe,
                owasp: Some("A06:2021".to_string()),
                taint_flow: None,
                taint_flows: vec![],
                code: dep.raw_line.clone(),
                context_before: String::new(),
                context_after: String::new(),
                // The version is exact and the range comes from the
                // advisory itself; the remaining doubt is whether the
                // vulnerable code path is used.
                confidence: 90,
                benefit: String::new(),
                committer: None,
                rule_source: "advisory_db".to_string(),
            }
        })
        .collect()
}

/// Loads and compiles all `.sca` files in a directory, **recursively**
/// (the real catalog is organized into subfolders by category, e.g.
/// `python/security/`, `python/arch/`, `python/maintenance/`). An
/// invalid file is reported in `rule_errors` but does not stop the
/// loading of the others.
fn load_rules(rules_dir: &Path) -> (Vec<serde_json::Value>, Vec<(PathBuf, String)>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    let sca_config = FileDiscoveryConfig {
        extensions: vec![".sca".to_string()],
        filenames: vec![],
        exclude_patterns: vec![],
        prune_excludes: vec![],
    };
    // Alphabetical sort by full path — mirrors
    // `sorted(rules_dir.rglob("*.sca"))` on the Python side (`rule_loader.py`).
    // `find_files` (filesystem walk via `read_dir`) guarantees no
    // particular order. Without this sort, the taint rule processing
    // order differs from Python — with no effect on WHICH findings are
    // detected, but it affects which one "wins" the display when
    // several rules merge on the same line (see
    // `integrate_taint_finding`).
    let mut paths = find_files(rules_dir, &[Path::new(".")], &sca_config);
    paths.sort();
    for path in paths {
        let Ok(source) = std::fs::read_to_string(&path) else {
            errors.push((path, "lecture impossible".to_string()));
            continue;
        };
        let filename = path.to_string_lossy().to_string();
        match compile_sca_to_json(&source, &filename) {
            Ok(compiled) => rules.extend(compiled),
            Err(e) => errors.push((path, e.to_string())),
        }
    }
    (rules, errors)
}

/// Splits a file's content into lines, keeping their original line
/// terminator (the `readlines()` contract expected by
/// `engine::pattern::execute_regex_rule`).
fn split_lines_with_terminators(content: &str) -> Vec<(usize, String)> {
    content
        .split_inclusive('\n')
        .enumerate()
        .map(|(i, l)| (i + 1, l.to_string()))
        .collect()
}

fn line_text(source_lines: &[(usize, String)], line: usize) -> String {
    source_lines
        .get(line.saturating_sub(1))
        .map(|(_, t)| t.trim_end_matches('\n').to_string())
        .unwrap_or_default()
}

pub(crate) fn rule_category(rule_json: &serde_json::Value) -> String {
    rule_json
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Extracts the i18n text of a DSL block (`risk`/`solution`/`benefit`).
///
/// `lang`: target language — tried first, then falls back to `"en"`,
/// then to the first available language. Deviation fixed (2026-08-26,
/// reported by the maintainer): used to ignore `lang` and always fall back to
/// `"en"` regardless of `--lang` — the `risk`/`solution`/`benefit`
/// text of a `--lang fr` report stayed systematically in English
/// despite correctly translated interface labels.
pub(crate) fn extract_i18n_block(rule_json: &serde_json::Value, key: &str, lang: &str) -> String {
    match rule_json.get(key) {
        Some(serde_json::Value::Object(map)) => {
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
        Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
        _ => String::new(),
    }
}

/// Displayable description of a rule: `message` if present, otherwise
/// falls back to `risk` — many (non-taint) regex rules only carry a
/// `risk` block, `message` being used mostly on the taint side (see
/// real examples from the builtin corpus, `base64_eval.sca` vs
/// `taint_codeinj.sca`).
fn rule_display_message(rule_json: &serde_json::Value, lang: &str) -> String {
    let m = extract_message(rule_json, lang);
    if m.is_empty() {
        extract_i18n_block(rule_json, "risk", lang)
    } else {
        m
    }
}

fn engine_finding_to_report(
    f: &crate::scan::engine::Finding,
    rule_json: &serde_json::Value,
    rel_path: &str,
    source_lines: &[String],
    lang: &str,
) -> ReportFinding {
    let (context_before, context_after) =
        crate::report::text::context_lines(source_lines, f.line, 2);
    ReportFinding {
        rule_key: f.rule_id.clone(),
        rule_name: f.rule_id.clone(),
        category: f.category.clone(),
        severity: f.severity.clone(),
        risk: rule_display_message(rule_json, lang),
        file: rel_path.to_string(),
        line: f.line,
        solution: Some(extract_i18n_block(rule_json, "solution", lang)),
        cwe: extract_cwe(rule_json).into_iter().collect(),
        owasp: rule_json
            .get("metadata")
            .and_then(|m| m.get("owasp"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        taint_flow: None,
        taint_flows: vec![],
        code: f.code.clone(),
        context_before,
        context_after,
        confidence: f.confidence,
        benefit: extract_i18n_block(rule_json, "benefit", lang),
        committer: None,
        rule_source: "json_builtin".to_string(),
    }
}

/// Builds the `TaintFlow` of a taint finding — mirrors the
/// construction of `sca.models.TaintFlow` on the Audit side
/// (`source_kind` excluded, which has no single per-finding equivalent
/// here: it comes from the matched `SourceSpec`, see `f.source_kind`).
/// Safe fallback when `f.flow` does not clearly distinguish
/// source/sink (hybrid text-based engines): uses `f.source_line`/
/// `f.line` directly rather than inventing a step.
fn build_taint_flow(f: &crate::scan::dataflow::transfer::Finding, rel_path: &str) -> TaintFlow {
    let source_step = f.flow.iter().find(|s| s.kind == "source");
    let sink_step = f.flow.iter().rev().find(|s| s.kind == "sink");
    let chain: Vec<(usize, String, String)> = f
        .flow
        .iter()
        .filter(|s| s.kind == "propagation")
        .map(|s| (s.line, String::new(), s.text.clone()))
        .collect();
    TaintFlow {
        rule_key: f.rule_id.clone(),
        source_file: rel_path.to_string(),
        source_line: source_step.map_or_else(|| f.source_line.unwrap_or(f.line), |s| s.line),
        source_expr: source_step.map_or_else(String::new, |s| s.text.clone()),
        chain,
        sink_file: rel_path.to_string(),
        sink_line: f.line,
        sink_expr: sink_step.map_or_else(|| f.sink_text.clone(), |s| s.text.clone()),
        source_kind: f.source_kind.clone(),
    }
}

fn taint_finding_to_report(
    f: &crate::scan::dataflow::transfer::Finding,
    rule_json: &serde_json::Value,
    rel_path: &str,
    source_lines: &[String],
    lang: &str,
) -> ReportFinding {
    let (context_before, context_after) =
        crate::report::text::context_lines(source_lines, f.line, 2);
    let flow = build_taint_flow(f, rel_path);
    // Actual code line displayed in the highlighted block — mirrors
    // `self._get_line_content(flow.sink_file, flow.sink_line)` on the
    // `rule_engine.py::_integrate_taint_flow` side. `f.sink_text`
    // (call/callee name alone, e.g. "render_template_string") was not
    // the right source here — found by the maintainer: the report displayed
    // just the function name instead of the whole line
    // (`return render_template_string(template)`). `sink_text` remains
    // the right source for `TaintFlow.sink_expr` (summarized in the
    // "🔬 Traced" detail), a different need.
    let code = source_lines
        .get(f.line.saturating_sub(1))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| f.sink_text.clone());
    ReportFinding {
        rule_key: f.rule_id.clone(),
        rule_name: f.rule_id.clone(),
        // Category declared by the DSL rule, not a pseudo-category
        // "Taint" — mirrors `cat_key = flow.category.upper()` on the
        // `rule_engine.py::_integrate_taint_flow` side (a taint finding
        // joins the same SECURITY/ARCH/... category as regex findings,
        // a necessary condition for the health score — computed on the
        // SECURITY category alone — to count them).
        category: rule_category(rule_json).to_uppercase(),
        severity: f.severity.clone(),
        risk: f.message.clone(),
        file: rel_path.to_string(),
        line: f.line,
        solution: Some(extract_i18n_block(rule_json, "solution", lang)),
        cwe: f.cwe.clone().into_iter().collect(),
        owasp: None,
        taint_flow: Some(flow.clone()),
        taint_flows: vec![flow],
        code,
        context_before,
        context_after,
        // Fixed at 90, mirrors `sca/rule_engine.py:1131` (confidence=90
        // for any finding coming from a taint flow).
        confidence: 90,
        benefit: extract_i18n_block(rule_json, "benefit", lang),
        committer: None,
        rule_source: "json_builtin".to_string(),
    }
}

/// Attaches the flows of a taint finding to an already-present finding
/// — mirrors `_attach(finding, fl)` (internal function of
/// `rule_engine.py::_integrate_taint_flow`). Idempotent per flow
/// `rule_key` (a flow already attached for this rule is not
/// duplicated), sets `taint_flow` (singular) only if it was still
/// empty (the first flow attached wins, as on the Python side), and
/// always raises confidence to 95 — Python calls `_attach` on EVERY
/// integrated flow, including a finding just created with no merge
/// (verified empirically: on
/// `AuditBenchmarks/data/crypto/failles.py`, `taint_sqli`/`taint_xss`
/// — alone on their line, no merge — are at confidence 95 in the
/// Python JSON, not 90).
fn attach_taint_flows(existing: &mut ReportFinding, new_finding: &ReportFinding) {
    for flow in &new_finding.taint_flows {
        if existing
            .taint_flows
            .iter()
            .any(|f| f.rule_key == flow.rule_key)
        {
            continue;
        }
        existing.taint_flows.push(flow.clone());
        if existing.taint_flow.is_none() {
            existing.taint_flow = Some(flow.clone());
        }
    }
    existing.confidence = existing.confidence.max(95);
}

/// Merges a taint finding with an already-present finding on the same
/// (file, line, category) rather than adding a duplicate report line —
/// mirrors `rule_engine.py::_integrate_taint_flow`. Without this
/// mechanism, the same vulnerability detected by two different rules
/// at the same spot produces two findings instead of one on the Rust
/// side, whereas Python merges them. Two real examples
/// (`AuditBenchmarks/data/crypto/failles.py`, triage of 2026-08-26): a
/// `taint_rce` flow on a line already reported by the regex rule
/// `os_system_injection` (the same `os.system(` detected twice,
/// differently); a `taint_xss` flow on a line already reported by
/// `taint_ssti` (`render_template_string(` is a sink listed in both
/// rules — both vulnerabilities are real, only the display must stay
/// unique).
///
/// Two passes, as on the Python side: (1) look for a finding from the
/// same rule "family" already present on this line (identical
/// `rule_key` or common prefix, e.g. `ssrf`/`ssrf_python`) — merge into
/// it if found; (2) otherwise, merge into the first finding found on
/// the line, regardless of its rule. The already-present finding
/// "wins" the display — the merged vulnerability is not lost (its flow
/// joins `taint_flows`), just not duplicated as a report line.
///
/// **Accepted deviation**: which rule "wins" the display on a given
/// line depends on the taint rule processing order — `load_rules` now
/// sorts by alphabetical path, mirroring
/// `sorted(rules_dir.rglob("*.sca"))` on the Python side
/// (`rule_loader.py`), a necessary condition for this tie-break to be
/// identical.
fn integrate_taint_finding(all_findings: &mut Vec<ReportFinding>, new_finding: ReportFinding) {
    let same_line: Vec<usize> = all_findings
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            f.file == new_finding.file
                && f.line == new_finding.line
                && f.category == new_finding.category
        })
        .map(|(i, _)| i)
        .collect();

    if same_line.is_empty() {
        // Mirrors Python: even a freshly created taint finding, with
        // no merge, is immediately "attached" to itself
        // (`_attach(f, flow)` right after `_add_finding`) — confidence
        // goes to 95 in every case.
        let mut new_finding = new_finding;
        new_finding.confidence = new_finding.confidence.max(95);
        all_findings.push(new_finding);
        return;
    }

    // Pass 1: rule_key from the same family (exact match or common prefix).
    for &i in &same_line {
        let fk = &all_findings[i].rule_key;
        let tk = &new_finding.rule_key;
        if fk == tk || fk.starts_with(tk.as_str()) || tk.starts_with(fk.as_str()) {
            attach_taint_flows(&mut all_findings[i], &new_finding);
            return;
        }
    }
    // Pass 2: merge into the first finding already present on the
    // line — EVEN when `rule_key` is unrelated (e.g. a taint finding
    // merged into an unrelated regex finding). Deliberately checked
    // against the actual execution of Python (not just by reading
    // `rule_engine.py::_integrate_taint_flow`, which this exactly
    // mirrors) on 2026-09-01, ticket #30: a JS file with
    // `eval(req.body.code)` matched both `eval_usage_js` (regex, phase
    // B — a Rust-only bootstrap rule, removed on 2026-11-04 since it had
    // no Python counterpart) and `taint_codeinj` (taint, phase C) on the same line — the
    // actual SARIF output of `run_audit.py` contains only ONE finding
    // on this line (`taint_codeinj`, with a mix of cross-language
    // metadata caused by an id collision between the Python/JS/Java
    // catalogs sharing the same rule name `taint_codeinj` — a separate
    // topic, not addressed here). This is therefore NOT a merge bug
    // introduced by this port: Python also merges two unrelated rules
    // that match the same line+category, as surprising as that may
    // seem to a future reader who discovers that a ported taint rule
    // silently "disappears" from the report when an unrelated regex
    // rule shares its line.
    attach_taint_flows(&mut all_findings[same_line[0]], &new_finding);
}

/// A file already read and parsed, kept in memory for the whole scan
/// duration — needed for Phase C (the multi-file `CallGraph` borrows
/// the tree-sitter trees of ALL files at once, not file by file).
struct ParsedFile {
    rel_path: String,
    filepath: PathBuf,
    source_bytes: Vec<u8>,
    source_text: String,
    all_lines: Vec<(usize, String)>,
    source_lines_plain: Vec<String>,
    tree: Tree,
    language: SourceLanguage,
}

/// Breakdown of already-parsed files by language — `BTreeMap` for a
/// stable (alphabetical) display order, not the order files were
/// encountered in. Computed once, reused by three consumers that used
/// to each independently derive the same information from
/// `parsed_files` (count displayed in phase A, ticket #46; language
/// list for test-command auto-detection; `ScanReport.languages`).
fn files_per_language(parsed_files: &[ParsedFile]) -> BTreeMap<&'static str, usize> {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for pf in parsed_files {
        *counts.entry(pf.language.rule_tag()).or_insert(0) += 1;
    }
    counts
}

/// Runs a full scan on `config.root`.
///
/// Three phases:
///   A. Reading + parsing of all files (once).
///   B. Regex/file_contains, per file (independent of the others).
///   C. Taint, **multi-file**: builds a `CallGraph` over the whole set
///      of files (mirrors `dataflow_adapter.py` — one graph per batch
///      of files analyzed together, here the whole scan since
///      Decision #10 = Python only, hence a single language), resolves
///      the interprocedural summaries per taint rule, then analyzes
///      each file with `specs.summaries` seeded (the file's own
///      summaries + resolved import summaries, own summaries taking
///      priority over imports — mirrors `merged.update(summaries)` on
///      the `dataflow_taint.py` side).
pub fn run_scan(config: &ScanConfig) -> ScanReport {
    // Total number of phases planned for THIS scan — mirrors
    // `runner.py::_compute_phase_total` (already referenced above by
    // `ScanConfig::quick_mode`: "Python only affects these 3 phases").
    // The 3 core phases always run (rules, phase A, phase B), the 5
    // phase C taint phases (Python/Java/JS-TS/PHP/C#) always run, plus the
    // optional phases actually enabled
    // (dependencies/tests/database), disabled by `--quick` as on the
    // Python side. Computed once, before any phase, so that the live
    // `[n/N]` counter (ticket #45) is correct from the very first
    // message rather than a frozen constant that would go wrong as
    // soon as a phase is added (went from 7 to 8 in ticket #79 when
    // wiring up the C# taint engine).
    // Rules, phase A, phase B — always run.
    const CORE_PHASES: usize = 3;
    // Phase C, one per taint language (Python/Java/JS-TS/PHP/C#).
    const TAINT_PHASES: usize = 5;
    // A single source of truth per optional phase, reused both here
    // (computing `total_phases`) and by the `if` guard of its own
    // block further down — prevents the two from drifting apart if one
    // is changed without the other.
    let deps_phase_active = config.with_deps && !config.quick_mode;
    let tests_phase_active = config.with_tests && !config.quick_mode;
    let database_phase_active = config.database.is_some() && !config.quick_mode;
    let total_phases = CORE_PHASES
        + TAINT_PHASES
        + [deps_phase_active, tests_phase_active, database_phase_active]
            .into_iter()
            .filter(|&active| active)
            .count();

    let mut phase_timings: Vec<(String, std::time::Duration)> = Vec::new();
    // `label: &str` (not `&'static str`) since ticket #46: the phase A
    // label is formatted dynamically (per-language count), hence
    // borrowed from a temporary `String` rather than a `'static`
    // literal. The 9 other calls always pass a literal, which coerces
    // fine to `&str`.
    let mut record_phase = |label: &str, elapsed: std::time::Duration| {
        phase_timings.push((label.to_string(), elapsed));
        if let Some(cb) = config.on_phase_complete {
            // The label stored in `phase_timings` stays the full label
            // (including the per-language count for phase A) — only
            // the `[n/N]` prefix is added specifically for the LIVE
            // progress callback, not persisted in `phase_timings`.
            let n = phase_timings.len();
            cb(&format!("[{n}/{total_phases}] {label}"), elapsed);
        }
    };
    let t_rules = std::time::Instant::now();
    let (mut loaded_rule_jsons, mut rule_errors) = if config.use_embedded_rules {
        crate::rules::embedded_rules::compile_embedded_rules()
    } else {
        load_rules(&config.rules_dir)
    };
    // Custom rules (ticket #84/spec #82): additive, NEVER when
    // `--rules <DIR>` is explicit (implicit ADR of this ticket — an
    // isolated test catalog must never see custom rules mixed in
    // without asking for it).
    if config.use_embedded_rules
        && let Some(custom_dir) = &config.custom_rules_dir
        && custom_dir.is_dir()
    {
        let (custom_rules, mut custom_errors) = load_rules(custom_dir);
        loaded_rule_jsons.extend(custom_rules);
        rule_errors.append(&mut custom_errors);
    }
    // Ed25519-signed update packs (ticket #85/spec #82): additive like
    // the custom rules above — see the doc comment of the
    // `rule_updates_dir` field and `rule_packs.rs` for the verification
    // itself (silent safe fallback if no publisher public key was
    // injected at build time).
    if config.use_embedded_rules
        && let Some(updates_dir) = &config.rule_updates_dir
        && updates_dir.is_dir()
    {
        let (pack_rules, mut pack_errors) =
            crate::rules::rule_packs::load_update_packs(updates_dir);
        loaded_rule_jsons.extend(pack_rules);
        rule_errors.append(&mut pack_errors);
    }
    record_phase(
        &phase_label(
            config,
            "scan_phase_rules",
            "règles (chargement + compilation DSL)",
        ),
        t_rules.elapsed(),
    );

    // `--only-category`/`categories.*.enabled`/`--disable-rule`
    // filtering — applied once here, upstream of all phases
    // (regex/hybrid + taint, all languages): an excluded rule is
    // simply never run, rather than having its findings filtered out
    // afterwards. Mirrors `runner.py::should_run` (ticket #41/spec
    // #27): `only_category` and `category_overrides` are NEVER
    // combined, see the doc comment of the `category_overrides` field
    // above.
    let rule_jsons: Vec<serde_json::Value> = loaded_rule_jsons
        .into_iter()
        .filter(|r| {
            let cat = r.get("category").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(only_cat) = &config.only_category {
                if !cat.eq_ignore_ascii_case(only_cat) {
                    return false;
                }
            } else if let Some(&enabled) = config.category_overrides.get(&cat.to_lowercase())
                && !enabled
            {
                return false;
            }
            if !config.disabled_rules.is_empty() {
                let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if config.disabled_rules.iter().any(|d| d == id) {
                    return false;
                }
            }
            true
        })
        .collect();

    let discovery_config = FileDiscoveryConfig {
        // Derived from `SourceLanguage::EXTENSIONS`, the sole authoritative
        // list (fix 2026-11-04): a hand-maintained copy here had drifted
        // from Python's `runner.py` lists (no `.vue`/`.svelte`/`.tsx`/`.inc`…).
        extensions: SourceLanguage::EXTENSIONS
            .iter()
            .map(|(e, _)| format!(".{e}"))
            .collect(),
        // `Dockerfile` has no standard extension — recognized by exact
        // case-insensitive name (ticket #69/spec #68, fixed on
        // 2026-09-01 to cover the same 3 names as Python), not via
        // `extensions` above. See `SourceLanguage::
        // DOCKERFILE_FILENAMES`, the sole authoritative list.
        filenames: SourceLanguage::DOCKERFILE_FILENAMES
            .iter()
            .map(|s| s.to_string())
            .collect(),
        exclude_patterns: config.exclude_patterns.clone(),
        prune_excludes: config.exclude_patterns.clone(),
    };
    let include_paths: Vec<&Path> = config.include_paths.iter().map(Path::new).collect();
    let files = find_files(&config.root, &include_paths, &discovery_config);

    let suppressions = config
        .suppress_file
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| Suppressions::load_from_json(&s))
        .unwrap_or_default();

    // Phase A — reading + parsing all files. Parallelized per file
    // (disk reads + tree-sitter parsing are independent; each task
    // creates its own `TsParser` — not shareable across threads). The
    // order of `files` is preserved (explicit indexing): the rest of
    // the pipeline (Phase B/C) and the reports depend on it to be
    // identical to the sequential version.
    let t_phase_a = std::time::Instant::now();
    let parsed_results: Vec<Option<(usize, ParsedFile)>> = files
        .par_iter()
        .map(|filepath| {
            let language = SourceLanguage::from_path(filepath)?; // unknown extension/name: should not happen (discovery already filtered).
            let source_bytes = std::fs::read(filepath).ok()?;
            let source_text = String::from_utf8_lossy(&source_bytes).into_owned();
            let all_lines = split_lines_with_terminators(&source_text);
            let source_lines_plain: Vec<String> =
                all_lines.iter().map(|(_, t)| t.clone()).collect();
            let rel_path = filepath
                .strip_prefix(&config.root)
                .unwrap_or(filepath)
                .to_string_lossy()
                .replace('\\', "/");

            let mut parser = TsParser::new();
            let ts_lang: tree_sitter::Language = match language {
                SourceLanguage::Python => tree_sitter_python::LANGUAGE.into(),
                SourceLanguage::Java => tree_sitter_java::LANGUAGE.into(),
                SourceLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
                SourceLanguage::TypeScript => ts_grammar_for(filepath),
                SourceLanguage::Php => tree_sitter_php::LANGUAGE_PHP.into(),
                SourceLanguage::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
                SourceLanguage::Html => tree_sitter_html::LANGUAGE.into(),
                SourceLanguage::Yaml => tree_sitter_yaml::LANGUAGE.into(),
                // The only crate with no official org (ticket #69): older
                // API, a `language()` function that already returns
                // `tree_sitter::Language` — no `LanguageFn`/`.into()`
                // like the 8 other grammars in this match.
                SourceLanguage::Dockerfile => tree_sitter_dockerfile_updated::language(),
            };
            parser.set_language(&ts_lang).ok()?;
            let tree = parser.parse(&source_text, None)?;

            let loc = match language {
                SourceLanguage::Python => count_python_loc(&source_bytes, &tree),
                SourceLanguage::Java => count_java_loc(&source_bytes, &tree),
                // `count_js_loc` operates purely on the "comment"
                // kind-string, identical across JS/TS/PHP/C#/HTML/YAML/
                // Dockerfile (verified empirically on the 4 new
                // grammars, ticket #69: a single "comment" node, no
                // line_comment/block_comment split like in Java) — no
                // need for a dedicated per-language counter.
                SourceLanguage::JavaScript
                | SourceLanguage::TypeScript
                | SourceLanguage::Php
                | SourceLanguage::CSharp
                | SourceLanguage::Html
                | SourceLanguage::Yaml
                | SourceLanguage::Dockerfile => count_js_loc(&source_bytes, &tree),
            };
            Some((
                loc,
                ParsedFile {
                    rel_path,
                    filepath: filepath.clone(),
                    source_bytes,
                    source_text,
                    all_lines,
                    source_lines_plain,
                    tree,
                    language,
                },
            ))
        })
        .collect();

    let loc_and_files: Vec<(usize, ParsedFile)> = parsed_results.into_iter().flatten().collect();

    let mut parsed_files: Vec<ParsedFile> = Vec::new();
    let mut total_loc = 0usize;
    for (loc, parsed_file) in loc_and_files {
        total_loc += loc;
        parsed_files.push(parsed_file);
    }

    // Per-language count (ticket #46) — computed here, not in a
    // separate pass: `parsed_files` already knows each file's language
    // (`ParsedFile::language`), phase A has just grouped them.
    let language_summary = files_per_language(&parsed_files)
        .iter()
        .map(|(lang, count)| format!("{lang}: {count}"))
        .collect::<Vec<_>>()
        .join(", ");
    record_phase(
        &format!(
            "{} — {language_summary}",
            phase_label(config, "scan_phase_a", "phase A (lecture + parsing)")
        ),
        t_phase_a.elapsed(),
    );

    let mut all_findings: Vec<ReportFinding> = Vec::new();

    // Phase B — regex/file_contains, per file. A rule only applies to
    // files of ITS declared language (`rule_json["language"]`), now
    // that Python and Java coexist in the same loaded catalog.
    //
    // Parallelized per file (independent of each other —
    // `dispatch_rule`/`suppressions.is_suppressed` are pure functions
    // of the current file, no shared state during computation). The
    // final order (file, then rule) is preserved identically by
    // flattening results in `parsed_files` order, for a report
    // strictly identical to the sequential version.
    let t_phase_b = std::time::Instant::now();
    let per_file_findings: Vec<Vec<ReportFinding>> = parsed_files
        .par_iter()
        .map(|pf| {
            let mut out = Vec::new();
            for rule_json in &rule_jsons {
                if rule_json.get("language").and_then(|v| v.as_str())
                    != Some(pf.language.rule_tag())
                {
                    continue;
                }
                let DispatchOutcome::Findings(findings) =
                    dispatch_rule(rule_json, &pf.filepath, &pf.all_lines, &pf.source_text)
                else {
                    continue; // Taint/Ast/Hook: handled elsewhere (Phase C) or out of scope.
                };
                for f in findings {
                    if suppressions.is_suppressed(&f.rule_id, &pf.rel_path, &f.code) {
                        continue;
                    }
                    if is_inline_ignored(&f.code, &f.rule_id) {
                        continue;
                    }
                    out.push(engine_finding_to_report(
                        &f,
                        rule_json,
                        &pf.rel_path,
                        &pf.source_lines_plain,
                        &config.lang,
                    ));
                }
            }
            out
        })
        .collect();
    for findings in per_file_findings {
        all_findings.extend(findings);
    }
    record_phase(
        &phase_label(config, "scan_phase_b", "phase B (regex/file_contains)"),
        t_phase_b.elapsed(),
    );

    // Phase C — multi-file taint, one batch per language. The call
    // graph is built ONCE per language (structure independent of the
    // rule: nodes = all functions, edges = all resolved calls); only
    // the summary resolution (`resolve_summaries`) depends on the rule
    // (sources/sinks specific to each taint rule).
    //
    // Global deduplication — key (file, rule_id, line, source_line).
    // The file MUST be part of the key: without it, two distinct files
    // sharing the same line number for the same rule_id (very common
    // on a corpus of structurally similar files, e.g. OWASP
    // BenchmarkJava — hundreds of nearly identical classes) silently
    // cancel each other out, making real findings disappear. Bug found
    // on 2026-08-25 while calibrating the Java taint engine on OWASP
    // BenchmarkJava (recall 34% instead of the ~100% expected) —
    // pre-existing on the Python side too (same `seen_taint` shared
    // between the two blocks), fixed for both languages.
    let mut seen_taint: HashSet<(String, String, usize, Option<usize>)> = HashSet::new();

    // --- Python ---------------------------------------------------------
    let t_phase_c_python = std::time::Instant::now();
    let python_files: Vec<&ParsedFile> = parsed_files
        .iter()
        .filter(|pf| pf.language == SourceLanguage::Python)
        .collect();
    let py_file_inputs: Vec<FileInput> = python_files
        .iter()
        .map(|pf| FileInput {
            filepath: pf.rel_path.clone(),
            root: pf.tree.root_node(),
            source: pf.source_bytes.as_slice(),
        })
        .collect();
    let call_graph = CallGraph::build(&py_file_inputs);
    let py_source_lines_by_file: BTreeMap<String, Vec<String>> = python_files
        .iter()
        .map(|pf| (pf.rel_path.clone(), pf.source_lines_plain.clone()))
        .collect();

    // Parallelized **per rule**, not per file — measured (2026-08-26,
    // `sample`/dedicated timers on `Audit/sca`, 34k lines):
    // `resolve_summaries` (function summary resolution over the WHOLE
    // call graph, once per rule) largely dominates the cost of this
    // phase — up to 6-7s per taint rule, ~25 rules, against only 8s
    // total for `run_taint_rule` over the 73 cumulative files.
    // Parallelizing per file (first version) therefore barely touched
    // the real bottleneck. Each rule is independent (its own
    // specs/summaries/results); the final merge
    // (deduplication/suppression/`integrate_taint_finding`) remains
    // strictly sequential, in the original order of rules THEN files,
    // for a result identical to the purely sequential version.
    let python_rule_jsons: Vec<&serde_json::Value> = rule_jsons
        .iter()
        .filter(|r| {
            r.get("language").and_then(|v| v.as_str()) == Some(SourceLanguage::Python.rule_tag())
        })
        .collect();
    let per_rule_results: Vec<Option<Vec<Vec<crate::scan::dataflow::transfer::Finding>>>> =
        python_rule_jsons
            .par_iter()
            .map(|rule_json| {
                // `rule_json_to_specs` returns `Some` as soon as the rule
                // has at least one source AND one sink — independently
                // of `patterns` (a `regex+taint` rule therefore goes
                // through BOTH pipelines, Phase B and Phase C, as on
                // the Python side).
                let base_specs = rule_json_to_specs(rule_json, &config.lang)?;
                let (own, extra) =
                    call_graph.resolve_summaries(&base_specs, Some(&py_source_lines_by_file));
                // Cloned ONCE per rule (not per file) — only
                // `.summaries` varies per file. Found on 2026-08-26
                // while investigating slowness reported by the maintainer on a
                // large Java corpus (same antipattern, see the Java
                // block below and `java_call_graph.rs::resolve_summaries`
                // fixed just before): `base_specs.clone()` (with its
                // sources/sinks/sanitizers/passthroughs `Regex`) used to
                // be redone for every file, i.e. (files × rules) times
                // in total — pure waste, `sources`/`sinks`/
                // `sanitizers`/`passthroughs` only depend on the rule,
                // never on the file.
                let mut node_specs = base_specs.clone();
                let per_file: Vec<Vec<crate::scan::dataflow::transfer::Finding>> = python_files
                    .iter()
                    .map(|pf| {
                        // File's own summaries take priority over
                        // resolved imports (mirrors
                        // `merged.update(summaries)` on the
                        // `dataflow_taint.py` side: local > import).
                        let mut summaries = extra.get(&pf.rel_path).cloned().unwrap_or_default();
                        if let Some(own_here) = own.get(&pf.rel_path) {
                            summaries.extend(own_here.clone());
                        }
                        node_specs.summaries = summaries;
                        run_taint_rule(
                            &pf.tree,
                            &pf.source_bytes,
                            &node_specs,
                            Some(&pf.source_lines_plain),
                        )
                    })
                    .collect();
                Some(per_file)
            })
            .collect();

    for (rule_json, maybe_per_file) in python_rule_jsons.iter().zip(per_rule_results) {
        let Some(per_file) = maybe_per_file else {
            continue;
        };
        for (pf, findings) in python_files.iter().zip(per_file) {
            for f in findings {
                let key = (
                    pf.rel_path.clone(),
                    f.rule_id.clone(),
                    f.line,
                    f.source_line,
                );
                if !seen_taint.insert(key) {
                    continue;
                }
                let code = line_text(&pf.all_lines, f.line);
                if suppressions.is_suppressed(&f.rule_id, &pf.rel_path, &code) {
                    continue;
                }
                if is_inline_ignored(&code, &f.rule_id) {
                    continue;
                }
                integrate_taint_finding(
                    &mut all_findings,
                    taint_finding_to_report(
                        &f,
                        rule_json,
                        &pf.rel_path,
                        &pf.source_lines_plain,
                        &config.lang,
                    ),
                );
            }
        }
    }
    record_phase(
        &phase_label(config, "scan_phase_c_python", "phase C - Python (taint)"),
        t_phase_c_python.elapsed(),
    );

    // --- Java -------------------------------------------------------------
    let t_phase_c_java = std::time::Instant::now();
    let java_files: Vec<&ParsedFile> = parsed_files
        .iter()
        .filter(|pf| pf.language == SourceLanguage::Java)
        .collect();
    let java_file_inputs: Vec<FileInput> = java_files
        .iter()
        .map(|pf| FileInput {
            filepath: pf.rel_path.clone(),
            root: pf.tree.root_node(),
            source: pf.source_bytes.as_slice(),
        })
        .collect();
    let java_call_graph = JavaCallGraph::build(&java_file_inputs);
    let java_source_lines_by_file: BTreeMap<String, Vec<String>> = java_files
        .iter()
        .map(|pf| (pf.rel_path.clone(), pf.source_lines_plain.clone()))
        .collect();
    // Round 5 (`scr.method()` resolution via declared type) —
    // recomputed per file, independently of the call graph (same
    // logical dict as `JavaCallGraph::build`, MUST stay in sync — see
    // the doc comment of `collect_java_field_types`, same choice as
    // `dataflow_taint_java.py` on the Python source side).
    let java_type_map_by_file: BTreeMap<String, BTreeMap<String, String>> = java_files
        .iter()
        .map(|pf| {
            let mut type_map = collect_java_field_types(pf.tree.root_node(), &pf.source_bytes);
            type_map.extend(collect_java_local_types(
                pf.tree.root_node(),
                &pf.source_bytes,
            ));
            (pf.rel_path.clone(), type_map)
        })
        .collect();

    // Parallelized **per rule**, not per file — same fix as the Python
    // block above (found while diagnosing Python, never reapplied to
    // Java until now: reported by the maintainer, 2026-08-26, while comparing a
    // Java scan to Python — `resolve_summaries` (function summary
    // resolution over the whole call graph, once per rule) dominates
    // the cost, not per-file `run_taint_rule_java`).
    let java_rule_jsons: Vec<&serde_json::Value> = rule_jsons
        .iter()
        .filter(|r| {
            r.get("language").and_then(|v| v.as_str()) == Some(SourceLanguage::Java.rule_tag())
        })
        .collect();
    let java_per_rule_results: Vec<Option<Vec<Vec<crate::scan::dataflow::transfer::Finding>>>> =
        java_rule_jsons
            .par_iter()
            .map(|rule_json| {
                let base_specs = rule_json_to_specs(rule_json, &config.lang)?;
                let (own, extra) = java_call_graph
                    .resolve_summaries(&base_specs, Some(&java_source_lines_by_file));
                // Cloned ONCE per rule — see the equivalent comment in
                // the Python block above. It was THIS clone, repeated
                // per file (40,000 times on a corpus of 2000 files ×
                // 20 rules), that dominated the real cost of the Java
                // phase on OWASP BenchmarkJava — not `resolve_summaries`
                // itself (already fixed, only a marginal gain).
                let mut node_specs = base_specs.clone();
                let per_file: Vec<Vec<crate::scan::dataflow::transfer::Finding>> = java_files
                    .iter()
                    .map(|pf| {
                        let mut summaries = extra.get(&pf.rel_path).cloned().unwrap_or_default();
                        if let Some(own_here) = own.get(&pf.rel_path) {
                            summaries.extend(own_here.clone());
                        }
                        node_specs.summaries = summaries;
                        node_specs.type_map = java_type_map_by_file
                            .get(&pf.rel_path)
                            .cloned()
                            .unwrap_or_default();
                        run_taint_rule_java(
                            pf.tree.root_node(),
                            &pf.source_bytes,
                            &node_specs,
                            Some(&pf.source_lines_plain),
                        )
                    })
                    .collect();
                Some(per_file)
            })
            .collect();

    for (rule_json, maybe_per_file) in java_rule_jsons.iter().zip(java_per_rule_results) {
        let Some(per_file) = maybe_per_file else {
            continue;
        };
        for (pf, findings) in java_files.iter().zip(per_file) {
            for f in findings {
                let key = (
                    pf.rel_path.clone(),
                    f.rule_id.clone(),
                    f.line,
                    f.source_line,
                );
                if !seen_taint.insert(key) {
                    continue;
                }
                let code = line_text(&pf.all_lines, f.line);
                if suppressions.is_suppressed(&f.rule_id, &pf.rel_path, &code) {
                    continue;
                }
                if is_inline_ignored(&code, &f.rule_id) {
                    continue;
                }
                integrate_taint_finding(
                    &mut all_findings,
                    taint_finding_to_report(
                        &f,
                        rule_json,
                        &pf.rel_path,
                        &pf.source_lines_plain,
                        &config.lang,
                    ),
                );
            }
        }
    }
    record_phase(
        &phase_label(config, "scan_phase_c_java", "phase C - Java (taint)"),
        t_phase_c_java.elapsed(),
    );

    // --- JavaScript / TypeScript ---------------------------------------------
    // Interprocedural resolution wired up on 08/30 (`js_call_graph.rs`)
    // — same pattern as Python/Java above (graph built once, summaries
    // resolved per rule, `own`/`extra` merged per file, own taking
    // priority). **New development, not a port**: the reference Python
    // engine has no JS call graph at all (intra-file lexical fallback
    // only, see the doc comment of `js_call_graph.rs`) — designed by analogy with
    // Python/Java, with import resolution specific to JS/TS (relative
    // path, not suffix or FQCN). Both languages share this same block
    // — `run_taint_rule_js` works indifferently on a JS or TS tree
    // (see the doc comment of `js_lowering.rs`).
    let t_phase_c_js = std::time::Instant::now();
    let js_files: Vec<&ParsedFile> = parsed_files
        .iter()
        .filter(|pf| {
            matches!(
                pf.language,
                SourceLanguage::JavaScript | SourceLanguage::TypeScript
            )
        })
        .collect();
    let js_file_inputs: Vec<FileInput> = js_files
        .iter()
        .map(|pf| FileInput {
            filepath: pf.rel_path.clone(),
            root: pf.tree.root_node(),
            source: pf.source_bytes.as_slice(),
        })
        .collect();
    let js_call_graph = JsCallGraph::build(&js_file_inputs);
    let js_source_lines_by_file: BTreeMap<String, Vec<String>> = js_files
        .iter()
        .map(|pf| (pf.rel_path.clone(), pf.source_lines_plain.clone()))
        .collect();

    // Parallelized per rule, not per file — see the equivalent comment
    // in the Python block above (`resolve_summaries` dominates the cost).
    let js_rule_jsons: Vec<&serde_json::Value> = rule_jsons
        .iter()
        .filter(|r| {
            r.get("language").and_then(|v| v.as_str())
                == Some(SourceLanguage::JavaScript.rule_tag())
        })
        .collect();
    let js_per_rule_results: Vec<Option<Vec<Vec<crate::scan::dataflow::transfer::Finding>>>> =
        js_rule_jsons
            .par_iter()
            .map(|rule_json| {
                let base_specs = rule_json_to_specs(rule_json, &config.lang)?;
                let (own, extra) =
                    js_call_graph.resolve_summaries(&base_specs, Some(&js_source_lines_by_file));
                let mut node_specs = base_specs.clone();
                let per_file: Vec<Vec<crate::scan::dataflow::transfer::Finding>> = js_files
                    .iter()
                    .map(|pf| {
                        // File's own summaries take priority over
                        // resolved imports (own > extra, same
                        // convention as the Python block).
                        let mut summaries = extra.get(&pf.rel_path).cloned().unwrap_or_default();
                        if let Some(own_here) = own.get(&pf.rel_path) {
                            summaries.extend(own_here.clone());
                        }
                        node_specs.summaries = summaries;
                        run_taint_rule_js(
                            pf.tree.root_node(),
                            &pf.source_bytes,
                            &node_specs,
                            Some(&pf.source_lines_plain),
                        )
                    })
                    .collect();
                Some(per_file)
            })
            .collect();

    for (rule_json, maybe_per_file) in js_rule_jsons.iter().zip(js_per_rule_results) {
        let Some(per_file) = maybe_per_file else {
            continue;
        };
        for (pf, findings) in js_files.iter().zip(per_file) {
            for f in findings {
                let key = (
                    pf.rel_path.clone(),
                    f.rule_id.clone(),
                    f.line,
                    f.source_line,
                );
                if !seen_taint.insert(key) {
                    continue;
                }
                let code = line_text(&pf.all_lines, f.line);
                if suppressions.is_suppressed(&f.rule_id, &pf.rel_path, &code) {
                    continue;
                }
                if is_inline_ignored(&code, &f.rule_id) {
                    continue;
                }
                integrate_taint_finding(
                    &mut all_findings,
                    taint_finding_to_report(
                        &f,
                        rule_json,
                        &pf.rel_path,
                        &pf.source_lines_plain,
                        &config.lang,
                    ),
                );
            }
        }
    }
    record_phase(
        &phase_label(config, "scan_phase_c_js", "phase C - JS/TS (taint)"),
        t_phase_c_js.elapsed(),
    );

    // --- PHP --------------------------------------------------------------
    // Interprocedural resolution wired up on 08/30 (`php_call_graph.rs`)
    // — same pattern as Python/Java/JS above. **New development, not a
    // port** (same situation as JS, see the doc comment of
    // `php_call_graph.rs`): two mechanisms specific to PHP (star merge
    // of `require`/`include`, global class-name index for static-scope
    // calls — no scope/namespace notion tracked). Separate rule
    // catalog (`rule_tag() == "php"`, not shared with JS).
    let t_phase_c_php = std::time::Instant::now();
    let php_files: Vec<&ParsedFile> = parsed_files
        .iter()
        .filter(|pf| pf.language == SourceLanguage::Php)
        .collect();
    let php_file_inputs: Vec<FileInput> = php_files
        .iter()
        .map(|pf| FileInput {
            filepath: pf.rel_path.clone(),
            root: pf.tree.root_node(),
            source: pf.source_bytes.as_slice(),
        })
        .collect();
    let php_call_graph = PhpCallGraph::build(&php_file_inputs);
    let php_source_lines_by_file: BTreeMap<String, Vec<String>> = php_files
        .iter()
        .map(|pf| (pf.rel_path.clone(), pf.source_lines_plain.clone()))
        .collect();

    // Parallelized per rule, not per file — see the equivalent comment
    // in the Python block above (`resolve_summaries` dominates the cost).
    let php_rule_jsons: Vec<&serde_json::Value> = rule_jsons
        .iter()
        .filter(|r| {
            r.get("language").and_then(|v| v.as_str()) == Some(SourceLanguage::Php.rule_tag())
        })
        .collect();
    let php_per_rule_results: Vec<Option<Vec<Vec<crate::scan::dataflow::transfer::Finding>>>> =
        php_rule_jsons
            .par_iter()
            .map(|rule_json| {
                let base_specs = rule_json_to_specs(rule_json, &config.lang)?;
                let (own, extra) =
                    php_call_graph.resolve_summaries(&base_specs, Some(&php_source_lines_by_file));
                let mut node_specs = base_specs.clone();
                let per_file: Vec<Vec<crate::scan::dataflow::transfer::Finding>> = php_files
                    .iter()
                    .map(|pf| {
                        let mut summaries = extra.get(&pf.rel_path).cloned().unwrap_or_default();
                        if let Some(own_here) = own.get(&pf.rel_path) {
                            summaries.extend(own_here.clone());
                        }
                        node_specs.summaries = summaries;
                        run_taint_rule_php(
                            pf.tree.root_node(),
                            &pf.source_bytes,
                            &node_specs,
                            Some(&pf.source_lines_plain),
                        )
                    })
                    .collect();
                Some(per_file)
            })
            .collect();

    for (rule_json, maybe_per_file) in php_rule_jsons.iter().zip(php_per_rule_results) {
        let Some(per_file) = maybe_per_file else {
            continue;
        };
        for (pf, findings) in php_files.iter().zip(per_file) {
            for f in findings {
                let key = (
                    pf.rel_path.clone(),
                    f.rule_id.clone(),
                    f.line,
                    f.source_line,
                );
                if !seen_taint.insert(key) {
                    continue;
                }
                let code = line_text(&pf.all_lines, f.line);
                if suppressions.is_suppressed(&f.rule_id, &pf.rel_path, &code) {
                    continue;
                }
                if is_inline_ignored(&code, &f.rule_id) {
                    continue;
                }
                integrate_taint_finding(
                    &mut all_findings,
                    taint_finding_to_report(
                        &f,
                        rule_json,
                        &pf.rel_path,
                        &pf.source_lines_plain,
                        &config.lang,
                    ),
                );
            }
        }
    }
    record_phase(
        &phase_label(config, "scan_phase_c_php", "phase C - PHP (taint)"),
        t_phase_c_php.elapsed(),
    );

    // --- C# (taint) ---------------------------------------------------------
    // Ticket #79/spec #77. **Intra-file only** — no C# call graph (see
    // the doc comment of `SourceLanguage::CSharp`): unlike the
    // Python/Java/JS/PHP blocks above, `compute_csharp_file_summaries`
    // is recomputed per (rule, file) directly on that single file — no
    // cross-file `own`/`extra` merge (there is no `extra` here).
    let t_phase_c_csharp = std::time::Instant::now();
    let csharp_files: Vec<&ParsedFile> = parsed_files
        .iter()
        .filter(|pf| pf.language == SourceLanguage::CSharp)
        .collect();
    let csharp_type_map_by_file: BTreeMap<String, BTreeMap<String, String>> = csharp_files
        .iter()
        .map(|pf| {
            let mut type_map = collect_csharp_field_types(pf.tree.root_node(), &pf.source_bytes);
            type_map.extend(collect_csharp_local_types(
                pf.tree.root_node(),
                &pf.source_bytes,
            ));
            (pf.rel_path.clone(), type_map)
        })
        .collect();

    let csharp_rule_jsons: Vec<&serde_json::Value> = rule_jsons
        .iter()
        .filter(|r| {
            r.get("language").and_then(|v| v.as_str()) == Some(SourceLanguage::CSharp.rule_tag())
        })
        .collect();
    let csharp_per_rule_results: Vec<Option<Vec<Vec<crate::scan::dataflow::transfer::Finding>>>> =
        csharp_rule_jsons
            .par_iter()
            .map(|rule_json| {
                let base_specs = rule_json_to_specs(rule_json, &config.lang)?;
                let mut node_specs = base_specs.clone();
                let per_file: Vec<Vec<crate::scan::dataflow::transfer::Finding>> = csharp_files
                    .iter()
                    .map(|pf| {
                        node_specs.summaries = compute_csharp_file_summaries(
                            pf.tree.root_node(),
                            &base_specs,
                            &pf.source_bytes,
                            Some(&pf.source_lines_plain),
                        );
                        node_specs.type_map = csharp_type_map_by_file
                            .get(&pf.rel_path)
                            .cloned()
                            .unwrap_or_default();
                        run_taint_rule_csharp(
                            pf.tree.root_node(),
                            &pf.source_bytes,
                            &node_specs,
                            Some(&pf.source_lines_plain),
                        )
                    })
                    .collect();
                Some(per_file)
            })
            .collect();

    for (rule_json, maybe_per_file) in csharp_rule_jsons.iter().zip(csharp_per_rule_results) {
        let Some(per_file) = maybe_per_file else {
            continue;
        };
        for (pf, findings) in csharp_files.iter().zip(per_file) {
            for f in findings {
                let key = (
                    pf.rel_path.clone(),
                    f.rule_id.clone(),
                    f.line,
                    f.source_line,
                );
                if !seen_taint.insert(key) {
                    continue;
                }
                let code = line_text(&pf.all_lines, f.line);
                if suppressions.is_suppressed(&f.rule_id, &pf.rel_path, &code) {
                    continue;
                }
                if is_inline_ignored(&code, &f.rule_id) {
                    continue;
                }
                integrate_taint_finding(
                    &mut all_findings,
                    taint_finding_to_report(
                        &f,
                        rule_json,
                        &pf.rel_path,
                        &pf.source_lines_plain,
                        &config.lang,
                    ),
                );
            }
        }
    }
    record_phase(
        &phase_label(config, "scan_phase_c_csharp", "phase C - C# (taint)"),
        t_phase_c_csharp.elapsed(),
    );

    let _ = rule_category; // kept for future use (CLI category filtering)

    let rule_catalog: BTreeMap<String, serde_json::Value> = rule_jsons
        .iter()
        .filter_map(|r| {
            r.get("id")
                .and_then(|v| v.as_str())
                .map(|id| (id.to_string(), r.clone()))
        })
        .collect();

    // --- Dependencies (opt-in, static detection only) --------------
    // `!config.quick_mode`: `--quick` forces the 3 slow optional
    // phases below to be disabled, even if otherwise requested
    // (mirrors `runner.py::_compute_phase_total`/`run`).
    let mut dependency_stats = None;
    if deps_phase_active {
        let t_deps = std::time::Instant::now();
        // Root + every `paths.include` entry, like Python — see
        // `dependencies::collect_dependencies` (fix 2026-11-04).
        let all_deps =
            crate::project::dependencies::collect_dependencies(&config.root, &config.include_paths);
        let unpinned: Vec<_> = all_deps.iter().filter(|d| d.version.is_none()).collect();
        for dep in &unpinned {
            all_findings.push(ReportFinding {
                rule_key: "unpinned_dependency".to_string(),
                rule_name: "Unpinned dependency".to_string(),
                category: "DEPENDENCIES".to_string(),
                severity: "HIGH".to_string(),
                risk: String::new(),
                file: dep.file.to_string_lossy().to_string(),
                line: dep.line,
                solution: None,
                cwe: vec![],
                owasp: None,
                taint_flow: None,
                taint_flows: vec![],
                code: dep.raw_line.clone(),
                context_before: String::new(),
                context_after: String::new(),
                confidence: 90,
                benefit: String::new(),
                committer: None,
                rule_source: "json_builtin".to_string(),
            });
        }
        let vulnerable = config
            .advisories_dir
            .as_deref()
            .filter(|dir| dir.is_dir())
            .map(|dir| vulnerable_dependency_findings(dir, &all_deps))
            .unwrap_or_default();
        let vulnerable_count = vulnerable.len();
        all_findings.extend(vulnerable);
        dependency_stats = Some(DependencyStats {
            total_scanned: all_deps.len(),
            unpinned: unpinned.len(),
            ok: all_deps.len().saturating_sub(unpinned.len()),
            vulnerable: vulnerable_count,
        });
        record_phase(
            &phase_label(
                config,
                "scan_phase_dependencies",
                "dépendances (détection statique)",
            ),
            t_deps.elapsed(),
        );
    }

    // --- Audited project's unit tests (opt-in) -------------------------
    let mut test_results = None;
    if tests_phase_active {
        let t_tests = std::time::Instant::now();
        // `BTreeMap::keys()` is already sorted and duplicate-free — no
        // need for separate `sort()`/`dedup()` as before
        // `files_per_language` was introduced (ticket #46).
        let languages: Vec<String> = files_per_language(&parsed_files)
            .keys()
            .map(|lang| lang.to_string())
            .collect();
        let command = config.test_command.clone().or_else(|| {
            crate::project::testing::auto_detect_test_command(&config.root, &languages)
        });
        if let Some(command) = command {
            test_results = crate::project::testing::run_tests(
                &config.root,
                &command,
                std::time::Duration::from_secs(300),
            )
            .ok();
        }
        record_phase(
            &phase_label(
                config,
                "scan_phase_tests",
                "tests unitaires du projet audité",
            ),
            t_tests.elapsed(),
        );
    }

    // --- Database (opt-in, live connection) ---------------------------
    let mut database_schema = None;
    let mut database_stats = None;
    if database_phase_active && let Some(db_config) = &config.database {
        let t_database = std::time::Instant::now();
        match crate::project::database::live::load_db_credentials(db_config, &config.root)
            .and_then(|creds| crate::project::database::live::extract_pg_schema(&creds))
        {
            Ok(schema) => {
                if let Some(datas_dir) = &config.datas_dir
                    && let Some(baseline_path) = crate::report::export_json::find_latest_baseline(
                        datas_dir,
                        &config.brand_prefix,
                    )
                    && let Ok(baseline) = crate::report::export_json::load_export(&baseline_path)
                    && let Some(baseline_schema) = baseline.database_schema
                {
                    let changes = crate::project::database::schema::compare_schemas(
                        &baseline_schema,
                        &schema,
                        &crate::project::database::schema::SeverityConfig::default(),
                        &crate::project::database::schema::TrackConfig::default(),
                    );
                    database_stats = Some(
                        crate::project::database::schema::calculate_schema_stats(&schema, &changes),
                    );
                } else {
                    database_stats = Some(
                        crate::project::database::schema::calculate_schema_stats(&schema, &[]),
                    );
                }
                database_schema = Some(schema);
            }
            Err(_) => { /* connection failure: no dedicated finding for now, see TODO below */ }
        }
        record_phase(
            &phase_label(
                config,
                "scan_phase_database",
                "base de données (schéma PostgreSQL)",
            ),
            t_database.elapsed(),
        );
    }

    // --- Injection post-pass (taint dedup + confidence cap) -----------------
    // Same position as the Python call (`runner.py:690`): after every
    // detection phase, before baseline comparison/export.
    adjust_injection_confidence(&mut all_findings);

    // --- `--severity` filter --------------------------------------------------
    // Applied before comparison/export: a finding filtered out here
    // enters neither the exported baseline nor the comparison,
    // consistent with a `--severity` that restricts the scan as a whole.
    if let Some(levels) = &config.severity_levels {
        all_findings.retain(|f| levels.iter().any(|l| l == &f.severity));
    }

    // --- Comparison against baseline + JSON export -----------------------------
    let mut comparison = None;
    let mut export_path = None;
    if let Some(datas_dir) = &config.datas_dir {
        if let Some(baseline_path) =
            crate::report::export_json::find_latest_baseline(datas_dir, &config.brand_prefix)
            && let Ok(baseline) = crate::report::export_json::load_export(&baseline_path)
        {
            comparison = Some(crate::report::comparison::compare_with_baseline(
                &all_findings,
                &baseline.findings,
                baseline.timestamp,
                baseline.totals,
            ));
        }
        let timestamp = if config.timestamp.is_empty() {
            chrono::Local::now().format("%Y-%m-%d-%H-%M").to_string()
        } else {
            config.timestamp.clone()
        };
        let export_data = crate::report::export_json::build_export_data(
            &all_findings,
            &timestamp,
            &chrono::Local::now().to_rfc3339(),
            database_schema.clone(),
        );
        export_path =
            crate::report::export_json::write_export(datas_dir, &config.brand_prefix, &export_data)
                .ok();
    }

    let languages: Vec<String> = files_per_language(&parsed_files)
        .keys()
        .map(|lang| lang.to_string())
        .collect();

    ScanReport {
        findings: all_findings,
        files_scanned: parsed_files.len(),
        total_loc,
        rule_errors,
        rule_catalog,
        test_results,
        dependency_stats,
        database_schema,
        database_stats,
        comparison,
        export_path,
        languages,
        phase_timings,
    }
}

/// Rule-id prefixes of the data-flow dependent (injection) families —
/// verbatim copy of `Audit/sca/runner.py::_INJECTION_RULE_PREFIXES`.
const INJECTION_RULE_PREFIXES: &[&str] = &[
    "sql_injection",
    "taint_sqli",
    "xss_",
    "taint_xss",
    "ssrf",
    "taint_ssrf",
    "path_traversal",
    "taint_path",
    "ssti",
    "taint_ssti",
    "ldap_injection",
    "taint_ldap",
    "xpath_injection",
    "taint_xpathi",
    "xxe_injection",
    "taint_xxe",
    "command_injection",
    "unvalidated_input",
    "taint_rce",
    "os_system",
    "dangerous_eval",
    "taint_codeinj",
    "prompt_injection",
    "llm_output_to_sink",
    "insecure_deserialization",
    "taint_deserialization",
    "unsafe_deserialization",
];

/// Confidence ceiling for an injection finding without a taint trace.
const UNTRACED_INJECTION_MAX_CONFIDENCE: i64 = 60;

/// Post-processing of injection findings — port of
/// `Audit/sca/runner.py::_adjust_injection_confidence`, missing from the
/// initial Rust port (found by the Python/Rust differential scan of
/// 2026-11-04: Rust reported e.g. `sql_injection_java_broad` on the same
/// line as a taint-confirmed `sql_injection_concat_java`, Python did not).
///
/// An injection only exists if untrusted data reaches the sink, which a
/// regex alone cannot prove. Two steps, both restricted to findings whose
/// `rule_key` starts with one of [`INJECTION_RULE_PREFIXES`]:
/// 1. collect the `(file, line)` locations of injection findings that DO
///    carry a taint trace;
/// 2. drop every untraced injection finding at one of those locations
///    (redundant: taint already proved it), and cap the confidence of the
///    remaining untraced ones at 60 — below the ≥ 80 bar used for HIGH
///    counting, exactly like Python.
///
/// "Has a taint trace" mirrors Python's `getattr(f, "taint_flow", None)`
/// truthiness: `taint_flow` present (Rust also keeps `taint_flows`, the
/// multi-path list, which is never set without `taint_flow`).
pub(crate) fn adjust_injection_confidence(findings: &mut Vec<ReportFinding>) {
    let is_injection = |f: &ReportFinding| {
        !f.rule_key.is_empty()
            && INJECTION_RULE_PREFIXES
                .iter()
                .any(|p| f.rule_key.starts_with(p))
    };
    let taint_locs: std::collections::HashSet<(String, usize)> = findings
        .iter()
        .filter(|f| f.taint_flow.is_some() && is_injection(f))
        .map(|f| (f.file.clone(), f.line))
        .collect();
    findings.retain_mut(|f| {
        if is_injection(f) && f.taint_flow.is_none() {
            if taint_locs.contains(&(f.file.clone(), f.line)) {
                return false;
            }
            if f.confidence > UNTRACED_INJECTION_MAX_CONFIDENCE {
                f.confidence = UNTRACED_INJECTION_MAX_CONFIDENCE;
            }
        }
        true
    });
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sast_orch_test_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn finding(rule_key: &str, category: &str, file: &str, line: usize) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_name: rule_key.to_string(),
            category: category.to_string(),
            severity: "HIGH".to_string(),
            risk: String::new(),
            file: file.to_string(),
            line,
            solution: None,
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: String::new(),
            context_before: String::new(),
            context_after: String::new(),
            confidence: 90,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
        }
    }

    #[test]
    fn test_integrate_taint_finding_no_existing_finding_pushes_new() {
        let mut all = Vec::new();
        integrate_taint_finding(&mut all, finding("taint_rce", "SECURITY", "a.py", 41));
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].rule_key, "taint_rce");
    }

    #[test]
    fn test_integrate_taint_finding_merges_into_regex_finding_same_line() {
        // Real case: os_system_injection (regex) already present on
        // line 41, a taint_rce flow arrives on the same line — merged,
        // no 2nd finding.
        let mut all = vec![finding("os_system_injection", "SECURITY", "a.py", 41)];
        integrate_taint_finding(&mut all, finding("taint_rce", "SECURITY", "a.py", 41));
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].rule_key, "os_system_injection");
        assert_eq!(all[0].confidence, 95);
    }

    #[test]
    fn test_integrate_taint_finding_merges_into_earlier_taint_finding_same_line() {
        // Real case: taint_ssti already present on line 18
        // (render_template_string), a taint_xss flow arrives on the
        // same line (same sink listed in both rules) — merged.
        let mut all = vec![finding("taint_ssti", "SECURITY", "a.py", 18)];
        integrate_taint_finding(&mut all, finding("taint_xss", "SECURITY", "a.py", 18));
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].rule_key, "taint_ssti");
    }

    #[test]
    fn test_integrate_taint_finding_same_family_rule_key_attaches_to_matching_finding() {
        // ssrf / ssrf_python: common prefix, considered the same family
        // (Pass 1) — even if another finding also exists on the line.
        let mut all = vec![
            finding("other_rule", "SECURITY", "a.py", 10),
            finding("ssrf", "SECURITY", "a.py", 10),
        ];
        integrate_taint_finding(&mut all, finding("ssrf_python", "SECURITY", "a.py", 10));
        assert_eq!(all.len(), 2);
        // Attached to the "ssrf" finding (same family), not to
        // "other_rule" (first found) — Pass 1 must take priority over Pass 2.
        assert_eq!(all[1].confidence, 95);
        assert_eq!(all[0].confidence, 90);
    }

    #[test]
    fn test_integrate_taint_finding_different_category_does_not_merge() {
        let mut all = vec![finding("rule_a", "SECURITY", "a.py", 5)];
        integrate_taint_finding(&mut all, finding("rule_b", "MAINTENANCE", "a.py", 5));
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_integrate_taint_finding_different_line_does_not_merge() {
        let mut all = vec![finding("rule_a", "SECURITY", "a.py", 5)];
        integrate_taint_finding(&mut all, finding("rule_b", "SECURITY", "a.py", 6));
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_integrate_taint_finding_different_file_does_not_merge() {
        let mut all = vec![finding("rule_a", "SECURITY", "a.py", 5)];
        integrate_taint_finding(&mut all, finding("rule_b", "SECURITY", "b.py", 5));
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_end_to_end_regex_rule_finds_eval_usage() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "eval_usage.sca",
            "rule eval_usage\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n",
        );
        write(&root, "app.py", "x = eval(user_input)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.files_scanned, 1);
        assert!(
            !report.findings.is_empty(),
            "eval( doit être détecté par la règle regex"
        );
        assert_eq!(report.findings[0].file, "app.py");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_end_to_end_taint_rule_finds_flow() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "cmd_injection.sca",
            "rule cmd_injection\n  language  python\n  category  security\n  severity  HIGH\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(\nend\n",
        );
        write(&root, "app.py", "x = input()\nos.system(x)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            !report.findings.is_empty(),
            "flux input()->os.system doit être détecté par le taint"
        );
        // Regression found by the maintainer (2026-08-26): the `code` field used
        // to display just the call name ("os.system") instead of the
        // actual file line ("os.system(x)") — mirrors
        // `self._get_line_content(...)` on the Python side.
        assert_eq!(report.findings[0].code, "os.system(x)");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_suppression_file_removes_finding() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "eval_usage.sca",
            "rule eval_usage\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n",
        );
        write(&root, "app.py", "x = eval(user_input)\n");
        let suppress_path = root.join(".sca-suppress.json");
        std::fs::write(&suppress_path, r#"{"suppressions": [{"rule_key": "eval_usage", "file": "app.py", "code_hash": null}]}"#).unwrap();

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: Some(suppress_path),
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.is_empty(),
            "finding supprimé par .sca-suppress.json"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_exclude_pattern_skips_directory() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "eval_usage.sca",
            "rule eval_usage\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n",
        );
        write(&root, "vendor/lib.py", "x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec!["vendor/".to_string()],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.files_scanned, 0, "vendor/ exclu de la découverte");
        std::fs::remove_dir_all(&root).ok();
    }

    fn write_two_category_rules(rules_dir: &Path) {
        write(
            rules_dir,
            "eval_usage.sca",
            "rule eval_usage\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n",
        );
        write(
            rules_dir,
            "long_function.sca",
            "rule long_function\n  language  python\n  category  maintenance\n  severity  LOW\n  match\n    pattern  def\\s+\\w+\n    scope    line\n  end\nend\n",
        );
    }

    #[test]
    fn test_only_category_restricts_to_matching_rules() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            only_category: Some("security".to_string()),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.findings.len(), 1, "seule la règle security matche");
        assert_eq!(report.findings[0].rule_key, "eval_usage");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_only_category_case_insensitive() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            only_category: Some("SECURITY".to_string()),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.findings.len(), 1);
        std::fs::remove_dir_all(&root).ok();
    }

    // === `category_overrides` (ticket #41/spec #27) — mirrors
    // `AuditRunner.enabled_categories`/`should_run`, distinct from
    // `only_category` above, see the field's doc comment in
    // `ScanConfig`. ===

    #[test]
    fn test_category_overrides_disables_matching_category() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            category_overrides: [("security".to_string(), false)].into_iter().collect(),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().all(|f| f.rule_key != "eval_usage"),
            "security désactivée, eval_usage ne doit jamais apparaître"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_key == "long_function"),
            "maintenance non mentionnée dans la carte, reste active par défaut"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_only_category_ignores_category_overrides_entirely() {
        // Exact mirror of `runner.py::should_run`: when `only_category`
        // is set, `category_overrides` is entirely ignored (never
        // combined) — here the map explicitly disables "security", but
        // `only_category = "security"` must still restrict to...
        // security. If the two were combined (logical AND), no rule
        // would match; the test verifies that this is NOT the case.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            only_category: Some("security".to_string()),
            category_overrides: [("security".to_string(), false)].into_iter().collect(),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(
            report.findings.len(),
            1,
            "only_category doit primer, category_overrides totalement ignorée"
        );
        assert_eq!(report.findings[0].rule_key, "eval_usage");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_disabled_rule_skips_matching_id() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            disabled_rules: vec!["eval_usage".to_string()],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().all(|f| f.rule_key != "eval_usage"),
            "eval_usage désactivée, ne doit jamais apparaître"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_key == "long_function"),
            "long_function reste active"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // === Additive custom rules (ticket #84/spec #82) — `use_embedded_
    // rules: true` needed for these tests: the `custom_rules_dir`
    // merge happens ONLY in this mode (never with an explicit
    // `--rules <DIR>`, see the field's doc comment in `ScanConfig`),
    // so proving the additive behavior necessarily goes through the
    // real embedded catalog rather than a fixture `rules_dir`. ===

    #[test]
    fn test_custom_rules_loaded_additively_with_embedded_catalog() {
        let root = temp_dir();
        let custom_dir = root.join("custom-rules");
        write(
            &custom_dir,
            "my_custom_rule.sca",
            "rule my_custom_rule\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  MY_CUSTOM_MARKER\n    scope    line\n  end\nend\n",
        );
        write(
            &root,
            "app.py",
            "import base64\neval(base64.b64decode(x))\nMY_CUSTOM_MARKER\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            use_embedded_rules: true,
            custom_rules_dir: Some(custom_dir),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.rule_key == "base64_eval"),
            "le catalogue builtin reste actif en plus des règles custom"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_key == "my_custom_rule"),
            "la règle custom est bien chargée et détecte"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// `adjust_injection_confidence`: an untraced injection finding on a
    /// taint-confirmed line is dropped; elsewhere it is capped at 60;
    /// non-injection and traced findings are untouched.
    #[test]
    fn test_adjust_injection_confidence_dedups_and_caps() {
        let mut traced = finding("sql_injection_concat_java", "SECURITY", "A.java", 18);
        traced.confidence = 95;
        traced.taint_flow = Some(crate::report::exports::sarif::TaintFlow {
            rule_key: "sql_injection_concat_java".to_string(),
            source_file: "A.java".to_string(),
            source_line: 14,
            source_expr: "request.getParameter(\"id\")".to_string(),
            chain: vec![],
            sink_file: "A.java".to_string(),
            sink_line: 18,
            sink_expr: "stmt.executeQuery(...)".to_string(),
            source_kind: "http".to_string(),
        });
        let mut dup = finding("sql_injection_java_broad", "SECURITY", "A.java", 18);
        dup.confidence = 70;
        let mut elsewhere = finding("command_injection_java_broad", "SECURITY", "A.java", 30);
        elsewhere.confidence = 85;
        let mut other = finding("hardcoded_secret", "SECURITY", "A.java", 18);
        other.confidence = 90;
        let mut findings = vec![traced, dup, elsewhere, other];

        adjust_injection_confidence(&mut findings);

        let got: Vec<(&str, usize, i64)> = findings
            .iter()
            .map(|f| (f.rule_key.as_str(), f.line, f.confidence))
            .collect();
        assert_eq!(
            got,
            vec![
                ("sql_injection_concat_java", 18, 95),
                ("command_injection_java_broad", 30, 60),
                ("hardcoded_secret", 18, 90),
            ]
        );
    }

    /// Extension parity with `Audit/sca/runner.py` (fix 2026-11-04):
    /// template formats go to the HTML rules, `.tsx` to JS/TS, `.inc` to
    /// PHP — none of them was even discovered before.
    #[test]
    fn test_extensions_mirror_python_runner_lists() {
        for (file, expected) in [
            ("a.vue", SourceLanguage::Html),
            ("a.svelte", SourceLanguage::Html),
            ("a.jsp", SourceLanguage::Html),
            ("a.cshtml", SourceLanguage::Html),
            ("a.twig", SourceLanguage::Html),
            ("a.tsx", SourceLanguage::TypeScript),
            ("a.inc", SourceLanguage::Php),
            ("a.cjs", SourceLanguage::JavaScript),
        ] {
            assert_eq!(
                SourceLanguage::from_path(Path::new(file)),
                Some(expected),
                "{file}"
            );
        }
        assert_eq!(SourceLanguage::from_path(Path::new("a.txt")), None);
    }

    /// End-to-end on the embedded catalog: the Vue/Svelte XSS rules fire
    /// (Python fixtures `sample_vue_xss.vue`/`sample_svelte_xss.svelte`),
    /// and a `.tsx` file is scanned with a JSX-capable grammar.
    #[test]
    fn test_template_and_tsx_files_are_scanned() {
        let root = temp_dir();
        write(
            &root,
            "App.vue",
            "<template>\n  <div v-html=\"userInput\"></div>\n</template>\n",
        );
        write(&root, "Page.svelte", "<div>{@html userInput}</div>\n");
        write(
            &root,
            "View.tsx",
            "export const V = () => <div>{x}</div>;\nconst token = Math.random();\n",
        );
        let config = ScanConfig {
            root: root.clone(),
            use_embedded_rules: true,
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        let has = |rule: &str, file: &str| {
            report
                .findings
                .iter()
                .any(|f| f.rule_key == rule && f.file == file)
        };
        assert!(has("xss_vue_vhtml", "App.vue"));
        assert!(has("xss_svelte_html", "Page.svelte"));
        assert!(
            has("insecure_random_js", "View.tsx"),
            ".tsx is discovered and scanned"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// `context-N` multi-line match (DOTALL, fix 2026-11-04): mirrors the
    /// Python fixture `secret_logged.py:17` that Rust used to miss.
    #[test]
    fn test_context_scope_matches_across_lines_on_embedded_catalog() {
        let root = temp_dir();
        write(
            &root,
            "auth.py",
            "import logging\nlogger = logging.getLogger(__name__)\n\ndef login(username, password):\n    logger.info(\n        f\"Login attempt for {username} with {password}\"\n    )\n",
        );
        let config = ScanConfig {
            root: root.clone(),
            use_embedded_rules: true,
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_key == "secret_logged_fstring" && f.line == 5),
            "{:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.rule_key, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_custom_rules_dir_ignored_when_rules_dir_explicit() {
        // `--rules <DIR>` (use_embedded_rules: false): custom_rules_dir
        // must NEVER be consulted, even if it is set.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        let custom_dir = root.join("custom-rules");
        write(
            &custom_dir,
            "my_custom_rule.sca",
            "rule my_custom_rule\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  MY_CUSTOM_MARKER\n    scope    line\n  end\nend\n",
        );
        write(
            &root,
            "app.py",
            "def f():\n    x = eval(y)\nMY_CUSTOM_MARKER\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            custom_rules_dir: Some(custom_dir),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.rule_key != "my_custom_rule"),
            "custom_rules_dir ne doit jamais être consulté quand --rules est explicite"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // === Signed update packs (ticket #85/spec #82) — the cryptographic
    // verification itself (valid/tampered/unsigned pack) is tested in
    // `rule_packs.rs`, with an explicit test key: no injection happens
    // at build time during `cargo test`, so these tests here can only
    // prove the WIRING (safe fallback, `--rules` exclusivity), not the
    // content of an actually loaded pack. ===

    #[test]
    fn test_rule_updates_dir_without_editor_key_loads_nothing_and_does_not_crash() {
        let root = temp_dir();
        let updates_dir = root.join("rules-updates");
        write(
            &updates_dir,
            "cve-pack/rules/pack_rule.sca",
            "rule pack_rule\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  MY_CUSTOM_MARKER\n    scope    line\n  end\nend\n",
        );
        write(
            &updates_dir,
            "cve-pack/manifest.json",
            r#"{"pack_id": "cve-pack", "rules": [], "signature": "base64:bogus"}"#,
        );
        write(&root, "app.py", "MY_CUSTOM_MARKER\n");

        let config = ScanConfig {
            root: root.clone(),
            use_embedded_rules: true,
            rule_updates_dir: Some(updates_dir),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().all(|f| f.rule_key != "pack_rule"),
            "aucune clé publique éditeur injectée en test — le pack ne doit jamais être consulté"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_rule_updates_dir_ignored_when_rules_dir_explicit() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        let updates_dir = root.join("rules-updates");
        write(
            &updates_dir,
            "cve-pack/manifest.json",
            r#"{"pack_id": "cve-pack", "rules": []}"#,
        );
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            rule_updates_dir: Some(updates_dir),
            ..ScanConfig::default()
        };
        // `use_embedded_rules: false` (default) — must never attempt to
        // read `rules-updates/`, so must never fail even with an
        // incomplete manifest (no "signature" field here).
        let report = run_scan(&config);
        assert!(
            report
                .rule_errors
                .iter()
                .all(|(p, _)| !p.starts_with(root.join("rules-updates"))),
            "rule_updates_dir ne doit jamais être consulté quand --rules est explicite"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_severity_levels_filters_findings() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            severity_levels: Some(vec!["HIGH".to_string()]),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(report.findings.iter().all(|f| f.severity == "HIGH"));
        assert!(
            report.findings.iter().any(|f| f.rule_key == "eval_usage"),
            "HIGH conservé"
        );
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.rule_key != "long_function"),
            "LOW filtré"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_quick_mode_forces_with_deps_off() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "requirements.txt", "flask\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            with_deps: true,
            quick_mode: true,
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.rule_key != "unpinned_dependency"),
            "--quick désactive with_deps même s'il est demandé"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Verifies the `[n/N]` counter introduced in ticket #45 — `N` must
    /// reflect the phases actually planned (7 base phases + enabled
    /// optional phases), not a constant frozen at 7. `on_phase_complete`
    /// is a plain function pointer (not a closure): captures the
    /// labels in a `static Mutex`, cleared between the two scenarios of
    /// this test to avoid any cross-contamination.
    #[test]
    fn test_total_phases_counter_reflects_optional_phases() {
        use std::sync::Mutex;
        static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn capture(label: &str, _elapsed: std::time::Duration) {
            CAPTURED.lock().unwrap().push(label.to_string());
        }

        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "x = 1\n");

        // With no optional phase: N = 8 (rules, phase A, phase B, phase
        // C × 5 languages/engines [Python/Java/JS-TS/PHP/C#] — mirrors
        // `_compute_phase_total`, which excludes these always-run
        // phases from its own count). Went from 7 to 8 in ticket #79
        // when wiring up the C# taint engine.
        CAPTURED.lock().unwrap().clear();
        let config = ScanConfig {
            root: root.clone(),
            rules_dir: rules_dir.clone(),
            on_phase_complete: Some(capture),
            ..ScanConfig::default()
        };
        run_scan(&config);
        let labels = CAPTURED.lock().unwrap().clone();
        assert_eq!(
            labels.len(),
            8,
            "8 phases de base attendues, obtenu {labels:?}"
        );
        assert!(labels[0].starts_with("[1/8] "), "{:?}", labels[0]);
        assert!(labels[7].starts_with("[8/8] "), "{:?}", labels[7]);

        // With `with_deps` enabled: N = 9, the 9th phase carries the
        // label dedicated to dependencies.
        write(&root, "requirements.txt", "flask\n");
        CAPTURED.lock().unwrap().clear();
        let config_with_deps = ScanConfig {
            with_deps: true,
            ..config
        };
        run_scan(&config_with_deps);
        let labels_with_deps = CAPTURED.lock().unwrap().clone();
        assert_eq!(
            labels_with_deps.len(),
            9,
            "9 phases attendues avec with_deps, obtenu {labels_with_deps:?}"
        );
        assert!(
            labels_with_deps[8].starts_with("[9/9] dépendances"),
            "{:?}",
            labels_with_deps[8]
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// Ticket #46: the phase A label carries the per-language file
    /// count, computed during the phase itself (no separate counting
    /// pass), on the same line as the `[n/N]` counter from ticket #45.
    #[test]
    fn test_phase_a_label_includes_per_language_file_counts() {
        use std::sync::Mutex;
        static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn capture(label: &str, _elapsed: std::time::Duration) {
            CAPTURED.lock().unwrap().push(label.to_string());
        }

        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "x = 1\n");
        write(&root, "app2.py", "y = 2\n");
        write(&root, "Main.java", "class Main {}\n");

        CAPTURED.lock().unwrap().clear();
        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            on_phase_complete: Some(capture),
            ..ScanConfig::default()
        };
        run_scan(&config);
        let labels = CAPTURED.lock().unwrap().clone();
        let phase_a_label = labels
            .iter()
            .find(|l| l.contains("phase A"))
            .unwrap_or_else(|| panic!("aucun libellé de phase A trouvé parmi {labels:?}"));

        assert!(
            phase_a_label.starts_with("[2/8] phase A (lecture + parsing)"),
            "le préfixe [n/N] et le libellé existant doivent rester intacts : {phase_a_label:?}"
        );
        assert!(
            phase_a_label.contains("python: 2"),
            "décompte python attendu : {phase_a_label:?}"
        );
        assert!(
            phase_a_label.contains("java: 1"),
            "décompte java attendu : {phase_a_label:?}"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// Ticket #48: `ScanConfig::script_locale` translates the phase
    /// labels (the `[n/N]` prefix and per-language detail from tickets
    /// #45/#46 stay intact); `None` (historical behavior, all other
    /// tests in this module) keeps producing the hard-coded French text.
    #[test]
    fn test_phase_labels_use_script_locale_when_provided() {
        use std::sync::Mutex;
        static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn capture(label: &str, _elapsed: std::time::Duration) {
            CAPTURED.lock().unwrap().push(label.to_string());
        }

        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "x = 1\n");

        CAPTURED.lock().unwrap().clear();
        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            on_phase_complete: Some(capture),
            script_locale: Some(crate::i18n::load_script_locale("de")),
            ..ScanConfig::default()
        };
        run_scan(&config);
        let labels = CAPTURED.lock().unwrap().clone();
        let phase_a_label = labels
            .iter()
            .find(|l| l.contains("python: 1"))
            .unwrap_or_else(|| panic!("aucun libellé de phase A trouvé parmi {labels:?}"));

        assert!(
            phase_a_label.starts_with("[2/8] Phase A (Einlesen + Parsen)"),
            "le libellé de phase A doit être traduit en allemand : {phase_a_label:?}"
        );
        assert!(
            !labels.iter().any(|l| l.contains("phase A (lecture")),
            "le texte français codé en dur ne doit plus apparaître avec une script_locale fournie : {labels:?}"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_invalid_sca_file_reported_but_does_not_crash_scan() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "broken.sca",
            "this is not valid DSL syntax {{{\n",
        );
        write(&root, "app.py", "x = 1\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            !report.rule_errors.is_empty(),
            "le fichier .sca cassé doit être signalé"
        );
        assert_eq!(
            report.files_scanned, 1,
            "le scan continue malgré la règle cassée"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_loc_counted_across_files() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(&root, "a.py", "x = 1\ny = 2\n");
        write(&root, "b.py", "z = 3\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.total_loc, 3);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_cross_file_taint_flow_resolved_via_call_graph() {
        // app.py calls helper() (defined in utils.py, imported) with a
        // tainted source; the sink (os.system) is INSIDE utils.py,
        // never visible from app.py without multi-file interprocedural
        // resolution. Without CallGraph wiring, `helper` stays an
        // opaque call -> no finding. With it, the summary of `helper`
        // (computed on utils.py) is seeded into app.py's specs, and the
        // finding appears at the call site (app.py).
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "cmd_injection.sca",
            "rule cmd_injection\n  language  python\n  category  security\n  severity  HIGH\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(\nend\n",
        );
        write(
            &root,
            "utils.py",
            "import os\n\ndef helper(cmd):\n    os.system(cmd)\n",
        );
        write(
            &root,
            "app.py",
            "from utils import helper\n\ndef main():\n    helper(input())\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "app.py"),
            "le flux cross-file (app.py appelle helper() de utils.py, qui atteint os.system) doit être résolu au site d'appel dans app.py ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_intra_file_sink_in_utils_also_detected() {
        // The direct INTRA-file flow (inside utils.py itself: if
        // utils.py also called os.system(tainted) locally) must keep
        // working with no regression after the move to multi-file.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "cmd_injection.sca",
            "rule cmd_injection\n  language  python\n  category  security\n  severity  HIGH\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(\nend\n",
        );
        write(&root, "app.py", "import os\nx = input()\nos.system(x)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            !report.findings.is_empty(),
            "flux intra-fichier toujours détecté après le câblage multi-fichiers"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_java_regex_rule_finds_runtime_exec() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "runtime_exec.sca",
            "rule runtime_exec\n  language  java\n  category  security\n  severity  HIGH\n  match\n    pattern  Runtime\\.getRuntime\\(\\)\\.exec\n    scope    line\n  end\nend\n",
        );
        write(
            &root,
            "App.java",
            "class App {\n    void run(String cmd) throws Exception {\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.files_scanned, 1);
        assert!(
            report.findings.iter().any(|f| f.file == "App.java"),
            "Runtime.exec doit être détecté par la règle regex java ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_rule_language_filtering_is_cross_isolated() {
        // A python rule must never trigger on a java file, and vice
        // versa, even if both files coexist in the same scan with a
        // textually identical pattern.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "py_eval.sca",
            "rule py_eval\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  DANGER_MARKER\n    scope    line\n  end\nend\n",
        );
        write(
            &rules_dir,
            "java_danger.sca",
            "rule java_danger\n  language  java\n  category  security\n  severity  HIGH\n  match\n    pattern  DANGER_MARKER\n    scope    line\n  end\nend\n",
        );
        write(&root, "app.py", "x = DANGER_MARKER\n");
        write(
            &root,
            "App.java",
            "class App { String x = \"DANGER_MARKER\"; }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.files_scanned, 2);
        let py_finding = report
            .findings
            .iter()
            .find(|f| f.file == "app.py")
            .expect("app.py doit être signalé par py_eval");
        assert_eq!(py_finding.rule_key, "py_eval");
        let java_finding = report
            .findings
            .iter()
            .find(|f| f.file == "App.java")
            .expect("App.java doit être signalé par java_danger");
        assert_eq!(java_finding.rule_key, "java_danger");
        assert_eq!(
            report.findings.len(),
            2,
            "chaque fichier ne doit être touché que par la règle de sa propre langue ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, &f.rule_key))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_java_taint_rule_detects_real_flow_end_to_end() {
        // Java taint is wired up (JavaCallGraph + java_taint_scan,
        // 2026-08-25) — a real java taint rule must now detect an
        // actual java source->sink flow, as on the Python side.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "java_cmd_injection.sca",
            "rule java_cmd_injection\n  language  java\n  category  security\n  severity  HIGH\n  source  request\\.getParameter\\s*\\(  kind=http\n  sink    Runtime\\.getRuntime\\(\\)\\.exec\nend\n",
        );
        write(
            &root,
            "App.java",
            "class App {\n    void run(HttpServletRequest request) throws Exception {\n        String cmd = request.getParameter(\"cmd\");\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.rule_errors.is_empty(),
            "la règle doit se charger sans erreur"
        );
        assert!(
            !report.findings.is_empty(),
            "le flux request.getParameter->Runtime.exec doit être détecté ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_python_taint_still_works_when_java_files_present() {
        // The Python subset of taint (Phase C) must not be disturbed
        // by the presence of java files in the same scan.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "cmd_injection.sca",
            "rule cmd_injection\n  language  python\n  category  security\n  severity  HIGH\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(\nend\n",
        );
        write(&root, "app.py", "import os\nx = input()\nos.system(x)\n");
        write(&root, "App.java", "class App {}\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.files_scanned, 2);
        assert!(
            report.findings.iter().any(|f| f.file == "app.py"),
            "le taint python doit continuer à fonctionner malgré la présence d'App.java"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_java_cross_file_taint_flow_resolved_via_call_graph() {
        // Api.java calls QueryRunner.runQuery() (defined in another
        // file, package + import) with a tainted source; the sink
        // (Statement.execute) is INSIDE QueryRunner.java, never visible
        // from Api.java without multi-file interprocedural resolution
        // via JavaCallGraph.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "java_sqli.sca",
            "rule java_sqli\n  language  java\n  category  security\n  severity  HIGH\n  source  request\\.getParameter\\s*\\(  kind=http\n  sink    \\.execute\\s*\\(\nend\n",
        );
        write(
            &root,
            "QueryRunner.java",
            "package com.acme.util;\nclass QueryRunner {\n    void runQuery(String query, java.sql.Statement db) throws Exception {\n        db.execute(query);\n    }\n}\n",
        );
        write(
            &root,
            "Api.java",
            "package com.acme.service;\nimport com.acme.util.QueryRunner;\nclass Api {\n    void handler(HttpServletRequest request, java.sql.Statement db) throws Exception {\n        String q = request.getParameter(\"q\");\n        QueryRunner qr = new QueryRunner();\n        qr.runQuery(q, db);\n    }\n}\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "Api.java"),
            "le flux cross-file (Api.java appelle qr.runQuery() de QueryRunner.java via type_map, qui atteint db.execute) doit être résolu au site d'appel dans Api.java ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_java_intra_file_sink_also_detected() {
        // Direct INTRA-file flow (inside App.java itself) — must keep
        // working with no regression after the multi-file wiring.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "java_cmd_injection.sca",
            "rule java_cmd_injection\n  language  java\n  category  security\n  severity  HIGH\n  source  request\\.getParameter\\s*\\(  kind=http\n  sink    Runtime\\.getRuntime\\(\\)\\.exec\nend\n",
        );
        write(
            &root,
            "App.java",
            "class App {\n    void run(HttpServletRequest request) throws Exception {\n        String cmd = request.getParameter(\"cmd\");\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            !report.findings.is_empty(),
            "flux intra-fichier java toujours détecté après le câblage multi-fichiers"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_js_intra_file_function_to_function_flow_resolved() {
        // JS call graph wired on 08/30 (`js_call_graph.rs`): before this
        // effort, even an A -> B call WITHIN THE SAME FILE wasn't
        // tracked (`specs.summaries` always empty) — this test verifies
        // that this basic flow is now detected.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "js_sqli.sca",
            "rule js_sqli\n  language  javascript\n  category  security\n  severity  HIGH\n  source  req\\.query\\.q  kind=http\n  sink    db\\.query\\s*\\(\nend\n",
        );
        write(
            &root,
            "app.js",
            "function helper(cmd) { db.query(cmd); }\nfunction main(req) { const q = req.query.q; helper(q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "app.js"),
            "flux main() -> helper() -> db.query() (même fichier) doit être résolu ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_js_cross_file_taint_flow_resolved_via_call_graph() {
        // api.js imports and calls runQuery (utils.js, CommonJS
        // require); the sink (db.query) is INSIDE utils.js, never
        // visible from api.js without multi-file interprocedural
        // resolution via JsCallGraph.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "js_sqli.sca",
            "rule js_sqli\n  language  javascript\n  category  security\n  severity  HIGH\n  source  req\\.query\\.q  kind=http\n  sink    db\\.query\\s*\\(\nend\n",
        );
        write(
            &root,
            "utils.js",
            "function runQuery(cmd) { db.query(cmd); }\n",
        );
        write(
            &root,
            "api.js",
            "const { runQuery } = require('./utils');\nfunction handler(req) { const q = req.query.q; runQuery(q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "api.js"),
            "le flux cross-file (api.js appelle runQuery() de utils.js via require, qui atteint db.query) doit être résolu au site d'appel dans api.js ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_js_bare_npm_import_does_not_introduce_false_flow() {
        // Non-relative import (npm package): never resolved, must not
        // introduce any false flow even if a method name coincides
        // with a sink-reaching function from ANOTHER scanned file.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "js_sqli.sca",
            "rule js_sqli\n  language  javascript\n  category  security\n  severity  HIGH\n  source  req\\.query\\.q  kind=http\n  sink    db\\.query\\s*\\(\nend\n",
        );
        write(
            &root,
            "danger.js",
            "function query(cmd) { db.query(cmd); }\n",
        );
        write(
            &root,
            "api.js",
            "import lodash from 'lodash';\nfunction handler(req) { const q = req.query.q; lodash.query(q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().all(|f| f.file != "api.js"),
            "import npm bare ('lodash') ne doit jamais être résolu vers danger.js ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_php_intra_file_function_to_function_flow_resolved() {
        // PHP call graph wired on 08/30 (`php_call_graph.rs`): before
        // this effort, even an A -> B call WITHIN THE SAME FILE wasn't
        // tracked (`specs.summaries` always empty).
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "php_sqli.sca",
            "rule php_sqli\n  language  php\n  category  security\n  severity  HIGH\n  source  \\$_GET\\[  kind=http\n  sink    ->query\\s*\\(\nend\n",
        );
        write(
            &root,
            "app.php",
            "<?php\nfunction helper($cmd) { $db->query($cmd); }\nfunction main() { $q = $_GET['q']; helper($q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "app.php"),
            "flux main() -> helper() -> $db->query() (même fichier) doit être résolu ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_php_cross_file_taint_flow_resolved_via_require() {
        // api.php requires utils.php and calls runQuery(); the sink
        // ($db->query) is INSIDE utils.php, never visible from
        // api.php without multi-file interprocedural resolution via
        // PhpCallGraph (star-merge of the requires).
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "php_sqli.sca",
            "rule php_sqli\n  language  php\n  category  security\n  severity  HIGH\n  source  \\$_GET\\[  kind=http\n  sink    ->query\\s*\\(\nend\n",
        );
        write(
            &root,
            "utils.php",
            "<?php\nfunction runQuery($cmd) { $db->query($cmd); }\n",
        );
        write(
            &root,
            "api.php",
            "<?php\nrequire './utils.php';\nfunction handler() { $q = $_GET['q']; runQuery($q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "api.php"),
            "le flux cross-file (api.php require utils.php et appelle runQuery(), qui atteint $db->query) doit être résolu au site d'appel dans api.php ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_php_ambiguous_static_class_name_does_not_introduce_false_flow() {
        // Two files each define a Utils class with a query() method
        // reaching the sink — the class name is ambiguous in the scanned
        // corpus and must never be resolved (anti-FP), even though
        // api.php calls Utils::query() without explicitly requiring
        // either file.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "php_sqli.sca",
            "rule php_sqli\n  language  php\n  category  security\n  severity  HIGH\n  source  \\$_GET\\[  kind=http\n  sink    ->query\\s*\\(\nend\n",
        );
        write(
            &root,
            "utils1.php",
            "<?php\nclass Utils {\n  static function query($cmd) { $db->query($cmd); }\n}\n",
        );
        write(
            &root,
            "utils2.php",
            "<?php\nclass Utils {\n  static function query($cmd) { $db->query($cmd); }\n}\n",
        );
        write(
            &root,
            "api.php",
            "<?php\nfunction handler() { $q = $_GET['q']; Utils::query($q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().all(|f| f.file != "api.php"),
            "nom de classe ambigu (Utils defini dans 2 fichiers) ne doit jamais etre resolu ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
