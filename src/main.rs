//! CLI for `sast-engine` (Step 5.1/5.2, Decision #7 for exit codes).
//! Compatibility contract: `0` remains the only success code (any
//! script that tests `$? != 0` keeps working identically); `1`/`2`/`4`
//! refine the cause for scripts that want to distinguish it.
//!
//! ```text
//! 0 = analysis succeeded, no blocking finding
//! 1 = security findings detected (HIGH/CRITICAL)
//! 2 = usage / configuration error
//! 4 = internal error
//! ```

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use sast_engine::report::brand::{
    Brand, brand_style_block, effective_company_name, effective_prefix, effective_tool_name,
    effective_website_url, inject_brand_style, load_brand_file,
};
use sast_engine::report::compliance_html::HealthThresholds;
use sast_engine::report::exports::sarif::build_sarif_report;
use sast_engine::report::html::{ReportContext, generate_html};
use sast_engine::rules::rule_wizard::{WizardPaths, run_wizard};
use sast_engine::scan::orchestrator::{ScanConfig, ScanReport, run_scan};

/// Exclusions applied by default to every scan — exact mirror of
/// `DEFAULT_CONFIG["paths"]["exclude"]` (`Audit/sca/config.py`), which
/// applies systematically on the Python side (merged with
/// `audit.config.json` if it exists, never absent). `--exclude`
/// ADDS to this list rather than replacing it: these are security
/// exclusions (never scan third-party/vendored code), not a project
/// choice to override. Deviation found by the maintainer (2026-08-26): a scan
/// of `Audit` (repo root, with `.venv/` + `videos/node_modules/` +
/// `videos/.piper-venv/` present) without an explicit `--exclude`
/// scanned tens of thousands of third-party files (numpy/transformers/
/// pytest...) — nothing to do with engine slowness, just the total
/// absence of these defaults on the Rust side.
const DEFAULT_EXCLUDES: &[&str] = &[
    "node_modules/",
    "vendor/",
    ".venv/",
    "__pycache__/",
    "*.min.js",
    "audit-reports/",
    "audit-datas/",
];

/// Resolves `paths.include`/`paths.exclude` for a scan.
///
/// 1. `audit.config.json` exists at the project root: read as-is
///    (`project_config::read_paths_config`) — mirror of
///    `sca/config.py::load_config`.
/// 2. Absent: **proposed** interactively (automatic detection +
///    prompt), an accepted deviation from Python (which auto-generates
///    it silently, `sca/cli.py:1108-1111`) — confirmed with the maintainer
///    (2026-08-26). Never blocking: only if `stdin` is a real
///    terminal and `!quiet` (otherwise a CI/script would hang
///    indefinitely on a prompt that will never arrive).
/// 3. Neither a file nor an accepted prompt: the whole directory
///    (`["."]`) + only the default security exclusions
///    (`DEFAULT_EXCLUDES`).
fn resolve_project_paths(
    root: &Path,
    quiet: bool,
    script_locale: &serde_json::Value,
) -> (Vec<String>, Vec<String>) {
    // Prompt messages in the `--lang` language (ticket #124 — they were
    // hard-coded in French).
    let say = |key: &str| sast_engine::i18n::t(script_locale, key);
    let default_excludes: Vec<String> = DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect();

    if let Some((include, exclude)) = sast_engine::project::project_config::read_paths_config(root)
    {
        let include = if include.is_empty() {
            vec![".".to_string()]
        } else {
            include
        };
        let exclude = if exclude.is_empty() {
            default_excludes
        } else {
            exclude
        };
        return (include, exclude);
    }

    // Never with `--log-format json` (ticket #92): an interactive
    // question has no place in a machine-readable event stream.
    if !quiet
        && !JSON_LOGS.load(std::sync::atomic::Ordering::Relaxed)
        && std::io::stdin().is_terminal()
    {
        let info = sast_engine::project::project_config::auto_detect_project(root);
        eprintln!(
            "[sast-engine] {}",
            say("config_prompt_not_found").replace("{path}", &root.display().to_string())
        );
        if !info.languages.is_empty() {
            eprintln!(
                "[sast-engine] {}",
                say("config_prompt_languages").replace("{languages}", &info.languages.join(", "))
            );
        }
        eprintln!(
            "[sast-engine] {}",
            say("config_prompt_include").replace("{paths}", &info.include_paths.join(", "))
        );
        eprint!("[sast-engine] {} ", say("config_prompt_question"));
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        // `Ok(0)` = EOF with no byte read at all (stdin closed/redirected
        // unexpectedly despite `is_terminal()`) — treated as a refusal,
        // not as an empty answer (plain Enter) which, in contrast,
        // accepts the default. Distinction needed so a file is
        // never written silently without a real human answer.
        match std::io::stdin().read_line(&mut answer) {
            Ok(0) => {
                eprintln!("[sast-engine] {}", say("config_prompt_input_closed"));
            }
            Ok(_) if accepts_prompt(&answer, &say("config_prompt_yes_answers")) => {
                match sast_engine::project::project_config::write_audit_config_json(root, &info) {
                    Ok(p) => eprintln!(
                        "[sast-engine] {}",
                        say("config_prompt_written").replace("{path}", &p.display().to_string())
                    ),
                    Err(e) => eprintln!(
                        "[sast-engine] {}",
                        say("config_prompt_write_error").replace("{error}", &e.to_string())
                    ),
                }
                return (info.include_paths, info.exclude_patterns);
            }
            Ok(_) => {
                eprintln!("[sast-engine] {}", say("config_prompt_declined"));
            }
            Err(_) => {}
        }
    }

    (vec![".".to_string()], default_excludes)
}

/// `ScanConfig::on_phase_complete` callback — displays progress LIVE,
/// phase by phase, instead of a single dump after the scan fully
/// completes (reported by the maintainer, 2026-08-26: nothing was displayed
/// until the very end). `run_scan` remains free of direct I/O (see
/// the field doc in `orchestrator.rs`); this callback is what writes
/// to stderr, one line per phase, as soon as it finishes.
fn print_phase_progress(label: &str, elapsed: std::time::Duration) {
    if JSON_LOGS.load(std::sync::atomic::Ordering::Relaxed) {
        emit_json_line(
            LogLevel::Info,
            label,
            Some(serde_json::json!(elapsed.as_millis())),
        );
    } else {
        eprintln!("[sast-engine]   {label} : {:.3}s", elapsed.as_secs_f64());
    }
}

/// `scan --log-format json` (ticket #92): every console line becomes one
/// JSON object instead of `[sast-engine] …` text. Process-wide because
/// the console helpers below are free functions called from everywhere
/// (and from a plain `fn` callback, `print_phase_progress`); set once at
/// the start of `run_scan_command`, before the first message.
static JSON_LOGS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Level of a console message, as written in JSON log lines.
#[derive(Clone, Copy)]
enum LogLevel {
    Info,
    Warn,
    Error,
}

/// Writes one single-line JSON log event to stderr: `timestamp` (UTC,
/// RFC 3339, milliseconds), `level`, `message` (without the
/// `[sast-engine]` text prefix), plus `duration_ms` for a finished
/// phase. Built with `serde_json`, so any message text is escaped.
fn emit_json_line(level: LogLevel, message: &str, duration_ms: Option<serde_json::Value>) {
    let level = match level {
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    };
    let message = message
        .trim()
        .strip_prefix("[sast-engine]")
        .unwrap_or(message.trim())
        .trim();
    let mut event = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "level": level,
        "message": message,
    });
    if let Some(duration_ms) = duration_ms {
        event["duration_ms"] = duration_ms;
    }
    eprintln!("{event}");
}

/// Single choke point of every console line (ticket #44's rationale,
/// kept for ticket #92): plain text by default, a JSON event with
/// `--log-format json`.
fn log_line(level: LogLevel, msg: &str) {
    if JSON_LOGS.load(std::sync::atomic::Ordering::Relaxed) {
        emit_json_line(level, msg, None);
    } else {
        eprintln!("{msg}");
    }
}

/// Intermediate progress message ("Analysis in
/// progress...", path of the written report) — suppressed by
/// `--quiet`. Distinct from `emit_result`: never used for the final
/// summary or an error, see ticket #44 (spec #29) where `--quiet` used
/// to suppress those two categories too, making a CI scan
/// undiagnosable.
fn emit_progress(quiet: bool, msg: &str) {
    if !quiet {
        log_line(LogLevel::Info, msg);
    }
}

/// Final result or error message — never suppressed by `--quiet`,
/// regardless of its caller. A silent CI scan must remain
/// diagnosable: an invalid path or the final
/// summary must never disappear silently.
fn emit_result(msg: &str) {
    log_line(LogLevel::Info, msg);
}

/// Like `emit_result`, for a warning: the scan goes on (ignored config
/// section, skipped rule).
fn emit_warning(msg: &str) {
    log_line(LogLevel::Warn, msg);
}

/// Like `emit_result`, for an error that ends the command.
fn emit_error(msg: &str) {
    log_line(LogLevel::Error, msg);
}

/// Interprets the answer to the `[Y/n]` prompt — an empty line (plain
/// Enter) accepts the default, everything else must explicitly match a
/// "yes" to create the file. `localized_yes` is the comma-separated
/// `config_prompt_yes_answers` of the `--lang` locale (`o,oui`,
/// `s,si,sí`, `j,ja`…, ticket #124); English `y`/`yes` is accepted in
/// every language, as a keyboard habit. Extracted from
/// `resolve_project_paths` so it's testable without a real TTY.
fn accepts_prompt(raw_answer: &str, localized_yes: &str) -> bool {
    let answer = raw_answer.trim().to_lowercase();
    answer.is_empty()
        || answer == "y"
        || answer == "yes"
        || localized_yes
            .split(',')
            .any(|yes| yes.trim().to_lowercase() == answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accepts_prompt_empty_line_accepts_default() {
        assert!(accepts_prompt("\n", "o,oui"));
        assert!(accepts_prompt("", "o,oui"));
    }

    #[test]
    fn test_accepts_prompt_yes_variants() {
        for s in ["o\n", "O\n", "oui\n", "y\n", "yes\n", "  o  \n"] {
            assert!(accepts_prompt(s, "o,oui"), "devrait accepter : {s:?}");
        }
    }

    #[test]
    fn test_accepts_prompt_no_variants_rejected() {
        for s in ["n\n", "N\n", "non\n", "no\n", "nope\n"] {
            assert!(!accepts_prompt(s, "o,oui"), "devrait refuser : {s:?}");
        }
    }

    /// Ticket #124: the accepted answers follow the locale, read from
    /// the real `script` locale files; `y`/`yes` work everywhere and a
    /// letter from another language does not (`o` is not yes in German).
    #[test]
    fn test_accepts_prompt_uses_localized_yes_answers() {
        let yes = |lang: &str| {
            sast_engine::i18n::t(
                &sast_engine::i18n::load_script_locale(lang),
                "config_prompt_yes_answers",
            )
        };
        assert!(accepts_prompt("oui\n", &yes("fr")));
        assert!(accepts_prompt("Sí\n", &yes("es")));
        assert!(accepts_prompt("ja\n", &yes("de")));
        assert!(accepts_prompt("yes\n", &yes("de")));
        assert!(!accepts_prompt("o\n", &yes("de")));
        assert!(!accepts_prompt("oui\n", &yes("en")));
    }
}

#[derive(Parser)]
#[command(
    name = "sast-engine",
    version,
    about = "SAST engine — Rust port of CodeFixture Audit"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// Expected, harmless size gap: this enum only exists during CLI
// argument parsing (never stored in a collection/hot loop) — boxing
// `Scan`'s fields would complicate the `derive(Parser)` macro for
// clap with no real benefit.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Scans a project (Python, Java, JavaScript/TypeScript, PHP, C#,
    /// HTML templates, YAML, Dockerfile).
    Scan {
        /// Path of the project to scan.
        path: PathBuf,
        /// Directory containing the `.sca` rule files. Absent by
        /// default: the builtin catalog embedded in the binary,
        /// compiled entirely in memory (no disk access) — only
        /// specify this option for a development/custom catalog.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Output format: `text`, `sarif` or `html`.
        #[arg(long, default_value = "html")]
        format: String,
        /// HTML report language (`en`/`fr`/`es`/`de`).
        #[arg(long, default_value = "en")]
        lang: String,
        /// Console log format: `text` (default, `[sast-engine] …` lines)
        /// or `json` (one JSON object per line: `timestamp`, `level`,
        /// `message`, `duration_ms` for phases — ticket #92).
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        log_format: String,
        /// Output file. Absent by default with `--format html`: writes
        /// `<PREFIX>-REPORT-<timestamp>.html` (`PREFIX` from
        /// `brand.json`, `SCA` by default) into `docs/audit-reports` of
        /// the scanned folder (mirrors Audit's default behavior). Absent with
        /// `--format text`/`sarif`: stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        /// `.sca-suppress.json` file.
        #[arg(long)]
        suppress_file: Option<PathBuf>,
        /// Exclusion pattern (repeatable, glob/directory/extension).
        #[arg(long = "exclude")]
        exclude: Vec<String>,
        /// Only displays the report, not the summary on stderr.
        #[arg(long)]
        quiet: bool,
        /// Runs the audited project's test suite (opt-in, executes
        /// arbitrary project code).
        #[arg(long)]
        with_tests: bool,
        /// Explicit test command (otherwise auto-detected).
        #[arg(long)]
        test_command: Option<String>,
        /// Detects unpinned dependencies (static, no CVE matching).
        #[arg(long)]
        with_deps: bool,
        /// PostgreSQL host — enables the DB schema audit if present.
        #[arg(long)]
        db_host: Option<String>,
        #[arg(long)]
        db_port: Option<u16>,
        #[arg(long)]
        db_name: Option<String>,
        #[arg(long)]
        db_user: Option<String>,
        /// `.env` file containing the DB password (default: `.env`).
        #[arg(long)]
        db_password_env_file: Option<String>,
        /// Variable in the `.env` file carrying the password (default: `DB_PASSWORD`).
        #[arg(long)]
        db_password_env_var: Option<String>,
        /// History directory (JSON export after every scan, compared
        /// against the last baseline found).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Quick mode — disables with-tests/with-deps/the database
        /// even if these options are otherwise requested.
        #[arg(long)]
        quick: bool,
        /// Scans only a single rule category (e.g. "security").
        #[arg(long)]
        only_category: Option<String>,
        /// Rule identifier to disable (repeatable).
        #[arg(long = "disable-rule")]
        disable_rule: Vec<String>,
        /// Severities to keep, comma-separated (e.g.
        /// "HIGH,CRITICAL"). Accepted values: CRITICAL/HIGH/MEDIUM/LOW/INFO.
        #[arg(long)]
        severity: Option<String>,
        /// Custom rules directory, loaded IN ADDITION to the builtin
        /// catalog (ticket #84) — default: `custom-rules/` next to
        /// the executable. Has no effect if `--rules <DIR>` is
        /// provided (total, exclusive replacement).
        #[arg(long)]
        custom_rules_dir: Option<PathBuf>,
        /// Directory of Ed25519-signed rule update packs (ticket #85)
        /// — default: `rules-updates/` next to the executable. Has no
        /// effect if `--rules <DIR>` is provided (total, exclusive
        /// replacement), nor if no publisher public key was injected
        /// at build time (safe fallback, no pack loaded).
        #[arg(long)]
        rule_updates_dir: Option<PathBuf>,
        /// `brand.json` runtime customization file (ticket #87/spec
        /// #83) — default: `brand.json` next to the executable
        /// (mirrors `custom_rules_dir`/`rule_updates_dir` above).
        /// Absent or invalid: strictly unchanged behavior ("CodeFixture"
        /// defaults).
        #[arg(long)]
        brand_file: Option<PathBuf>,
        /// Also writes a CycloneDX SBOM of the statically detected
        /// dependencies (`<PREFIX>-SBOM-<timestamp>.json` in the data
        /// directory) (mirrors `--sbom`).
        #[arg(long)]
        sbom: bool,
        /// Writes a JSON file of scan metrics (files/LOC scanned,
        /// findings by severity, per-phase durations, exit code) to this
        /// path — opt-in, local file only (ticket #90).
        #[arg(long)]
        metrics_output: Option<PathBuf>,
    },
    /// Lists the builtin rules by category (mirrors `--list-rules`).
    ListRules {
        /// Display language (`en`/`fr`/`es`/`de`).
        #[arg(long, default_value = "en")]
        lang: String,
    },
    /// Interactive wizard for creating/editing a custom `.sca` rule.
    CreateRule {
        /// Custom rules directory (write).
        #[arg(long)]
        custom_rules: PathBuf,
        /// Builtin rules directory (read-only, duplicate detection).
        #[arg(long)]
        builtin_rules: PathBuf,
        /// Wizard message language (`en`/`fr`/`es`/`de`).
        #[arg(long, default_value = "en")]
        lang: String,
    },
}

impl Command {
    /// Console language of the subcommand, for messages emitted outside
    /// it (the panic hook).
    fn lang(&self) -> &str {
        match self {
            Command::Scan { lang, .. }
            | Command::ListRules { lang }
            | Command::CreateRule { lang, .. } => lang,
        }
    }
}

/// Installs the hook first, then runs the subcommand under
/// `catch_unwind` so any panic — on the main thread or resumed from a
/// rayon worker — ends with exit code 4 ("internal error", ADR-0015)
/// instead of Rust's default 101 (ticket #91).
fn main() -> ExitCode {
    let cli = Cli::parse();
    install_panic_hook(cli.command.lang());
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(cli.command)))
        .unwrap_or(ExitCode::from(4))
}

/// Replaces Rust's default panic output (raw message + `RUST_BACKTRACE`
/// hint) with one translated line carrying an incident id and the path
/// of a local crash log (ticket #91). The log gets the full details —
/// version, thread, panic message and location, a backtrace captured
/// regardless of `RUST_BACKTRACE` — so a client can attach it to a
/// support request after the fact. Several threads can panic during one
/// scan (rayon workers): each one is appended to the same log, but the
/// console line is printed once. Written to the system temp directory,
/// not next to the report as the ticket suggested: the hook cannot know
/// which subcommand or output path was running, and the temp directory
/// is always writable. Local only, never sent anywhere (ticket #93).
fn install_panic_hook(lang: &str) {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    static REPORTED: AtomicBool = AtomicBool::new(false);

    let locale = sast_engine::i18n::load_script_locale(lang);
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let incident = format!("{started:x}-{:x}", std::process::id());
    let log_path = std::env::temp_dir().join(format!("sast-engine-crash-{incident}.log"));
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let entry = format!(
            "sast-engine {}\nincident: {incident}\nthread: {}\n{info}\n\nbacktrace:\n{}\n\n",
            env!("CARGO_PKG_VERSION"),
            thread.name().unwrap_or("<unnamed>"),
            std::backtrace::Backtrace::force_capture()
        );
        let written = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .and_then(|mut f| f.write_all(entry.as_bytes()))
            .is_ok();
        if REPORTED.swap(true, Ordering::SeqCst) {
            return;
        }
        let message = if written {
            sast_engine::i18n::t(&locale, "internal_panic")
                .replace("{log}", &log_path.display().to_string())
        } else {
            sast_engine::i18n::t(&locale, "internal_panic_no_log")
        };
        emit_error(&format!(
            "[sast-engine] {}",
            message.replace("{incident}", &incident)
        ));
    }));
}

/// Runs the parsed subcommand.
fn dispatch(command: Command) -> ExitCode {
    // Debug builds only: lets the CLI tests exercise the panic hook on
    // the real binary. Compiled out of release builds.
    #[cfg(debug_assertions)]
    if std::env::var_os("SAST_ENGINE_DEBUG_PANIC").is_some() {
        panic!("SAST_ENGINE_DEBUG_PANIC set");
    }
    match command {
        Command::Scan {
            path,
            rules,
            format,
            lang,
            log_format,
            output,
            suppress_file,
            exclude,
            quiet,
            with_tests,
            test_command,
            with_deps,
            db_host,
            db_port,
            db_name,
            db_user,
            db_password_env_file,
            db_password_env_var,
            data_dir,
            quick,
            only_category,
            disable_rule,
            severity,
            custom_rules_dir,
            rule_updates_dir,
            brand_file,
            sbom,
            metrics_output,
        } => run_scan_command(ScanArgs {
            path,
            rules,
            format,
            lang,
            log_format,
            output,
            suppress_file,
            exclude,
            quiet,
            with_tests,
            test_command,
            with_deps,
            db_host,
            db_port,
            db_name,
            db_user,
            db_password_env_file,
            db_password_env_var,
            data_dir,
            quick,
            only_category,
            disable_rule,
            severity,
            custom_rules_dir,
            rule_updates_dir,
            brand_file,
            sbom,
            metrics_output,
        }),
        Command::CreateRule {
            custom_rules,
            builtin_rules,
            lang,
        } => run_create_rule_command(custom_rules, builtin_rules, lang),
        Command::ListRules { lang } => run_list_rules_command(&lang),
    }
}

/// Display order, icon and default activation of the listed categories
/// — verbatim from `Audit/sca/cli.py::list_rules` (`categories`), with
/// the folder → display key mapping (`dir_to_display`: `arch` →
/// `architecture`, every other folder maps to itself).
const LIST_RULES_CATEGORIES: [(&str, &str, bool); 8] = [
    ("security", "🛡️", true),
    ("architecture", "🏗️", true),
    ("ui", "🎨", true),
    ("ux", "🧑‍💻", true),
    ("maintenance", "🔧", true),
    ("dependencies", "📦", false),
    ("database", "🗄️", false),
    ("cicd", "⚙️", false),
];

/// Display name of a rule in `list-rules`: the `rules.<id>.name` entry
/// of the report locale, otherwise the rule's own `risk` text in `lang`
/// (fallback `en`) truncated to 60 characters, otherwise the id — same
/// fallback chain as `list_rules` on the Python side.
fn rule_display_name(
    rule: &sast_engine::rules::embedded_rules::RuleListing,
    report_locale: &serde_json::Value,
    lang: &str,
) -> String {
    if let Some(name) = report_locale
        .get("rules")
        .and_then(|r| r.get(&rule.id))
        .and_then(|r| r.get("name"))
        .and_then(|n| n.as_str())
        .filter(|n| !n.is_empty())
    {
        return name.to_string();
    }
    let risk = rule
        .risk
        .get(lang)
        .or_else(|| rule.risk.get("en"))
        .and_then(|v| v.as_str())
        .or_else(|| rule.risk.as_str());
    match risk {
        Some(text) if text.chars().count() > 60 => {
            format!("{}…", text.chars().take(60).collect::<String>())
        }
        Some(text) => text.to_string(),
        None => rule.id.clone(),
    }
}

/// `sast-engine list-rules` — port of `Audit/sca/cli.py::list_rules`
/// on the embedded catalog: header with the total, then one block per
/// category (translated title, rule count, `[disabled by default]` for
/// the opt-in ones) listing `id` and display name. The "project
/// fixtures" footer of the Python version is not ported: it reads the
/// per-project registry `Audit/projects/<slug>/`, classified out of
/// scope (issue #23).
fn run_list_rules_command(lang: &str) -> ExitCode {
    let script_locale = sast_engine::i18n::load_script_locale(lang);
    let report_locale = sast_engine::i18n::load_report_locale(lang);
    let listing = sast_engine::rules::embedded_rules::embedded_rule_listing();
    let rules_label = sast_engine::i18n::t(&script_locale, "rules_count");
    // `writeln!` with ignored errors rather than `println!`: the latter
    // panics on a closed pipe (`list-rules | head`).
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "\n📋 {} ({} {rules_label}):\n",
        sast_engine::i18n::t(&script_locale, "available_rules"),
        listing.len()
    );
    for (display_key, icon, enabled_by_default) in LIST_RULES_CATEGORIES {
        let rules: Vec<_> = listing
            .iter()
            .filter(|r| {
                let display = if r.category_dir == "arch" {
                    "architecture"
                } else {
                    r.category_dir.as_str()
                };
                display == display_key
            })
            .collect();
        let title = report_locale
            .get("category_titles")
            .and_then(|t| t.get(display_key))
            .and_then(|t| t.as_str())
            .map(String::from)
            .unwrap_or_else(|| {
                let mut c = display_key.chars();
                c.next()
                    .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                    .unwrap_or_default()
            });
        let suffix = if enabled_by_default {
            String::new()
        } else {
            format!(
                "  [{}]",
                sast_engine::i18n::t(&script_locale, "disabled_by_default")
            )
        };
        let _ = writeln!(
            out,
            "{icon}  {title} ({} {rules_label}){suffix}",
            rules.len()
        );
        for rule in rules {
            let _ = writeln!(
                out,
                "   {:<40} {}",
                rule.id,
                rule_display_name(rule, &report_locale, lang)
            );
        }
        let _ = writeln!(out);
    }
    ExitCode::from(0)
}

fn run_create_rule_command(
    custom_rules: PathBuf,
    builtin_rules: PathBuf,
    lang: String,
) -> ExitCode {
    let script_locale = sast_engine::i18n::load_script_locale(&lang);
    let paths = WizardPaths {
        custom_rules_dir: &custom_rules,
        builtin_rules_dir: &builtin_rules,
    };
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();

    match run_wizard(&mut reader, &mut writer, &script_locale, &paths) {
        Ok(Some(_)) => ExitCode::from(0),
        Ok(None) => ExitCode::from(0),
        Err(e) => {
            eprintln!("Internal error: {e}");
            ExitCode::from(4)
        }
    }
}

/// Writes the CycloneDX SBOM of the project's statically parsed
/// dependencies to `<data dir>/<PREFIX>-SBOM-<timestamp>.json` — same
/// location and name pattern as Python (`comparison.py::_export_sbom`,
/// `{datas_dir}/{brand_prefix}-SBOM-{timestamp}.json`), same manifests as
/// the `--with-deps` phase (`dependencies::collect_dependencies`).
/// Returns the written path, or a description of the I/O/serialization
/// failure.
fn write_sbom(
    config: &ScanConfig,
    project_name: &str,
    brand: &Brand,
    now: &chrono::DateTime<chrono::Local>,
) -> Result<PathBuf, String> {
    let dir = config
        .datas_dir
        .clone()
        .unwrap_or_else(|| config.root.join("docs/audit-reports/audit-datas"));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let deps = sast_engine::project::dependencies::collect_dependencies(
        &config.root,
        &config.include_paths,
    );
    let sbom = sast_engine::report::exports::sbom::build_dependency_sbom(
        &deps,
        project_name,
        "",
        &effective_tool_name(brand),
        env!("CARGO_PKG_VERSION"),
        &now.to_rfc3339(),
    );
    let json = sbom
        .to_json_string()
        .map_err(|e| format!("SBOM serialization: {e}"))?;
    let path = dir.join(format!(
        "{}-SBOM-{}.json",
        config.brand_prefix, config.timestamp
    ));
    std::fs::write(&path, json).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// Arguments of the `scan` subcommand, grouped so as not to blow up
/// the number of parameters of `run_scan_command`.
struct ScanArgs {
    path: PathBuf,
    rules: Option<PathBuf>,
    format: String,
    lang: String,
    log_format: String,
    output: Option<PathBuf>,
    suppress_file: Option<PathBuf>,
    exclude: Vec<String>,
    quiet: bool,
    with_tests: bool,
    test_command: Option<String>,
    with_deps: bool,
    db_host: Option<String>,
    db_port: Option<u16>,
    db_name: Option<String>,
    db_user: Option<String>,
    db_password_env_file: Option<String>,
    db_password_env_var: Option<String>,
    data_dir: Option<PathBuf>,
    quick: bool,
    only_category: Option<String>,
    disable_rule: Vec<String>,
    severity: Option<String>,
    custom_rules_dir: Option<PathBuf>,
    rule_updates_dir: Option<PathBuf>,
    brand_file: Option<PathBuf>,
    sbom: bool,
    metrics_output: Option<PathBuf>,
}

fn run_scan_command(args: ScanArgs) -> ExitCode {
    let ScanArgs {
        path,
        rules,
        format,
        lang,
        log_format,
        output,
        suppress_file,
        exclude,
        quiet,
        with_tests,
        test_command,
        with_deps,
        db_host,
        db_port,
        db_name,
        db_user,
        db_password_env_file,
        db_password_env_var,
        data_dir,
        quick,
        only_category,
        disable_rule,
        severity,
        custom_rules_dir,
        rule_updates_dir,
        brand_file,
        sbom,
        metrics_output,
    } = args;
    let t_command_start = std::time::Instant::now();
    JSON_LOGS.store(log_format == "json", std::sync::atomic::Ordering::Relaxed);
    // Loaded right from the start, before the first possible error —
    // same mechanism as `run_create_rule_command` (ticket #47): before
    // this ticket, `scan`'s CLI messages (errors, progress) stayed in
    // French regardless of `--lang`, only the HTML report was
    // translated.
    let script_locale = sast_engine::i18n::load_script_locale(&lang);
    if !path.is_dir() {
        emit_error(
            &sast_engine::i18n::t(&script_locale, "scan_invalid_path")
                .replace("{path}", &path.display().to_string()),
        );
        return ExitCode::from(2);
    }
    // `None` (no explicit `--rules <DIR>`): builtin catalog compiled
    // directly from `EMBEDDED_RULES` in memory (see
    // `embedded_rules::compile_embedded_rules`) — no directory to
    // validate, nor to extract to disk.
    let use_embedded_rules = rules.is_none();
    let rules_dir = match &rules {
        Some(dir) => {
            if !dir.is_dir() {
                emit_error(
                    &sast_engine::i18n::t(&script_locale, "scan_invalid_rules_dir")
                        .replace("{path}", &dir.display().to_string()),
                );
                return ExitCode::from(2);
            }
            dir.clone()
        }
        None => PathBuf::new(),
    };
    if format != "text" && format != "sarif" && format != "html" {
        emit_error(
            &sast_engine::i18n::t(&script_locale, "scan_unknown_format")
                .replace("{format}", &format),
        );
        return ExitCode::from(2);
    }

    let project_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string();

    let database = if db_host.is_some() || db_name.is_some() || db_user.is_some() {
        Some(sast_engine::project::database::live::DbConfig {
            host: db_host,
            port: db_port,
            database: db_name,
            user: db_user,
            password_env_file: db_password_env_file,
            password_env_var: db_password_env_var,
        })
    } else {
        None
    };

    const VALID_SEVERITIES: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    let severity_levels = match severity {
        None => None,
        Some(raw) => {
            let levels: Vec<String> = raw
                .split(',')
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .collect();
            let invalid: Vec<&String> = levels
                .iter()
                .filter(|s| !VALID_SEVERITIES.contains(&s.as_str()))
                .collect();
            if !invalid.is_empty() {
                // The order of the two `.replace()` calls is safe here:
                // `invalid` has already been uppercased (`.to_uppercase()`
                // above), so a user who literally typed "{valid}" as a
                // severity level would produce "{VALID}", never
                // recognized by the second `.replace()`. This safety
                // relies on case, not structure — don't copy this
                // chaining as-is onto non-normalized user data.
                emit_error(
                    &sast_engine::i18n::t(&script_locale, "scan_invalid_severities")
                        .replace(
                            "{invalid}",
                            &invalid
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                        )
                        .replace("{valid}", &VALID_SEVERITIES.join("/")),
                );
                return ExitCode::from(2);
            }
            Some(levels)
        }
    };

    // Single scan timestamp (mirror of `self.timestamp` on the Audit
    // side, computed only once — shared by the HTML report and the
    // JSON export so they carry exactly the same name). The
    // `%Y-%m-%d-%H-%M` format was verified empirically against a real
    // Python run (`SCA-REPORT-2026-08-26-09-16.html`), not assumed.
    let now = chrono::Local::now();
    let timestamp = now.format("%Y-%m-%d-%H-%M").to_string();

    // By default (no --data-dir), the JSON export is written to
    // `docs/audit-reports/audit-datas` — mirror of Audit's real
    // default (`resources/templates/audit.config.template.json`, verified
    // empirically: a project without `audit.config.json` gets this
    // configuration generated on the first run, never
    // `<project>/audit-datas`).
    let data_dir = data_dir.or_else(|| Some(path.join("docs/audit-reports/audit-datas")));
    if let Some(dir) = &data_dir
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        emit_error(
            &sast_engine::i18n::t(&script_locale, "scan_internal_error")
                .replace("{error}", &format!("{}: {e}", dir.display())),
        );
        return ExitCode::from(4);
    }

    let (include_paths, base_excludes) = resolve_project_paths(&path, quiet, &script_locale);
    let exclude_patterns: Vec<String> = base_excludes.into_iter().chain(exclude).collect();

    // Ticket #43/spec #27 — a single grouped warning (not one per
    // key), never suppressed by `--quiet`: it's actionable information
    // about the config, same treatment as the ignored rules below
    // (`report.rule_errors`), not a mere intermediate progress
    // message.
    let unsupported_sections =
        sast_engine::project::project_config::unsupported_config_sections(&path);
    if !unsupported_sections.is_empty() {
        emit_warning(&format!(
            "[sast-engine] {}",
            sast_engine::i18n::t(&script_locale, "scan_unsupported_config_sections")
                .replace("{keys}", &unsupported_sections.join(", "))
        ));
    }

    // Priority CLI > file > default (ticket #40/spec #27).
    // `--disable-rule` is repeatable, so there's no "explicitly empty"
    // value distinct from "not provided": a non-empty vector means
    // "provided on the CLI", exactly like the other multi-value flags
    // of this binary.
    let disabled_rules = if !disable_rule.is_empty() {
        disable_rule
    } else {
        sast_engine::project::project_config::read_disabled_rules_config(&path)
    };
    // Always read, even if `only_category` (CLI) is already provided:
    // the CLI > file priority (ticket #41/spec #27) is resolved in
    // `orchestrator.rs` (rule filtering), not here — unlike
    // `disabled_rules` above, `only_category` and `category_overrides`
    // remain two distinct `ScanConfig` fields, see the field doc in
    // `orchestrator.rs`.
    let category_overrides =
        sast_engine::project::project_config::read_category_overrides_config(&path);

    // Default: next to the executable (ticket #84/spec #82, mirrors
    // `{SCRIPT_DIR}/custom-rules/` on the Python side) — `None` only if
    // `current_exe()` fails (pathological case), in which case no
    // custom rule is consulted rather than guessing a path. The
    // directory doesn't need to exist: `run_scan` checks
    // `is_dir()` before any read, a missing default is silent.
    let custom_rules_dir = custom_rules_dir.or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("custom-rules")))
    });
    // Default: next to the executable (ticket #85/spec #82, mirrors
    // `{SCRIPT_DIR}/rules-updates/` on the Python side) — same reasoning
    // as `custom_rules_dir` above. The directory doesn't need to
    // exist nor contain a valid pack: `rule_packs.rs` checks
    // `is_dir()` and each manifest's signature before any
    // rule read.
    let rule_updates_dir = rule_updates_dir.or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("rules-updates")))
    });

    // Default: next to the executable (ticket #87/spec #83, mirrors
    // `custom_rules_dir`/`rule_updates_dir` above). `load_brand_file`
    // returns `None` on any anomaly (missing file, unreadable,
    // invalid JSON) — safe, silent fallback to `Brand::default()`
    // (all the "CodeFixture" defaults), never a blocking error.
    let brand_file = brand_file.or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("brand.json")))
    });
    let brand: Brand = brand_file
        .and_then(|p| load_brand_file(&p))
        .unwrap_or_default();

    let config = ScanConfig {
        root: path,
        include_paths,
        rules_dir,
        use_embedded_rules,
        suppress_file,
        exclude_patterns,
        with_tests,
        test_command,
        with_deps,
        database,
        datas_dir: data_dir,
        timestamp: timestamp.clone(),
        quick_mode: quick,
        only_category,
        category_overrides,
        disabled_rules,
        severity_levels,
        lang: lang.clone(),
        on_phase_complete: if quiet {
            None
        } else {
            Some(print_phase_progress)
        },
        custom_rules_dir,
        rule_updates_dir,
        script_locale: Some(script_locale.clone()),
        brand_prefix: effective_prefix(&brand),
    };
    emit_progress(
        quiet,
        &format!(
            "[sast-engine] {}",
            sast_engine::i18n::t(&script_locale, "scan_analyzing")
        ),
    );
    let t_scan_start = std::time::Instant::now();
    let report = run_scan(&config);

    for (rule_path, err) in &report.rule_errors {
        emit_warning(
            &sast_engine::i18n::t(&script_locale, "scan_rule_skipped")
                .replace("{path}", &rule_path.display().to_string())
                .replace("{error}", &err.to_string()),
        );
    }

    // By default (no --output), the HTML report is written to
    // `docs/audit-reports` under the scanned directory — same default as
    // the JSON export above, same source of truth. `text`/`sarif`
    // without --output stay on stdout (explicitly requested format,
    // Unix convention — accepted deviation vs Audit, which always writes its
    // HTML report regardless of the format additionally requested).
    let output = output.or_else(|| {
        if format == "html" {
            let dir = config.root.join("docs/audit-reports");
            if let Err(e) = std::fs::create_dir_all(&dir) {
                emit_error(
                    &sast_engine::i18n::t(&script_locale, "scan_internal_error")
                        .replace("{error}", &format!("{}: {e}", dir.display())),
                );
                return None;
            }
            // Brand prefix, like `runner.py:167`
            // (`{brand_prefix}-REPORT-{timestamp}.html`) — was hard-coded
            // to `SCA`, so a white-label delivery still produced
            // `SCA-REPORT-*` files (found by ticket #106).
            Some(dir.join(format!(
                "{}-REPORT-{timestamp}.html",
                effective_prefix(&brand)
            )))
        } else {
            None
        }
    });
    if format == "html" && output.is_none() {
        return ExitCode::from(4);
    }

    if sbom {
        match write_sbom(&config, &project_name, &brand, &now) {
            Ok(sbom_path) => emit_progress(
                quiet,
                &format!("[sast-engine] SBOM : {}", sbom_path.display()),
            ),
            Err(e) => {
                emit_error(&format!(
                    "[sast-engine] {}",
                    sast_engine::i18n::t(&script_locale, "scan_internal_error")
                        .replace("{error}", &e)
                ));
                return ExitCode::from(4);
            }
        }
    }

    let output_text = match format.as_str() {
        "sarif" => {
            let sarif = build_sarif_report(
                &report.findings,
                "sast-engine",
                env!("CARGO_PKG_VERSION"),
                &effective_website_url(&brand),
            );
            match serde_json::to_string_pretty(&sarif) {
                Ok(s) => s,
                Err(e) => {
                    emit_error(
                        &sast_engine::i18n::t(&script_locale, "scan_internal_error")
                            .replace("{error}", &format!("SARIF serialization: {e}")),
                    );
                    return ExitCode::from(4);
                }
            }
        }
        "html" => {
            let ctx = ReportContext {
                project_name,
                project_version: String::new(),
                project_uuid: String::new(),
                project_description: String::new(),
                project_path: config.root.display().to_string(),
                tool_name: effective_tool_name(&brand),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                company_name: effective_company_name(&brand),
                report_lang: lang,
                date_str: now.format("%d/%m/%Y à %H:%M").to_string(),
                timestamp,
                audit_total_time_secs: t_scan_start.elapsed().as_secs(),
                total_lines_code: report.total_loc,
                total_files_scanned: report.files_scanned,
                health_thresholds: HealthThresholds::default(),
                rule_catalog: &report.rule_catalog,
            };
            let audit_params_info = sast_engine::report::audit_params::AuditParamsInfo {
                languages: report.languages.clone(),
                include_paths: config.include_paths.clone(),
                exclude_patterns: config.exclude_patterns.clone(),
                quick_mode: config.quick_mode,
                only_category: config.only_category.clone(),
                disabled_rules: config.disabled_rules.clone(),
                with_tests: config.with_tests,
                with_deps: config.with_deps,
                database_configured: config.database.is_some(),
                severity_levels: config.severity_levels.clone(),
                report_lang: ctx.report_lang.clone(),
            };
            let html = generate_html(
                &report.findings,
                &ctx,
                report.comparison.as_ref(),
                Some(&audit_params_info),
                report.test_results.as_ref(),
            );
            // Ticket #87/spec #83: brand color override,
            // injected after the main stylesheet (just
            // before `</head>`) — the CSS cascade does the rest, without
            // touching the embedded static `.css` file. No-op if
            // `brand.json` has no color (or doesn't exist).
            inject_brand_style(html, brand_style_block(&brand).as_deref())
        }
        _ => format_text_report(&report),
    };

    match &output {
        Some(out_path) => {
            if let Err(e) = std::fs::write(out_path, &output_text) {
                emit_error(
                    &sast_engine::i18n::t(&script_locale, "scan_internal_error")
                        .replace("{error}", &format!("{}: {e}", out_path.display())),
                );
                return ExitCode::from(4);
            }
            emit_progress(
                quiet,
                &format!(
                    "[sast-engine] {} : {}",
                    sast_engine::i18n::t(&script_locale, "report_generated"),
                    out_path.display()
                ),
            );
        }
        None => println!("{output_text}"),
    }

    // Never suppressed by `--quiet` (see ticket #44): it's the only
    // message guaranteed by a silent CI scan — without it, a run that
    // "succeeds" with no finding is indistinguishable from a run that scanned
    // nothing at all.
    emit_result(&format!(
        "[sast-engine] {}",
        sast_engine::i18n::t(&script_locale, "scan_summary")
            .replace("{files}", &report.files_scanned.to_string())
            .replace("{loc}", &report.total_loc.to_string())
            .replace("{findings}", &report.findings.len().to_string())
    ));

    let high_count = report
        .findings
        .iter()
        .filter(|f| f.severity == "HIGH" || f.severity == "CRITICAL")
        .count();
    // Configurable threshold (ticket #42/spec #27) — `0` by default
    // (missing file or no `thresholds` section) reproduces
    // exactly the previous hardcoded behavior: failure as soon as
    // at least one HIGH/CRITICAL exists. Accepted deviations vs Python
    // documented in `read_max_high_threshold_config`.
    let max_high_threshold =
        sast_engine::project::project_config::read_max_high_threshold_config(&config.root);
    let exit_code: u8 = if high_count as i64 > max_high_threshold {
        1
    } else {
        0
    };

    // Ticket #90: written last, so it records the real exit code. A
    // write failure is an internal error (4), like the report itself.
    if let Some(metrics_path) = &metrics_output {
        let metrics = sast_engine::report::exports::metrics::build_scan_metrics(
            &report,
            "sast-engine",
            env!("CARGO_PKG_VERSION"),
            &now.to_rfc3339(),
            t_command_start.elapsed().as_millis(),
            exit_code,
        );
        let written = serde_json::to_string_pretty(&metrics)
            .map_err(|e| e.to_string())
            .and_then(|s| std::fs::write(metrics_path, s).map_err(|e| e.to_string()));
        if let Err(e) = written {
            emit_error(
                &sast_engine::i18n::t(&script_locale, "scan_internal_error")
                    .replace("{error}", &format!("{}: {e}", metrics_path.display())),
            );
            return ExitCode::from(4);
        }
    }
    ExitCode::from(exit_code)
}

fn format_text_report(report: &ScanReport) -> String {
    let mut out = String::new();
    for f in &report.findings {
        let message = if f.risk.is_empty() {
            &f.rule_name
        } else {
            &f.risk
        };
        out.push_str(&format!(
            "{}:{}: [{}] {} — {}\n",
            f.file, f.line, f.severity, f.rule_key, message
        ));
    }
    out
}
