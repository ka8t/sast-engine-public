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
use sast_engine::scan::orchestrator::{ScanConfig, ScanReport, run_scan};


/// Exclusions applied to every scan — same list as
/// `DEFAULT_CONFIG["paths"]["exclude"]` (`Audit/sca/config.py`).
/// `paths.exclude` (`audit.config.json`) and `--exclude` ADD to this
/// list, never replace it: these are security exclusions (never scan
/// third-party/vendored code, nor the engine's own reports), not a
/// project choice to override.
///
/// **Deliberate deviation from Python (ticket #132, 2026-11-09)**:
/// `sca/config.py::_merge_config` replaces lists, so a project
/// declaring its own `paths.exclude` silently lost these defaults —
/// and scanned its previous HTML reports (279 phantom findings on a
/// 4-line project). The Rust port had copied that replacement while
/// this comment claimed a merge.
///
/// Earlier deviation found by the maintainer (2026-08-26): a scan of `Audit`
/// (repo root, with `.venv/` + `videos/node_modules/` +
/// `videos/.piper-venv/` present) without an explicit `--exclude`
/// scanned tens of thousands of third-party files (numpy/transformers/
/// pytest...) — nothing to do with engine slowness, just the total
/// absence of these defaults on the Rust side.
///
/// The list lives in the library (`project_config::DEFAULT_SCAN_EXCLUDES`)
/// so that every caller of `run_scan` skips the same folders.
const DEFAULT_EXCLUDES: &[&str] = sast_engine::project::project_config::DEFAULT_SCAN_EXCLUDES;

/// Default report directory, relative to the scanned folder (ticket
/// #133, 2026-11-09). **Deliberate deviation from Python**, which writes
/// into `<project>/docs/audit-reports`: that silently added files to the
/// audited project's own `docs/` folder. See
/// `docs/adr/0036-reports-written-to-project-root-audit-reports.md`.
const REPORTS_DIR: &str = "audit-reports";

/// Default JSON history directory (exports, SBOM), inside
/// [`REPORTS_DIR`] — same nesting as before ticket #133.
const DATAS_DIR: &str = "audit-reports/audit-datas";

/// History directory used before ticket #133. Read only, as a
/// fallback when [`DATAS_DIR`] holds no baseline yet, so the first scan
/// after the upgrade still compares against the previous one. Nothing
/// is ever written there any more.
const LEGACY_DATAS_DIR: &str = "docs/audit-reports/audit-datas";

/// Path of `target` relative to `root`, with `/` separators, when
/// `target` lies strictly inside `root` — `None` otherwise (outside the
/// project, or the project root itself). Both sides are canonicalized
/// (`target` through its parent when it does not exist yet, like a
/// report about to be written), so `.`, relative paths and symlinks
/// such as macOS `/tmp` → `/private/tmp` compare correctly.
fn path_inside_root(root: &Path, target: &Path) -> Option<String> {
    let root = root.canonicalize().ok()?;
    let target = match target.canonicalize() {
        Ok(t) => t,
        Err(_) => {
            let parent = target.parent().filter(|p| !p.as_os_str().is_empty());
            let parent = parent.unwrap_or(Path::new(".")).canonicalize().ok()?;
            parent.join(target.file_name()?)
        }
    };
    let rel = target.strip_prefix(&root).ok()?;
    let rel = rel.to_string_lossy().replace('\\', "/");
    (!rel.is_empty()).then_some(rel)
}

/// Exclusion patterns for the engine's own outputs located inside the
/// scanned folder (ticket #132): the history directory and the report
/// file, wherever `--data-dir`/`--output` put them. `DEFAULT_EXCLUDES`
/// already covers the default locations (`audit-reports/`,
/// `audit-datas/`); this covers moved ones, so a scan never reads its
/// previous reports back as source code (an HTML report is a scanned
/// language).
fn output_excludes(root: &Path, data_dir: Option<&Path>, output: Option<&Path>) -> Vec<String> {
    [data_dir, output]
        .into_iter()
        .flatten()
        .filter_map(|p| path_inside_root(root, p))
        .collect()
}

/// Resolves `paths.include`/`paths.exclude` for a scan.
///
/// 1. `audit.config.json` exists at the project root: read
///    (`project_config::read_paths_config`) — mirror of
///    `sca/config.py::load_config`. A file without a `paths` section is
///    still a present file (default paths, no prompt). A present but
///    invalid file is reported and the defaults are used, never the
///    prompt (ticket #137: the prompt overwrote it).
/// 2. Absent: the whole directory (`["."]`). In a terminal the file is
///    created first by `project::config_wizard`, called by
///    `run_scan_command`, which then stops without scanning
///    (2026-11-12); this branch is reached without a terminal, with
///    `--quiet` or with JSON logs.
///
/// In every case the returned exclusions start with `DEFAULT_EXCLUDES`
/// (see its doc comment); the project's own patterns follow. The third
/// value says where the paths came from, for the scope line printed at
/// scan start (ticket #140).
fn resolve_project_paths(
    root: &Path,
    script_locale: &serde_json::Value,
) -> (Vec<String>, Vec<String>, PathsOrigin) {
    // Prompt messages in the `--lang` language (ticket #124 — they were
    // hard-coded in French).
    let say = |key: &str| sast_engine::i18n::t(script_locale, key);

    match sast_engine::project::project_config::load_config_json(root) {
        Ok(Some(_)) => {
            let (include, exclude) =
                sast_engine::project::project_config::read_paths_config(root).unwrap_or_default();
            let include = if include.is_empty() {
                vec![".".to_string()]
            } else {
                include
            };
            return (
                include,
                with_default_excludes(exclude),
                PathsOrigin::ConfigFile,
            );
        }
        Err(error) => {
            emit_warning(&format!(
                "[sast-engine] {}",
                say("config_invalid")
                    .replace(
                        "{path}",
                        &root.join("audit.config.json").display().to_string()
                    )
                    .replace("{error}", &error)
            ));
            return (
                vec![".".to_string()],
                with_default_excludes(Vec::new()),
                PathsOrigin::InvalidConfig,
            );
        }
        Ok(None) => {}
    }

    // No file: the whole folder. In a terminal the scan never gets
    // here without a file: `run_scan_command` asks for one first
    // (`project::config_wizard`) and stops.
    (
        vec![".".to_string()],
        with_default_excludes(Vec::new()),
        PathsOrigin::NoConfig,
    )
}

/// Entries of an include or exclude list printed on the scope line before
/// the rest is counted. A list one entry longer is printed in full: "+1
/// more" would take the room of the entry itself.
const SCOPE_LIST_MAX: usize = 5;

/// Where the include/exclude paths of a scan come from (ticket #140).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathsOrigin {
    /// `audit.config.json` read at the project root (or just written by
    /// the interactive prompt).
    ConfigFile,
    /// `audit.config.json` present but unreadable or invalid JSON: the
    /// whole project is scanned (the error is reported separately).
    InvalidConfig,
    /// No `audit.config.json` and no accepted prompt: the whole project.
    NoConfig,
}

/// The scope line printed once at scan start (ticket #140): where the
/// paths come from, the include paths applied, and the exclusions the
/// user chose (project file and `--exclude`), the built-in ones only as a
/// count. A tester's scan widened to the whole project after a rewrite of
/// `audit.config.json`, and nothing in the output said so.
///
/// `include` of `["."]` reads as "the whole project". Shown like the
/// other progress lines: in normal mode and as a JSON log event, not with
/// `--quiet`, which only keeps results, warnings and errors (ticket #44);
/// the problems that widen the scope silently are warnings, so they still
/// show under `--quiet`.
fn scope_line(
    root: &Path,
    origin: PathsOrigin,
    include: &[String],
    excludes: &[String],
    say: impl Fn(&str) -> String,
) -> String {
    let source = match origin {
        PathsOrigin::ConfigFile => say("scan_scope_source_config"),
        PathsOrigin::InvalidConfig => say("scan_scope_source_invalid"),
        PathsOrigin::NoConfig => {
            say("scan_scope_source_none").replace("{path}", &root.display().to_string())
        }
    };
    // A tester's file listed 67 project folders: past `SCOPE_LIST_MAX`
    // entries, the list is cut and the rest counted.
    let shorten = |items: &[&str]| -> String {
        if items.len() <= SCOPE_LIST_MAX + 1 {
            return items.join(", ");
        }
        let more =
            say("scan_scope_more").replace("{count}", &(items.len() - SCOPE_LIST_MAX).to_string());
        format!("{}, {more}", items[..SCOPE_LIST_MAX].join(", "))
    };
    let include = if include.iter().all(|p| p == "." || p == "./") {
        say("scan_scope_whole_project")
    } else {
        shorten(&include.iter().map(String::as_str).collect::<Vec<_>>())
    };
    let chosen: Vec<&str> = excludes
        .iter()
        .map(String::as_str)
        .filter(|p| !DEFAULT_EXCLUDES.contains(p))
        .collect();
    let defaults =
        say("scan_scope_default_excludes").replace("{count}", &DEFAULT_EXCLUDES.len().to_string());
    let exclude = if chosen.is_empty() {
        defaults
    } else {
        format!("{} + {defaults}", shorten(&chosen))
    };
    say("scan_scope_line")
        .replace("{source}", &source)
        .replace("{include}", &include)
        .replace("{exclude}", &exclude)
}

/// Whether `--rules` and `rules list` accept a folder of plain `.sca`
/// files. The shared binary only reads rule packs: plain rules are the
/// private repository's sources (ADR-0041), never delivered.
const RULE_FOLDERS_ACCEPTED: bool = false;

/// Catalog for `scan` and `list-rules` (ADR-0040): the `--rules` value
/// (a pack file, or a folder holding at least one `.sca` file), else
/// `rules.scapack` next to the executable. Anything else stops the
/// command with exit code 2 and names the path searched, rather than
/// running with no rule.
fn resolve_rules_path(
    rules: Option<PathBuf>,
    script_locale: &serde_json::Value,
) -> Result<PathBuf, ExitCode> {
    let fail = |key: &str, path: &Path| {
        emit_error(
            &sast_engine::i18n::t(script_locale, key)
                .replace("{path}", &path.display().to_string()),
        );
        Err(ExitCode::from(2))
    };
    match rules {
        Some(path) if path.is_dir() && RULE_FOLDERS_ACCEPTED => {
            if sast_engine::rules::catalog::has_rule_files(&path) {
                Ok(path)
            } else {
                fail("scan_no_rule_files", &path)
            }
        }
        Some(path) if path.is_dir() => fail("scan_rules_pack_only", &path),
        Some(path) if path.is_file() => Ok(path),
        Some(path) => fail("scan_invalid_rules_dir", &path),
        None => {
            let pack = sast_engine::rules::catalog::default_pack_path()
                .unwrap_or_else(|| PathBuf::from(sast_engine::rules::pack_format::PACK_FILE_NAME));
            if pack.is_file() {
                Ok(pack)
            } else {
                fail("scan_no_rule_pack", &pack)
            }
        }
    }
}

/// Every rule file of a pack or folder for the `rules` subcommands, or
/// exit code 2 with the path and the reason.
fn read_rules_or_exit(
    path: &Path,
    script_locale: &serde_json::Value,
) -> Result<Vec<sast_engine::rules::catalog::RuleSource>, ExitCode> {
    sast_engine::rules::catalog::read_all_rule_sources(path).map_err(|error| {
        emit_error(
            &sast_engine::i18n::t(script_locale, "rules_open_error")
                .replace("{path}", &path.display().to_string())
                .replace("{error}", &error),
        );
        ExitCode::from(2)
    })
}

/// `sast-engine rules list <pack>` (ADR-0040): the rule files of a pack
/// (or folder), one per line with the first 12 hex characters of their
/// SHA-256 — the value `rules diff` compares.
fn run_rules_list_command(lang: &str, path: &Path) -> ExitCode {
    let script_locale = sast_engine::i18n::load_script_locale(lang);
    if path.is_dir() && !RULE_FOLDERS_ACCEPTED {
        emit_error(
            &sast_engine::i18n::t(&script_locale, "scan_rules_pack_only")
                .replace("{path}", &path.display().to_string()),
        );
        return ExitCode::from(2);
    }
    let files = match read_rules_or_exit(path, &script_locale) {
        Ok(files) => files,
        Err(code) => return code,
    };
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "{}",
        sast_engine::i18n::t(&script_locale, "rules_list_header")
            .replace("{path}", &path.display().to_string())
            .replace("{count}", &files.len().to_string())
    );
    for (rel, content) in &files {
        let hash = sast_engine::rules::pack_format::source_sha256(content);
        let _ = writeln!(out, "  {}  {rel}", &hash[..12]);
    }
    ExitCode::SUCCESS
}

/// Rule languages declared by the project (ADR-0038): the `languages` key
/// of `audit.config.json`, warning once about the values that name no
/// supported language. `None` when the key is absent or gives no
/// supported language: the scan then reads the rules of the languages of
/// the files it finds.
fn declared_rule_languages(root: &Path, say: impl Fn(&str) -> String) -> Option<Vec<String>> {
    let config = sast_engine::project::project_config::read_languages_config(root)?;
    if !config.unknown.is_empty() {
        emit_warning(&format!(
            "[sast-engine] {}",
            say("scan_languages_unknown").replace("{languages}", &config.unknown.join(", "))
        ));
    }
    (!config.languages.is_empty()).then_some(config.languages)
}

/// Console lines saying what the rule sources gave a scan (ADR-0040,
/// feedback of 2026-11-10: a tester could not tell which rules were
/// loaded). Per source: rule files kept over files available and the
/// pack or folder path; last, the number of rules kept and the languages
/// they cover.
fn rule_source_lines(report: &ScanReport, script_locale: &serde_json::Value) -> Vec<String> {
    use sast_engine::rules::catalog::RuleSourceKind;
    let say = |key: &str| sast_engine::i18n::t(script_locale, key);
    let mut lines: Vec<String> = report
        .rule_sources
        .iter()
        .map(|source| {
            let key = match source.kind {
                RuleSourceKind::Pack => "scan_rules_source_pack",
                RuleSourceKind::Folder => "scan_rules_source_folder",
            };
            say(key)
                .replace("{read}", &source.files_read.to_string())
                .replace("{available}", &source.files_available.to_string())
                .replace("{path}", &source.path.display().to_string())
        })
        .collect();
    lines.push(
        say("scan_rule_languages")
            .replace("{count}", &report.rules_loaded.to_string())
            .replace("{languages}", &report.rule_languages.join(", ")),
    );
    lines
}

/// Console line naming the folders the walk skipped as holding no project
/// code (tickets #148 and #152): their path relative to the project, with
/// a trailing `/`, and why — `docs/ (documentation)`. Past
/// `SCOPE_LIST_MAX` folders the rest is counted, like the scope line.
/// `None` when nothing was skipped. A documentation folder can hold code
/// that runs: this line is what keeps it from going unchecked without a
/// word.
fn skipped_dirs_line(
    root: &Path,
    skipped: &[sast_engine::scan::discovery::SkippedDir],
    say: impl Fn(&str) -> String,
) -> Option<String> {
    use sast_engine::scan::discovery::SkippedDirKind;
    if skipped.is_empty() {
        return None;
    }
    let items: Vec<String> = skipped
        .iter()
        .map(|(path, kind)| {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            let reason = match kind {
                SkippedDirKind::Documentation => say("scan_skipped_documentation"),
                SkippedDirKind::Virtualenv => say("scan_skipped_virtualenv"),
                SkippedDirKind::BuildOutput => say("scan_skipped_build_output"),
            };
            format!("{rel}/ ({reason})")
        })
        .collect();
    let dirs = if items.len() <= SCOPE_LIST_MAX + 1 {
        items.join(", ")
    } else {
        let more =
            say("scan_scope_more").replace("{count}", &(items.len() - SCOPE_LIST_MAX).to_string());
        format!("{}, {more}", items[..SCOPE_LIST_MAX].join(", "))
    };
    Some(say("scan_skipped_dirs").replace("{dirs}", &dirs))
}

/// Include paths of `audit.config.json` that do not exist under `root`,
/// in their configured order. The walk skips them (`find_files`), so the
/// CLI reports them once per scan instead of letting a typo scan nothing
/// without a word (ticket #138 — Python skips them silently too).
fn missing_include_paths(root: &Path, include_paths: &[String]) -> Vec<String> {
    include_paths
        .iter()
        .filter(|p| !root.join(p).exists())
        .cloned()
        .collect()
}

/// `DEFAULT_EXCLUDES` followed by `project_excludes`, without
/// duplicates (first occurrence kept) — the project's patterns can
/// only add exclusions, never remove a default one (ticket #132).
fn with_default_excludes(project_excludes: Vec<String>) -> Vec<String> {
    let mut merged: Vec<String> = DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect();
    for pattern in project_excludes {
        if !merged.contains(&pattern) {
            merged.push(pattern);
        }
    }
    merged
}

/// The line naming the advisory database of a `--with-deps` scan
/// (ADR-0042), and whether it is a warning: the database read with its
/// date and advisories per ecosystem, or why the dependencies were not
/// checked (no file, unusable file).
fn advisory_database_line(
    status: &sast_engine::scan::orchestrator::AdvisoryDatabaseStatus,
    say: impl Fn(&str) -> String,
) -> (bool, String) {
    use sast_engine::scan::orchestrator::AdvisoryDatabaseStatus;
    match status {
        AdvisoryDatabaseStatus::Read {
            path,
            created,
            counts,
        } => {
            let counts: Vec<String> = counts.iter().map(|(name, n)| format!("{name} {n}")).collect();
            (
                false,
                say("scan_advisories_read")
                    .replace("{path}", &path.display().to_string())
                    .replace("{date}", created)
                    .replace("{counts}", &counts.join(", ")),
            )
        }
        AdvisoryDatabaseStatus::Missing { path } => (
            true,
            say("scan_advisories_missing").replace(
                "{path}",
                &path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| sast_engine::project::advisory_file::FILE_NAME.to_string()),
            ),
        ),
        AdvisoryDatabaseStatus::Unreadable { error, .. } => {
            (true, say("scan_advisories_unreadable").replace("{error}", error))
        }
    }
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
        eprintln!("{}", phase_progress_line(label, elapsed));
    }
}

/// Text-mode progress line of one phase, as printed by
/// `print_phase_progress` (kept separate so its format is testable
/// without capturing stderr).
fn phase_progress_line(label: &str, elapsed: std::time::Duration) -> String {
    format!("[sast-engine]   {label} : {}", format_duration(elapsed))
}

/// Human-readable duration for the console (ticket #135): `850 ms`
/// under a second, `12.4 s` under a minute, `1 min 12 s` under an hour,
/// `1 h 02 min` beyond. Units are the same in the four console languages
/// (SI symbols), hence no locale lookup. JSON logs keep the raw
/// `duration_ms`. Truncates rather than rounds at each level, so a
/// displayed value is never larger than the real one (`59.99 s` shows
/// `59.9 s`, not `60.0 s`).
fn format_duration(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms < 1_000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{}.{} s", ms / 1_000, (ms % 1_000) / 100)
    } else if ms < 3_600_000 {
        let secs = ms / 1_000;
        format!("{} min {} s", secs / 60, secs % 60)
    } else {
        let mins = ms / 60_000;
        format!("{} h {:02} min", mins / 60, mins % 60)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration_picks_unit_by_magnitude() {
        use std::time::Duration;
        let cases = [
            (Duration::from_millis(31), "31 ms"),
            (Duration::from_millis(999), "999 ms"),
            (Duration::from_millis(12_480), "12.4 s"),
            (Duration::from_millis(59_990), "59.9 s"),
            (Duration::from_secs(72), "1 min 12 s"),
            (Duration::from_secs(3_720), "1 h 02 min"),
        ];
        for (duration, expected) in cases {
            // Called outside the macro so the code graph sees the call.
            let formatted = format_duration(duration);
            assert_eq!(formatted, expected);
        }
    }

    /// ADR-0042: the database read is named with its date and counts;
    /// a missing or unusable one is a warning saying the dependencies
    /// were not checked.
    #[test]
    fn test_advisory_database_line_names_database_or_says_not_checked() {
        use sast_engine::scan::orchestrator::AdvisoryDatabaseStatus;
        let en = sast_engine::i18n::load_script_locale("en");
        let say = |k: &str| sast_engine::i18n::t(&en, k);
        let (warning, line) = advisory_database_line(
            &AdvisoryDatabaseStatus::Read {
                path: PathBuf::from("/x/advisories.sadb"),
                created: "2026-11-11T00:00:00Z".into(),
                counts: vec![("PyPI".into(), 12), ("npm".into(), 30)],
            },
            say,
        );
        assert!(!warning);
        assert!(line.contains("/x/advisories.sadb") && line.contains("2026-11-11") && line.contains("PyPI 12, npm 30"), "{line}");
        let (warning, line) = advisory_database_line(&AdvisoryDatabaseStatus::Missing { path: Some(PathBuf::from("/x/a.sadb")) }, say);
        assert!(warning && line.contains("/x/a.sadb") && line.contains("not checked"), "{line}");
        let (warning, line) = advisory_database_line(
            &AdvisoryDatabaseStatus::Unreadable { path: PathBuf::from("/x/a.sadb"), error: "bad magic".into() },
            say,
        );
        assert!(warning && line.contains("bad magic") && line.contains("not checked"), "{line}");
    }

    #[test]
    fn test_with_default_excludes_keeps_defaults_and_adds_project_patterns() {
        let merged = with_default_excludes(vec!["legacy/".into(), "vendor/".into()]);
        assert!(merged.iter().any(|p| p == "audit-reports/"));
        assert_eq!(merged.iter().filter(|p| *p == "vendor/").count(), 1);
        assert_eq!(merged.last().map(String::as_str), Some("legacy/"));
    }

    #[test]
    fn test_missing_include_paths_keeps_only_absent_ones() {
        let root = std::env::temp_dir().join(format!("sast_missing_inc_{}", std::process::id()));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.py"), "x = 1\n").unwrap();
        let include = ["src/", "src/a.py", "srcc/", "."].map(String::from);
        // Called outside the macro so the code graph sees the call.
        let missing = missing_include_paths(&root, &include);
        assert_eq!(missing, vec!["srcc/".to_string()]);
        std::fs::remove_dir_all(&root).ok();
    }

    /// `rules/builtin` of the repository, the folder `build.rs` packs
    /// next to the binary (unit test binaries run from `deps/`, where
    /// there is no pack).
    fn builtin_rules_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/builtin")
    }

    /// Ticket #152: skipped folders are named relative to the project with
    /// their reason, cut past `SCOPE_LIST_MAX`; nothing skipped, no line.
    #[test]
    fn test_skipped_dirs_line_names_folders_and_reasons() {
        use sast_engine::scan::discovery::SkippedDirKind;
        let locale = sast_engine::i18n::load_script_locale("en");
        let say = |key: &str| sast_engine::i18n::t(&locale, key);
        let root = Path::new("/p");
        let skipped = vec![
            (root.join("docs"), SkippedDirKind::Documentation),
            (root.join("tools/.venv-clone"), SkippedDirKind::Virtualenv),
            (root.join("api/target"), SkippedDirKind::BuildOutput),
        ];
        let line = skipped_dirs_line(root, &skipped, say).expect("a line");
        assert_eq!(
            line,
            "Skipped, not project code: docs/ (documentation), tools/.venv-clone/ (Python virtualenv), api/target/ (build output). Name a folder in paths.include to scan it."
        );
        let many: Vec<_> = (0..8)
            .map(|i| {
                (
                    root.join(format!("m{i}/docs")),
                    SkippedDirKind::Documentation,
                )
            })
            .collect();
        let cut = skipped_dirs_line(root, &many, say).unwrap();
        assert!(
            cut.contains("m4/docs/") && !cut.contains("m5/docs/"),
            "{cut}"
        );
        assert!(skipped_dirs_line(root, &[], say).is_none());
    }

    /// ADR-0040: `--rules` takes a pack file, or a folder holding `.sca`
    /// files; a folder without any, or a path that does not exist, stops
    /// the command with exit code 2.
    #[test]
    fn test_resolve_rules_path_accepts_pack_or_rule_folder() {
        let parent =
            std::env::temp_dir().join(format!("sast_resolve_rules_{}", std::process::id()));
        let empty = parent.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let pack = parent.join("rules.scapack");
        std::fs::write(&pack, b"any file: opened at scan time").unwrap();
        let locale = sast_engine::i18n::load_script_locale("en");

        let folder = resolve_rules_path(Some(builtin_rules_dir()), &locale);
        let file = resolve_rules_path(Some(pack.clone()), &locale);
        let no_rules = resolve_rules_path(Some(empty), &locale);
        let missing = resolve_rules_path(Some(parent.join("missing")), &locale);
        std::fs::remove_dir_all(&parent).ok();

        // A folder of plain rules: private build only (ADR-0041).
        assert_eq!(folder.is_ok(), RULE_FOLDERS_ACCEPTED);
        assert_eq!(file.ok(), Some(pack));
        assert_eq!(no_rules.err(), Some(ExitCode::from(2)));
        assert_eq!(missing.err(), Some(ExitCode::from(2)));
    }


    #[test]
    fn test_phase_progress_line_and_print() {
        let elapsed = std::time::Duration::from_millis(1_250);
        let line = phase_progress_line("[2/4] phase A", elapsed);
        assert_eq!(line, "[sast-engine]   [2/4] phase A : 1.2 s");
        // Writes the same line to stderr; must not panic.
        print_phase_progress("[2/4] phase A", elapsed);
    }

    #[test]
    fn test_path_inside_root_cases() {
        let root = std::env::temp_dir().join(format!("sast_inside_{}", std::process::id()));
        std::fs::create_dir_all(root.join("out")).unwrap();
        let existing = path_inside_root(&root, &root.join("out"));
        let not_yet_written = path_inside_root(&root, &root.join("out/report.html"));
        let root_itself = path_inside_root(&root, &root);
        let outside = path_inside_root(&root, &std::env::temp_dir());
        let missing_parent = path_inside_root(&root, &root.join("nope/report.html"));
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(existing.as_deref(), Some("out"));
        assert_eq!(not_yet_written.as_deref(), Some("out/report.html"));
        assert_eq!(root_itself, None);
        assert_eq!(outside, None);
        assert_eq!(missing_parent, None, "parent must exist to canonicalize");
    }

    /// The non-interactive branches of `resolve_project_paths` (`quiet`
    /// never prompts): valid file, file with an empty include, invalid
    /// file, no file.
    #[test]
    fn test_resolve_project_paths_branches() {
        let locale = sast_engine::i18n::load_script_locale("en");
        let root = std::env::temp_dir().join(format!("sast_resolve_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let config = root.join("audit.config.json");
        let defaults = with_default_excludes(Vec::new());

        let absent = resolve_project_paths(&root, &locale);

        std::fs::write(
            &config,
            r#"{"paths": {"include": ["src/"], "exclude": ["legacy/", "vendor/"]}}"#,
        )
        .unwrap();
        let valid = resolve_project_paths(&root, &locale);

        std::fs::write(&config, r#"{"paths": {"include": []}}"#).unwrap();
        let empty_include = resolve_project_paths(&root, &locale);

        let invalid_text = r#"{"paths": {"include": ["src/"],}}"#;
        std::fs::write(&config, invalid_text).unwrap();
        let invalid = resolve_project_paths(&root, &locale);
        let after_invalid = std::fs::read_to_string(&config).unwrap();
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(
            absent,
            (
                vec![".".to_string()],
                defaults.clone(),
                PathsOrigin::NoConfig
            )
        );
        assert_eq!(valid.0, vec!["src/".to_string()]);
        assert_eq!(valid.2, PathsOrigin::ConfigFile);
        assert_eq!(
            valid.1,
            with_default_excludes(vec!["legacy/".into(), "vendor/".into()])
        );
        assert_eq!(empty_include.0, vec![".".to_string()]);
        assert_eq!(empty_include.1, defaults);
        assert_eq!(empty_include.2, PathsOrigin::ConfigFile);
        assert_eq!(
            invalid,
            (vec![".".to_string()], defaults, PathsOrigin::InvalidConfig)
        );
        assert_eq!(
            after_invalid, invalid_text,
            "an invalid file is never rewritten"
        );
    }

    /// Ticket #140: the scope line names the source, reads `["."]` as
    /// the whole project, lists the user's exclusions and counts the
    /// built-in ones.
    #[test]
    fn test_scope_line_per_origin() {
        let locale = sast_engine::i18n::load_script_locale("en");
        let say = |key: &str| sast_engine::i18n::t(&locale, key);
        let root = Path::new("/work/app");
        let defaults = with_default_excludes(Vec::new());
        let count = DEFAULT_EXCLUDES.len();

        let none = scope_line(root, PathsOrigin::NoConfig, &[".".into()], &defaults, say);
        let mut chosen = with_default_excludes(vec!["legacy/".into()]);
        chosen.push("*.mustache".into());
        let config = scope_line(
            root,
            PathsOrigin::ConfigFile,
            &["src/".into(), "web/".into()],
            &chosen,
            say,
        );
        let invalid = scope_line(
            root,
            PathsOrigin::InvalidConfig,
            &[".".into()],
            &defaults,
            say,
        );

        assert_eq!(
            none,
            format!(
                "Scope (no audit.config.json in /work/app): include the whole project; exclude {count} default patterns"
            )
        );
        assert_eq!(
            config,
            format!(
                "Scope (audit.config.json): include src/, web/; exclude legacy/, *.mustache + {count} default patterns"
            )
        );
        assert!(
            invalid.starts_with("Scope (invalid audit.config.json): include the whole project")
        );

        let many: Vec<String> = (1..=67).map(|i| format!("app-{i}/")).collect();
        let long = scope_line(root, PathsOrigin::ConfigFile, &many, &defaults, say);
        assert!(
            long.contains("app-5/, +62 more;") && !long.contains("app-6/"),
            "{long}"
        );
    }

    #[test]
    fn test_write_sbom_writes_named_cyclonedx_file() {
        let root = std::env::temp_dir().join(format!("sast_sbom_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("requirements.txt"), "requests==2.31.0\n").unwrap();
        let config = ScanConfig {
            root: root.clone(),
            datas_dir: Some(root.join("datas")),
            timestamp: "2026-11-09-08-00".to_string(),
            ..ScanConfig::default()
        };
        let written = write_sbom(&config, "demo", &Brand::default(), &chrono::Local::now());
        let path = written.expect("SBOM written");
        let json = std::fs::read_to_string(&path).unwrap_or_default();
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(path, root.join("datas/SCA-SBOM-2026-11-09-08-00.json"));
        assert!(json.contains("CycloneDX"), "{json}");
        assert!(json.contains("requests"), "{json}");
    }

    #[test]
    fn test_output_excludes_only_paths_inside_root() {
        let root = std::env::temp_dir().join(format!("sast_out_excl_{}", std::process::id()));
        std::fs::create_dir_all(root.join("out/hist")).unwrap();
        let outside = std::env::temp_dir();
        let excludes = output_excludes(
            &root,
            Some(&root.join("out/hist")),
            Some(&root.join("report.html")),
        );
        assert_eq!(
            excludes,
            vec!["out/hist".to_string(), "report.html".to_string()]
        );
        let outside_only = output_excludes(&root, Some(&outside), Some(&root));
        assert!(outside_only.is_empty());
        std::fs::remove_dir_all(&root).ok();
    }
}

#[derive(Parser)]
#[command(
    name = "sast-engine",
    version = sast_engine::BUILD_VERSION,
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
        /// Rules: a rule pack (`*.scapack`), ADR-0040 — default:
        /// `rules.scapack` next to the executable. Only the rules of the
        /// project's languages are kept.
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
        /// `brand.json`, `SCA` by default) into `audit-reports/` of
        /// the scanned folder (Audit uses `docs/audit-reports/`). Absent with
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
        /// Detects unpinned dependencies, and dependencies whose exact
        /// version has a published vulnerability according to the offline
        /// advisory database (see `--advisories`).
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
        /// Offline advisory database file of published vulnerabilities,
        /// read by `--with-deps` (ADR-0042) — default: `advisories.sadb`
        /// next to the executable. Missing: no vulnerability matching, and
        /// the scan says so; the rest of `--with-deps` is unchanged. The
        /// scan itself never uses the network.
        #[arg(long)]
        advisories: Option<PathBuf>,
        /// `brand.json` runtime customization file (ticket #87/spec
        /// #83) — default: `brand.json` next to the executable
        /// (like `advisories` above).
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
        /// Rules: a rule pack — default: `rules.scapack` next to the
        /// executable (same as `scan --rules`). Every language is listed.
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Rule pack tools (ADR-0040).
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
}

/// Subcommands of `sast-engine rules`.
#[derive(Subcommand)]
enum RulesAction {
    /// Lists the rule files of a pack with the start of their SHA-256.
    List {
        /// Rule pack (`*.scapack`).
        pack: PathBuf,
        /// Message language (`en`/`fr`/`es`/`de`).
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
            | Command::ListRules { lang, .. }
            | Command::Rules {
                action: RulesAction::List { lang, .. },
            } => lang,
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
            sast_engine::BUILD_VERSION,
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
            advisories,
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
            advisories,
            brand_file,
            sbom,
            metrics_output,
        }),
        Command::ListRules { lang, rules } => run_list_rules_command(&lang, rules),
        Command::Rules {
            action: RulesAction::List { pack, lang },
        } => run_rules_list_command(&lang, &pack),
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
    rule: &sast_engine::rules::catalog::RuleListing,
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
/// on the whole catalog, every language: header with the total, then one block per
/// category (translated title, rule count, `[disabled by default]` for
/// the opt-in ones) listing `id` and display name. The "project
/// fixtures" footer of the Python version is not ported: it reads the
/// per-project registry `Audit/projects/<slug>/`, classified out of
/// scope (issue #23).
fn run_list_rules_command(lang: &str, rules: Option<PathBuf>) -> ExitCode {
    use sast_engine::rules::catalog;
    let script_locale = sast_engine::i18n::load_script_locale(lang);
    let report_locale = sast_engine::i18n::load_report_locale(lang);
    let rules_path = match resolve_rules_path(rules, &script_locale) {
        Ok(path) => path,
        Err(code) => return code,
    };
    let sources = match read_rules_or_exit(&rules_path, &script_locale) {
        Ok(files) => files,
        Err(code) => return code,
    };
    let listing = catalog::rule_listing(&sources);
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
        .unwrap_or_else(|| config.root.join(DATAS_DIR));
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
        sast_engine::BUILD_VERSION,
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
    advisories: Option<PathBuf>,
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
        advisories,
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
    // 2026-11-12 (request from the maintainer): in a terminal, a folder without
    // `audit.config.json` is not scanned. The engine asks what to scan,
    // writes the file and asks to run the command again
    // (`project::config_wizard`). Never with `--quiet` or JSON logs
    // (ticket #92: no question in a machine-readable stream), nor without
    // a terminal (a script would wait forever): the whole folder is
    // scanned then, as before. Before the history folder is created, so
    // that nothing else is written into the project.
    if matches!(
        sast_engine::project::project_config::load_config_json(&path),
        Ok(None)
    ) && !quiet
        && log_format != "json"
        && std::io::stdin().is_terminal()
    {
        use sast_engine::project::config_wizard::{ConfigWizardOutcome, run_config_wizard};
        let say = |key: &str| sast_engine::i18n::t(&script_locale, key);
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        let mut writer = std::io::stderr();
        return match run_config_wizard(&mut reader, &mut writer, &path, &say) {
            Ok(ConfigWizardOutcome::Written(_)) => ExitCode::SUCCESS,
            Ok(ConfigWizardOutcome::Declined) => ExitCode::from(1),
            Ok(ConfigWizardOutcome::InputClosed) => {
                eprintln!();
                emit_error(&format!("[sast-engine] {}", say("config_prompt_input_closed")));
                ExitCode::from(2)
            }
            Err(error) => {
                emit_error(&format!(
                    "[sast-engine] {}",
                    say("config_prompt_write_error").replace("{error}", &error.to_string())
                ));
                ExitCode::from(4)
            }
        };
    }
    // ADR-0040: `--rules <PATH>`, else `rules.scapack` next to the
    // executable. A missing pack or a folder without any `.sca` file would
    // scan with no rule at all, so it stops here with the path searched.
    let rules_path = match resolve_rules_path(rules, &script_locale) {
        Ok(path) => path,
        Err(code) => return code,
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
    // `audit-reports/audit-datas` (`DATAS_DIR`, ticket #133 — Audit uses
    // `docs/audit-reports/audit-datas`). With the default only, the
    // pre-#133 location stays readable for the baseline lookup.
    let legacy_datas_dir = data_dir.is_none().then(|| path.join(LEGACY_DATAS_DIR));
    let data_dir = data_dir.or_else(|| Some(path.join(DATAS_DIR)));
    if let Some(dir) = &data_dir
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        emit_error(
            &sast_engine::i18n::t(&script_locale, "scan_internal_error")
                .replace("{error}", &format!("{}: {e}", dir.display())),
        );
        return ExitCode::from(4);
    }

    // Ticket #149 — the exact build first, even with `--quiet`: one line,
    // and the first thing a bug report needs.
    emit_result(&format!(
        "[sast-engine] sast-engine {}",
        sast_engine::BUILD_VERSION
    ));

    let (include_paths, base_excludes, paths_origin) =
        resolve_project_paths(&path, &script_locale);
    let exclude_patterns: Vec<String> = base_excludes.into_iter().chain(exclude).collect();

    // Ticket #140 — the scope actually applied, once per scan.
    emit_progress(
        quiet,
        &format!(
            "[sast-engine] {}",
            scope_line(
                &path,
                paths_origin,
                &include_paths,
                &exclude_patterns,
                |key| sast_engine::i18n::t(&script_locale, key),
            )
        ),
    );

    // Ticket #140 — paths keys that are ignored, wholly or partly, so the
    // scope silently differs from what the file seems to say. One
    // grouped warning, never suppressed by `--quiet` (like #138 below).
    let malformed_paths = sast_engine::project::project_config::malformed_paths_keys(&path);
    if !malformed_paths.is_empty() {
        emit_warning(&format!(
            "[sast-engine] {}",
            sast_engine::i18n::t(&script_locale, "scan_paths_config_malformed")
                .replace("{keys}", &malformed_paths.join(", "))
        ));
    }

    // Ticket #138 — one grouped warning, never suppressed by `--quiet`
    // (same treatment as the unsupported sections below).
    let missing_includes = missing_include_paths(&path, &include_paths);
    if !missing_includes.is_empty() {
        emit_warning(&format!(
            "[sast-engine] {}",
            sast_engine::i18n::t(&script_locale, "scan_include_paths_missing")
                .replace("{paths}", &missing_includes.join(", "))
        ));
    }

    // ADR-0038 — the rule languages declared by the project, if any.
    let target_languages =
        declared_rule_languages(&path, |key| sast_engine::i18n::t(&script_locale, key));

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

    // Custom rules are read by the private build only (ADR-0041): the
    // shared binary scans with the delivered pack alone.
    let custom_rules_dir: Option<PathBuf> = None;
    // Default: `advisories.sadb` next to the executable, where
    // `sast-advisories update` writes it when both binaries share a
    // directory, and where it is placed by hand with the full pack
    // (ADR-0042). A missing file only disables vulnerability matching, and
    // the scan says so.
    let advisories = advisories.or_else(sast_engine::project::advisory_file::default_path);

    // Default: next to the executable (ticket #87/spec #83, like
    // `advisories` above). `load_brand_file`
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

    // By default (no --output), the HTML report is written to
    // `audit-reports` (`REPORTS_DIR`) under the scanned directory — same
    // root as the JSON export above. Resolved before the scan so the
    // report path can be excluded from it (ticket #132). `text`/`sarif`
    // without --output stay on stdout (explicitly requested format,
    // Unix convention — accepted deviation vs Audit, which always writes its
    // HTML report regardless of the format additionally requested).
    let output = output.or_else(|| {
        if format == "html" {
            let dir = path.join(REPORTS_DIR);
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

    let exclude_patterns: Vec<String> = exclude_patterns
        .into_iter()
        .chain(output_excludes(
            &path,
            data_dir.as_deref(),
            output.as_deref(),
        ))
        .collect();

    let config = ScanConfig {
        root: path,
        include_paths,
        rules_path,
        target_languages,
        suppress_file,
        exclude_patterns,
        with_tests,
        test_command,
        with_deps,
        database,
        datas_dir: data_dir,
        legacy_datas_dir,
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
        advisories_file: advisories,
        script_locale: Some(script_locale.clone()),
        brand_prefix: effective_prefix(&brand),
        // Every file is discovered, so undeclared languages are named.
        only_target_language_files: false,
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
    // ADR-0040: where the rules came from and how many were kept, then the
    // languages found in the project but left out of `languages`, whose
    // files got no rule — a warning, never suppressed by `--quiet`.
    for line in rule_source_lines(&report, &script_locale) {
        emit_progress(quiet, &format!("[sast-engine] {line}"));
    }
    // Ticket #152: the folders skipped as holding no project code, named
    // once per scan (`--quiet` hides it, like the scope line).
    if let Some(line) = skipped_dirs_line(&config.root, &report.skipped_dirs, |key| {
        sast_engine::i18n::t(&script_locale, key)
    }) {
        emit_progress(quiet, &format!("[sast-engine] {line}"));
    }
    if !report.undeclared_languages.is_empty() {
        emit_warning(&format!(
            "[sast-engine] {}",
            sast_engine::i18n::t(&script_locale, "scan_languages_undeclared")
                .replace("{languages}", &report.undeclared_languages.join(", "))
        ));
    }
    // ADR-0042: every `--with-deps` scan names the advisory database it
    // read, even with `--quiet`; without one it says the dependencies were
    // not checked, so that no vulnerable dependency reads as "none".
    if let Some(status) = &report.advisory_database {
        let (warning, line) = advisory_database_line(status, |key| {
            sast_engine::i18n::t(&script_locale, key)
        });
        if warning {
            emit_warning(&format!("[sast-engine] {line}"));
        } else {
            emit_result(&format!("[sast-engine] {line}"));
        }
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
                sast_engine::BUILD_VERSION,
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
                tool_version: sast_engine::BUILD_VERSION.to_string(),
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
    // Whole command, from argument parsing to the written report
    // (ticket #135) — the per-phase lines don't add up to it (rule
    // loading aside, discovery and report rendering are not phases).
    // Same never-suppressed treatment as the summary line above.
    let total_elapsed = t_command_start.elapsed();
    if JSON_LOGS.load(std::sync::atomic::Ordering::Relaxed) {
        emit_json_line(
            LogLevel::Info,
            &sast_engine::i18n::t(&script_locale, "scan_total_duration")
                .replace("{duration}", &format_duration(total_elapsed)),
            Some(serde_json::json!(total_elapsed.as_millis())),
        );
    } else {
        emit_result(&format!(
            "[sast-engine] {}",
            sast_engine::i18n::t(&script_locale, "scan_total_duration")
                .replace("{duration}", &format_duration(total_elapsed))
        ));
    }

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
            sast_engine::BUILD_VERSION,
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
