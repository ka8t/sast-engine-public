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
const DEFAULT_EXCLUDES: &[&str] = &[
    "node_modules/",
    "vendor/",
    ".venv/",
    "__pycache__/",
    "*.min.js",
    "audit-reports/",
    "audit-datas/",
];

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
/// 2. Absent: **proposed** interactively (automatic detection +
///    prompt), an accepted deviation from Python (which auto-generates
///    it silently, `sca/cli.py:1108-1111`) — confirmed with the maintainer
///    (2026-08-26). Never blocking: only if `stdin` is a real
///    terminal and `!quiet` (otherwise a CI/script would hang
///    indefinitely on a prompt that will never arrive).
/// 3. Neither a file nor an accepted prompt: the whole directory
///    (`["."]`).
///
/// In every case the returned exclusions start with `DEFAULT_EXCLUDES`
/// (see its doc comment); the project's own patterns follow.
fn resolve_project_paths(
    root: &Path,
    quiet: bool,
    script_locale: &serde_json::Value,
) -> (Vec<String>, Vec<String>) {
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
            return (include, with_default_excludes(exclude));
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
            return (vec![".".to_string()], with_default_excludes(Vec::new()));
        }
        Ok(None) => {}
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
                return (
                    info.include_paths,
                    with_default_excludes(info.exclude_patterns),
                );
            }
            Ok(_) => {
                eprintln!("[sast-engine] {}", say("config_prompt_declined"));
            }
            Err(_) => {}
        }
    }

    (vec![".".to_string()], with_default_excludes(Vec::new()))
}

/// Rule packs directory for `scan` and `list-rules` (ADR-0037): the
/// `--packs-dir` value, else `rules/` next to the executable. It must hold
/// at least one `*.scapack` file; otherwise the command stops with exit
/// code 2 and names the folder searched, rather than running with no rule.
fn resolve_packs_dir(
    packs_dir: Option<PathBuf>,
    script_locale: &serde_json::Value,
) -> Result<PathBuf, ExitCode> {
    let dir = packs_dir
        .or_else(sast_engine::rules::catalog::default_packs_dir)
        .unwrap_or_else(|| PathBuf::from("rules"));
    if sast_engine::rules::catalog::pack_files(&dir).is_empty() {
        emit_error(
            &sast_engine::i18n::t(script_locale, "scan_no_rule_pack")
                .replace("{path}", &dir.display().to_string()),
        );
        return Err(ExitCode::from(2));
    }
    Ok(dir)
}

/// Client key for `scan`, `list-rules` and `rules key` (ticket #142):
/// `--key-file`, else the `SAST_ENGINE_KEY` environment variable, else
/// `sast-engine.key` next to the executable (`client_key::load_client_key`;
/// the scanned project is not searched, so no key file sits in a client
/// repository). `Ok(None)` when there is none (demo key only). A key that
/// cannot be read or parsed stops the command with exit code 2: scanning
/// on with fewer rules than the client paid for would go unseen. The
/// message names the source and the problem, never the key.
fn resolve_client_key(
    key_file: Option<PathBuf>,
    script_locale: &serde_json::Value,
) -> Result<
    Option<(
        sast_engine::rules::client_key::KeySource,
        sast_engine::rules::client_key::ClientKey,
    )>,
    ExitCode,
> {
    use sast_engine::rules::client_key;
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let env_value = std::env::var(client_key::KEY_ENV_VAR).ok();
    let Some((source, result)) =
        client_key::load_client_key(key_file, env_value.as_deref(), exe_dir.as_deref())
    else {
        return Ok(None);
    };
    match result {
        Ok(key) => Ok(Some((source, key))),
        Err(error) => {
            emit_error(
                &sast_engine::i18n::t(script_locale, "key_file_invalid")
                    .replace("{path}", &source.to_string())
                    .replace("{error}", &error),
            );
            Err(ExitCode::from(2))
        }
    }
}

/// One grouped notice for the rule packs skipped because they need
/// another key (ticket #142): `path (key fingerprint)`, comma-separated.
fn warn_foreign_packs(packs: &[(PathBuf, String)], script_locale: &serde_json::Value) {
    if packs.is_empty() {
        return;
    }
    let list = packs
        .iter()
        .map(|(path, fingerprint)| format!("{} ({fingerprint})", path.display()))
        .collect::<Vec<_>>()
        .join(", ");
    emit_warning(&format!(
        "[sast-engine] {}",
        sast_engine::i18n::t(script_locale, "packs_need_other_key")
            .replace("{count}", &packs.len().to_string())
            .replace("{packs}", &list)
    ));
}

/// `sast-engine rules key`: which key opens the rule packs. Prints the
/// client name, the key fingerprint and the key file, or says that only
/// the demo key is available. Never prints the key itself.
fn run_rules_key_command(lang: &str, key_file: Option<PathBuf>) -> ExitCode {
    let script_locale = sast_engine::i18n::load_script_locale(lang);
    let found = match resolve_client_key(key_file, &script_locale) {
        Ok(found) => found,
        Err(code) => return code,
    };
    let line = match found {
        Some((source, key)) => {
            let message = if key.client.is_empty() {
                "rules_key_unnamed"
            } else {
                "rules_key_client"
            };
            sast_engine::i18n::t(&script_locale, message)
                .replace("{client}", &key.client)
                .replace("{fingerprint}", &key.fingerprint())
                .replace("{path}", &source.to_string())
        }
        None => sast_engine::i18n::t(&script_locale, "rules_key_demo_only").replace(
            "{fingerprint}",
            &sast_engine::rules::pack_format::key_fingerprint(
                &sast_engine::rules::pack_format::demo_key(),
            ),
        ),
    };
    let _ = writeln!(std::io::stdout().lock(), "{line}");
    ExitCode::SUCCESS
}

/// `sast-engine rules pack <dir> --out <file>` (ADR-0037, ticket #143):
/// packs the client's own `.sca` rules with the client key. Refuses
/// without a client key (the demo key is public: rules packed with it
/// would be readable by anyone), refuses an empty folder, and compiles
/// every file first with the engine's own parser: one invalid file is
/// reported with its path and line and no pack is written. Client packs
/// are unsigned; the engine loads them as client rules.
fn run_rules_pack_command(
    lang: &str,
    dir: &Path,
    out: &Path,
    name: Option<String>,
    key_file: Option<PathBuf>,
) -> ExitCode {
    use sast_engine::rules::pack_format;
    let script_locale = sast_engine::i18n::load_script_locale(lang);
    let say = |key: &str| sast_engine::i18n::t(&script_locale, key);
    let key = match resolve_client_key(key_file, &script_locale) {
        Ok(Some((_, key))) => key,
        Ok(None) => {
            emit_error(&say("rules_pack_needs_client_key"));
            return ExitCode::from(2);
        }
        Err(code) => return code,
    };
    let files = pack_format::collect_sca_sources(dir);
    if files.is_empty() {
        emit_error(&say("rules_pack_no_rules").replace("{path}", &dir.display().to_string()));
        return ExitCode::from(2);
    }
    let invalid: Vec<String> = files
        .iter()
        .filter_map(|(rel, content)| {
            let path = dir.join(rel).display().to_string();
            sast_engine::scan::parser::compile_sca_to_json(content, &path)
                .err()
                .map(|e| e.to_string())
        })
        .collect();
    if !invalid.is_empty() {
        for error in &invalid {
            emit_error(&say("rules_pack_invalid_rule").replace("{error}", error));
        }
        return ExitCode::from(2);
    }
    let pack_name = name.unwrap_or_else(|| {
        dir.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "client".to_string())
    });
    let pack = pack_format::write_pack(&pack_name, &files, &key.key);
    if let Err(e) = std::fs::write(out, pack) {
        emit_error(&format!("[sast-engine] {}: {e}", out.display()));
        return ExitCode::from(2);
    }
    let _ = writeln!(
        std::io::stdout().lock(),
        "{}",
        say("rules_pack_written")
            .replace("{path}", &out.display().to_string())
            .replace("{count}", &files.len().to_string())
            .replace("{fingerprint}", &key.fingerprint())
    );
    ExitCode::SUCCESS
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

    /// A packs folder holding `rules/builtin` packed with the demo key,
    /// like the one `build.rs` writes next to the binary (unit test
    /// binaries run from `deps/`, where there is none).
    fn test_packs_dir(parent: &Path) -> PathBuf {
        use sast_engine::rules::pack_format;
        let sources = pack_format::collect_sca_sources(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/builtin"),
        );
        let dir = parent.join("packs");
        std::fs::create_dir_all(&dir).unwrap();
        let pack = pack_format::write_pack("builtin", &sources, &pack_format::demo_key());
        std::fs::write(dir.join("builtin.scapack"), pack).unwrap();
        dir
    }

    /// Ticket #141: `--packs-dir` is used when it holds a pack; a folder
    /// without any pack stops the command with exit code 2.
    #[test]
    fn test_resolve_packs_dir_requires_a_pack() {
        let parent =
            std::env::temp_dir().join(format!("sast_resolve_packs_{}", std::process::id()));
        let empty = parent.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let with_pack = test_packs_dir(&parent);
        let locale = sast_engine::i18n::load_script_locale("en");

        let found = resolve_packs_dir(Some(with_pack.clone()), &locale);
        let missing = resolve_packs_dir(Some(empty), &locale);
        std::fs::remove_dir_all(&parent).ok();

        assert_eq!(found.ok(), Some(with_pack));
        assert_eq!(missing.err(), Some(ExitCode::from(2)));
    }

    /// `run_scan_command` end to end, in-process (ticket #138): a file
    /// include scans that file only, and a missing include does not stop
    /// the scan.
    #[test]
    fn test_run_scan_command_scans_file_include_only() {
        let root = std::env::temp_dir().join(format!("sast_run_scan_{}", std::process::id()));
        std::fs::create_dir_all(root.join("src/app")).unwrap();
        let tainted = "import os\nos.system(input())\n";
        std::fs::write(root.join("src/app/a.py"), tainted).unwrap();
        std::fs::write(root.join("src/b.py"), tainted).unwrap();
        std::fs::write(
            root.join("audit.config.json"),
            r#"{"paths": {"include": ["src/app/a.py", "srcc/"], "exclude": []}}"#,
        )
        .unwrap();
        let out_dir =
            std::env::temp_dir().join(format!("sast_run_scan_out_{}", std::process::id()));
        std::fs::create_dir_all(&out_dir).unwrap();
        let report = out_dir.join("report.txt");
        let metrics = out_dir.join("metrics.json");
        let packs_dir = test_packs_dir(&out_dir);

        run_scan_command(ScanArgs {
            path: root.clone(),
            rules: None,
            packs_dir: Some(packs_dir.clone()),
            key_file: None,
            format: "text".into(),
            lang: "en".into(),
            log_format: "text".into(),
            output: Some(report.clone()),
            suppress_file: None,
            exclude: vec![],
            quiet: true,
            with_tests: false,
            test_command: None,
            with_deps: false,
            db_host: None,
            db_port: None,
            db_name: None,
            db_user: None,
            db_password_env_file: None,
            db_password_env_var: None,
            data_dir: Some(out_dir.join("datas")),
            quick: false,
            only_category: None,
            disable_rule: vec![],
            severity: None,
            custom_rules_dir: None,
            rule_updates_dir: None,
            advisories_dir: None,
            brand_file: None,
            sbom: false,
            metrics_output: Some(metrics.clone()),
        });
        let text = std::fs::read_to_string(&report).unwrap_or_default();
        let metrics: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&metrics).unwrap_or_default())
                .unwrap_or_default();
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&out_dir).ok();

        assert!(text.contains("a.py:"), "{text}");
        assert!(!text.contains("b.py:"), "{text}");
        assert!(
            metrics.to_string().contains("\"files_scanned\":1"),
            "{metrics}"
        );
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

        let absent = resolve_project_paths(&root, true, &locale);

        std::fs::write(
            &config,
            r#"{"paths": {"include": ["src/"], "exclude": ["legacy/", "vendor/"]}}"#,
        )
        .unwrap();
        let valid = resolve_project_paths(&root, true, &locale);

        std::fs::write(&config, r#"{"paths": {"include": []}}"#).unwrap();
        let empty_include = resolve_project_paths(&root, true, &locale);

        let invalid_text = r#"{"paths": {"include": ["src/"],}}"#;
        std::fs::write(&config, invalid_text).unwrap();
        let invalid = resolve_project_paths(&root, true, &locale);
        let after_invalid = std::fs::read_to_string(&config).unwrap();
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(absent, (vec![".".to_string()], defaults.clone()));
        assert_eq!(valid.0, vec!["src/".to_string()]);
        assert_eq!(
            valid.1,
            with_default_excludes(vec!["legacy/".into(), "vendor/".into()])
        );
        assert_eq!(empty_include.0, vec![".".to_string()]);
        assert_eq!(empty_include.1, defaults);
        assert_eq!(invalid, (vec![".".to_string()], defaults));
        assert_eq!(
            after_invalid, invalid_text,
            "an invalid file is never rewritten"
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
        /// Directory containing plain `.sca` rule files, used INSTEAD of
        /// the rule packs — only for a development/test catalog. Absent
        /// by default: the catalog comes from the encrypted rule packs
        /// (`--packs-dir`).
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Directory of encrypted rule packs (`*.scapack`, ADR-0037) —
        /// default: `rules/` next to the executable. Ignored with
        /// `--rules <DIR>`.
        #[arg(long)]
        packs_dir: Option<PathBuf>,
        /// Client key file (ADR-0037) that opens the client's rule packs —
        /// default: the `SAST_ENGINE_KEY` environment variable, then
        /// `sast-engine.key` next to the executable. Without one, only the
        /// demo key is available.
        #[arg(long)]
        key_file: Option<PathBuf>,
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
        /// advisory database (see `--advisories-dir`).
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
        /// Offline advisory database of published vulnerabilities, read by
        /// `--with-deps` — default: `advisories/` next
        /// to the executable. Missing: no vulnerability matching, the rest
        /// of `--with-deps` is unchanged. The scan itself never uses the
        /// network.
        #[arg(long)]
        advisories_dir: Option<PathBuf>,
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
        /// Directory of encrypted rule packs — default: `rules/` next
        /// to the executable (same as `scan --packs-dir`).
        #[arg(long)]
        packs_dir: Option<PathBuf>,
        /// Client key file — default: the `SAST_ENGINE_KEY` environment
        /// variable, then `sast-engine.key` next to the executable.
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// Rule pack tools (ADR-0037).
    Rules {
        #[command(subcommand)]
        action: RulesAction,
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

/// Subcommands of `sast-engine rules`.
#[derive(Subcommand)]
enum RulesAction {
    /// Shows which key opens the rule packs: the client key file found
    /// (client name and fingerprint, never the key) or the demo key only.
    Key {
        /// Client key file — default: the `SAST_ENGINE_KEY` environment
        /// variable, then `sast-engine.key` next to the executable.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Message language (`en`/`fr`/`es`/`de`).
        #[arg(long, default_value = "en")]
        lang: String,
    },
    /// Encrypts the client's own `.sca` rules of a folder into a rule
    /// pack, with the client key (never the public demo key). Every file
    /// is checked first; one invalid file and no pack is written.
    Pack {
        /// Folder of `.sca` rule files (searched recursively).
        dir: PathBuf,
        /// Pack file to write (`*.scapack`), to copy into the packs folder.
        #[arg(long)]
        out: PathBuf,
        /// Pack name shown in messages — default: the folder name.
        #[arg(long)]
        name: Option<String>,
        /// Client key file — default: the `SAST_ENGINE_KEY` environment
        /// variable, then `sast-engine.key` next to the executable.
        #[arg(long)]
        key_file: Option<PathBuf>,
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
                action: RulesAction::Key { lang, .. } | RulesAction::Pack { lang, .. },
            }
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
            packs_dir,
            key_file,
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
            advisories_dir,
            brand_file,
            sbom,
            metrics_output,
        } => run_scan_command(ScanArgs {
            path,
            rules,
            packs_dir,
            key_file,
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
            advisories_dir,
            brand_file,
            sbom,
            metrics_output,
        }),
        Command::CreateRule {
            custom_rules,
            builtin_rules,
            lang,
        } => run_create_rule_command(custom_rules, builtin_rules, lang),
        Command::ListRules {
            lang,
            packs_dir,
            key_file,
        } => run_list_rules_command(&lang, packs_dir, key_file),
        Command::Rules {
            action: RulesAction::Key { key_file, lang },
        } => run_rules_key_command(&lang, key_file),
        Command::Rules {
            action:
                RulesAction::Pack {
                    dir,
                    out,
                    name,
                    key_file,
                    lang,
                },
        } => run_rules_pack_command(&lang, &dir, &out, name, key_file),
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
/// on the embedded catalog: header with the total, then one block per
/// category (translated title, rule count, `[disabled by default]` for
/// the opt-in ones) listing `id` and display name. The "project
/// fixtures" footer of the Python version is not ported: it reads the
/// per-project registry `Audit/projects/<slug>/`, classified out of
/// scope (issue #23).
fn run_list_rules_command(
    lang: &str,
    packs_dir: Option<PathBuf>,
    key_file: Option<PathBuf>,
) -> ExitCode {
    let script_locale = sast_engine::i18n::load_script_locale(lang);
    let report_locale = sast_engine::i18n::load_report_locale(lang);
    let packs_dir = match resolve_packs_dir(packs_dir, &script_locale) {
        Ok(dir) => dir,
        Err(code) => return code,
    };
    let client_key = match resolve_client_key(key_file, &script_locale) {
        Ok(found) => found.map(|(_, key)| key),
        Err(code) => return code,
    };
    let catalog =
        sast_engine::rules::catalog::load_catalog(&packs_dir, client_key.as_ref().map(|k| &k.key));
    for (pack, reason) in &catalog.errors {
        emit_warning(&format!("[sast-engine] {}: {reason}", pack.display()));
    }
    warn_foreign_packs(&catalog.foreign_packs, &script_locale);
    let listing = sast_engine::rules::catalog::rule_listing(&catalog.files);
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
    packs_dir: Option<PathBuf>,
    key_file: Option<PathBuf>,
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
    advisories_dir: Option<PathBuf>,
    brand_file: Option<PathBuf>,
    sbom: bool,
    metrics_output: Option<PathBuf>,
}

fn run_scan_command(args: ScanArgs) -> ExitCode {
    let ScanArgs {
        path,
        rules,
        packs_dir,
        key_file,
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
        advisories_dir,
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
    // No explicit `--rules <DIR>`: the catalog comes from the encrypted
    // rule packs (ADR-0037), opened and compiled in memory by
    // `rules::catalog`. A folder without any pack would scan with no rule
    // at all, so it stops here with the folder that was searched.
    let rule_packs_dir = match &rules {
        Some(_) => None,
        None => match resolve_packs_dir(packs_dir, &script_locale) {
            Ok(dir) => Some(dir),
            Err(code) => return code,
        },
    };
    // Client key (ticket #142): only meaningful with packs. An invalid
    // key file stops here rather than silently scanning with fewer rules.
    let client_key = match &rule_packs_dir {
        Some(_) => match resolve_client_key(key_file, &script_locale) {
            Ok(found) => found.map(|(_, key)| key),
            Err(code) => return code,
        },
        None => None,
    };
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

    let (include_paths, base_excludes) = resolve_project_paths(&path, quiet, &script_locale);
    let exclude_patterns: Vec<String> = base_excludes.into_iter().chain(exclude).collect();

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
    // Default: next to the executable, where `sast-advisories update`
    // writes by default when both binaries share a directory (ADR-0035).
    // A missing directory only disables vulnerability matching.
    let advisories_dir = advisories_dir.or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("advisories")))
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
        rules_dir,
        rule_packs_dir,
        client_key,
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
        rule_updates_dir,
        advisories_dir,
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
    warn_foreign_packs(&report.skipped_rule_packs, &script_locale);

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
