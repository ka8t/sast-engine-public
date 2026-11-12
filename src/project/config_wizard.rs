//! Interactive creation of `audit.config.json` (2026-11-12, request from
//! the maintainer).
//!
//! A scan run in a terminal on a folder without `audit.config.json`
//! does not scan: it asks what to scan, writes the file, and tells the
//! user to run the same command again. The questions:
//!
//! 1. the whole folder, or only some of its sub-folders (listed and
//!    picked by number);
//! 2. whether to exclude folders, and if so which ones (the sub-folders
//!    of what was picked, listed and picked by number);
//! 3. the final file is shown — the user's choices plus the default
//!    exclusions (dependencies, build output, caches) — and written
//!    after a last confirmation.
//!
//! **Deliberate deviation from Python**, which generates the file
//! silently (`sca/cli.py:1108-1111`) and from the previous Rust prompt
//! (ticket #124), which proposed the detected folders with one yes/no
//! question and then scanned at once. Without a terminal, with `--quiet`
//! or with JSON logs nothing is asked and the whole folder is scanned,
//! as before (`main.rs::run_scan_command`).
//!
//! The questions read from any `BufRead` and write to any `Write`, so
//! that the whole dialog is tested without a terminal.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use super::project_config::{
    DetectedProjectInfo, audit_config_json_text, auto_detect_project, is_skipped_dir_name,
    write_audit_config_json,
};

/// How the dialog ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigWizardOutcome {
    /// The file was written at this path.
    Written(PathBuf),
    /// The user declined at the last confirmation: nothing written.
    Declined,
    /// The input closed before the end: nothing written.
    InputClosed,
}

/// `true` when the answer to a yes/no question is yes. An empty line
/// takes `default_yes`; otherwise English `y`/`yes` (a keyboard habit,
/// accepted in every language) or one of `localized_yes`, the
/// comma-separated `config_prompt_yes_answers` of the console language
/// (`o,oui`, `s,si,sí`, `j,ja`, ticket #124).
pub fn is_yes(raw_answer: &str, localized_yes: &str, default_yes: bool) -> bool {
    let answer = raw_answer.trim().to_lowercase();
    if answer.is_empty() {
        return default_yes;
    }
    answer == "y"
        || answer == "yes"
        || localized_yes
            .split(',')
            .any(|yes| yes.trim().to_lowercase() == answer)
}

/// The direct sub-folders of `root/base`, as paths relative to `root`
/// ending with `/` (`src/`, `src/legacy/`), sorted. Hidden folders and
/// the ones every scan skips (`node_modules`, `target`, previous reports…)
/// are left out: offering them would only offer what is never scanned.
pub fn sub_folders(root: &Path, base: &str) -> Vec<String> {
    let dir = if base == "." { root.to_path_buf() } else { root.join(base) };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let prefix = if base == "." { String::new() } else { base.to_string() };
    let mut out: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|name| !name.starts_with('.') && !is_skipped_dir_name(name))
        .map(|name| format!("{prefix}{name}/"))
        .collect();
    out.sort();
    out
}

/// Parses a list of numbers between 1 and `max`, separated by commas or
/// spaces, into sorted distinct 0-based indexes. `None` when one entry
/// is not such a number. An empty answer gives an empty list.
fn parse_numbers(answer: &str, max: usize) -> Option<Vec<usize>> {
    let mut out = Vec::new();
    for part in answer.split([',', ' ']).filter(|p| !p.trim().is_empty()) {
        let n: usize = part.trim().parse().ok()?;
        if n == 0 || n > max {
            return None;
        }
        out.push(n - 1);
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// Reads one line; `None` when the input is closed.
fn read_answer<R: BufRead>(reader: &mut R) -> io::Result<Option<String>> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line))
}

/// Asks `question` and reads the answer; `None` when the input closed.
fn ask<R: BufRead, W: Write>(reader: &mut R, writer: &mut W, question: &str) -> io::Result<Option<String>> {
    write!(writer, "[sast-engine] {question} ")?;
    writer.flush()?;
    read_answer(reader)
}

/// Lists `folders` numbered from 1, then reads numbers until the answer
/// is valid. `allow_empty`: an empty answer is accepted (no folder);
/// otherwise at least one number is required. `None` when the input
/// closed.
fn pick_folders<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    say: &dyn Fn(&str) -> String,
    folders: &[String],
    question: &str,
    allow_empty: bool,
) -> io::Result<Option<Vec<String>>> {
    writeln!(writer, "[sast-engine] {}", say("config_wizard_folders"))?;
    for (i, folder) in folders.iter().enumerate() {
        writeln!(writer, "    {:>2}. {folder}", i + 1)?;
    }
    loop {
        let Some(answer) = ask(reader, writer, question)? else {
            return Ok(None);
        };
        match parse_numbers(&answer, folders.len()) {
            Some(picked) if allow_empty || !picked.is_empty() => {
                return Ok(Some(picked.into_iter().map(|i| folders[i].clone()).collect()));
            }
            _ => writeln!(
                writer,
                "[sast-engine] {}",
                say("config_wizard_bad_numbers").replace("{max}", &folders.len().to_string())
            )?,
        }
    }
}

/// The file the dialog writes: the detected languages, the chosen
/// `include` (`["."]` for the whole folder), and `exclude` = the chosen
/// folders followed by the default exclusions of the detection
/// (`**/node_modules/**`, `**/target/**`…).
pub fn chosen_config(
    detected: &DetectedProjectInfo,
    include: Vec<String>,
    exclude: Vec<String>,
) -> DetectedProjectInfo {
    let mut exclude_patterns = exclude;
    for pattern in &detected.exclude_patterns {
        if !exclude_patterns.contains(pattern) {
            exclude_patterns.push(pattern.clone());
        }
    }
    DetectedProjectInfo {
        languages: detected.languages.clone(),
        include_paths: include,
        exclude_patterns,
    }
}

/// Runs the dialog of the module doc for the folder `root`. `say` looks
/// a key up in the script locale of the console language. Writes
/// `audit.config.json` only on a confirmed answer, and never over an
/// existing file (`write_audit_config_json` refuses it).
pub fn run_config_wizard<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    root: &Path,
    say: &dyn Fn(&str) -> String,
) -> io::Result<ConfigWizardOutcome> {
    let detected = auto_detect_project(root);
    writeln!(
        writer,
        "[sast-engine] {}",
        say("config_wizard_intro").replace("{path}", &root.display().to_string())
    )?;
    if !detected.languages.is_empty() {
        writeln!(
            writer,
            "[sast-engine] {}",
            say("config_prompt_languages").replace("{languages}", &detected.languages.join(", "))
        )?;
    }

    // 1. The whole folder or some sub-folders.
    let top = sub_folders(root, ".");
    writeln!(writer, "[sast-engine] {}", say("config_wizard_scope_title"))?;
    writeln!(writer, "     1. {}", say("config_wizard_scope_all"))?;
    writeln!(writer, "     2. {}", say("config_wizard_scope_some"))?;
    let some = loop {
        let Some(answer) = ask(reader, writer, &say("config_wizard_scope_choice"))? else {
            return Ok(ConfigWizardOutcome::InputClosed);
        };
        match answer.trim() {
            "" | "1" => break false,
            "2" => break true,
            _ => writeln!(
                writer,
                "[sast-engine] {}",
                say("config_wizard_bad_numbers").replace("{max}", "2")
            )?,
        }
    };
    let include = if some && top.is_empty() {
        writeln!(writer, "[sast-engine] {}", say("config_wizard_no_subfolders"))?;
        vec![".".to_string()]
    } else if some {
        match pick_folders(reader, writer, say, &top, &say("config_wizard_pick_include"), false)? {
            Some(picked) => picked,
            None => return Ok(ConfigWizardOutcome::InputClosed),
        }
    } else {
        vec![".".to_string()]
    };

    // 2. Folders to exclude, among the sub-folders of what is scanned.
    let yes_words = say("config_prompt_yes_answers");
    let Some(answer) = ask(reader, writer, &say("config_wizard_exclude_question"))? else {
        return Ok(ConfigWizardOutcome::InputClosed);
    };
    let mut exclude = Vec::new();
    if is_yes(&answer, &yes_words, false) {
        let candidates: Vec<String> = include.iter().flat_map(|base| sub_folders(root, base)).collect();
        if candidates.is_empty() {
            writeln!(writer, "[sast-engine] {}", say("config_wizard_no_exclude_candidates"))?;
        } else {
            match pick_folders(reader, writer, say, &candidates, &say("config_wizard_pick_exclude"), true)? {
                Some(picked) => exclude = picked,
                None => return Ok(ConfigWizardOutcome::InputClosed),
            }
        }
    }

    // 3. The final file, then the confirmation.
    let config = chosen_config(&detected, include, exclude);
    let path = root.join("audit.config.json");
    writeln!(
        writer,
        "[sast-engine] {}",
        say("config_wizard_preview").replace("{path}", &path.display().to_string())
    )?;
    for line in audit_config_json_text(root, &config).lines() {
        writeln!(writer, "    {line}")?;
    }
    writeln!(writer, "[sast-engine] {}", say("config_wizard_defaults_note"))?;
    let Some(answer) = ask(reader, writer, &say("config_wizard_write_question"))? else {
        return Ok(ConfigWizardOutcome::InputClosed);
    };
    if !is_yes(&answer, &yes_words, true) {
        writeln!(writer, "[sast-engine] {}", say("config_wizard_declined"))?;
        return Ok(ConfigWizardOutcome::Declined);
    }
    let written = write_audit_config_json(root, &config)?;
    writeln!(
        writer,
        "[sast-engine] {}",
        say("config_wizard_written").replace("{path}", &written.display().to_string())
    )?;
    Ok(ConfigWizardOutcome::Written(written))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn project(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sast-config-wizard-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["src/legacy", "src/app", "tests", "docs", "node_modules/x", ".git"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        std::fs::write(dir.join("src/app/main.py"), "print(1)\n").unwrap();
        std::fs::write(dir.join("tests/test_main.py"), "print(2)\n").unwrap();
        dir
    }

    fn run(dir: &Path, input: &str) -> (ConfigWizardOutcome, String) {
        let en = crate::i18n::load_script_locale("en");
        let say = |k: &str| crate::i18n::t(&en, k);
        let mut out = Vec::new();
        let outcome = run_config_wizard(&mut Cursor::new(input.as_bytes()), &mut out, dir, &say).unwrap();
        (outcome, String::from_utf8(out).unwrap())
    }

    fn written(dir: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(dir.join("audit.config.json")).unwrap()).unwrap()
    }

    /// Whole folder, no exclusion, Enter at the confirmation: the file
    /// holds `["."]` and the default exclusions, shown before writing.
    #[test]
    fn test_whole_folder_defaults() {
        let dir = project("whole");
        let (outcome, out) = run(&dir, "\n\n\n");
        assert_eq!(outcome, ConfigWizardOutcome::Written(dir.join("audit.config.json")));
        let file = written(&dir);
        assert_eq!(file["paths"]["include"], serde_json::json!(["."]));
        assert!(file["paths"]["exclude"].as_array().unwrap().contains(&"**/node_modules/**".into()));
        assert_eq!(file["languages"], serde_json::json!(["python"]));
        assert!(out.contains("\"include\""), "the file is shown: {out}");
        assert!(out.contains("Run the same command again"), "{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Some sub-folders, then folders to exclude among theirs: the list
    /// leaves out hidden and always-skipped folders; a wrong number is
    /// asked again.
    #[test]
    fn test_sub_folders_and_exclusions() {
        let dir = project("some");
        // Folders: 1 docs/, 2 src/, 3 tests/. Pick src and tests (after a
        // wrong answer), exclude src/legacy/ (2nd of src/app/,
        // src/legacy/).
        let (outcome, out) = run(&dir, "2\n9\n2,3\ny\n2\n\n");
        assert!(matches!(outcome, ConfigWizardOutcome::Written(_)), "{out}");
        // Never offered (the file still excludes them by default).
        assert!(!out.contains(". node_modules/"), "{out}");
        assert!(!out.contains(". .git/"), "{out}");
        assert!(out.contains("between 1 and 3"), "{out}");
        let file = written(&dir);
        assert_eq!(file["paths"]["include"], serde_json::json!(["src/", "tests/"]));
        let exclude = file["paths"]["exclude"].as_array().unwrap();
        assert_eq!(exclude[0], "src/legacy/");
        assert!(exclude.contains(&"**/target/**".into()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Declined at the confirmation, or input closed mid-way: nothing is
    /// written.
    #[test]
    fn test_declined_or_closed_writes_nothing() {
        let dir = project("declined");
        let (outcome, _) = run(&dir, "1\nn\nn\n");
        assert_eq!(outcome, ConfigWizardOutcome::Declined);
        assert!(!dir.join("audit.config.json").exists());
        let (outcome, _) = run(&dir, "2\n");
        assert_eq!(outcome, ConfigWizardOutcome::InputClosed);
        assert!(!dir.join("audit.config.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_numbers() {
        assert_eq!(parse_numbers("1, 3 3\n", 3), Some(vec![0, 2]));
        assert_eq!(parse_numbers("\n", 3), Some(vec![]));
        assert_eq!(parse_numbers("4", 3), None);
        assert_eq!(parse_numbers("0", 3), None);
        assert_eq!(parse_numbers("a", 3), None);
    }

    /// Ticket #124: the accepted answers follow the locale; `y`/`yes`
    /// work everywhere; an empty line takes the default.
    #[test]
    fn test_is_yes() {
        let yes = |lang: &str| crate::i18n::t(&crate::i18n::load_script_locale(lang), "config_prompt_yes_answers");
        assert!(is_yes("\n", "o,oui", true));
        assert!(!is_yes("\n", "o,oui", false));
        for s in ["o\n", "O\n", "oui\n", "y\n", "yes\n", "  o  \n"] {
            assert!(is_yes(s, "o,oui", false), "{s:?}");
        }
        for s in ["n\n", "non\n", "no\n", "nope\n"] {
            assert!(!is_yes(s, "o,oui", true), "{s:?}");
        }
        assert!(is_yes("Sí\n", &yes("es"), false));
        assert!(is_yes("ja\n", &yes("de"), false));
        assert!(!is_yes("o\n", &yes("de"), false));
        assert!(!is_yes("oui\n", &yes("en"), false));
    }
}
