//! Interactive wizard for creating/editing custom `.sca` rules —
//! ported from `Audit/sca/rule_wizard.py` (`run_wizard` and the helpers
//! actually used by this flow; the « Compatibility functions —
//! preserved for existing tests » at the end of the Python file — legacy,
//! not called by `run_wizard` — are not ported).
//!
//! Guides the user step by step (name, language, category, severity,
//! pattern, risk, fix, benefit, fix example), generates
//! a `.sca` file conforming to the DSL and validates it before writing. Reading/
//! writing abstracted via generic `BufRead`/`Write` (not
//! directly `stdin`/`stdout`) to remain testable with boxed
//! input.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::i18n::t as t_locale;
use crate::scan::parser::compile_sca_to_json;

pub const LANGUAGES: [(&str, &str); 7] = [
    ("python", "Python"),
    ("javascript", "JavaScript / TypeScript"),
    ("java", "Java"),
    ("csharp", "C#"),
    ("php", "PHP"),
    ("html", "HTML"),
    ("yaml", "YAML / CI-CD"),
];

pub const CATEGORIES: [(&str, &str); 5] = [
    (
        "security",
        "Sécurité — vulnérabilités, injections, crypto...",
    ),
    ("arch", "Architecture — couplage, séparation des couches..."),
    (
        "maintenance",
        "Maintenance — lisibilité, dette technique...",
    ),
    ("ui", "Interface — accessibilité, ergonomie..."),
    ("ux", "Expérience utilisateur — flux, retours..."),
];

pub const SEVERITIES: [(&str, &str); 3] = [
    ("HIGH", "Critique — à corriger immédiatement"),
    ("MEDIUM", "Important — à corriger dans un délai raisonnable"),
    ("LOW", "Bonne pratique — amélioration suggérée"),
];

fn t(script_locale: &Value, key: &str) -> String {
    t_locale(script_locale, key)
}

// ---------------------------------------------------------------------
// Interaction helpers — ported from _prompt/_prompt_choice/_prompt_yes_no/_section
// ---------------------------------------------------------------------

fn read_line<R: BufRead>(reader: &mut R) -> io::Result<String> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    // `read_line` returns "" at end of stream (EOF) with no error -- treated
    // as an empty answer by callers, the same way an `input()` on
    // a closed stream on the Python side would raise EOFError; here we stay
    // permissive (answers "" = default value).
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn prompt<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    question: &str,
    default: &str,
) -> io::Result<String> {
    if !default.is_empty() {
        write!(writer, "  {question} [{default}] : ")?;
        writer.flush()?;
        let answer = read_line(reader)?;
        let answer = answer.trim();
        Ok(if answer.is_empty() {
            default.to_string()
        } else {
            answer.to_string()
        })
    } else {
        write!(writer, "  {question} : ")?;
        writer.flush()?;
        Ok(read_line(reader)?.trim().to_string())
    }
}

fn prompt_choice<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    script_locale: &Value,
    question: &str,
    choices: &[(&str, &str)],
    default_idx: usize,
) -> io::Result<String> {
    writeln!(writer, "\n  {question}")?;
    for (i, (value, desc)) in choices.iter().enumerate() {
        let marker = if i == default_idx { ">" } else { " " };
        writeln!(writer, "    {marker} {}. {value} — {desc}", i + 1)?;
    }
    loop {
        write!(
            writer,
            "  {} [1-{}, {} {}] : ",
            t(script_locale, "wiz_choice"),
            choices.len(),
            t(script_locale, "wizard_old_default"),
            default_idx + 1
        )?;
        writer.flush()?;
        let answer = read_line(reader)?;
        let answer = answer.trim();
        if answer.is_empty() {
            return Ok(choices[default_idx].0.to_string());
        }
        if let Ok(n) = answer.parse::<i64>() {
            let idx = n - 1;
            if idx >= 0 && (idx as usize) < choices.len() {
                return Ok(choices[idx as usize].0.to_string());
            }
        } else if let Some((value, _)) =
            choices.iter().find(|(v, _)| v.eq_ignore_ascii_case(answer))
        {
            return Ok(value.to_string());
        }
        writeln!(
            writer,
            "    {}",
            t(script_locale, "wizard_choice_invalid").replace("{max}", &choices.len().to_string())
        )?;
    }
}

fn prompt_yes_no<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    question: &str,
    default: bool,
) -> io::Result<bool> {
    let suffix = if default { "(O/n)" } else { "(o/N)" };
    write!(writer, "  {question} {suffix} : ")?;
    writer.flush()?;
    let answer = read_line(reader)?.trim().to_lowercase();
    if answer.is_empty() {
        return Ok(default);
    }
    Ok(matches!(answer.as_str(), "o" | "oui" | "y" | "yes"))
}

fn section<W: Write>(writer: &mut W, title: &str) -> io::Result<()> {
    writeln!(writer, "\n  --- {title} ---")
}

// ---------------------------------------------------------------------
// Existing rules — ported from _find_existing_rule/_load_existing_rule
// ---------------------------------------------------------------------

/// Looks for an existing custom rule by file name (stem) under
/// `custom_rules_dir` — ported from `_find_existing_rule`.
pub fn find_existing_rule(custom_rules_dir: &Path, name: &str) -> Option<PathBuf> {
    if !custom_rules_dir.exists() {
        return None;
    }
    walk_sca_files(custom_rules_dir)
        .into_iter()
        .find(|p| p.file_stem().is_some_and(|s| s == name))
}

fn walk_sca_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_sca_files(&path));
        } else if path.extension().is_some_and(|e| e == "sca") {
            out.push(path);
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct RuleFormData {
    pub lang: String,
    pub cat: String,
    pub sev: String,
    pub pattern: String,
    pub neutralizer: String,
    pub risk: [String; 4], // en, fr, es, de
    pub solution: [String; 4],
    pub benefit: [String; 4],
    pub fix_before: String,
    pub fix_after: String,
}

impl RuleFormData {
    fn defaults() -> Self {
        Self {
            lang: "python".to_string(),
            cat: "security".to_string(),
            sev: "HIGH".to_string(),
            ..Default::default()
        }
    }
}

const LANG_CODES: [&str; 4] = ["en", "fr", "es", "de"];

/// Parses an existing `.sca` to prefill the wizard — ported from
/// `_load_existing_rule`.
pub fn load_existing_rule(path: &Path) -> RuleFormData {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut data = RuleFormData::defaults();

    if let Some(v) = capture_line(&content, r"^\s*language\s+(\S+)") {
        data.lang = v;
    }
    if let Some(v) = capture_line(&content, r"^\s*category\s+(\S+)") {
        data.cat = v;
    }
    if let Some(v) = capture_line(&content, r"^\s*severity\s+(\S+)") {
        data.sev = v;
    }

    if let Some(block) = capture_block(&content, "match") {
        if let Some(v) = capture_line(&block, r"^\s*text\s+(.+)$") {
            data.pattern = v.trim().to_string();
        }
        if let Some(v) = capture_line(&block, r"^\s*text-not\s+(.+)$") {
            data.neutralizer = v.trim().to_string();
        }
    }

    for (block_name, target) in [
        ("risk", &mut data.risk),
        ("solution", &mut data.solution),
        ("benefit", &mut data.benefit),
    ] {
        if let Some(block) = capture_block(&content, block_name) {
            for (i, lang_code) in LANG_CODES.iter().enumerate() {
                let re =
                    fancy_regex::Regex::new(&format!(r"(?m)^\s*{lang_code}:\s*(.+)$")).unwrap();
                if let Ok(Some(caps)) = re.captures(&block) {
                    target[i] = caps
                        .get(1)
                        .map(|m| m.as_str().trim().to_string())
                        .unwrap_or_default();
                }
            }
        }
    }

    data.fix_before = capture_code_block(&content, "fix_before");
    data.fix_after = capture_code_block(&content, "fix_after");

    data
}

fn capture_line(content: &str, pattern: &str) -> Option<String> {
    let re = fancy_regex::Regex::new(&format!("(?m){pattern}")).ok()?;
    re.captures(content)
        .ok()
        .flatten()
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn capture_block(content: &str, block_name: &str) -> Option<String> {
    let re = fancy_regex::Regex::new(&format!(r"(?s)\b{block_name}\b(.*?)\bend\b")).ok()?;
    re.captures(content)
        .ok()
        .flatten()
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn capture_code_block(content: &str, block_name: &str) -> String {
    let Ok(re) = fancy_regex::Regex::new(&format!(r"(?s)\b{block_name}\b\n(.*?)\bend\b")) else {
        return String::new();
    };
    let Ok(Some(caps)) = re.captures(content) else {
        return String::new();
    };
    let Some(m) = caps.get(1) else {
        return String::new();
    };
    let mut lines: Vec<&str> = m.as_str().lines().map(|l| l.trim_end()).collect();
    while lines.first().is_some_and(|l| l.is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------
// Duplicate detection — ported from _check_custom_pattern_duplicate/_check_builtin_duplicate
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DuplicateMatch {
    pub id: String,
    pub path: String,
}

/// Custom rules already using this pattern for this language — ported
/// from `_check_custom_pattern_duplicate`.
pub fn check_custom_pattern_duplicate(
    custom_rules_dir: &Path,
    pattern: &str,
    language: &str,
    exclude_name: &str,
) -> Vec<DuplicateMatch> {
    if !custom_rules_dir.exists() {
        return vec![];
    }
    let mut matches = Vec::new();
    for sca_file in walk_sca_files(custom_rules_dir) {
        if sca_file.file_stem().is_some_and(|s| s == exclude_name) {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(&sca_file) else {
            continue;
        };
        let Ok(compiled) = compile_sca_to_json(&source, &sca_file.to_string_lossy()) else {
            continue;
        };
        for rule in &compiled {
            if rule.get("language").and_then(|v| v.as_str()) != Some(language) {
                continue;
            }
            let Some(patterns) = rule.get("patterns").and_then(|v| v.as_array()) else {
                continue;
            };
            for p in patterns {
                if p.get("pattern").and_then(|v| v.as_str()).map(|s| s.trim())
                    == Some(pattern.trim())
                {
                    let id = rule
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_else(|| {
                            sca_file.file_stem().and_then(|s| s.to_str()).unwrap_or("")
                        })
                        .to_string();
                    let rel = sca_file.strip_prefix(custom_rules_dir).unwrap_or(&sca_file);
                    matches.push(DuplicateMatch {
                        id,
                        path: rel.to_string_lossy().to_string(),
                    });
                }
            }
        }
    }
    matches
}

/// Does a builtin rule already exist with this name? — ported from
/// `_check_builtin_duplicate`.
pub fn check_builtin_duplicate(builtin_rules_dir: &Path, name: &str) -> Option<String> {
    for sca_file in walk_sca_files(builtin_rules_dir) {
        let Ok(source) = std::fs::read_to_string(&sca_file) else {
            continue;
        };
        let Ok(compiled) = compile_sca_to_json(&source, &sca_file.to_string_lossy()) else {
            continue;
        };
        for rule in &compiled {
            if rule.get("id").and_then(|v| v.as_str()) == Some(name) {
                let rel = sca_file
                    .strip_prefix(builtin_rules_dir)
                    .unwrap_or(&sca_file);
                return Some(rel.to_string_lossy().to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------
// DSL generation — ported from _build_sca_content
// ---------------------------------------------------------------------

/// Generates the full contents of a `.sca` file — ported from
/// `_build_sca_content`.
#[allow(clippy::too_many_arguments)]
pub fn build_sca_content(
    name: &str,
    lang: &str,
    cat: &str,
    sev: &str,
    pattern: &str,
    neutralizer: &str,
    risk: &[String; 4],
    solution: &[String; 4],
    benefit: &[String; 4],
    fix_before: &str,
    fix_after: &str,
) -> String {
    let mut lines = vec![
        format!("rule {name}"),
        format!("  language  {lang}"),
        format!("  category  {cat}"),
        format!("  severity  {sev}"),
        String::new(),
        "  match".to_string(),
        format!("    text  {pattern}"),
    ];
    if !neutralizer.is_empty() {
        lines.push(format!("    text-not  {neutralizer}"));
    }
    lines.push("  end".to_string());
    lines.push(String::new());

    push_i18n_block(&mut lines, "risk", risk);
    push_i18n_block(&mut lines, "solution", solution);
    if !benefit[0].is_empty() {
        push_i18n_block(&mut lines, "benefit", benefit);
    }

    if !fix_before.is_empty() && !fix_after.is_empty() {
        lines.push("  fix_before".to_string());
        for l in fix_before.lines() {
            lines.push(format!("    {l}"));
        }
        lines.push("  end".to_string());
        lines.push(String::new());
        lines.push("  fix_after".to_string());
        for l in fix_after.lines() {
            lines.push(format!("    {l}"));
        }
        lines.push("  end".to_string());
        lines.push(String::new());
    }

    lines.push("end".to_string());
    lines.push(String::new());
    lines.join("\n")
}

fn push_i18n_block(lines: &mut Vec<String>, block_name: &str, texts: &[String; 4]) {
    lines.push(format!("  {block_name}"));
    lines.push(format!("    en: {}", texts[0]));
    for (i, code) in ["fr", "es", "de"].iter().enumerate() {
        if !texts[i + 1].is_empty() {
            lines.push(format!("    {code}: {}", texts[i + 1]));
        }
    }
    lines.push("  end".to_string());
    lines.push(String::new());
}

// ---------------------------------------------------------------------
// Main wizard — ported from run_wizard
// ---------------------------------------------------------------------

/// Roots needed by the wizard (custom-rules/builtin directories,
/// distinct from `ScanConfig::rules_dir` which points to one or
/// the other depending on the call).
pub struct WizardPaths<'a> {
    pub custom_rules_dir: &'a Path,
    pub builtin_rules_dir: &'a Path,
}

/// Runs the interactive wizard end to end — ported from
/// `run_wizard`. Returns the path of the written file, or `None` if
/// cancelled by the user or by a DSL validation error.
pub fn run_wizard<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    script_locale: &Value,
    paths: &WizardPaths,
) -> io::Result<Option<PathBuf>> {
    writeln!(writer, "\n  {}", t(script_locale, "wizard_title"))?;
    writeln!(writer, "  {}", "=".repeat(48))?;

    let mut defaults = RuleFormData::defaults();
    let mut edit_mode = false;
    let mut existing_path: Option<PathBuf> = None;

    // --- STEP 1: name -------------------------------------------------
    section(writer, &format!("1 — {}", t(script_locale, "wizard_name")))?;
    let name = loop {
        let candidate = prompt(reader, writer, &t(script_locale, "wizard_name"), "")?;
        if candidate.is_empty() {
            continue;
        }
        let valid_name = fancy_regex::Regex::new(r"^[a-z][a-z0-9_]*$")
            .unwrap()
            .is_match(&candidate)
            .unwrap_or(false);
        if !valid_name {
            writeln!(
                writer,
                "    {} : '{candidate}'",
                t(script_locale, "wizard_invalid_id")
            )?;
            writeln!(writer, "    {}", t(script_locale, "wizard_id_format"))?;
            continue;
        }

        if let Some(builtin_path) = check_builtin_duplicate(paths.builtin_rules_dir, &candidate) {
            writeln!(
                writer,
                "    {} : {builtin_path}",
                t(script_locale, "wiz_rule_exists_builtin")
            )?;
            writeln!(writer, "    {}", t(script_locale, "wiz_rule_exists_hint"))?;
            continue;
        }

        if let Some(existing) = find_existing_rule(paths.custom_rules_dir, &candidate) {
            writeln!(
                writer,
                "\n    {} : {}",
                t(script_locale, "wizard_rule_exists_custom"),
                existing.display()
            )?;
            if prompt_yes_no(
                reader,
                writer,
                &t(script_locale, "wizard_edit_existing"),
                true,
            )? {
                defaults = load_existing_rule(&existing);
                edit_mode = true;
                existing_path = Some(existing);
            }
        }
        break candidate;
    };

    let default_lang_idx = LANGUAGES
        .iter()
        .position(|(v, _)| *v == defaults.lang)
        .unwrap_or(0);
    let language = prompt_choice(
        reader,
        writer,
        script_locale,
        &t(script_locale, "wizard_language"),
        &LANGUAGES,
        default_lang_idx,
    )?;

    let default_cat_idx = CATEGORIES
        .iter()
        .position(|(v, _)| *v == defaults.cat)
        .unwrap_or(0);
    let category = prompt_choice(
        reader,
        writer,
        script_locale,
        &t(script_locale, "wizard_category"),
        &CATEGORIES,
        default_cat_idx,
    )?;

    let default_sev_idx = SEVERITIES
        .iter()
        .position(|(v, _)| *v == defaults.sev)
        .unwrap_or(0);
    let severity = prompt_choice(
        reader,
        writer,
        script_locale,
        &t(script_locale, "wizard_severity"),
        &SEVERITIES,
        default_sev_idx,
    )?;

    // --- STEP 2: detection ---------------------------------------------
    section(
        writer,
        &format!("2 — {}", t(script_locale, "wizard_step_pattern")),
    )?;
    let pattern = loop {
        let candidate = prompt(
            reader,
            writer,
            &t(script_locale, "wizard_pattern_prompt"),
            &defaults.pattern,
        )?;
        if candidate.is_empty() {
            writeln!(
                writer,
                "    {}",
                t(script_locale, "wizard_pattern_required")
            )?;
            continue;
        }
        break candidate;
    };

    let dupes = check_custom_pattern_duplicate(
        paths.custom_rules_dir,
        &pattern,
        &language,
        if edit_mode { &name } else { "" },
    );
    if !dupes.is_empty() {
        writeln!(
            writer,
            "\n    {}",
            t(script_locale, "wiz_pattern_duplicate_warning")
        )?;
        for d in &dupes {
            writeln!(writer, "      → {}  ({})", d.id, d.path)?;
        }
        if !prompt_yes_no(
            reader,
            writer,
            &t(script_locale, "wiz_overlap_continue"),
            false,
        )? {
            return Ok(None);
        }
    }

    let neutralizer = prompt(
        reader,
        writer,
        &t(script_locale, "wizard_neutralizer_prompt"),
        &defaults.neutralizer,
    )?;

    // --- STEP 3: risk -------------------------------------------------
    section(
        writer,
        &format!("3 — {}", t(script_locale, "wizard_step_risk")),
    )?;
    let mut risk = [String::new(), String::new(), String::new(), String::new()];
    loop {
        risk[0] = prompt(
            reader,
            writer,
            &t(script_locale, "wizard_risk_en"),
            &defaults.risk[0],
        )?;
        if risk[0].is_empty() {
            writeln!(writer, "    {}", t(script_locale, "wizard_field_required"))?;
            continue;
        }
        break;
    }
    risk[1] = prompt(
        reader,
        writer,
        &t(script_locale, "wizard_risk_fr"),
        &defaults.risk[1],
    )?;
    risk[2] = prompt(
        reader,
        writer,
        &t(script_locale, "wizard_risk_es"),
        &defaults.risk[2],
    )?;
    risk[3] = prompt(
        reader,
        writer,
        &t(script_locale, "wizard_risk_de"),
        &defaults.risk[3],
    )?;

    // --- STEP 4: solution -----------------------------------------------
    section(
        writer,
        &format!("4 — {}", t(script_locale, "wizard_step_solution")),
    )?;
    let mut solution = [String::new(), String::new(), String::new(), String::new()];
    loop {
        solution[0] = prompt(
            reader,
            writer,
            &t(script_locale, "wizard_solution_en"),
            &defaults.solution[0],
        )?;
        if solution[0].is_empty() {
            writeln!(writer, "    {}", t(script_locale, "wizard_field_required"))?;
            continue;
        }
        break;
    }
    solution[1] = prompt(
        reader,
        writer,
        &t(script_locale, "wizard_solution_fr"),
        &defaults.solution[1],
    )?;
    solution[2] = prompt(
        reader,
        writer,
        &t(script_locale, "wizard_solution_es"),
        &defaults.solution[2],
    )?;
    solution[3] = prompt(
        reader,
        writer,
        &t(script_locale, "wizard_solution_de"),
        &defaults.solution[3],
    )?;

    // --- STEP 5: benefit (optional) ------------------------------------
    section(
        writer,
        &format!("5 — {}", t(script_locale, "wizard_step_benefit")),
    )?;
    let mut benefit = [String::new(), String::new(), String::new(), String::new()];
    benefit[0] = prompt(
        reader,
        writer,
        &t(script_locale, "wizard_benefit_en"),
        &defaults.benefit[0],
    )?;
    if !benefit[0].is_empty() {
        benefit[1] = prompt(
            reader,
            writer,
            &t(script_locale, "wizard_benefit_fr"),
            &defaults.benefit[1],
        )?;
        benefit[2] = prompt(
            reader,
            writer,
            &t(script_locale, "wizard_benefit_es"),
            &defaults.benefit[2],
        )?;
        benefit[3] = prompt(
            reader,
            writer,
            &t(script_locale, "wizard_benefit_de"),
            &defaults.benefit[3],
        )?;
    }

    // --- STEP 6: fix example (optional) ------------------------
    section(
        writer,
        &format!("6 — {}", t(script_locale, "wizard_step_fix")),
    )?;
    let fix_before = prompt(
        reader,
        writer,
        &t(script_locale, "wizard_fix_before_prompt"),
        &defaults.fix_before,
    )?;
    let fix_after = if !fix_before.is_empty() {
        prompt(
            reader,
            writer,
            &t(script_locale, "wizard_fix_after_prompt"),
            &defaults.fix_after,
        )?
    } else {
        String::new()
    };

    // --- STEP 7: generation + preview + confirmation + validation + writing
    let sca_content = build_sca_content(
        &name,
        &language,
        &category,
        &severity,
        &pattern,
        &neutralizer,
        &risk,
        &solution,
        &benefit,
        &fix_before,
        &fix_after,
    );

    writeln!(writer, "\n  {}\n", t(script_locale, "wizard_old_preview"))?;
    for line in sca_content.trim().lines() {
        writeln!(writer, "    {line}")?;
    }
    writeln!(writer)?;

    let confirm_key = if edit_mode {
        "wizard_update_confirm"
    } else {
        "wizard_old_create_confirm"
    };
    if !prompt_yes_no(reader, writer, &t(script_locale, confirm_key), true)? {
        writeln!(writer, "  {}", t(script_locale, "wizard_old_cancelled"))?;
        return Ok(None);
    }

    if compile_sca_to_json(&sca_content, &format!("{name}.sca")).is_err() {
        writeln!(writer, "\n  {}", t(script_locale, "wizard_old_errors"))?;
        writeln!(writer, "  {}", t(script_locale, "wizard_old_cancelled"))?;
        return Ok(None);
    }

    let target_file = if edit_mode {
        existing_path.expect("existing_path défini quand edit_mode est vrai")
    } else {
        let target_dir = paths.custom_rules_dir.join(&language).join(&category);
        std::fs::create_dir_all(&target_dir)?;
        target_dir.join(format!("{name}.sca"))
    };
    std::fs::write(&target_file, &sca_content)?;

    let result_key = if edit_mode {
        "wizard_updated"
    } else {
        "wizard_old_created"
    };
    writeln!(
        writer,
        "\n  {} : {}",
        t(script_locale, result_key),
        target_file.display()
    )?;

    Ok(Some(target_file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_script_locale;
    use std::io::Cursor;

    fn tmp_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("auditrust-wizard-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_build_sca_content_minimal() {
        let risk = [
            "Risque".to_string(),
            String::new(),
            String::new(),
            String::new(),
        ];
        let solution = [
            "Solution".to_string(),
            String::new(),
            String::new(),
            String::new(),
        ];
        let benefit = [String::new(), String::new(), String::new(), String::new()];
        let content = build_sca_content(
            "my_rule", "python", "security", "HIGH", "eval\\(", "", &risk, &solution, &benefit, "",
            "",
        );
        assert!(content.contains("rule my_rule"));
        assert!(content.contains("language  python"));
        assert!(content.contains("text  eval\\("));
        assert!(content.contains("en: Risque"));
        assert!(!content.contains("benefit")); // benefit empty -> block absent
        assert!(content.trim_end().ends_with("end"));
    }

    #[test]
    fn test_build_sca_content_with_fix_example() {
        let risk = ["R".to_string(), String::new(), String::new(), String::new()];
        let solution = ["S".to_string(), String::new(), String::new(), String::new()];
        let benefit = [String::new(), String::new(), String::new(), String::new()];
        let content = build_sca_content(
            "r",
            "python",
            "security",
            "HIGH",
            "p",
            "",
            &risk,
            &solution,
            &benefit,
            "eval(x)",
            "ast.literal_eval(x)",
        );
        assert!(content.contains("fix_before"));
        assert!(content.contains("eval(x)"));
        assert!(content.contains("ast.literal_eval(x)"));
    }

    #[test]
    fn test_load_existing_rule_roundtrip() {
        let dir = tmp_dir("load");
        let path = dir.join("my_rule.sca");
        let risk = [
            "Risk EN".to_string(),
            "Risque FR".to_string(),
            String::new(),
            String::new(),
        ];
        let solution = [
            "Sol EN".to_string(),
            String::new(),
            String::new(),
            String::new(),
        ];
        let benefit = [String::new(), String::new(), String::new(), String::new()];
        let content = build_sca_content(
            "my_rule", "java", "arch", "MEDIUM", "foo\\(", "bar", &risk, &solution, &benefit, "",
            "",
        );
        std::fs::write(&path, &content).unwrap();

        let data = load_existing_rule(&path);
        assert_eq!(data.lang, "java");
        assert_eq!(data.cat, "arch");
        assert_eq!(data.sev, "MEDIUM");
        assert_eq!(data.pattern, "foo\\(");
        assert_eq!(data.neutralizer, "bar");
        assert_eq!(data.risk[0], "Risk EN");
        assert_eq!(data.risk[1], "Risque FR");
        assert_eq!(data.solution[0], "Sol EN");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_find_existing_rule_by_stem() {
        let dir = tmp_dir("find");
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        std::fs::write(
            dir.join("python/security/my_rule.sca"),
            "rule my_rule\nend\n",
        )
        .unwrap();
        let found = find_existing_rule(&dir, "my_rule");
        assert!(found.is_some());
        assert!(find_existing_rule(&dir, "does_not_exist").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_check_builtin_duplicate_detects_existing_id() {
        let dir = tmp_dir("builtin");
        std::fs::write(
            dir.join("existing.sca"),
            "rule existing_rule\n  language python\n  category security\n  severity HIGH\n  match\n    text foo\n  end\n  risk\n    en: r\n  end\n  solution\n    en: s\n  end\nend\n",
        )
        .unwrap();
        let found = check_builtin_duplicate(&dir, "existing_rule");
        assert!(found.is_some());
        assert!(check_builtin_duplicate(&dir, "nonexistent_rule").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_run_wizard_end_to_end_creates_rule() {
        let custom_dir = tmp_dir("run-custom");
        let builtin_dir = tmp_dir("run-builtin");
        let en = load_script_locale("en");
        let paths = WizardPaths {
            custom_rules_dir: &custom_dir,
            builtin_rules_dir: &builtin_dir,
        };

        // Name, language(default), category(default), severity(default),
        // pattern, neutralizer(empty), risk EN, risk FR/ES/DE(empty),
        // solution EN, solution FR/ES/DE(empty), benefit EN(empty),
        // fix_before(empty), write confirmation (yes by default).
        let input = "detect_eval\n\n\n\n\\beval\\(\n\n\
Dangerous eval() call\n\n\n\n\
Use ast.literal_eval instead\n\n\n\n\n\n\n";
        let mut reader = Cursor::new(input.as_bytes());
        let mut output: Vec<u8> = Vec::new();

        let result = run_wizard(&mut reader, &mut output, &en, &paths).unwrap();
        assert!(result.is_some());
        let path = result.unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("rule detect_eval"));
        assert!(content.contains("Dangerous eval() call"));

        std::fs::remove_dir_all(&custom_dir).ok();
        std::fs::remove_dir_all(&builtin_dir).ok();
    }

    #[test]
    fn test_run_wizard_refuses_invalid_name_then_accepts() {
        let custom_dir = tmp_dir("run-invalid-custom");
        let builtin_dir = tmp_dir("run-invalid-builtin");
        let en = load_script_locale("en");
        let paths = WizardPaths {
            custom_rules_dir: &custom_dir,
            builtin_rules_dir: &builtin_dir,
        };

        // Invalid name (uppercase) then valid name, then abort at the
        // final confirmation (minimal pattern required to get there).
        let input =
            "InvalidName\nvalid_name\n\n\n\n\\bfoo\\(\n\nRisk\n\n\n\nSolution\n\n\n\n\n\nn\n";
        let mut reader = Cursor::new(input.as_bytes());
        let mut output: Vec<u8> = Vec::new();

        let result = run_wizard(&mut reader, &mut output, &en, &paths).unwrap();
        assert!(result.is_none()); // cancelled at confirmation
        let out_str = String::from_utf8_lossy(&output);
        assert!(out_str.contains(&t(&en, "wizard_invalid_id")));
        assert!(out_str.contains(&t(&en, "wizard_old_cancelled")));
        // No file written: the final confirmation was refused.
        assert!(!custom_dir.join("python/security/valid_name.sca").exists());

        std::fs::remove_dir_all(&custom_dir).ok();
        std::fs::remove_dir_all(&builtin_dir).ok();
    }
}
