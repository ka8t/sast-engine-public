//! Semantic validator for `.sca` rules — faithful port of
//! `Audit/sca/dsl/validator.py`.

use super::compiler::text_to_regex;
use super::model::{MatchBlock, RuleNode};

pub const VALID_LANGUAGES: &[&str] = &[
    "python",
    "javascript",
    "java",
    "csharp",
    "php",
    "yaml",
    "html",
    "dockerfile",
];
pub const VALID_CATEGORIES: &[&str] = &[
    "security",
    "arch",
    "ui",
    "ux",
    "maintenance",
    "cicd",
    "database",
    "dependencies",
];
pub const VALID_SEVERITIES: &[&str] = &["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
pub const VALID_MODES_DSL: &[&str] = &[
    "regex",
    "taint",
    "regex+taint",
    "ast",
    "file_contains",
    "python_hook",
];
pub const VALID_SOURCE_KINDS: &[&str] = &["http", "cli", "env", "stdin", "file", "network"];
pub const VALID_TIERS: &[&str] = &["demo", "solo", "team", "enterprise"];

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

pub fn validate_rule(node: &RuleNode) -> Vec<String> {
    let mut errors = Vec::new();

    if node.id.is_empty() {
        errors.push("Identifiant de regle manquant".to_string());
    } else if !valid_id(&node.id) {
        errors.push(format!(
            "Identifiant invalide : '{}' (attendu : [a-z0-9_]+)",
            node.id
        ));
    }

    if node.language.is_empty() {
        errors.push("Langage manquant".to_string());
    } else if !VALID_LANGUAGES.contains(&node.language.as_str()) {
        errors.push(format!("Langage inconnu : '{}'", node.language));
    }

    if !node.category.is_empty() && !VALID_CATEGORIES.contains(&node.category.as_str()) {
        errors.push(format!("Categorie inconnue : '{}'", node.category));
    }

    if node.severity.is_empty() {
        errors.push("Severite manquante".to_string());
    } else if !VALID_SEVERITIES.contains(&node.severity.as_str()) {
        errors.push(format!("Severite inconnue : '{}'", node.severity));
    }

    if !node.mode.is_empty() && !VALID_MODES_DSL.contains(&node.mode.as_str()) {
        errors.push(format!("Mode inconnu : '{}'", node.mode));
    }

    if !(0..=100).contains(&node.confidence) {
        errors.push(format!(
            "Confidence hors plage : {} (attendu : 0-100)",
            node.confidence
        ));
    }

    if !node.mode.is_empty() {
        let mode = node.mode.as_str();
        if (mode == "regex" || mode == "regex+taint") && node.match_blocks.is_empty() {
            errors.push(format!("Mode '{mode}' requiert au moins un bloc 'match'"));
        }
        if mode == "taint" || mode == "regex+taint" {
            if node.sources.is_empty() {
                errors.push(format!("Mode '{mode}' requiert au moins une source"));
            }
            if node.sinks.is_empty() {
                errors.push(format!("Mode '{mode}' requiert au moins un sink"));
            }
        }
        if mode == "ast" && node.match_blocks.is_empty() {
            errors.push("Mode 'ast' requiert un bloc 'match ast'".to_string());
        }
        if mode == "file_contains"
            && node.match_blocks.is_empty()
            && node.file_conditions.is_empty()
        {
            errors.push(
                "Mode 'file_contains' requiert un bloc 'match file_contains' ou 'requires' (has/not_has)"
                    .to_string(),
            );
        }
        if mode == "python_hook" && node.hook.is_empty() {
            errors.push("Mode 'python_hook' requiert un 'hook'".to_string());
        }
    } else {
        let has_content = !node.match_blocks.is_empty()
            || !node.file_conditions.is_empty()
            || !node.sources.is_empty()
            || !node.sinks.is_empty()
            || !node.hook.is_empty();
        if !has_content {
            errors.push(
                "La regle doit contenir au moins un bloc 'match', 'requires' (has/not_has), 'taint', ou 'hook'"
                    .to_string(),
            );
        }
    }

    validate_regex_blocks(node, &mut errors);
    validate_file_conditions(node, &mut errors);
    validate_taint_patterns(node, &mut errors);

    if !VALID_TIERS.contains(&node.license.min_tier.as_str()) {
        errors.push(format!("Tier inconnu : '{}'", node.license.min_tier));
    }

    for src in &node.sources {
        if !VALID_SOURCE_KINDS.contains(&src.kind.as_str()) {
            errors.push(format!("Kind de source inconnu : '{}'", src.kind));
        }
    }

    errors
}

fn validate_regex_blocks(node: &RuleNode, errors: &mut Vec<String>) {
    for block in &node.match_blocks {
        match block {
            MatchBlock::Regex(b) => {
                let pat = if b.is_text {
                    text_to_regex(&b.pattern)
                } else {
                    b.pattern.clone()
                };
                try_compile(&pat, if b.is_text { "text" } else { "pattern" }, errors);

                let wp = if b.with_is_text {
                    text_to_regex(&b.with_pattern)
                } else {
                    b.with_pattern.clone()
                };
                try_compile(&wp, "with", errors);

                let np = if b.pattern_not_is_text {
                    text_to_regex(&b.pattern_not)
                } else {
                    b.pattern_not.clone()
                };
                try_compile(
                    &np,
                    if b.pattern_not_is_text {
                        "text-not"
                    } else {
                        "pattern-not"
                    },
                    errors,
                );

                try_compile(&b.pattern_inside, "pattern-inside", errors);
                try_compile(&b.pattern_not_inside, "pattern-not-inside", errors);
            }
            MatchBlock::FileContains(b) => {
                for p in &b.has_patterns {
                    try_compile(p, "has", errors);
                }
                for p in &b.not_has_patterns {
                    try_compile(p, "not_has", errors);
                }
            }
            MatchBlock::Ast(_) => {}
        }
    }
}

fn validate_file_conditions(node: &RuleNode, errors: &mut Vec<String>) {
    for fc in &node.file_conditions {
        for p in &fc.has_patterns {
            try_compile(p, "requires has", errors);
        }
        for p in &fc.not_has_patterns {
            try_compile(p, "requires not_has", errors);
        }
    }
}

fn validate_taint_patterns(node: &RuleNode, errors: &mut Vec<String>) {
    for src in &node.sources {
        try_compile(&src.pattern, "source", errors);
    }
    for snk in &node.sinks {
        try_compile(&snk.pattern, "sink", errors);
    }
    for san in &node.sanitizers {
        try_compile(&san.pattern, "sanitizer", errors);
    }
}

/// Compiles via `fancy-regex`, not `regex`: a large share of real
/// rules use lookahead/lookbehind/backreferences (supported by
/// Python's `re`, not by the standard `regex` crate) — confirmed
/// empirically against the corpus of 703 builtin rules (Decision #2),
/// where `regex` wrongly rejected ~30 rules.
fn try_compile(pattern: &str, field_name: &str, errors: &mut Vec<String>) {
    if pattern.is_empty() {
        return;
    }
    if let Err(e) = fancy_regex::Regex::new(pattern) {
        errors.push(format!("Regex invalide dans {field_name} : {e}"));
    }
}
