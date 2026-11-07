//! Regex executor — faithful port of `Audit/sca/executors/regex.py`.
//!
//! Input contract for `all_lines`: each `(number, text)` must
//! carry the **raw text with its original line terminator
//! included** (equivalent of Python's `readlines()`), not un-terminated
//! text (`str::lines()` strips it). Computing line positions
//! for the `context-N` scope depends on counting the `\n` in the
//! reassembled text — losing the terminators would desynchronize the
//! line numbers.

use super::Finding;
use fancy_regex::Regex;
use std::collections::BTreeMap;

/// A rule whose pattern (as well as `with`/`pattern-not`) is already
/// compiled — mirrors `_compile_rule_patterns` (rule_loader.py) for
/// the `patterns[]` subset (regex/regex+taint mode). Sources/
/// sinks/sanitizers (taint) and `file_contains` are out of scope for
/// this module.
pub struct CompiledRegexRule {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub confidence: i64,
    pub language: String,
    pub patterns: Vec<CompiledPattern>,
}

pub struct CompiledPattern {
    pub match_scope: String,
    pub compiled: Regex,
    pub compiled_with: Option<Regex>,
    pub compiled_pattern_not: Option<Regex>,
}

/// Rules whose `pattern-not`/`with` legitimately depends on the comment
/// syntax itself (the safe case *is* a comment) — cf. the
/// comment on `_COMMENT_STRIP_EXEMPT_RULES` on the Python side: an
/// explicit set rather than a new DSL flag, since only one rule
/// needs it today.
const COMMENT_STRIP_EXEMPT_RULES: &[&str] = &["gha_version_comment_missing"];

fn line_comment_marker(language: &str) -> Option<&'static str> {
    match language {
        "python" | "yaml" | "dockerfile" => Some("#"),
        "javascript" | "java" | "csharp" | "php" => Some("//"),
        _ => None,
    }
}

fn block_comment_delims(language: &str) -> Option<(&'static str, &'static str)> {
    match language {
        "javascript" | "java" | "csharp" | "php" => Some(("/*", "*/")),
        "html" => Some(("<!--", "-->")),
        _ => None,
    }
}

/// Strips comment content (for the `pattern-not`/`with` checks
/// only — the main `pattern` search and the reported code fragment
/// always use the original, uncleaned `all_lines`: some rules,
/// like `todo_unresolved`, deliberately search *inside* comments).
pub fn strip_comments_from_lines(
    all_lines: &[(usize, String)],
    language: &str,
) -> Vec<(usize, String)> {
    let stripped_texts: Vec<String> = if let Some((open, close)) = block_comment_delims(language) {
        let full_text: String = all_lines.iter().map(|(_, t)| t.as_str()).collect();
        let stripped_full = strip_block_comments(&full_text, open, close);
        stripped_full.split('\n').map(|s| s.to_string()).collect()
    } else {
        all_lines.iter().map(|(_, t)| t.clone()).collect()
    };

    let final_texts: Vec<String> = if let Some(marker) = line_comment_marker(language) {
        stripped_texts
            .iter()
            .map(|t| strip_line_comment(t, marker))
            .collect()
    } else {
        stripped_texts
    };

    // If stripping block comments re-split the text, the
    // line count may differ from the original line count
    // (a block spanning multiple lines is replaced by the same
    // number of '\n' — cf. strip_block_comments — so in theory the
    // count stays identical; we bound it as a safety net).
    all_lines
        .iter()
        .zip(final_texts.iter().chain(std::iter::repeat(&String::new())))
        .map(|((num, _), text)| (*num, text.clone()))
        .collect()
}

/// Strips `open...close` block comments (non-greedy, like
/// `open.*?close` with DOTALL in Python), replaced by as many `\n`
/// as the removed fragment contained — preserves the alignment of
/// line numbers for everything that follows.
fn strip_block_comments(text: &str, open: &str, close: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        match rest.find(open) {
            Some(start) => {
                result.push_str(&rest[..start]);
                let after_open = &rest[start..];
                match after_open.find(close) {
                    Some(end_rel) => {
                        let matched = &after_open[..end_rel + close.len()];
                        let newlines = matched.matches('\n').count();
                        result.push_str(&"\n".repeat(newlines));
                        rest = &after_open[end_rel + close.len()..];
                    }
                    None => {
                        // No closing delimiter: like the Python regex
                        // (`.*?close`), this fragment never matches —
                        // left as-is.
                        result.push_str(after_open);
                        return result;
                    }
                }
            }
            None => {
                result.push_str(rest);
                return result;
            }
        }
    }
}

/// Strips `marker` and everything after it on the line, preserving a
/// trailing `\n` if present (equivalent of `re.sub(f"{marker}.*$", "", text)`
/// without `DOTALL`: `.` doesn't consume the terminal `\n`).
fn strip_line_comment(text: &str, marker: &str) -> String {
    match text.find(marker) {
        Some(pos) => {
            let mut result = text[..pos].to_string();
            if text.ends_with('\n') {
                result.push('\n');
            }
            result
        }
        None => text.to_string(),
    }
}

fn is_match(re: &Regex, text: &str) -> bool {
    re.is_match(text).unwrap_or(false)
}

/// Executes a regex rule against a file — one finding per
/// match. Mirrors `execute()` (regex.py).
pub fn execute_regex_rule(rule: &CompiledRegexRule, all_lines: &[(usize, String)]) -> Vec<Finding> {
    if rule.patterns.is_empty() || all_lines.is_empty() {
        return Vec::new();
    }

    let clean_lines = if COMMENT_STRIP_EXEMPT_RULES.contains(&rule.id.as_str()) {
        all_lines.to_vec()
    } else {
        strip_comments_from_lines(all_lines, &rule.language)
    };

    let negative_patterns: Vec<&Regex> = rule
        .patterns
        .iter()
        .filter_map(|p| p.compiled_pattern_not.as_ref())
        .collect();

    let mut candidates: BTreeMap<usize, String> = BTreeMap::new();

    for p in &rule.patterns {
        if p.match_scope == "file" {
            // Python also computes `full_content` (same construction) but
            // never uses it — the main pattern is matched line
            // by line (loop below), not against the whole text.
            // Dead code on the Python side, not reproduced here.
            let clean_content: String = clean_lines
                .iter()
                .map(|(_, l)| l.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if let Some(neg) = &p.compiled_pattern_not
                && is_match(neg, &clean_content)
            {
                continue;
            }
            if let Some(with) = &p.compiled_with
                && !is_match(with, &clean_content)
            {
                continue;
            }
            for (line_num, line) in all_lines {
                if is_match(&p.compiled, line) {
                    candidates.insert(*line_num, clean_content.clone());
                }
            }
        } else if p.match_scope == "line" {
            for ((line_num, line), (_, clean_line)) in all_lines.iter().zip(clean_lines.iter()) {
                if is_match(&p.compiled, line) {
                    if let Some(with) = &p.compiled_with
                        && !is_match(with, clean_line)
                    {
                        continue;
                    }
                    candidates.insert(*line_num, clean_line.clone());
                }
            }
        } else if let Some(window_str) = p.match_scope.strip_prefix("context-") {
            let window: usize = window_str.parse().unwrap_or(6);
            let n_lines = all_lines.len();
            let first_line_num = all_lines[0].0;

            for start_idx in 0..n_lines {
                let block_end = (start_idx + window).min(n_lines);
                let block_text: String = all_lines[start_idx..block_end]
                    .iter()
                    .map(|(_, l)| l.as_str())
                    .collect();
                if block_text.is_empty() {
                    continue;
                }

                let m = match p.compiled.find(&block_text) {
                    Ok(Some(m)) => m,
                    _ => continue,
                };

                let clean_block_text: String = clean_lines[start_idx..block_end]
                    .iter()
                    .map(|(_, l)| l.as_str())
                    .collect();
                if let Some(with) = &p.compiled_with
                    && !is_match(with, &clean_block_text)
                {
                    continue;
                }

                let local_start = m.start();
                let newlines_before = block_text[..local_start].matches('\n').count();
                let start_line = all_lines[start_idx].0 + newlines_before;

                // block_text only extends forward from
                // start_idx: pattern-not could never see a
                // guard/sanitizer declared on an earlier line.
                // Purely additive addition of a backward window (up to
                // `window` lines before the match line) — the forward
                // scope is unchanged, the backward scope becomes
                // available for pattern-not.
                let match_idx = start_line.saturating_sub(first_line_num);
                let back_start = match_idx.saturating_sub(window);
                let clean_backward_text: String = clean_lines[back_start..match_idx]
                    .iter()
                    .map(|(_, l)| l.as_str())
                    .collect();

                candidates.insert(
                    start_line,
                    format!("{clean_backward_text}{clean_block_text}"),
                );
            }
        }
    }

    if candidates.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let n_lines = all_lines.len();
    for (&line_num, context_text) in &candidates {
        if line_num < 1 || line_num > n_lines {
            continue;
        }
        if negative_patterns
            .iter()
            .any(|neg| is_match(neg, context_text))
        {
            continue;
        }
        let line_text = &all_lines[line_num - 1].1;
        findings.push(Finding {
            rule_id: rule.id.clone(),
            category: rule.category.to_uppercase(),
            severity: rule.severity.clone(),
            line: line_num,
            code: line_text.clone(),
            confidence: rule.confidence,
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(texts: &[&str]) -> Vec<(usize, String)> {
        texts
            .iter()
            .enumerate()
            .map(|(i, t)| (i + 1, format!("{t}\n")))
            .collect()
    }

    fn simple_rule(pattern: &str, scope: &str) -> CompiledRegexRule {
        CompiledRegexRule {
            id: "test_rule".to_string(),
            category: "security".to_string(),
            severity: "HIGH".to_string(),
            confidence: 80,
            language: "python".to_string(),
            patterns: vec![CompiledPattern {
                match_scope: scope.to_string(),
                compiled: Regex::new(pattern).unwrap(),
                compiled_with: None,
                compiled_pattern_not: None,
            }],
        }
    }

    #[test]
    fn test_line_scope_basic_match() {
        let rule = simple_rule(r"eval\(", "line");
        let all_lines = lines(&["x = 1", "eval(user_input)", "y = 2"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn test_line_scope_with_condition_filters() {
        let mut rule = simple_rule(r"password\s*=", "line");
        rule.patterns[0].compiled_with = Some(Regex::new(r#""[^"]{8,}""#).unwrap());
        let all_lines = lines(&["password = short", r#"password = "longenoughvalue""#]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn test_pattern_not_suppresses_finding() {
        // "safe" in real code (not inside a Python "#" comment, which
        // would be stripped before the pattern-not check — cf.
        // test_comment_stripped_before_pattern_not_check).
        let mut rule = simple_rule(r"\.execute\(", "line");
        rule.patterns[0].compiled_pattern_not = Some(Regex::new(r"parameterized").unwrap());
        let all_lines = lines(&["cursor.execute(parameterized_query)"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_comment_stripped_before_pattern_not_check() {
        // The pattern-not trigger word is inside a comment —
        // must NOT suppress the finding (comment stripping
        // applies to pattern-not, so the word disappears there).
        let mut rule = simple_rule(r"eval\(", "line");
        rule.patterns[0].compiled_pattern_not = Some(Regex::new(r"safe_context").unwrap());
        let all_lines = lines(&["eval(x)  # safe_context supposedly"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_file_scope_pattern_not_skips_whole_pattern() {
        // "ALLOW_TODO" in real code, not inside a Python "#" comment
        // (which would be stripped before the pattern-not check).
        let mut rule = simple_rule(r"TODO", "file");
        rule.patterns[0].compiled_pattern_not = Some(Regex::new(r"ALLOW_TODO").unwrap());
        let all_lines = lines(&["ALLOW_TODO = True", "x = 1  # TODO fix this"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_context_scope_multiline_match() {
        let rule = simple_rule(r"(?s)open\(.*?\).*?without_close", "context-6");
        let all_lines = lines(&["x = 1", "open(f)", "do_stuff()", "without_close()"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn test_no_patterns_no_findings() {
        let rule = CompiledRegexRule {
            id: "empty".to_string(),
            category: "security".to_string(),
            severity: "LOW".to_string(),
            confidence: 80,
            language: "python".to_string(),
            patterns: vec![],
        };
        let all_lines = lines(&["anything"]);
        assert!(execute_regex_rule(&rule, &all_lines).is_empty());
    }

    #[test]
    fn test_strip_block_comment_preserves_line_alignment() {
        let all_lines = lines(&["a", "/* comment", "spanning */ b", "c"]);
        let clean = strip_comments_from_lines(&all_lines, "javascript");
        assert_eq!(clean.len(), 4);
        assert_eq!(clean[3].0, 4); // the last line's number stays correct
    }

    #[test]
    fn test_strip_line_comment_preserves_trailing_newline() {
        let stripped = strip_line_comment("foo # bar\n", "#");
        assert_eq!(stripped, "foo \n");
    }

    #[test]
    fn test_exempt_rule_skips_comment_stripping() {
        let mut rule = simple_rule(r"v4", "line");
        rule.id = "gha_version_comment_missing".to_string();
        rule.patterns[0].compiled_pattern_not = Some(Regex::new(r"pinned").unwrap());
        rule.language = "yaml".to_string();
        // The "pinned" keyword is inside a YAML comment (#) — without
        // the exemption, it would be stripped by the cleanup and
        // wouldn't suppress the finding; with the exemption, it stays
        // visible and suppresses the finding.
        let all_lines = lines(&["uses: action@v4  # pinned"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert!(findings.is_empty());
    }
}
