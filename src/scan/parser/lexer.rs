//! Lexer for the `.sca` DSL — faithful port of `Audit/sca/dsl/lexer.py`.
//!
//! Line-by-line tokenization: handles comments (#), quoted
//! strings, key=value pairs and raw words
//! (regex, identifiers, numbers). See the original Python docstring
//! for the full strategy — reproduced here line for line.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Word,
    String,
    Number,
    Kv,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenType,
    pub value: String,
    pub line: usize,
    pub col: usize,
    pub kv_key: String,
    pub kv_val: String,
}

impl Token {
    fn simple(kind: TokenType, value: impl Into<String>, line: usize, col: usize) -> Self {
        Token {
            kind,
            value: value.into(),
            line,
            col,
            kv_key: String::new(),
            kv_val: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub number: usize,
    pub indent: usize,
    pub tokens: Vec<Token>,
    pub raw_content: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DslSyntaxError {
    pub message: String,
    pub line: usize,
    pub col: usize,
    pub filename: String,
}

impl fmt::Display for DslSyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut loc = String::new();
        if !self.filename.is_empty() {
            loc.push_str(&self.filename);
            loc.push(':');
        }
        if self.line != 0 {
            loc.push_str(&self.line.to_string());
        }
        if self.col != 0 {
            loc.push(':');
            loc.push_str(&self.col.to_string());
        }
        if loc.is_empty() {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{}: {}", loc, self.message)
        }
    }
}

impl std::error::Error for DslSyntaxError {}

impl DslSyntaxError {
    pub fn new(message: impl Into<String>, line: usize, filename: &str) -> Self {
        DslSyntaxError {
            message: message.into(),
            line,
            col: 0,
            filename: filename.to_string(),
        }
    }
}

/// Reproduces `_KV_PATTERN = re.compile(r'^([a-z_][a-z0-9_]*)=(\S+)$')`
/// without a regex dependency (the pattern is simple, a manual
/// state machine is faster and avoids compiling a Regex per call).
fn match_kv(word: &str) -> Option<(String, String)> {
    let bytes = word.as_bytes();
    let eq_pos = word.find('=')?;
    if eq_pos == 0 {
        return None;
    }
    let key = &word[..eq_pos];
    let val = &word[eq_pos + 1..];
    if val.is_empty() || val.contains(char::is_whitespace) {
        return None;
    }
    let mut chars = key.chars();
    let first = chars.next()?;
    if !(first == '_' || first.is_ascii_lowercase()) {
        return None;
    }
    for c in chars {
        if !(c == '_' || c.is_ascii_lowercase() || c.is_ascii_digit()) {
            return None;
        }
    }
    let _ = bytes; // clarifies intent: we did work on ASCII-safe bytes via `word`
    Some((key.to_string(), val.to_string()))
}

pub struct DslLexer<'a> {
    filename: &'a str,
    raw_lines: Vec<&'a str>,
}

impl<'a> DslLexer<'a> {
    pub fn new(source: &'a str, filename: &'a str) -> Self {
        DslLexer {
            filename,
            raw_lines: split_lines(source),
        }
    }

    pub fn tokenize(&self) -> Vec<Line> {
        let mut result = Vec::new();
        let mut in_plaintext = false;

        for (idx, raw) in self.raw_lines.iter().enumerate() {
            let i = idx + 1;

            if in_plaintext {
                let stripped = raw.trim_end();
                let content = stripped.trim_start();
                if content.is_empty() {
                    continue;
                }
                if content == "end" {
                    in_plaintext = false;
                    result.push(Line {
                        number: i,
                        indent: stripped.len() - content.len(),
                        tokens: vec![Token::simple(TokenType::Word, "end", i, 0)],
                        raw_content: "end".to_string(),
                    });
                    continue;
                }
                let indent = stripped.len() - content.len();
                let first_word = content.split_whitespace().next().unwrap_or("");
                result.push(Line {
                    number: i,
                    indent,
                    tokens: vec![Token::simple(TokenType::Word, first_word, i, 0)],
                    raw_content: content.to_string(),
                });
                continue;
            }

            let text = strip_comment(raw);
            let stripped = text.trim_end();
            let content = stripped.trim_start();
            if content.is_empty() {
                continue;
            }

            let indent = stripped.len() - content.len();
            let tokens = tokenize_content(content, i).unwrap_or_else(|_| {
                content
                    .split_whitespace()
                    .map(|w| Token::simple(TokenType::Word, w, i, 0))
                    .collect()
            });

            if !tokens.is_empty() {
                let single_plaintext_kw = tokens.len() == 1
                    && (tokens[0].value == "fix_before" || tokens[0].value == "fix_after");
                result.push(Line {
                    number: i,
                    indent,
                    tokens,
                    raw_content: content.to_string(),
                });
                if single_plaintext_kw {
                    in_plaintext = true;
                }
            }
        }

        result
    }
}

fn split_lines(source: &str) -> Vec<&str> {
    // Equivalent of Python str.splitlines() for the usual
    // line endings (\n, \r\n) — sufficient for .sca files (text,
    // no isolated lone \r expected).
    if source.is_empty() {
        return Vec::new();
    }
    source.lines().collect()
}

/// Reproduces `_strip_comment`: `#` is a comment only at the start of
/// a line or preceded by a space, and never inside a string
/// (preserves `(#match?` in tree-sitter S-expressions).
fn strip_comment(line: &str) -> &str {
    let chars: Vec<char> = line.chars().collect();
    let mut in_string: Option<char> = None;
    let mut escape = false;

    for (i, &ch) in chars.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        if (ch == '"' || ch == '\'') && in_string.is_none() {
            in_string = Some(ch);
        } else if Some(ch) == in_string {
            in_string = None;
        } else if ch == '#' && in_string.is_none() && (i == 0 || chars[i - 1].is_whitespace()) {
            let byte_idx: usize = chars[..i].iter().map(|c| c.len_utf8()).sum();
            return &line[..byte_idx];
        }
    }
    line
}

fn tokenize_content(text: &str, line_num: usize) -> Result<Vec<Token>, DslSyntaxError> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut pos = 0usize;

    while pos < chars.len() {
        if chars[pos].is_whitespace() {
            pos += 1;
            continue;
        }
        if chars[pos] == '"' || chars[pos] == '\'' {
            let (tok, next) = read_string(&chars, pos, line_num)?;
            tokens.push(tok);
            pos = next;
        } else {
            let (tok, next) = read_word(&chars, pos, line_num);
            tokens.push(tok);
            pos = next;
        }
    }
    Ok(tokens)
}

fn read_string(
    chars: &[char],
    pos: usize,
    line_num: usize,
) -> Result<(Token, usize), DslSyntaxError> {
    let quote = chars[pos];
    let start = pos;
    let mut pos = pos + 1;
    let mut value = String::new();

    while pos < chars.len() {
        let ch = chars[pos];
        if ch == '\\' && pos + 1 < chars.len() {
            let next_ch = chars[pos + 1];
            if next_ch == quote || next_ch == '\\' {
                value.push(next_ch);
                pos += 2;
                continue;
            }
            value.push(ch);
            value.push(next_ch);
            pos += 2;
            continue;
        }
        if ch == quote {
            pos += 1;
            return Ok((
                Token::simple(TokenType::String, value, line_num, start),
                pos,
            ));
        }
        value.push(ch);
        pos += 1;
    }
    Err(DslSyntaxError::new("Chaîne non fermée", line_num, ""))
}

fn read_word(chars: &[char], pos: usize, line_num: usize) -> (Token, usize) {
    let start = pos;
    let mut pos = pos;
    while pos < chars.len() && !chars[pos].is_whitespace() {
        pos += 1;
    }
    let word: String = chars[start..pos].iter().collect();

    if let Some((key, val)) = match_kv(&word) {
        let mut tok = Token::simple(TokenType::Kv, word, line_num, start);
        tok.kv_key = key;
        tok.kv_val = val;
        return (tok, pos);
    }

    if !word.is_empty() && word.chars().all(|c| c.is_ascii_digit()) {
        return (Token::simple(TokenType::Number, word, line_num, start), pos);
    }

    (Token::simple(TokenType::Word, word, line_num, start), pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_simple_line() {
        let lexer = DslLexer::new("language  python", "<test>");
        let lines = lexer.tokenize();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].tokens.len(), 2);
        assert_eq!(lines[0].tokens[0].value, "language");
        assert_eq!(lines[0].tokens[1].value, "python");
    }

    #[test]
    fn test_tokenize_string() {
        let lexer = DslLexer::new(r#"en "Hardcoded secret detected""#, "<test>");
        let lines = lexer.tokenize();
        assert_eq!(lines[0].tokens[1].kind, TokenType::String);
        assert_eq!(lines[0].tokens[1].value, "Hardcoded secret detected");
    }

    #[test]
    fn test_tokenize_kv_pair() {
        let lexer = DslLexer::new("source foo kind=http", "<test>");
        let lines = lexer.tokenize();
        let kv = &lines[0].tokens[2];
        assert_eq!(kv.kind, TokenType::Kv);
        assert_eq!(kv.kv_key, "kind");
        assert_eq!(kv.kv_val, "http");
    }

    #[test]
    fn test_tokenize_number() {
        let lexer = DslLexer::new("confidence 90", "<test>");
        let lines = lexer.tokenize();
        assert_eq!(lines[0].tokens[1].kind, TokenType::Number);
    }

    #[test]
    fn test_tokenize_comment_stripped() {
        let lexer = DslLexer::new("language python # commentaire", "<test>");
        let lines = lexer.tokenize();
        assert_eq!(lines[0].tokens.len(), 2);
    }

    #[test]
    fn test_tokenize_comment_in_string_preserved() {
        let lexer = DslLexer::new(r#"pattern (#match? @x "foo")"#, "<test>");
        let lines = lexer.tokenize();
        // '#' preceded by a space but outside a string: it's a comment here
        // (no quote before it) — only 'pattern' should remain.
        assert_eq!(lines[0].tokens[0].value, "pattern");
    }

    #[test]
    fn test_tokenize_empty_lines_skipped() {
        let lexer = DslLexer::new("a b\n\n\nc d", "<test>");
        let lines = lexer.tokenize();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_tokenize_indent_tracked() {
        let lexer = DslLexer::new("  language python", "<test>");
        let lines = lexer.tokenize();
        assert_eq!(lines[0].indent, 2);
    }

    #[test]
    fn test_tokenize_escaped_quote_in_string() {
        // The `\'` escape only applies to the same quote as the
        // delimiter (here `'`) — cf. lexer.py::_read_string.
        let lexer = DslLexer::new(r"en 'it\'s here'", "<test>");
        let lines = lexer.tokenize();
        assert_eq!(lines[0].tokens[1].value, "it's here");
    }

    #[test]
    fn test_tokenize_other_escape_sequences_kept_as_is() {
        // `\'` inside a string delimited by `"` matches neither the
        // quote nor `\\`: kept as-is (backslash + quote).
        let lexer = DslLexer::new(r#"en "it\'s here""#, "<test>");
        let lines = lexer.tokenize();
        assert_eq!(lines[0].tokens[1].value, r"it\'s here");
    }

    #[test]
    fn test_tokenize_unclosed_string_fallback() {
        let lexer = DslLexer::new(r#"pattern "unclosed"#, "<test>");
        let lines = lexer.tokenize();
        // Fallback: split on whitespace, no error surfaced.
        assert_eq!(lines[0].tokens.len(), 2);
    }

    #[test]
    fn test_tokenize_regex_with_equals() {
        let lexer = DslLexer::new(r"pattern (?:password|secret)\s*=\s*", "<test>");
        let lines = lexer.tokenize();
        // The word contains '=' but not in the simple key=value format
        // (non-alphanumeric prefix) → must remain a WORD.
        assert_eq!(lines[0].tokens[1].kind, TokenType::Word);
    }

    #[test]
    fn test_tokenize_single_quoted_string() {
        let lexer = DslLexer::new("en 'hello'", "<test>");
        let lines = lexer.tokenize();
        assert_eq!(lines[0].tokens[1].kind, TokenType::String);
        assert_eq!(lines[0].tokens[1].value, "hello");
    }

    #[test]
    fn test_raw_content_preserved() {
        let lexer = DslLexer::new(r#"  pattern  \s*=\s*["']  "#, "<test>");
        let lines = lexer.tokenize();
        assert_eq!(lines[0].raw_content, r#"pattern  \s*=\s*["']"#);
    }

    #[test]
    fn test_fix_before_enters_plaintext_mode() {
        let src = "fix_before\n  # ceci n'est pas un commentaire DSL\n  x = 1\nend\n";
        let lexer = DslLexer::new(src, "<test>");
        let lines = lexer.tokenize();
        // fix_before, then 2 lines of raw content, then end.
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[1].raw_content, "# ceci n'est pas un commentaire DSL");
    }
}
