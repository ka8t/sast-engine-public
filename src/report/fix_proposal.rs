//! Fixes written on the user's own line, for the rules whose fix is a
//! mechanical rewrite of that line.
//!
//! The report showed only each rule's generic before/after example
//! (`fix_before`/`fix_after`), unrelated to the user's code. The maintainer asked
//! (2026-11-14) that every finding show the code found AND a fix with the
//! real code. The engine has no AI and no network (ADR-0035, ADR-0041), and a
//! rule-agnostic rewrite would be wrong more often than right (an
//! `innerHTML` holding an SVG icon is not fixed by `textContent`). So a fix
//! is proposed only by a transform written for one rule, and only when that
//! transform can prove the rewrite keeps the meaning; otherwise `None`, and
//! the report says that no automatic fix exists.
//!
//! Transforms are picked by frequency on a real project (my-ia, 2026-11-14):
//! `fstring_in_logging` (822 findings), `html_button_missing_type` (226) and
//! `html_th_scope_missing` (161). `heading_skip_level` and
//! `event_listeners_not_cleaned` have none: the right heading level depends
//! on the previous heading, and the fix of a listener is a
//! `removeEventListener` elsewhere, neither on the line found.

/// A fix for one finding: the rewritten line and, when the rewrite rests on
/// an assumption the engine cannot check, the locale key of a note that
/// states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixProposal {
    /// The user's line rewritten, indentation kept.
    pub code: String,
    /// Locale key of a caveat shown under the fix (`None`: none needed).
    pub note_key: Option<&'static str>,
}

/// The fix of `rule_key` applied to `line`, or `None` when the rule has no
/// transform or the line is outside what the transform handles safely.
pub fn propose_fix(rule_key: &str, line: &str) -> Option<FixProposal> {
    match rule_key {
        "fstring_in_logging" => fstring_logging_to_args(line).map(|code| FixProposal {
            code,
            note_key: None,
        }),
        "html_button_missing_type" => button_with_type(line).map(|code| FixProposal {
            code,
            note_key: Some("fix_note_button_submit"),
        }),
        "html_th_scope_missing" => th_with_scope(line).map(|code| FixProposal {
            code,
            note_key: Some("fix_note_th_row"),
        }),
        _ => None,
    }
}

/// `<th>Name</th>` → `<th scope="col">Name</th>`, for every `<th` of the
/// line without a `scope`: the usual case is a column header. The note
/// says to write `scope="row"` for a row header, which the line alone
/// does not show.
fn th_with_scope(line: &str) -> Option<String> {
    let tag = fancy_regex::Regex::new(r"<th\b(?![^>]*\bscope\s*=)").expect("valid regex");
    if !tag.is_match(line).unwrap_or(false) {
        return None;
    }
    Some(tag.replace_all(line, r#"<th scope="col""#).into_owned())
}

/// `logger.info(f"User {name} from {ip!r}")` →
/// `logger.info("User %s from %r", name, ip)`: the logging module formats
/// the message only when the level is enabled, and log aggregators group
/// the messages by template.
///
/// Handled: one f-string, first argument of a `logger`/`log` call on this
/// line, with plain `{expr}`, `{expr!r}`/`{expr!s}` and `{{`/`}}`; a literal
/// `%` becomes `%%`. Refused (`None`): a format spec (`{x:.2f}`), the debug
/// form (`{x=}`), a triple-quoted, raw or byte string, a string not closed
/// on this line.
fn fstring_logging_to_args(line: &str) -> Option<String> {
    let call = regex::Regex::new(
        r#"^(?P<head>.*?\blog(?:ger)?\.(?:info|warning|error|debug|critical|exception)\s*\(\s*)[fF](?P<q>['"])"#,
    )
    .expect("valid regex");
    let caps = call.captures(line)?;
    let head = caps.name("head")?.as_str();
    let quote = caps.name("q")?.as_str().chars().next()?;
    let body_start = caps.get(0)?.end();
    let rest = &line[body_start..];
    // A triple-quoted string starts with two more quotes.
    if rest.starts_with(quote) {
        return None;
    }

    let mut template = String::new();
    let mut args: Vec<String> = Vec::new();
    let chars: Vec<char> = rest.chars().collect();
    let mut i = 0;
    let end = loop {
        let c = *chars.get(i)?;
        match c {
            '\\' => {
                template.push(c);
                template.push(*chars.get(i + 1)?);
                i += 2;
            }
            c if c == quote => break i,
            '%' => {
                template.push_str("%%");
                i += 1;
            }
            '{' if chars.get(i + 1) == Some(&'{') => {
                template.push('{');
                i += 2;
            }
            '}' if chars.get(i + 1) == Some(&'}') => {
                template.push('}');
                i += 2;
            }
            '}' => return None,
            '{' => {
                let (expr, conv, next) = placeholder(&chars, i + 1, quote)?;
                template.push_str(if conv == Some('r') { "%r" } else { "%s" });
                args.push(expr);
                i = next;
            }
            _ => {
                template.push(c);
                i += 1;
            }
        }
    };
    let tail: String = chars[end + 1..].iter().collect();
    let args_text: String = args.iter().map(|a| format!(", {a}")).collect();
    Some(format!("{head}{quote}{template}{quote}{args_text}{tail}"))
}

/// Reads one f-string placeholder from `start` (just after `{`): returns
/// the expression, its `!r`/`!s` conversion, and the index after `}`.
/// `None` for a format spec, the `=` debug form, or a quote that would end
/// the enclosing string.
fn placeholder(chars: &[char], start: usize, quote: char) -> Option<(String, Option<char>, usize)> {
    let mut depth = 0usize;
    let mut inner_quote: Option<char> = None;
    let mut i = start;
    loop {
        let c = *chars.get(i)?;
        if let Some(q) = inner_quote {
            if c == q {
                inner_quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            c if c == quote => return None,
            '\'' | '"' => inner_quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' => depth = depth.checked_sub(1)?,
            '}' if depth > 0 => depth -= 1,
            '}' | '!' | ':' | '=' if depth == 0 => break,
            _ => {}
        }
        i += 1;
    }
    let expr: String = chars[start..i].iter().collect::<String>().trim().to_string();
    if expr.is_empty() {
        return None;
    }
    match chars[i] {
        '}' => Some((expr, None, i + 1)),
        '!' => {
            // `!=` is a comparison inside the expression: not handled.
            let conv = *chars.get(i + 1)?;
            (matches!(conv, 'r' | 's') && chars.get(i + 2) == Some(&'}'))
                .then_some((expr, Some(conv), i + 3))
        }
        _ => None,
    }
}

/// `<button class="x">` → `<button type="button" class="x">`, for every
/// `<button` of the line without a `type`. The engine cannot see whether
/// the button submits a form; the note says to write `type="submit"`
/// then.
fn button_with_type(line: &str) -> Option<String> {
    let tag = fancy_regex::Regex::new(r"<button\b(?![^>]*\btype\s*=)").expect("valid regex");
    if !tag.is_match(line).unwrap_or(false) {
        return None;
    }
    Some(tag.replace_all(line, r#"<button type="button""#).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fix(rule: &str, line: &str) -> Option<String> {
        propose_fix(rule, line).map(|f| f.code)
    }

    #[test]
    fn test_fstring_logging_becomes_lazy_arguments() {
        assert_eq!(
            fix(
                "fstring_in_logging",
                r#"        logger.error(f"Error checking '{username}': {e}")"#
            )
            .as_deref(),
            Some(r#"        logger.error("Error checking '%s': %s", username, e)"#)
        );
    }

    #[test]
    fn test_fstring_logging_keeps_conversions_kwargs_and_escapes() {
        assert_eq!(
            fix(
                "fstring_in_logging",
                r#"log.warning(f'{user.id!r} at 100% {{x}} {d["k"]}', exc_info=True)"#
            )
            .as_deref(),
            Some(r#"log.warning('%r at 100%% {x} %s', user.id, d["k"], exc_info=True)"#)
        );
    }

    #[test]
    fn test_fstring_logging_refuses_what_it_cannot_prove() {
        for line in [
            r#"logger.info(f"took {elapsed:.2f}s")"#,
            r#"logger.info(f"{value=}")"#,
            r#"logger.info(f"""multi"""),"#,
            r#"logger.info(f"not closed {x}"#,
            r#"logger.info(f"{a != b}")"#,
            r#"print(f"{x}")"#,
        ] {
            assert_eq!(fix("fstring_in_logging", line), None, "{line}");
        }
    }

    #[test]
    fn test_button_gets_a_type_and_a_caveat() {
        let p = propose_fix(
            "html_button_missing_type",
            r#"  <button class="btn" onclick="go()">Go</button> <button type="submit">Ok</button>"#,
        )
        .unwrap();
        assert_eq!(
            p.code,
            r#"  <button type="button" class="btn" onclick="go()">Go</button> <button type="submit">Ok</button>"#
        );
        assert_eq!(p.note_key, Some("fix_note_button_submit"));
        assert_eq!(fix("html_button_missing_type", r#"<button type="reset">"#), None);
    }

    #[test]
    fn test_th_gets_a_column_scope_and_a_caveat() {
        let p = propose_fix(
            "html_th_scope_missing",
            r#"<tr><th>Name</th><th scope="row">Id</th><th class="x">Age</th></tr>"#,
        )
        .unwrap();
        assert_eq!(
            p.code,
            r#"<tr><th scope="col">Name</th><th scope="row">Id</th><th scope="col" class="x">Age</th></tr>"#
        );
        assert_eq!(p.note_key, Some("fix_note_th_row"));
        assert_eq!(fix("html_th_scope_missing", "<thead>"), None);
    }

    #[test]
    fn test_rule_without_transform_has_no_fix() {
        assert_eq!(
            fix(
                "xss_unsafe_html_construction",
                "indicator.innerHTML = `${Icons.cube()} ${providerLabel}`;"
            ),
            None
        );
    }
}
