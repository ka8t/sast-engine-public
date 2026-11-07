//! Lines-of-code counters (Step 4.3) — a corrected port of
//! `Audit/sca/runner.py::_read_file` (an extension-based heuristic:
//! only strips comments for a subset of languages, no multi-line
//! docstring detection).
//!
//! **Decision #4 (settled on 2026-08-24)**: fix rather than reproduce
//! identically — precise exclusion of tree-sitter's `comment` nodes,
//! per actually-ported language (paired with Decision #10, extended
//! on 2026-08-25 to Python+Java). A Python docstring in comment
//! position (the first statement of a module/class/function) counts
//! as a comment (SonarQube/cloc convention), not as code — a
//! **deliberate behavior change vs Python**, an assumed deviation, not
//! a parity bug. Java has no docstring convention: only `line_comment`/
//! `block_comment` nodes are excluded.

use tree_sitter::Node;

/// Counts the lines of code of an already-parsed Python file.
///
/// Excludes: blank lines (after trimming), and any portion of a line
/// covered by a `comment` node or by a docstring (a `string` node in
/// comment position — the first statement of a module/class/
/// function). A line with at least one real byte of code (even mixed
/// with a trailing comment) is counted.
pub fn count_python_loc(source: &[u8], tree: &tree_sitter::Tree) -> usize {
    let excluded = collect_excluded_ranges(tree.root_node());
    let mut count = 0usize;
    let mut line_start = 0usize;
    for i in 0..=source.len() {
        if i == source.len() || source[i] == b'\n' {
            if line_has_code(source, line_start, i, &excluded) {
                count += 1;
            }
            line_start = i + 1;
        }
    }
    count
}

/// Counts the lines of code of an already-parsed Java file.
///
/// Same principle as [`count_python_loc`], but Java has no docstring
/// convention — `tree-sitter-java` directly distinguishes
/// `line_comment` (`//...`) and `block_comment` (`/* ... */`,
/// including Javadoc `/** ... */`, just a plain `block_comment` from
/// the grammar's point of view). No position rule to apply.
pub fn count_java_loc(source: &[u8], tree: &tree_sitter::Tree) -> usize {
    let mut excluded = Vec::new();
    walk_collect_java(tree.root_node(), &mut excluded);
    let mut count = 0usize;
    let mut line_start = 0usize;
    for i in 0..=source.len() {
        if i == source.len() || source[i] == b'\n' {
            if line_has_code(source, line_start, i, &excluded) {
                count += 1;
            }
            line_start = i + 1;
        }
    }
    count
}

/// Counts the lines of code of an already-parsed JavaScript file.
///
/// Same principle as [`count_java_loc`]: `tree-sitter-javascript` has
/// only a single `comment` node for both syntaxes (`//...` and
/// `/* ... */`), verified empirically (no line_comment/block_comment
/// split like in Java) — no position rule to apply (no docstring
/// convention in JS).
pub fn count_js_loc(source: &[u8], tree: &tree_sitter::Tree) -> usize {
    let mut excluded = Vec::new();
    walk_collect_js(tree.root_node(), &mut excluded);
    let mut count = 0usize;
    let mut line_start = 0usize;
    for i in 0..=source.len() {
        if i == source.len() || source[i] == b'\n' {
            if line_has_code(source, line_start, i, &excluded) {
                count += 1;
            }
            line_start = i + 1;
        }
    }
    count
}

fn walk_collect_js(node: Node, out: &mut Vec<(usize, usize)>) {
    if node.kind() == "comment" {
        out.push((node.start_byte(), node.end_byte()));
        return;
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_collect_js(child, out);
    }
}

fn walk_collect_java(node: Node, out: &mut Vec<(usize, usize)>) {
    if node.kind() == "line_comment" || node.kind() == "block_comment" {
        out.push((node.start_byte(), node.end_byte()));
        return;
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_collect_java(child, out);
    }
}

/// True if the line `[line_start, line_end)` contains at least one
/// non-whitespace byte not covered by an excluded range.
fn line_has_code(
    source: &[u8],
    line_start: usize,
    line_end: usize,
    excluded: &[(usize, usize)],
) -> bool {
    source[line_start..line_end]
        .iter()
        .enumerate()
        .any(|(offset, &b)| {
            if b == b' ' || b == b'\t' || b == b'\r' {
                return false;
            }
            let idx = line_start + offset;
            !excluded.iter().any(|&(s, e)| idx >= s && idx < e)
        })
}

/// Walks the tree and collects the byte ranges to exclude from the
/// count (comments + docstrings). Doesn't descend into a found
/// comment/docstring (no relevant children inside).
fn collect_excluded_ranges(root: Node) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    walk_collect(root, &mut out);
    out
}

fn walk_collect(node: Node, out: &mut Vec<(usize, usize)>) {
    if node.kind() == "comment" {
        out.push((node.start_byte(), node.end_byte()));
        return;
    }
    if node.kind() == "string" && is_docstring_string_node(node) {
        out.push((node.start_byte(), node.end_byte()));
        return;
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_collect(child, out);
    }
}

/// True if `node` (a `string` node) is a docstring: the sole content
/// of an `expression_statement` which is itself the first statement
/// (ignoring leading comments) of a `module` or a `block` (function/
/// class body — the same grammar node for both on the
/// tree-sitter-python side).
fn is_docstring_string_node(node: Node) -> bool {
    if node.kind() != "string" {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "expression_statement" {
        return false;
    }
    let mut w = parent.walk();
    let mut named = parent.named_children(&mut w);
    if named.next().map(|n| n.id()) != Some(node.id()) {
        return false; // not the sole content of the expression_statement
    }
    if named.next().is_some() {
        return false;
    }
    let Some(container) = parent.parent() else {
        return false;
    };
    if container.kind() != "module" && container.kind() != "block" {
        return false;
    }
    let mut cw = container.walk();
    let container_first = container
        .named_children(&mut cw)
        .find(|c| c.kind() != "comment");
    container_first.map(|n| n.id()) == Some(parent.id())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn loc(src: &str) -> usize {
        let tree = parse(src);
        count_python_loc(src.as_bytes(), &tree)
    }

    #[test]
    fn test_simple_code_all_counted() {
        assert_eq!(loc("x = 1\ny = 2\nz = 3\n"), 3);
    }

    #[test]
    fn test_blank_lines_excluded() {
        assert_eq!(loc("x = 1\n\n\ny = 2\n"), 2);
    }

    #[test]
    fn test_whitespace_only_line_excluded() {
        assert_eq!(loc("x = 1\n   \ny = 2\n"), 2);
    }

    #[test]
    fn test_comment_only_line_excluded() {
        assert_eq!(loc("x = 1\n# un commentaire\ny = 2\n"), 2);
    }

    #[test]
    fn test_trailing_comment_still_counts_as_code() {
        assert_eq!(loc("x = 1  # inline\n"), 1);
    }

    #[test]
    fn test_module_docstring_excluded() {
        let src = "\"\"\"Module docstring.\n\nSur plusieurs lignes.\n\"\"\"\nx = 1\n";
        assert_eq!(
            loc(src),
            1,
            "le docstring de module ne doit compter aucune ligne"
        );
    }

    #[test]
    fn test_function_docstring_excluded() {
        let src = "def f():\n    \"\"\"Docstring de fonction.\"\"\"\n    return 1\n";
        // def f(): + return 1 = 2 lines of code; the docstring is excluded.
        assert_eq!(loc(src), 2);
    }

    #[test]
    fn test_class_docstring_excluded() {
        let src = "class Foo:\n    \"\"\"Docstring de classe.\"\"\"\n    x = 1\n";
        assert_eq!(loc(src), 2);
    }

    #[test]
    fn test_string_literal_not_in_docstring_position_counts_as_code() {
        // Assigned string, not the first statement of a docstring -> counts as code.
        let src = "def f():\n    x = 1\n    y = \"pas un docstring\"\n";
        assert_eq!(loc(src), 3);
    }

    #[test]
    fn test_docstring_after_other_statement_not_treated_as_docstring() {
        // The string is no longer in first position -> counts as code.
        let src = "x = 1\n\"pas un docstring ici\"\n";
        assert_eq!(loc(src), 2);
    }

    #[test]
    fn test_multiline_docstring_fully_excluded_even_with_blank_lines_inside() {
        let src = "def f():\n    \"\"\"Ligne 1.\n\n    Ligne 3 après une ligne vide.\n    \"\"\"\n    pass\n";
        assert_eq!(
            loc(src),
            2,
            "def f(): + pass = 2, tout le docstring exclu quel que soit son contenu interne"
        );
    }

    #[test]
    fn test_empty_file_zero_loc() {
        assert_eq!(loc(""), 0);
    }

    #[test]
    fn test_only_comments_zero_loc() {
        assert_eq!(loc("# a\n# b\n"), 0);
    }

    fn parse_java(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn java_loc(src: &str) -> usize {
        let tree = parse_java(src);
        count_java_loc(src.as_bytes(), &tree)
    }

    #[test]
    fn test_java_simple_code_all_counted() {
        let src = "class Foo {\n    int x = 1;\n}\n";
        assert_eq!(java_loc(src), 3);
    }

    #[test]
    fn test_java_blank_and_whitespace_lines_excluded() {
        let src = "class Foo {\n\n   \n    int x = 1;\n}\n";
        assert_eq!(java_loc(src), 3);
    }

    #[test]
    fn test_java_line_comment_only_line_excluded() {
        let src = "class Foo {\n    // un commentaire\n    int x = 1;\n}\n";
        assert_eq!(java_loc(src), 3);
    }

    #[test]
    fn test_java_trailing_comment_still_counts_as_code() {
        assert_eq!(java_loc("int x = 1; // inline\n"), 1);
    }

    #[test]
    fn test_java_block_comment_excluded_even_multiline() {
        let src = "class Foo {\n    /* bloc\n       sur plusieurs lignes */\n    int x = 1;\n}\n";
        assert_eq!(java_loc(src), 3);
    }

    #[test]
    fn test_java_javadoc_block_comment_excluded() {
        let src = "/**\n * Javadoc.\n * @param x un param\n */\nclass Foo {\n}\n";
        assert_eq!(java_loc(src), 2);
    }

    #[test]
    fn test_java_empty_file_zero_loc() {
        assert_eq!(java_loc(""), 0);
    }

    #[test]
    fn test_java_only_comments_zero_loc() {
        assert_eq!(java_loc("// a\n// b\n"), 0);
    }

    fn parse_js(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn js_loc(src: &str) -> usize {
        let tree = parse_js(src);
        count_js_loc(src.as_bytes(), &tree)
    }

    #[test]
    fn test_js_simple_code_all_counted() {
        assert_eq!(js_loc("const x = 1;\nconst y = 2;\n"), 2);
    }

    #[test]
    fn test_js_blank_and_whitespace_lines_excluded() {
        assert_eq!(js_loc("const x = 1;\n\n   \nconst y = 2;\n"), 2);
    }

    #[test]
    fn test_js_line_comment_only_line_excluded() {
        assert_eq!(js_loc("const x = 1;\n// comment\nconst y = 2;\n"), 2);
    }

    #[test]
    fn test_js_trailing_comment_still_counts_as_code() {
        assert_eq!(js_loc("const x = 1; // inline\n"), 1);
    }

    #[test]
    fn test_js_block_comment_excluded_even_multiline() {
        let src = "const x = 1;\n/* bloc\n   sur plusieurs lignes */\nconst y = 2;\n";
        assert_eq!(js_loc(src), 2);
    }

    #[test]
    fn test_js_empty_file_zero_loc() {
        assert_eq!(js_loc(""), 0);
    }

    #[test]
    fn test_js_only_comments_zero_loc() {
        assert_eq!(js_loc("// a\n/* b */\n"), 0);
    }
}
