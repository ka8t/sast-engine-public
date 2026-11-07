//! Free functions for resolving PHP files/classes — needed by
//! `php_call_graph.rs::PhpCallGraph::build`, which builds its edges
//! BEFORE the summaries exist. Direct template of
//! `js_module_registry.rs`/`java_module_registry.rs` for the shape
//! (free functions, no stateful registry), but a resolution model
//! specific to PHP — **no equivalent Python source** (same
//! investigation as for JS, see `js_call_graph.rs` doc:
//! `lexical_taint.py` has no notion of
//! a call graph/imports).
//!
//! **Two distinct mechanisms, not a single import model like
//! JS/Python/Java** — PHP has no namespaced module system at
//! runtime:
//!
//! 1. **`require`/`require_once`/`include`/`include_once`** —
//!    **textual** inclusion into the calling file's global namespace
//!    (NOT a qualified import like JS/Python `import`/`use`):
//!    `require './utils.php';` makes ALL functions of `utils.php`
//!    callable **without a prefix** from the current file, as if
//!    they were defined there. Modeled here as a "star" merge (same
//!    spirit as the Python star-import,
//!    `call_graph.rs::resolve_import_bindings`): if several files
//!    required by the same file each define a function with the same
//!    name, neither is kept (collision, anti-FP). Only a **literal
//!    string** argument is recognized (`require
//!    __DIR__ . '/f.php'` — dynamic concatenation — is not resolved,
//!    same principle as the non-literal argument of JS `require()`).
//! 2. **Static-scope call** (`Klass::method()`,
//!    `scoped_call_expression`) — resolved via a **global class-name
//!    index** built over the WHOLE scanned corpus (not just the
//!    files explicitly `require`d or `use`-imported): a class name
//!    that appears in only ONE scanned file resolves to that file,
//!    otherwise (carried by several files, or absent) it stays
//!    unresolved — anti-FP identical to Python (ambiguous imports)
//!    and Java (FQCN carried by several files). **Deliberately no
//!    namespace/visibility scoping** (unlike Java, which limits
//!    itself to classes in the same package + explicit imports):
//!    modern PHP (Composer/PSR-4) resolves most classes via the
//!    autoloader, with no explicit `require` in the calling file —
//!    a global bare-name index over the whole corpus captures this
//!    case without needing to read `composer.json`/the PSR-4 rules.
//!    Accepted consequence: **`use App\Ns\Classe;` is not parsed at
//!    all** — it would be no more precise than the global index
//!    anyway (no real namespace→directory resolution available),
//!    hence redundant with mechanism 2 above.
//!
//! **Out of scope for v1** (see `php_call_graph.rs` for the full
//! detail of `outgoing_edges` limitations): instance call
//! `$obj->method()` except `$this->method()` (no variable type
//! tracking, like JS without `type_map`), `parent::method()` (would
//! require knowing which class encloses which method, not tracked),
//! dynamic `require` path (concatenation, variable).

use std::collections::{BTreeMap, HashSet};

use tree_sitter::Node;

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

fn string_literal_value(string_node: Node, source: &[u8]) -> String {
    string_node
        .named_children(&mut string_node.walk())
        .find(|c| c.kind() == "string_content")
        .map(|f| text(f, source))
        .unwrap_or_default()
}

const REQUIRE_LIKE_KINDS: [&str; 4] = [
    "require_expression",
    "require_once_expression",
    "include_expression",
    "include_once_expression",
];

fn walk_requires(node: Node, source: &[u8], out: &mut Vec<String>) {
    if REQUIRE_LIKE_KINDS.contains(&node.kind())
        && let Some(arg) = node.named_children(&mut node.walk()).next()
        && arg.kind() == "string"
    {
        out.push(string_literal_value(arg, source));
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_requires(child, source, out);
    }
}

/// Lists the `require`/`require_once`/`include`/`include_once`
/// specifiers of a PHP file with a **literal string** argument (the
/// whole tree is walked, since these statements can appear anywhere
/// — conditional bootstrap, lazy loading).
pub fn collect_php_requires(root: Node, source: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    walk_requires(root, source, &mut out);
    out
}

const TOP_LEVEL_TYPE_DECLS: [&str; 3] = [
    "class_declaration",
    "interface_declaration",
    "trait_declaration",
];

fn walk_class_names(node: Node, source: &[u8], out: &mut Vec<String>) {
    if TOP_LEVEL_TYPE_DECLS.contains(&node.kind())
        && let Some(name_node) = node.child_by_field_name("name")
    {
        out.push(text(name_node, source));
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_class_names(child, source, out);
    }
}

/// Lists the class/interface/trait names declared in a PHP file
/// (recursive walk — a declaration can be nested inside a
/// `namespace Foo { ... }` block, unlike the `namespace Foo;` form
/// where it is a top-level sibling of `program`).
pub fn collect_php_class_names(root: Node, source: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    walk_class_names(root, source, &mut out);
    out
}

/// `{class_name: file}` — `None` if the name is carried by several
/// files of the scanned corpus (ambiguous, anti-FP).
/// `class_names_by_file = {filepath: [declared class names]}`.
pub fn build_class_name_index(
    class_names_by_file: &BTreeMap<String, Vec<String>>,
) -> BTreeMap<String, Option<String>> {
    let mut index: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    for (fp, names) in class_names_by_file {
        for cname in names {
            match owner.get(cname) {
                Some(existing) if existing != fp => {
                    index.insert(cname.clone(), None);
                }
                _ => {
                    owner.insert(cname.clone(), fp.clone());
                    index.insert(cname.clone(), Some(fp.clone()));
                }
            }
        }
    }
    index
}

fn path_parts(path: &str) -> Vec<String> {
    path.replace('\\', "/")
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .map(|s| s.to_string())
        .collect()
}

fn navigate_relative(importer: &str, specifier: &str) -> Option<String> {
    if specifier.starts_with('/') {
        return None; // absolute filesystem path, outside the scanned project.
    }
    let importer_parts = path_parts(importer);
    let mut dir_parts: Vec<String> = if importer_parts.is_empty() {
        vec![]
    } else {
        importer_parts[..importer_parts.len() - 1].to_vec()
    };
    for seg in specifier.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                dir_parts.pop()?;
            }
            s => dir_parts.push(s.to_string()),
        }
    }
    if dir_parts.is_empty() {
        return None;
    }
    Some(dir_parts.join("/"))
}

/// Resolves a `require`/`include` specifier (relative to the calling
/// file's directory — PHP does not have CommonJS's mandatory `./`
/// convention, `require 'foo.php'` and `require './foo.php'` are
/// equivalent) against `known_files`. Exact path first, then `.php`
/// appended if missing (the extension is almost always written
/// explicitly in PHP, unlike JS — no implicit `index.php`
/// resolution, no equivalent convention exists on the PHP side).
pub fn resolve_required_file(
    importer: &str,
    specifier: &str,
    known_files: &[String],
) -> Option<String> {
    let base = navigate_relative(importer, specifier)?;
    let known: HashSet<&str> = known_files.iter().map(|s| s.as_str()).collect();
    if known.contains(base.as_str()) {
        return Some(base);
    }
    if !base.ends_with(".php") {
        let candidate = format!("{base}.php");
        if known.contains(candidate.as_str()) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn test_collect_require_literal_path() {
        let src = "<?php require './utils.php';";
        let tree = parse(src);
        let reqs = collect_php_requires(tree.root_node(), src.as_bytes());
        assert_eq!(reqs, vec!["./utils.php".to_string()]);
    }

    #[test]
    fn test_collect_require_once_and_include_variants() {
        let src = "<?php require_once 'a.php'; include 'b.php'; include_once 'c.php';";
        let tree = parse(src);
        let reqs = collect_php_requires(tree.root_node(), src.as_bytes());
        assert_eq!(reqs.len(), 3);
    }

    #[test]
    fn test_dynamic_require_path_not_collected() {
        let src = "<?php require_once __DIR__ . '/foo.php';";
        let tree = parse(src);
        let reqs = collect_php_requires(tree.root_node(), src.as_bytes());
        assert!(reqs.is_empty());
    }

    #[test]
    fn test_collect_class_and_interface_and_trait_names() {
        let src = "<?php class A {} interface B {} trait C {}";
        let tree = parse(src);
        let names = collect_php_class_names(tree.root_node(), src.as_bytes());
        assert_eq!(
            names,
            vec!["A".to_string(), "B".to_string(), "C".to_string()]
        );
    }

    #[test]
    fn test_class_name_index_unique_resolves() {
        let mut m = BTreeMap::new();
        m.insert("a.php".to_string(), vec!["Foo".to_string()]);
        let index = build_class_name_index(&m);
        assert_eq!(index.get("Foo"), Some(&Some("a.php".to_string())));
    }

    #[test]
    fn test_class_name_index_ambiguous_gives_up() {
        let mut m = BTreeMap::new();
        m.insert("a.php".to_string(), vec!["Foo".to_string()]);
        m.insert("b.php".to_string(), vec!["Foo".to_string()]);
        let index = build_class_name_index(&m);
        assert_eq!(index.get("Foo"), Some(&None));
    }

    #[test]
    fn test_resolve_required_file_exact_path() {
        let known = vec!["a.php".to_string(), "utils.php".to_string()];
        assert_eq!(
            resolve_required_file("a.php", "./utils.php", &known),
            Some("utils.php".to_string())
        );
    }

    #[test]
    fn test_resolve_required_file_without_dot_slash_prefix() {
        let known = vec!["a.php".to_string(), "utils.php".to_string()];
        assert_eq!(
            resolve_required_file("a.php", "utils.php", &known),
            Some("utils.php".to_string())
        );
    }

    #[test]
    fn test_resolve_required_file_missing_extension_appended() {
        let known = vec!["a.php".to_string(), "utils.php".to_string()];
        assert_eq!(
            resolve_required_file("a.php", "./utils", &known),
            Some("utils.php".to_string())
        );
    }

    #[test]
    fn test_resolve_required_file_subdirectory() {
        let known = vec!["src/a.php".to_string(), "src/lib/utils.php".to_string()];
        assert_eq!(
            resolve_required_file("src/a.php", "./lib/utils.php", &known),
            Some("src/lib/utils.php".to_string())
        );
    }

    #[test]
    fn test_resolve_required_file_absolute_filesystem_path_not_resolved() {
        let known = vec!["a.php".to_string()];
        assert_eq!(
            resolve_required_file("a.php", "/etc/config.php", &known),
            None
        );
    }

    #[test]
    fn test_resolve_required_file_unresolved_when_missing() {
        let known = vec!["a.php".to_string()];
        assert_eq!(
            resolve_required_file("a.php", "./missing.php", &known),
            None
        );
    }
}
