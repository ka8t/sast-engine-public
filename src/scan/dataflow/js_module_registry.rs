//! Free functions for resolving JavaScript/TypeScript imports/modules
//! — needed by `js_call_graph.rs::JsCallGraph::build`, which builds its
//! edges BEFORE summaries exist. Direct template of
//! `java_module_registry.rs`/`call_graph.rs` (Python resolution) for
//! the shape (free functions, no stateful registry), but a resolution
//! algorithm entirely specific to JS/TS — **no equivalent Python
//! source** (`lexical_taint.py` has no notion of a call/import graph).
//!
//! **Resolution model chosen**: closer to Python (resolution by path,
//! not by FQCN like Java) — a **relative** specifier (`./x`, `../x`) is
//! resolved by path navigation from the importing file, trying known
//! JS/TS extensions then `index.<ext>` if the result looks like a
//! directory, matched by **exact path** against the set of scanned
//! files (more precise than the Python suffix approach: a normalized
//! relative path designates only one possible file, no notion of
//! ambiguity to handle here). A **non-relative** specifier
//! (`import x from 'lodash'`, npm/native Node packages) → never
//! resolved, the same natural exclusion as Python (stdlib/third-party)
//! and Java (classes outside the analyzed classpath).
//!
//! **Recognized forms** (verified empirically against the
//! `tree-sitter-javascript` grammar, `to_sexp()`, before writing this
//! code — same discipline as `js_lowering.rs`):
//!   - ESM `import x from './f'` (default), `import { a, b as c } from './f'`
//!     (named, with alias), `import * as ns from './f'` (namespace),
//!     `import x, { a } from './f'` (default + named combined). `import
//!     './f';` (side effect only, no bound name) — ignored, nothing to
//!     resolve. `import type { A } from './f'` (TypeScript) produces
//!     the same tree as an ordinary named import (the `type` keyword
//!     does not appear in the AST) — no special handling required.
//!   - CommonJS `const/let/var m = require('./f')` (simple binding) and
//!     `const { a, b } = require('./f')` / `const { a: x } = require('./f')`
//!     (destructuring, with alias) — recognized at any depth (a
//!     `require` at the top of a file or inside a function), mirror of
//!     the Python import collection which also descends into lazy
//!     imports.
//!
//! **Out of scope for v1** (see the JS call graph onboarding plan):
//!   - Dynamic `import()` — too many varied forms (`await import()`,
//!     `.then()`) for uncertain gain; the `import` node (keyword) is
//!     not an `identifier` anyway, so it is never recognized by
//!     [`crate::scan::dataflow::js_call_graph`]'s call extraction either —
//!     consistent, not an oversight.
//!   - Path aliases (`tsconfig.json` `paths`, `package.json`
//!     `exports`/`imports`) — no project configuration reading here.
//!   - `mod = require('./f')` without a declaration (a bare
//!     `assignment_expression`) — only declarative forms
//!     (`const`/`let`/`var`) are recognized, the dominant pattern in
//!     practice.

use std::collections::HashSet;

use tree_sitter::Node;

const JS_EXTENSIONS: [&str; 6] = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"];

/// A JS/TS import (ESM or CommonJS `require`), after normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsImportInfo {
    /// Name bound in the importing file (alias included if there is
    /// one).
    pub local_name: String,
    /// Raw specifier exactly as written in the code (`"./foo"`,
    /// `"../bar/baz"`, `"lodash"`...).
    pub specifier: String,
    /// Original name in the target module (exported name/property);
    /// `""` for a binding that designates the **entire module**
    /// (default import, plain `require(...)`, `import ns from`); `"*"`
    /// for a namespace import (`import * as ns`) — no single function
    /// designated, never resolved to a precise
    /// [`super::call_graph::NodeKey`] (same logic as the Python star:
    /// matched only at `outgoing_edges` time via `ns.func`, not here).
    pub orig_name: String,
}

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

fn string_literal_value(string_node: Node, source: &[u8]) -> String {
    string_node
        .named_children(&mut string_node.walk())
        .find(|c| c.kind() == "string_fragment")
        .map(|f| text(f, source))
        .unwrap_or_default()
}

fn collect_import_statement(node: Node, source: &[u8], out: &mut Vec<JsImportInfo>) {
    let Some(source_node) = node.child_by_field_name("source") else {
        return;
    };
    let specifier = string_literal_value(source_node, source);
    let Some(clause) = node
        .named_children(&mut node.walk())
        .find(|c| c.kind() == "import_clause")
    else {
        return; // `import './f';` — side effect only, no bound name.
    };
    let mut w = clause.walk();
    for child in clause.named_children(&mut w) {
        match child.kind() {
            "identifier" => out.push(JsImportInfo {
                local_name: text(child, source),
                specifier: specifier.clone(),
                orig_name: String::new(),
            }),
            "named_imports" => {
                let mut nw = child.walk();
                for spec in child.named_children(&mut nw) {
                    if spec.kind() != "import_specifier" {
                        continue;
                    }
                    let Some(name_node) = spec.child_by_field_name("name") else {
                        continue;
                    };
                    let orig = text(name_node, source);
                    let local = spec
                        .child_by_field_name("alias")
                        .map(|a| text(a, source))
                        .unwrap_or_else(|| orig.clone());
                    out.push(JsImportInfo {
                        local_name: local,
                        specifier: specifier.clone(),
                        orig_name: orig,
                    });
                }
            }
            "namespace_import" => {
                if let Some(name_node) = child.named_children(&mut child.walk()).next() {
                    out.push(JsImportInfo {
                        local_name: text(name_node, source),
                        specifier: specifier.clone(),
                        orig_name: "*".to_string(),
                    });
                }
            }
            _ => {}
        }
    }
}

/// Recognizes `const/let/var <target> = require('...')` — `decl` is a
/// `lexical_declaration` node (`const`/`let`) or `variable_declaration`
/// (`var`).
fn collect_require_declaration(decl: Node, source: &[u8], out: &mut Vec<JsImportInfo>) {
    let mut w = decl.walk();
    for declarator in decl.named_children(&mut w) {
        if declarator.kind() != "variable_declarator" {
            continue;
        }
        let Some(value) = declarator.child_by_field_name("value") else {
            continue;
        };
        if value.kind() != "call_expression" {
            continue;
        }
        let Some(func) = value.child_by_field_name("function") else {
            continue;
        };
        if func.kind() != "identifier" || text(func, source) != "require" {
            continue;
        }
        let Some(args) = value.child_by_field_name("arguments") else {
            continue;
        };
        let Some(arg0) = args.named_children(&mut args.walk()).next() else {
            continue;
        };
        if arg0.kind() != "string" {
            continue; // dynamic specifier (variable, template) — not statically resolvable.
        }
        let specifier = string_literal_value(arg0, source);
        let Some(name_node) = declarator.child_by_field_name("name") else {
            continue;
        };
        match name_node.kind() {
            "identifier" => out.push(JsImportInfo {
                local_name: text(name_node, source),
                specifier,
                orig_name: String::new(),
            }),
            "object_pattern" => {
                let mut pw = name_node.walk();
                for prop in name_node.named_children(&mut pw) {
                    match prop.kind() {
                        "shorthand_property_identifier_pattern" => {
                            let n = text(prop, source);
                            out.push(JsImportInfo {
                                local_name: n.clone(),
                                specifier: specifier.clone(),
                                orig_name: n,
                            });
                        }
                        "pair_pattern" => {
                            let Some(key) = prop.child_by_field_name("key") else {
                                continue;
                            };
                            let Some(val) = prop.child_by_field_name("value") else {
                                continue;
                            };
                            if val.kind() == "identifier" {
                                out.push(JsImportInfo {
                                    local_name: text(val, source),
                                    specifier: specifier.clone(),
                                    orig_name: text(key, source),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

fn walk_imports(node: Node, source: &[u8], out: &mut Vec<JsImportInfo>) {
    match node.kind() {
        "import_statement" => collect_import_statement(node, source, out),
        "lexical_declaration" | "variable_declaration" => {
            collect_require_declaration(node, source, out)
        }
        _ => {}
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_imports(child, source, out);
    }
}

/// Lists all imports (ESM + CommonJS `require`) of a JS/TS file,
/// including those nested inside a function (lazy `require`) — the
/// whole tree is walked, not just top-level statements.
pub fn collect_js_imports(root: Node, source: &[u8]) -> Vec<JsImportInfo> {
    let mut out = Vec::new();
    walk_imports(root, source, &mut out);
    out
}

fn path_parts(path: &str) -> Vec<String> {
    path.replace('\\', "/")
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .map(|s| s.to_string())
        .collect()
}

/// Resolves a **relative** specifier (`./x`, `../x`) to a path in the
/// directory of the importing file — pure navigation (`..` pops a
/// segment, `.` is ignored), no extension resolution yet. `None` if
/// navigation goes past the project root (too many `..`).
fn navigate_relative(importer: &str, specifier: &str) -> Option<String> {
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

/// Returns the file from `known_files` targeted by `specifier`, written
/// in `importer`, or `None` if not resolvable. A non-relative specifier
/// (doesn't start with `./`/`../`) → always `None` (npm/native Node
/// package, outside the analyzed set). Otherwise: exact path first,
/// then each known extension, then `index.<ext>` ("directory"
/// resolution) — first candidate that matches a scanned file wins
/// (exact-path resolution, no concept of ambiguity here unlike the
/// Python suffix approach: a normalized relative path designates only
/// one possible file on disk).
pub fn resolve_target_file(
    importer: &str,
    specifier: &str,
    known_files: &[String],
) -> Option<String> {
    if !(specifier.starts_with("./") || specifier.starts_with("../")) {
        return None;
    }
    let base = navigate_relative(importer, specifier)?;
    let known: HashSet<&str> = known_files.iter().map(|s| s.as_str()).collect();
    if known.contains(base.as_str()) {
        return Some(base);
    }
    for ext in JS_EXTENSIONS {
        let candidate = format!("{base}{ext}");
        if known.contains(candidate.as_str()) {
            return Some(candidate);
        }
    }
    for ext in JS_EXTENSIONS {
        let candidate = format!("{base}/index{ext}");
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
        let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn test_default_import() {
        let src = "import x from './foo';";
        let tree = parse(src);
        let imports = collect_js_imports(tree.root_node(), src.as_bytes());
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].local_name, "x");
        assert_eq!(imports[0].specifier, "./foo");
        assert_eq!(imports[0].orig_name, "");
    }

    #[test]
    fn test_named_imports_with_alias() {
        let src = "import { a, b as c } from './foo';";
        let tree = parse(src);
        let imports = collect_js_imports(tree.root_node(), src.as_bytes());
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].local_name, "a");
        assert_eq!(imports[0].orig_name, "a");
        assert_eq!(imports[1].local_name, "c");
        assert_eq!(imports[1].orig_name, "b");
    }

    #[test]
    fn test_namespace_import() {
        let src = "import * as ns from './foo';";
        let tree = parse(src);
        let imports = collect_js_imports(tree.root_node(), src.as_bytes());
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].local_name, "ns");
        assert_eq!(imports[0].orig_name, "*");
    }

    #[test]
    fn test_default_plus_named_combined() {
        let src = "import x, { a } from './foo';";
        let tree = parse(src);
        let imports = collect_js_imports(tree.root_node(), src.as_bytes());
        assert_eq!(imports.len(), 2);
    }

    #[test]
    fn test_side_effect_only_import_yields_nothing() {
        let src = "import './foo';";
        let tree = parse(src);
        let imports = collect_js_imports(tree.root_node(), src.as_bytes());
        assert!(imports.is_empty());
    }

    #[test]
    fn test_require_simple_binding() {
        let src = "const mod = require('./foo');";
        let tree = parse(src);
        let imports = collect_js_imports(tree.root_node(), src.as_bytes());
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].local_name, "mod");
        assert_eq!(imports[0].orig_name, "");
    }

    #[test]
    fn test_require_destructured() {
        let src = "const { a, b: x } = require('./foo');";
        let tree = parse(src);
        let imports = collect_js_imports(tree.root_node(), src.as_bytes());
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].local_name, "a");
        assert_eq!(imports[0].orig_name, "a");
        assert_eq!(imports[1].local_name, "x");
        assert_eq!(imports[1].orig_name, "b");
    }

    #[test]
    fn test_require_var_and_nested_in_function() {
        let src = "function f() { var mod = require('./foo'); }";
        let tree = parse(src);
        let imports = collect_js_imports(tree.root_node(), src.as_bytes());
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].local_name, "mod");
    }

    #[test]
    fn test_bare_import_not_resolved() {
        let known = vec!["a.js".to_string()];
        assert_eq!(resolve_target_file("a.js", "lodash", &known), None);
    }

    #[test]
    fn test_relative_import_exact_extension_match() {
        let known = vec!["a.js".to_string(), "foo.js".to_string()];
        assert_eq!(
            resolve_target_file("a.js", "./foo", &known),
            Some("foo.js".to_string())
        );
    }

    #[test]
    fn test_relative_import_into_subdirectory() {
        let known = vec!["src/a.js".to_string(), "src/utils/foo.ts".to_string()];
        assert_eq!(
            resolve_target_file("src/a.js", "./utils/foo", &known),
            Some("src/utils/foo.ts".to_string())
        );
    }

    #[test]
    fn test_relative_import_parent_directory() {
        let known = vec!["src/a/b.js".to_string(), "src/utils.js".to_string()];
        assert_eq!(
            resolve_target_file("src/a/b.js", "../utils", &known),
            Some("src/utils.js".to_string())
        );
    }

    #[test]
    fn test_relative_import_resolves_index() {
        let known = vec!["a.js".to_string(), "lib/index.js".to_string()];
        assert_eq!(
            resolve_target_file("a.js", "./lib", &known),
            Some("lib/index.js".to_string())
        );
    }

    #[test]
    fn test_relative_import_with_explicit_extension_in_specifier() {
        let known = vec!["a.js".to_string(), "foo.js".to_string()];
        assert_eq!(
            resolve_target_file("a.js", "./foo.js", &known),
            Some("foo.js".to_string())
        );
    }

    #[test]
    fn test_relative_import_unresolved_when_no_matching_file() {
        let known = vec!["a.js".to_string()];
        assert_eq!(resolve_target_file("a.js", "./missing", &known), None);
    }

    #[test]
    fn test_relative_import_too_many_parent_segments_gives_up() {
        let known = vec!["a.js".to_string()];
        assert_eq!(resolve_target_file("a.js", "../../../x", &known), None);
    }
}
