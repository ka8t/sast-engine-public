//! Free functions for resolving Java imports/packages — partial port
//! of `Audit/sca/dataflow/java_module_registry.py`.
//!
//! **What is NOT ported**: the `JavaModuleRegistry` class itself
//! (stateful registry, `add_file`/`resolve_imported_summaries`,
//! 1-hop resolution) — same choice as on the Python side for
//! `module_registry.py::ModuleRegistry`, dead code in production (confirmed:
//! `java_call_graph.py` uses ONLY the free functions of this
//! module, never the `JavaModuleRegistry` class), replaced by the
//! multi-hop resolution of `java_call_graph.rs::JavaCallGraph`. Only
//! this subset (package/imports/classes/superclasses extraction +
//! FQCN resolution/visible imports/static bindings) is reproduced here.
//!
//! Semantic differences from `module_registry.py`/`call_graph.rs`
//! (Python resolution):
//!   - Resolution by **FQCN** (package + class name), not by
//!     file path suffix: two files at the same relative path
//!     in different packages are never confused.
//!   - A class from the **same package** is visible without an explicit import
//!     — no equivalent on the Python side (which always requires an import).
//!   - `import pkg.Class;` imports a **class** (method
//!     namespace) — never a single directly callable function
//!     (Java has no top-level functions).
//!   - `import static pkg.Class.member;` is the only Java case that
//!     exposes a name directly callable without a prefix.
//!   - `import pkg.*;` imports all classes in the package;
//!     `import static pkg.Class.*;` imports all static members
//!     of ONE class under their bare name.
//!
//! Anti-FP (false positive) safeguard identical to Python: an FQCN carried by several
//! analyzed files is not resolved — better to miss a flow than
//! invent a false one.

use std::collections::{BTreeMap, BTreeSet};

use tree_sitter::Node;

pub use super::call_graph::NodeKey;

const TOP_LEVEL_TYPE_DECLS: [&str; 4] = [
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
];

/// A Java import.
///
/// `path`: dotted path as written in the source code.
///   - `import pkg.Class;`               → `"pkg.Class"`
///   - `import pkg.*;`                   → `"pkg"` (`wildcard=true`)
///   - `import static pkg.Class.member;` → `"pkg.Class.member"` (`is_static=true`)
///   - `import static pkg.Class.*;`      → `"pkg.Class"` (`is_static=true`, `wildcard=true`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaImportInfo {
    pub path: String,
    pub is_static: bool,
    pub wildcard: bool,
}

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// Declared package name (`""` = default package).
pub fn collect_package(root: Node, source: &[u8]) -> String {
    let mut w = root.walk();
    for child in root.named_children(&mut w) {
        if child.kind() == "package_declaration"
            && let Some(name_node) = child.named_children(&mut child.walk()).next()
        {
            return text(name_node, source);
        }
    }
    String::new()
}

/// Lists the imports of a Java file (`program`, tree-sitter root).
pub fn collect_java_imports(root: Node, source: &[u8]) -> Vec<JavaImportInfo> {
    let mut imports = Vec::new();
    let mut w = root.walk();
    for child in root.named_children(&mut w) {
        if child.kind() != "import_declaration" {
            continue;
        }
        let mut cw = child.walk();
        let is_static = child.children(&mut cw).any(|c| c.kind() == "static");
        let mut cw2 = child.walk();
        let wildcard = child.children(&mut cw2).any(|c| c.kind() == "asterisk");
        let scoped = child
            .named_children(&mut child.walk())
            .find(|c| c.kind() == "scoped_identifier" || c.kind() == "identifier");
        let Some(scoped) = scoped else { continue };
        imports.push(JavaImportInfo {
            path: text(scoped, source),
            is_static,
            wildcard,
        });
    }
    imports
}

/// Names of the classes/interfaces/enums/records declared at the top level of
/// the file (nested classes are out of scope — a call
/// `Outer.Inner.method()` from another file will not be resolved).
pub fn collect_java_class_names(root: Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut w = root.walk();
    for child in root.named_children(&mut w) {
        if TOP_LEVEL_TYPE_DECLS.contains(&child.kind())
            && let Some(name_node) = child.child_by_field_name("name")
        {
            names.push(text(name_node, source));
        }
    }
    names
}

/// `{simple_class_name: simple_superclass_name_or_None}` for each
/// top-level class declaration in the file (interfaces/enums/records
/// have no superclass in the Java sense — absent from the dict, not
/// `None`). Needed to resolve `super.foo()`
/// (`java_call_graph.rs`). Nested classes out of scope, same
/// limitation as `collect_java_class_names`.
pub fn collect_java_superclass(root: Node, source: &[u8]) -> BTreeMap<String, Option<String>> {
    const TYPE_NODE_KINDS: [&str; 3] =
        ["type_identifier", "scoped_type_identifier", "generic_type"];
    let mut out = BTreeMap::new();
    let mut w = root.walk();
    for child in root.named_children(&mut w) {
        if child.kind() != "class_declaration" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let cname = text(name_node, source);
        let simple_super = child.child_by_field_name("superclass").and_then(|sc| {
            sc.named_children(&mut sc.walk())
                .find(|c| TYPE_NODE_KINDS.contains(&c.kind()))
                .map(|type_node| simple_type_text(type_node, source))
        });
        out.insert(cname, simple_super);
    }
    out
}

fn simple_type_text(type_node: Node, source: &[u8]) -> String {
    let t = text(type_node, source);
    let before_generic = t.split('<').next().unwrap_or(&t).to_string();
    before_generic
        .rsplit('.')
        .next()
        .unwrap_or(&before_generic)
        .to_string()
}

// ============================================================================
// Free functions — resolution without depending on a stateful registry
// (needed by `java_call_graph.rs::JavaCallGraph::build`, which
// builds its edges BEFORE summaries exist).
// ============================================================================

/// Returns `fqcn -> filepath`, or `None` if carried by several
/// files (ambiguous, anti-FP — better to miss a flow than
/// invent a false one). `class_names_by_file = {filepath: (package,
/// [class_names])}`.
pub fn build_fqcn_index(
    class_names_by_file: &BTreeMap<String, (String, Vec<String>)>,
) -> BTreeMap<String, Option<String>> {
    let mut index: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    for (fp, (package, class_names)) in class_names_by_file {
        for cname in class_names {
            let fqcn = if package.is_empty() {
                cname.clone()
            } else {
                format!("{package}.{cname}")
            };
            match owner.get(&fqcn) {
                Some(existing) if existing != fp => {
                    index.insert(fqcn, None);
                }
                _ => {
                    owner.insert(fqcn.clone(), fp.clone());
                    index.insert(fqcn, Some(fp.clone()));
                }
            }
        }
    }
    index
}

/// Returns `{simple_class_name: defining_file}` visible from
/// `filepath`: classes from the same package (auto-visible, Java
/// specificity) + explicit non-static imports (`import pkg.Class`/
/// `import pkg.*`). An ambiguous FQCN (`fqcn_index[...] is None`) is
/// excluded. Static imports are NOT handled here (see
/// [`build_static_import_bindings`] — different semantics: they
/// expose a bare member, not a class).
pub fn resolve_visible_classes(
    filepath: &str,
    package: &str,
    imports: &[JavaImportInfo],
    class_names_by_file: &BTreeMap<String, (String, Vec<String>)>,
    fqcn_index: &BTreeMap<String, Option<String>>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (other_fp, (other_package, other_classes)) in class_names_by_file {
        if other_fp == filepath || other_package != package {
            continue;
        }
        for cname in other_classes {
            out.insert(cname.clone(), other_fp.clone());
        }
    }
    for imp in imports {
        if imp.is_static {
            continue;
        }
        if imp.wildcard {
            for (other_fp, (other_package, other_classes)) in class_names_by_file {
                if other_fp == filepath || other_package != &imp.path {
                    continue;
                }
                for cname in other_classes {
                    out.insert(cname.clone(), other_fp.clone());
                }
            }
            continue;
        }
        let Some(Some(target_fp)) = fqcn_index.get(&imp.path) else {
            continue;
        };
        let cname = imp.path.rsplit('.').next().unwrap_or(&imp.path);
        out.insert(cname.to_string(), target_fp.clone());
    }
    out
}

/// `import static pkg.Class.member;` / `import static pkg.Class.*;` →
/// `{bare_name: (target_file, "Class.member")}`. Mirrors the
/// `is_static` branches of import resolution, but resolves to
/// [`NodeKey`] (the graph does not yet have a `FunctionSummary` when its
/// edges are built) rather than looking up directly in already
/// computed summaries. `file_function_names = {filepath: {dotted
/// names "Class.member" known in this file}}`, needed so an
/// edge is produced ONLY if the static member actually exists
/// (same anti-FP safeguard as the rest of this module).
pub fn build_static_import_bindings(
    // Unused (faithful to `java_module_registry.py::
    // build_static_import_bindings`, which receives `filepath` without ever
    // reading it — resolution depends only on `imports`/`fqcn_index`/
    // `file_function_names`).
    _filepath: &str,
    imports: &[JavaImportInfo],
    fqcn_index: &BTreeMap<String, Option<String>>,
    file_function_names: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, NodeKey> {
    let mut out = BTreeMap::new();
    for imp in imports {
        if !imp.is_static {
            continue;
        }
        if imp.wildcard {
            let Some(Some(target_fp)) = fqcn_index.get(&imp.path) else {
                continue;
            };
            let cname = imp.path.rsplit('.').next().unwrap_or(&imp.path);
            let prefix = format!("{cname}.");
            if let Some(names) = file_function_names.get(target_fp) {
                for dotted in names {
                    if let Some(bare) = dotted.strip_prefix(&prefix) {
                        out.entry(bare.to_string())
                            .or_insert_with(|| (target_fp.clone(), dotted.clone()));
                    }
                }
            }
            continue;
        }
        let Some((class_fqcn, member)) = imp.path.rsplit_once('.') else {
            continue;
        };
        let Some(Some(target_fp)) = fqcn_index.get(class_fqcn) else {
            continue;
        };
        let cname = class_fqcn.rsplit('.').next().unwrap_or(class_fqcn);
        let dotted = format!("{cname}.{member}");
        if file_function_names
            .get(target_fp)
            .is_some_and(|names| names.contains(&dotted))
        {
            out.insert(member.to_string(), (target_fp.clone(), dotted));
        }
    }
    out
}
