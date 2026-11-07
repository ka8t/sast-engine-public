//! Construction of the CFG (Control Flow Graph) for C# — tree-sitter
//! front-end. Mirrors `java_cfg.rs`, a faithful port of
//! `Audit/sca/dataflow/csharp_cfg.py` (ticket #78, spec #77).
//!
//! Fully reuses the language-neutral structures from `cfg.rs`
//! (`Cfg`/`CfgNode`/`NodeKind`/`EdgeLabel`/`prune_unreachable`/
//! `field_children`) — same general contract as any language front-end
//! for the dataflow engine (cf. `dataflow/mod.rs` doc).
//!
//! Entry unit: a tree-sitter `block` node (method/constructor/accessor
//! body). Unlike Java, this grammar has NO separate `constructor_body`
//! type — constructors, methods, and property accessors (`get`/`set`)
//! all use `block` (verified empirically, cf. `_BODY_NODE_KINDS`).
//! Expression-bodied methods/constructors (`int F(int a) => a * 2;`,
//! body = `arrow_expression_clause`) are built as one implicit
//! `return <expr>;` node (ticket #123) — what the C# compiler does.
//! **Deliberate deviation from Python**: `csharp_cfg.py` receives the
//! same node and visits the bare expression as a statement, which its
//! lowering turns into a no-op, so taint inside such methods is lost
//! on both sides of the original port. Expression-bodied *properties*
//! are not collected as functions at all (`csharp_summary.rs`).
//!
//! Differences verified empirically against the Java front-end (real
//! parsing with `tree-sitter-c-sharp` 0.23.5, never assumed from the
//! Java grammar nor blindly copied from the Python docstring — any
//! doubt was resolved by dumping the real tree, cf. `mod tests::explore`
//! which has since disappeared from this file's history):
//!   - `using_statement` (disposal, `using (var x = ...) { }`) is a
//!     tree-sitter type DISTINCT from `using_directive` (import) — no
//!     ambiguity. Its resource clause (`variable_declaration` or a bare
//!     expression) has NO field name (positional child) — found by
//!     scanning named children, excluding `body`.
//!   - No separate "try-with-resources" form: only `try_statement`,
//!     with the resource being a `using_statement` nested in the try's
//!     `body` like any other statement. `catch_clause`/`finally_clause`
//!     are NOT named fields of `try_statement` — scanned by type over
//!     positional children, as in Java. `finally_clause` itself does
//!     NOT expose a `body` field — its `block` child has no field name
//!     either (scanned by type).
//!   - `lock_statement` (lock, no direct Java equivalent — the closest
//!     is `synchronized`) does NOT expose a `body` field (verified
//!     empirically — contrary to a naive assumption by analogy with
//!     Java's `synchronized_statement`): its `block` is scanned by
//!     type, same handling as `finally_clause`.
//!   - `switch_statement` (not `switch_expression`: C# 8+ switch
//!     EXPRESSIONS, `x switch { ... }`, are a distinct type, never
//!     encountered in statement position — left opaque), with a `value`
//!     field (not `condition`) and a `body` of type `switch_body`
//!     containing `switch_section`s (not
//!     `switch_block_statement_group`/`switch_rule`). Fall-through
//!     (`case 1: case 2: f(); break;`) verified to produce the SAME
//!     pattern as in Java: an empty section per label with no statement
//!     of its own, which must fall through into the next section.
//!     Unlike Java, labels AND statements of a `switch_section` are in
//!     the SAME flat list of named children (no `switch_label` wrapper)
//!     — distinguished by an explicit list of label pattern types
//!     (`constant_pattern`, etc.), with everything else treated as a
//!     statement (conservative: never drops a statement — an
//!     unenumerated pattern type would be executed wrongly rather than
//!     silently dropped).
//!   - `break_statement`/`continue_statement` NEVER carry a label (C#
//!     has no labeled break/continue — `goto label;` plays that role, a
//!     distinct mechanism, not modeled, left to `_ => append_to_basic`).
//!     No `pending_label`/`labeled_statement` mechanism on the C# side
//!     (unlike Java); `break` still uses the unified loop+switch stack
//!     (`break_stack`): an unlabeled `break` inside a `switch` inside a
//!     loop must resolve to the switch, exactly as in Java.
//!   - `for_statement` field names verified: `initializer`/
//!     `condition`/`update`/`body` (Java uses `init`, not
//!     `initializer`).
//!   - `foreach_statement` field names verified: `type`/`left` (loop
//!     variable)/`right` (collection)/`body`.
//!   - `if_statement`/`while_statement`: same field names as in Java
//!     (`condition`/`consequence`/`alternative`;
//!     `condition`/`body`).
//!   - `do_statement` (`do { ... } while (cond);`): a distinct type,
//!     with no equivalent in `java_cfg.rs` (absent from its targeted
//!     grammar as of today) — body executed at least once before the
//!     first condition check.
//!   - The Juliet corpus methods (validation, ticket #81) are wrapped
//!     in a REAL `preproc_if` node (`#if (!OMITBAD)`), not simply
//!     stripped out like a classic C preprocessor — verified
//!     empirically: without explicit flattening
//!     (`flatten_preproc_members`), NO method is discovered inside a
//!     class body wrapped this way (bug already documented on the
//!     Python side, `csharp_summary.py::_iter_members_flattening_preproc`).
//!     The CFG builder itself does not need this (its input is already
//!     a `block` node given directly) — exposed here (not in
//!     `csharp_summary.rs`) because it is a generic tree-sitter utility
//!     and ticket #78 requires proof of it at this stage.

use super::cfg::{Cfg, EdgeLabel, NodeKind, field_children, prune_unreachable};
use tree_sitter::Node;

/// C# tree-sitter node accepted as an executable entry point for
/// `build_csharp_cfg` (method/constructor/accessor body). No separate
/// `constructor_body` type in this grammar, unlike Java.
const BODY_NODE_KINDS: [&str; 2] = ["block", "arrow_expression_clause"];

/// A `break_stack` entry — a loop or switch reachable via `break`. No
/// `label` field (unlike Java): see the module doc.
struct BreakTarget {
    exit_id: usize,
    is_loop: bool,
    /// Used only if `is_loop` (target of `continue`).
    loop_head_id: Option<usize>,
}

struct CSharpCfgBuilder<'tree, 'src> {
    cfg: Cfg<'tree>,
    break_stack: Vec<BreakTarget>,
    /// Stack of lists of active `catch` handlers (HANDLER node ids), to
    /// connect a `throw` to its closest handler(s).
    try_handler_stack: Vec<Vec<usize>>,
    source: &'src [u8],
}

/// Builds a CFG from a C# method/constructor/accessor body (tree-sitter
/// `block` node — NOT the whole file, cf. module doc).
pub fn build_csharp_cfg<'tree>(body: Node<'tree>, source: &[u8]) -> Cfg<'tree> {
    debug_assert!(
        BODY_NODE_KINDS.contains(&body.kind()),
        "build_csharp_cfg expects a block or arrow_expression_clause node, got {:?}",
        body.kind()
    );
    let mut builder = CSharpCfgBuilder {
        cfg: Cfg::new(),
        break_stack: Vec::new(),
        try_handler_stack: Vec::new(),
        source,
    };
    builder.cfg.entry = builder.cfg.add_node(NodeKind::Entry, "entry");
    builder.cfg.exit = builder.cfg.add_node(NodeKind::Exit, "exit");

    // `=> expr`: a single return-like node holding the clause itself;
    // `csharp_lowering.rs` lowers `arrow_expression_clause` as
    // `return <expr>` (ticket #123).
    if body.kind() == "arrow_expression_clause" {
        let entry = builder.cfg.entry;
        builder.visit_return(body, entry);
        prune_unreachable(&mut builder.cfg);
        return builder.cfg;
    }
    let mut w = body.walk();
    let stmts: Vec<Node<'tree>> = body.named_children(&mut w).collect();
    let cursor = builder.visit_stmts(&stmts, Some(builder.cfg.entry));
    if let Some(c) = cursor {
        builder.cfg.add_edge(c, builder.cfg.exit, EdgeLabel::Flow);
    }
    prune_unreachable(&mut builder.cfg);
    builder.cfg
}

/// C# preprocessor wrapper types to traverse transparently (cf. module
/// doc — Juliet corpus).
const PREPROC_CONTAINER_KINDS: [&str; 3] = ["preproc_if", "preproc_elif", "preproc_else"];

/// Recursively flattens the named children of `body`, traversing any
/// nested `preproc_if`/`preproc_elif`/`preproc_else` wrapper (which can
/// itself nest other preprocessor branches, e.g. `#if X ... #elif Y
/// ... #endif`). No preprocessor condition evaluation: each branch is
/// treated as reachable code (same conservative philosophy as the rest
/// of the engine), consistent with
/// `csharp_summary.py::_iter_members_flattening_preproc`.
pub(super) fn flatten_preproc_members<'tree>(body: Node<'tree>) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut w = body.walk();
    for member in body.named_children(&mut w) {
        if PREPROC_CONTAINER_KINDS.contains(&member.kind()) {
            out.extend(flatten_preproc_members(member));
        } else {
            out.push(member);
        }
    }
    out
}

/// Label pattern types recognized inside a `switch_section` (labels AND
/// statements share the same flat list of named children in this
/// grammar — no `switch_label` wrapper like in Java). Any type NOT
/// present here is treated as a statement — conservative in the sense
/// of never dropping a statement (cf. module doc).
const SWITCH_LABEL_PATTERN_KINDS: [&str; 5] = [
    "constant_pattern",
    "discard_pattern",
    "declaration_pattern",
    "var_pattern",
    "case_pattern_switch_label",
];

/// Literal node types accepted as the value of a simple
/// `constant_pattern`, to let `eval_const` statically determine which
/// `case` is active (same list as
/// `java_cfg.rs::LITERAL_LABEL_KINDS`, adapted to this grammar's
/// literal node names).
const LITERAL_LABEL_KINDS: [&str; 6] = [
    "character_literal",
    "string_literal",
    "integer_literal",
    "real_literal",
    "boolean_literal",
    "null_literal",
];

impl<'tree, 'src> CSharpCfgBuilder<'tree, 'src> {
    // --------------------------------------------------------------- visitors

    fn visit_stmts(&mut self, stmts: &[Node<'tree>], cursor: Option<usize>) -> Option<usize> {
        let mut cursor = cursor;
        for &stmt in stmts {
            let Some(c) = cursor else { break };
            cursor = self.visit_stmt(stmt, c);
        }
        cursor
    }

    fn visit_stmt(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        match stmt.kind() {
            "block" => self.visit_block(stmt, cursor),
            "return_statement" => self.visit_return(stmt, cursor),
            "throw_statement" => self.visit_throw(stmt, cursor),
            "break_statement" => self.visit_break(stmt, cursor),
            "continue_statement" => self.visit_continue(stmt, cursor),
            "if_statement" => self.visit_if(stmt, cursor),
            "while_statement" => self.visit_while(stmt, cursor),
            "do_statement" => self.visit_do(stmt, cursor),
            "for_statement" => self.visit_for(stmt, cursor),
            "foreach_statement" => self.visit_foreach(stmt, cursor),
            "try_statement" => self.visit_try(stmt, cursor),
            "using_statement" => self.visit_using(stmt, cursor),
            "lock_statement" => self.visit_lock(stmt, cursor),
            "switch_statement" => self.visit_switch(stmt, cursor),
            // Catch-all: linear statement (or unmodeled construct, e.g.
            // nested method_declaration/class_declaration,
            // goto_statement, local function) → opaque append to the
            // current BasicBlock. Conservative by construction.
            _ => Some(self.append_to_basic(stmt, cursor)),
        }
    }

    // ------------------------------------------------------------- basic block

    fn append_to_basic(&mut self, stmt: Node<'tree>, cursor: usize) -> usize {
        let can_extend = {
            let node = &self.cfg.nodes[&cursor];
            node.kind == NodeKind::Basic && self.cfg.successors(cursor).is_empty()
        };
        if can_extend {
            self.cfg
                .nodes
                .get_mut(&cursor)
                .unwrap()
                .statements
                .push(stmt);
            return cursor;
        }
        let bb = self
            .cfg
            .add_node(NodeKind::Basic, format!("bb_{}", self.cfg.nodes.len()));
        self.cfg.nodes.get_mut(&bb).unwrap().statements.push(stmt);
        self.cfg.add_edge(cursor, bb, EdgeLabel::Flow);
        bb
    }

    // Bare block (`{ ... }` in statement position, not a method body):
    // descends into its content.
    fn visit_block(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let mut w = stmt.walk();
        let stmts: Vec<Node<'tree>> = stmt.named_children(&mut w).collect();
        self.visit_stmts(&stmts, Some(cursor))
    }

    fn visit_return(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let bb = self.cfg.add_node(
            NodeKind::Basic,
            format!("return_{}", stmt.start_position().row),
        );
        self.cfg.nodes.get_mut(&bb).unwrap().statements.push(stmt);
        self.cfg.add_edge(cursor, bb, EdgeLabel::Flow);
        self.cfg.add_edge(bb, self.cfg.exit, EdgeLabel::Flow);
        None
    }

    // Throw — equivalent of `raise` on the Python side.

    fn visit_throw(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let rs = self.cfg.add_node(
            NodeKind::RaiseSite,
            format!("throw_{}", stmt.start_position().row),
        );
        self.cfg.nodes.get_mut(&rs).unwrap().statements.push(stmt);
        self.cfg.add_edge(cursor, rs, EdgeLabel::Flow);
        let handler_ids = self.active_catch_handlers();
        if handler_ids.is_empty() {
            self.cfg.add_edge(rs, self.cfg.exit, EdgeLabel::Escape);
        } else {
            for hid in handler_ids {
                self.cfg.add_edge(rs, hid, EdgeLabel::Except);
            }
        }
        None
    }

    fn active_catch_handlers(&self) -> Vec<usize> {
        self.try_handler_stack.last().cloned().unwrap_or_default()
    }

    // Break / Continue — never labeled (cf. module doc), unified
    // loop+switch stack for `break` only.

    fn visit_break(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let _ = stmt;
        let Some(target) = self.break_stack.last() else {
            return Some(cursor); // source code error; conservative, no-op
        };
        self.cfg.add_edge(cursor, target.exit_id, EdgeLabel::Flow);
        None
    }

    fn visit_continue(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let _ = stmt;
        let Some(target) = self.break_stack.iter().rev().find(|t| t.is_loop) else {
            return Some(cursor); // no enclosing loop; conservative, no-op
        };
        let loop_head_id = target.loop_head_id.unwrap();
        self.cfg.add_edge(cursor, loop_head_id, EdgeLabel::Back);
        None
    }

    // If / else-if / else — direct recursion via `visit_stmt`: the
    // `alternative` field is either another `if_statement` (else-if)
    // or a `block` (else), both dispatch naturally.

    fn visit_if(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let condition = stmt.child_by_field_name("condition");
        let branch = self.cfg.add_node(NodeKind::Branch, format!("if_{lineno}"));
        self.cfg.nodes.get_mut(&branch).unwrap().condition = condition;
        self.cfg.add_edge(cursor, branch, EdgeLabel::Flow);

        let true_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("if_true_{lineno}"));
        self.cfg.add_edge(branch, true_seed, EdgeLabel::True);
        let t_end = match stmt.child_by_field_name("consequence") {
            Some(c) => self.visit_stmt(c, true_seed),
            None => Some(true_seed),
        };

        let false_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("if_false_{lineno}"));
        self.cfg.add_edge(branch, false_seed, EdgeLabel::False);
        let f_end = match stmt.child_by_field_name("alternative") {
            Some(alt) => self.visit_stmt(alt, false_seed),
            None => Some(false_seed),
        };

        let join = self
            .cfg
            .add_node(NodeKind::Join, format!("if_join_{lineno}"));
        if let Some(t) = t_end {
            self.cfg.add_edge(t, join, EdgeLabel::Flow);
        }
        if let Some(f) = f_end {
            self.cfg.add_edge(f, join, EdgeLabel::Flow);
        }
        if t_end.is_none() && f_end.is_none() {
            None
        } else {
            Some(join)
        }
    }

    // While

    fn visit_while(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let condition = stmt.child_by_field_name("condition");
        let loop_head = self.cfg.add_node(NodeKind::Loop, format!("while_{lineno}"));
        self.cfg.nodes.get_mut(&loop_head).unwrap().condition = condition;
        self.cfg.add_edge(cursor, loop_head, EdgeLabel::Flow);
        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("while_end_{lineno}"));

        self.break_stack.push(BreakTarget {
            exit_id: exit_join,
            is_loop: true,
            loop_head_id: Some(loop_head),
        });

        let body_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("while_body_{lineno}"));
        self.cfg.add_edge(loop_head, body_seed, EdgeLabel::True);
        let body_end = match stmt.child_by_field_name("body") {
            Some(b) => self.visit_stmt(b, body_seed),
            None => Some(body_seed),
        };
        if let Some(be) = body_end {
            self.cfg.add_edge(be, loop_head, EdgeLabel::Back);
        }

        self.cfg.add_edge(loop_head, exit_join, EdgeLabel::False);
        self.break_stack.pop();
        Some(exit_join)
    }

    // Do-while — condition checked AFTER the body (absent from
    // `java_cfg.rs`, a distinct `do_statement` type in this grammar).
    // The body is visited ONLY ONCE, from a `body_seed` fed both by the
    // initial unconditional entry (`cursor`: the body always executes
    // at least once before the first condition check) and by the TRUE
    // branch of `loop_head` (re-entry) — avoids revisiting the body's
    // statements a second time, which would duplicate CFG nodes.

    fn visit_do(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let condition = stmt.child_by_field_name("condition");
        let loop_head = self.cfg.add_node(NodeKind::Loop, format!("do_{lineno}"));
        self.cfg.nodes.get_mut(&loop_head).unwrap().condition = condition;
        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("do_end_{lineno}"));

        self.break_stack.push(BreakTarget {
            exit_id: exit_join,
            is_loop: true,
            loop_head_id: Some(loop_head),
        });

        let body_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("do_body_{lineno}"));
        self.cfg.add_edge(cursor, body_seed, EdgeLabel::Flow);
        let body_end = match stmt.child_by_field_name("body") {
            Some(b) => self.visit_stmt(b, body_seed),
            None => Some(body_seed),
        };
        if let Some(be) = body_end {
            self.cfg.add_edge(be, loop_head, EdgeLabel::Flow);
        }

        self.cfg.add_edge(loop_head, body_seed, EdgeLabel::Back);
        self.cfg.add_edge(loop_head, exit_join, EdgeLabel::False);
        self.break_stack.pop();
        Some(exit_join)
    }

    // For (classic) — `initializer` field (not `init` like Java).

    fn visit_for(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let pre_cursor = match stmt.child_by_field_name("initializer") {
            Some(init) => self.visit_stmt(init, cursor),
            None => Some(cursor),
        }?;

        let condition = stmt.child_by_field_name("condition");
        let loop_head = self.cfg.add_node(NodeKind::Loop, format!("for_{lineno}"));
        self.cfg.nodes.get_mut(&loop_head).unwrap().condition = condition;
        self.cfg.add_edge(pre_cursor, loop_head, EdgeLabel::Flow);
        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("for_end_{lineno}"));

        self.break_stack.push(BreakTarget {
            exit_id: exit_join,
            is_loop: true,
            loop_head_id: Some(loop_head),
        });

        let body_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("for_body_{lineno}"));
        self.cfg.add_edge(loop_head, body_seed, EdgeLabel::True);
        let body_end = match stmt.child_by_field_name("body") {
            Some(b) => self.visit_stmt(b, body_seed),
            None => Some(body_seed),
        };

        // update (i++, etc.) — one or more, executed after the body,
        // before looping back to the condition. tree-sitter exposes
        // multiple `update`s (repeated field, e.g. `for (;; i++,
        // j--)`) — all collected via `field_children`.
        let update_nodes = field_children(stmt, "update");
        if let Some(mut upd_cursor) = body_end {
            for upd in update_nodes {
                upd_cursor = self.append_to_basic(upd, upd_cursor);
            }
            self.cfg.add_edge(upd_cursor, loop_head, EdgeLabel::Back);
        }

        self.cfg.add_edge(loop_head, exit_join, EdgeLabel::False);
        self.break_stack.pop();
        Some(exit_join)
    }

    // For-each — `type`/`left`/`right`/`body` fields (not
    // `value`/`name` like Java's `enhanced_for_statement`).

    fn visit_foreach(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let value = stmt.child_by_field_name("right"); // collection/iterable
        let loop_head = self
            .cfg
            .add_node(NodeKind::Loop, format!("foreach_{lineno}"));
        {
            let n = self.cfg.nodes.get_mut(&loop_head).unwrap();
            n.condition = value;
            n.for_target = stmt.child_by_field_name("left");
        }
        self.cfg.add_edge(cursor, loop_head, EdgeLabel::Flow);
        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("foreach_end_{lineno}"));

        self.break_stack.push(BreakTarget {
            exit_id: exit_join,
            is_loop: true,
            loop_head_id: Some(loop_head),
        });

        let body_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("foreach_body_{lineno}"));
        self.cfg.add_edge(loop_head, body_seed, EdgeLabel::True);
        let body_end = match stmt.child_by_field_name("body") {
            Some(b) => self.visit_stmt(b, body_seed),
            None => Some(body_seed),
        };
        if let Some(be) = body_end {
            self.cfg.add_edge(be, loop_head, EdgeLabel::Back);
        }

        self.cfg.add_edge(loop_head, exit_join, EdgeLabel::False);
        self.break_stack.pop();
        Some(exit_join)
    }

    // Try (with or without a nested `using_statement` — no separate
    // "try-with-resources" form in this grammar, cf. module doc).
    // `catch_clause`/`finally_clause` are scanned by type over the
    // positional children (not named fields).

    fn visit_try(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let try_entry = self
            .cfg
            .add_node(NodeKind::TryEntry, format!("try_{lineno}"));
        self.cfg.add_edge(cursor, try_entry, EdgeLabel::Flow);

        let mut w = stmt.walk();
        let catch_clauses: Vec<Node<'tree>> = stmt
            .children(&mut w)
            .filter(|c| c.kind() == "catch_clause")
            .collect();
        let mut w2 = stmt.walk();
        let finally_clauses: Vec<Node<'tree>> = stmt
            .children(&mut w2)
            .filter(|c| c.kind() == "finally_clause")
            .collect();

        let mut handler_ids: Vec<usize> = Vec::new();
        for h in &catch_clauses {
            let decl = h
                .children(&mut h.walk())
                .find(|c| c.kind() == "catch_declaration");
            let hid = self.cfg.add_node(
                NodeKind::Handler,
                format!("catch_{}", h.start_position().row),
            );
            self.cfg.nodes.get_mut(&hid).unwrap().handler_type = decl;
            handler_ids.push(hid);
        }

        self.try_handler_stack.push(handler_ids.clone());
        let body_cursor = match stmt.child_by_field_name("body") {
            Some(b) => self.visit_stmt(b, try_entry),
            None => Some(try_entry),
        };
        self.try_handler_stack.pop();

        let mut handler_end_cursors: Vec<Option<usize>> = Vec::new();
        for (h, &hid) in catch_clauses.iter().zip(handler_ids.iter()) {
            self.cfg.add_edge(try_entry, hid, EdgeLabel::Except);
            let h_body = h.child_by_field_name("body");
            handler_end_cursors.push(match h_body {
                Some(b) => self.visit_stmt(b, hid),
                None => Some(hid),
            });
        }

        // `finally_clause` does not expose a `body` field (verified
        // empirically, cf. module doc) — its `block` child is scanned
        // by type.
        let fin = if let Some(fc) = finally_clauses.first() {
            let fin_id = self
                .cfg
                .add_node(NodeKind::Finally, format!("finally_{lineno}"));
            if let Some(block) = fc.children(&mut fc.walk()).find(|c| c.kind() == "block") {
                let mut bw = block.walk();
                for s in block.named_children(&mut bw) {
                    self.cfg.nodes.get_mut(&fin_id).unwrap().statements.push(s);
                }
            }
            fin_id
        } else {
            self.cfg
                .add_node(NodeKind::Join, format!("try_join_{lineno}"))
        };

        if let Some(bc) = body_cursor {
            self.cfg.add_edge(bc, fin, EdgeLabel::Flow);
        }
        for hc in handler_end_cursors.into_iter().flatten() {
            self.cfg.add_edge(hc, fin, EdgeLabel::Flow);
        }

        Some(fin)
    }

    // Using statement (resource disposal) — like a Python `with`:
    // opaque wrapper for the resource declaration (unnamed field, cf.
    // module doc), then descends into the body.

    fn visit_using(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let body = stmt.child_by_field_name("body");
        let mut w = stmt.walk();
        let resource = stmt.named_children(&mut w).find(|c| Some(*c) != body);
        let entry_cursor = match resource {
            Some(r) => self.append_to_basic(r, cursor),
            None => cursor,
        };
        match body {
            Some(b) => self.visit_stmt(b, entry_cursor),
            None => Some(entry_cursor),
        }
    }

    // Lock — like `synchronized` in Java: opaque wrapper then descends
    // into the body. `lock_statement` does NOT expose a `body` field
    // (verified empirically, contrary to a naive assumption by analogy
    // with `synchronized` — cf. module doc): the `block` is scanned by
    // type.

    fn visit_lock(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lock_bb = self.cfg.add_node(
            NodeKind::Basic,
            format!("lock_{}", stmt.start_position().row),
        );
        self.cfg
            .nodes
            .get_mut(&lock_bb)
            .unwrap()
            .statements
            .push(stmt);
        self.cfg.add_edge(cursor, lock_bb, EdgeLabel::Flow);
        let body = stmt
            .children(&mut stmt.walk())
            .find(|c| c.kind() == "block");
        match body {
            Some(b) => self.visit_stmt(b, lock_bb),
            None => Some(lock_bb),
        }
    }

    // Switch (colon form, the only statement form in this grammar —
    // cf. module doc for the empirical verification of fall-through and
    // the label/statement distinction).

    fn visit_switch(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let subject = stmt.child_by_field_name("value");
        let Some(body) = stmt.child_by_field_name("body") else {
            return Some(cursor);
        };
        let mut w = body.walk();
        let groups: Vec<Node<'tree>> = body
            .named_children(&mut w)
            .filter(|c| c.kind() == "switch_section")
            .collect();
        if groups.is_empty() {
            return Some(cursor);
        }

        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("switch_end_{lineno}"));
        self.break_stack.push(BreakTarget {
            exit_id: exit_join,
            is_loop: false,
            loop_head_id: None,
        });

        let mut prev_false = cursor;
        // `None` = no group processed yet; `Some(None)` = the last
        // group ended unreachable; `Some(Some(id))` = reachable, to be
        // linked to the next group (fall-through).
        let mut fallthrough_cursor: Option<Option<usize>> = None;

        for (i, grp) in groups.iter().enumerate() {
            let labels: Vec<Node<'tree>> = grp
                .named_children(&mut grp.walk())
                .filter(|c| SWITCH_LABEL_PATTERN_KINDS.contains(&c.kind()))
                .collect();
            let branch = self
                .cfg
                .add_node(NodeKind::Branch, format!("switch_case_{lineno}_{i}"));
            {
                let n = self.cfg.nodes.get_mut(&branch).unwrap();
                n.condition = subject;
                n.switch_case_label = Self::switch_case_condition(*grp, &labels);
            }
            self.cfg.add_edge(prev_false, branch, EdgeLabel::Flow);

            let body_seed = self
                .cfg
                .add_node(NodeKind::Join, format!("switch_body_{lineno}_{i}"));
            self.cfg.add_edge(branch, body_seed, EdgeLabel::True);
            if let Some(Some(fc)) = fallthrough_cursor {
                self.cfg.add_edge(fc, body_seed, EdgeLabel::Flow);
            }

            let stmts: Vec<Node<'tree>> = grp
                .named_children(&mut grp.walk())
                .filter(|c| !SWITCH_LABEL_PATTERN_KINDS.contains(&c.kind()))
                .collect();
            let body_end = self.visit_stmts(&stmts, Some(body_seed));
            fallthrough_cursor = Some(body_end);

            let next_false = self
                .cfg
                .add_node(NodeKind::Join, format!("switch_else_{lineno}_{i}"));
            self.cfg.add_edge(branch, next_false, EdgeLabel::False);
            prev_false = next_false;
        }

        self.cfg.add_edge(prev_false, exit_join, EdgeLabel::Flow);
        if let Some(Some(fc)) = fallthrough_cursor {
            self.cfg.add_edge(fc, exit_join, EdgeLabel::Flow);
        }

        self.break_stack.pop();
        Some(exit_join)
    }

    /// Condition of a `case` — the simple literal label of a single
    /// `constant_pattern` (`case 1:`), to let `eval_const` statically
    /// determine which `case` is active. For `default` (first
    /// positional child of type `default`, an unnamed token — hence
    /// absent from `labels`), a multi-label group, or a non-literal
    /// pattern (type/declaration, type resolution out of scope):
    /// `None` (opaque, conservative) — same strategy as
    /// `java_cfg.rs::switch_case_condition`.
    fn switch_case_condition(grp: Node<'tree>, labels: &[Node<'tree>]) -> Option<Node<'tree>> {
        if grp.child(0).map(|c| c.kind()) == Some("default") {
            return None;
        }
        if labels.len() != 1 || labels[0].kind() != "constant_pattern" {
            return None;
        }
        let mut w = labels[0].walk();
        let value_nodes: Vec<Node<'tree>> = labels[0].named_children(&mut w).collect();
        if value_nodes.len() != 1 || !LITERAL_LABEL_KINDS.contains(&value_nodes[0].kind()) {
            return None;
        }
        Some(value_nodes[0])
    }
}

// ============================================================================
// Tests — mirrors `Audit/tests/dataflow/test_cfg_csharp.py` (same
// invariants), with density equivalent to `java_cfg.rs::tests` (~40
// tests), plus the C#-specific syntax cases listed in the module doc.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tree_sitter::Parser;

    fn parse_csharp(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_c_sharp::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn find_first<'t>(node: Node<'t>, kind: &str) -> Option<Node<'t>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut w = node.walk();
        for child in node.children(&mut w) {
            if let Some(found) = find_first(child, kind) {
                return Some(found);
            }
        }
        None
    }

    /// Parses a C# method body (wrapped in a class/method), builds its
    /// CFG, and exposes it to `f`.
    fn with_cfg<R>(method_body_src: &str, f: impl FnOnce(&Cfg) -> R) -> R {
        let src = format!("class Foo {{ void t() {{ {method_body_src} }} }}");
        let tree = parse_csharp(&src);
        assert!(
            !tree.root_node().has_error(),
            "syntaxe C# invalide : {method_body_src:?}"
        );
        let method = find_first(tree.root_node(), "method_declaration").unwrap();
        let body = method.child_by_field_name("body").unwrap();
        let cfg = build_csharp_cfg(body, src.as_bytes());
        f(&cfg)
    }

    fn count_kind(cfg: &Cfg, kind: NodeKind) -> usize {
        cfg.nodes.values().filter(|n| n.kind == kind).count()
    }

    fn count_label(cfg: &Cfg, label: EdgeLabel) -> usize {
        cfg.edges.iter().filter(|e| e.label == label).count()
    }

    fn has_path(cfg: &Cfg, src: usize, dst: usize) -> bool {
        let mut visited = HashSet::new();
        let mut stack = vec![src];
        while let Some(n) = stack.pop() {
            if n == dst {
                return true;
            }
            if !visited.insert(n) {
                continue;
            }
            for e in cfg.successors(n) {
                stack.push(e.dst);
            }
        }
        false
    }

    fn all_reachable_from_entry(cfg: &Cfg) -> bool {
        let mut visited = HashSet::new();
        let mut stack = vec![cfg.entry];
        while let Some(n) = stack.pop() {
            if !visited.insert(n) {
                continue;
            }
            for e in cfg.successors(n) {
                stack.push(e.dst);
            }
        }
        visited == cfg.nodes.keys().copied().collect::<HashSet<_>>()
    }

    // ------------------------------------------------------- invariants

    #[test]
    fn test_unique_entry_and_exit() {
        for src in [
            "",
            "int x = 1;",
            "int x = 1; int y = 2; int z = 3;",
            "if (x) { y = 1; }",
            "if (x) { y = 1; } else { y = 2; }",
            "while (x) { x = x - 1; }",
            "for (int i = 0; i < 10; i++) { doIt(); }",
            "try { f(); } catch (Exception e) { }",
            "return;",
        ] {
            with_cfg(src, |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Entry), 1, "src={src:?}");
                assert_eq!(count_kind(cfg, NodeKind::Exit), 1, "src={src:?}");
                assert!(cfg.nodes.contains_key(&cfg.entry));
                assert!(cfg.nodes.contains_key(&cfg.exit));
            });
        }
    }

    #[test]
    fn test_entry_has_no_predecessors() {
        for src in [
            "int x = 1;",
            "if (x) { y = 1; } else { y = 2; }",
            "while (x) { x = x - 1; }",
        ] {
            with_cfg(src, |cfg| {
                assert!(cfg.predecessors(cfg.entry).is_empty(), "src={src:?}");
            });
        }
    }

    #[test]
    fn test_exit_has_no_successors() {
        for src in ["int x = 1;", "if (x) { y = 1; } else { y = 2; }", "return;"] {
            with_cfg(src, |cfg| {
                assert!(cfg.successors(cfg.exit).is_empty(), "src={src:?}");
            });
        }
    }

    #[test]
    fn test_all_nodes_reachable_from_entry() {
        for src in [
            "int x = 1;",
            "if (x) { y = 1; } else { y = 2; }",
            "while (x) { x = x - 1; }",
            "foreach (var it in items) { doIt(it); }",
            "try { f(); } catch (Exception e) { g(); } finally { h(); }",
            "switch (x) { case 1: y = 1; break; default: y = 2; break; }",
            "do { f(); } while (x);",
        ] {
            with_cfg(src, |cfg| {
                assert!(all_reachable_from_entry(cfg), "src={src:?}");
            });
        }
    }

    // ------------------------------------------------------------ linear

    #[test]
    fn test_empty_body() {
        with_cfg("", |cfg| {
            assert_eq!(cfg.nodes.len(), 2); // entry + exit
            assert_eq!(cfg.edges.len(), 1);
            assert_eq!(cfg.edges[0].label, EdgeLabel::Flow);
        });
    }

    #[test]
    fn test_single_statement() {
        with_cfg("int x = 1;", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Basic), 1);
            assert_eq!(cfg.edges.len(), 2);
        });
    }

    #[test]
    fn test_linear_statements_aggregated() {
        with_cfg("int x = 1; int y = 2; int z = x + y; f(z);", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Basic), 1);
            let bb = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Basic)
                .unwrap();
            assert_eq!(bb.statements.len(), 4);
        });
    }

    #[test]
    fn test_nested_bare_block_not_opaque() {
        with_cfg("int x = 1; { int y = 2; } int z = 3;", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Basic), 1);
            let bb = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Basic)
                .unwrap();
            assert_eq!(bb.statements.len(), 3);
        });
    }

    // ------------------------------------------------------- if / else

    #[test]
    fn test_if_without_else() {
        with_cfg("if (x) { y = 1; } z = 2;", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Branch), 1);
            assert_eq!(count_label(cfg, EdgeLabel::True), 1);
            assert_eq!(count_label(cfg, EdgeLabel::False), 1);
        });
    }

    #[test]
    fn test_if_else() {
        with_cfg("if (x) { y = 1; } else { y = 2; }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Branch), 1);
            assert!(has_path(cfg, cfg.entry, cfg.exit));
        });
    }

    #[test]
    fn test_else_if_cascade() {
        with_cfg(
            "if (a) { x = 1; } else if (b) { x = 2; } else if (c) { x = 3; } else { x = 4; }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Branch), 3);
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_nested_if() {
        with_cfg(
            "if (a) { if (b) { x = 1; } else { x = 2; } } else { x = 3; }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Branch), 2);
            },
        );
    }

    #[test]
    fn test_if_with_return_in_branch() {
        with_cfg("if (x) { return; } y = 2;", |cfg| {
            assert!(has_path(cfg, cfg.entry, cfg.exit));
        });
    }

    // ---------------------------------------------------- while/for/foreach

    #[test]
    fn test_while_basic() {
        with_cfg("while (x > 0) { x = x - 1; }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Loop), 1);
            assert!(count_label(cfg, EdgeLabel::Back) >= 1);
            assert_eq!(count_label(cfg, EdgeLabel::True), 1);
            assert_eq!(count_label(cfg, EdgeLabel::False), 1);
        });
    }

    #[test]
    fn test_for_basic() {
        with_cfg("for (int i = 0; i < 10; i++) { doIt(); }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Loop), 1);
            assert!(count_label(cfg, EdgeLabel::Back) >= 1);
        });
    }

    #[test]
    fn test_for_multiple_updates() {
        with_cfg(
            "for (int i = 0, j = 10; i < j; i++, j--) { doIt(); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Loop), 1);
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_foreach_basic() {
        with_cfg("foreach (var s in items) { f(s); }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Loop), 1);
            assert!(count_label(cfg, EdgeLabel::Back) >= 1);
            let loop_node = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Loop)
                .unwrap();
            assert!(loop_node.for_target.is_some());
        });
    }

    #[test]
    fn test_nested_loops() {
        with_cfg(
            "for (int i = 0; i < 10; i++) { for (int j = 0; j < 10; j++) { f(i, j); } }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Loop), 2);
            },
        );
    }

    // ---------------------------------------------------------- do-while

    #[test]
    fn test_do_while_basic() {
        with_cfg("do { f(); } while (x);", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Loop), 1);
            assert!(count_label(cfg, EdgeLabel::Back) >= 1);
            assert!(has_path(cfg, cfg.entry, cfg.exit));
        });
    }

    #[test]
    fn test_do_while_body_visited_once() {
        // The body must not be duplicated (a single BasicBlock for
        // `f(); g();`, not two copies).
        with_cfg("do { f(); g(); } while (x);", |cfg| {
            let bodies: Vec<_> = cfg
                .nodes
                .values()
                .filter(|n| n.kind == NodeKind::Basic && n.statements.len() == 2)
                .collect();
            assert_eq!(bodies.len(), 1);
        });
    }

    #[test]
    fn test_do_while_break() {
        with_cfg("do { if (x) { break; } f(); } while (true);", |cfg| {
            assert!(has_path(cfg, cfg.entry, cfg.exit));
        });
    }

    // ------------------------------------------------- break / continue

    #[test]
    fn test_break_in_while() {
        with_cfg("while (x) { if (y) { break; } x = x - 1; }", |cfg| {
            assert!(has_path(cfg, cfg.entry, cfg.exit));
        });
    }

    #[test]
    fn test_continue_in_while() {
        with_cfg("while (x) { if (y) { continue; } x = x - 1; }", |cfg| {
            assert!(count_label(cfg, EdgeLabel::Back) >= 2);
        });
    }

    #[test]
    fn test_break_inside_nested_loop_breaks_innermost() {
        with_cfg(
            "for (int i = 0; i < 10; i++) { for (int j = 0; j < 10; j++) { if (cond) { break; } f(j); } g(i); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Loop), 2);
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_unlabeled_break_in_switch_does_not_target_enclosing_loop() {
        with_cfg(
            "for (int i = 0; i < 10; i++) { \
               switch (i) { \
                 case 1: break; \
                 default: doIt(); break; \
               } \
               after(); \
             }",
            |cfg| {
                let switch_end = cfg
                    .nodes
                    .values()
                    .find(|n| n.label.starts_with("switch_end"))
                    .unwrap()
                    .id;
                let loop_head = cfg
                    .nodes
                    .values()
                    .find(|n| n.kind == NodeKind::Loop)
                    .unwrap()
                    .id;
                let case1_body = cfg
                    .nodes
                    .values()
                    .find(|n| n.label.starts_with("switch_body") && n.label.ends_with("_0"))
                    .unwrap()
                    .id;
                assert!(cfg.edges.iter().any(|e| e.src == case1_body
                    && e.dst == switch_end
                    && e.label == EdgeLabel::Flow));
                assert!(!cfg.edges.iter().any(|e| e.src == case1_body
                    && e.dst == loop_head
                    && e.label == EdgeLabel::Back));
            },
        );
    }

    #[test]
    fn test_break_continue_carry_no_label() {
        // Empirically verifies the absence of a label on
        // break/continue — neither should have a named child.
        let tree = parse_csharp("class C { void M() { break; continue; } }");
        assert!(!tree.root_node().has_error());
        let brk = find_first(tree.root_node(), "break_statement").unwrap();
        let cnt = find_first(tree.root_node(), "continue_statement").unwrap();
        assert_eq!(brk.named_child_count(), 0);
        assert_eq!(cnt.named_child_count(), 0);
    }

    // -------------------------------------------- try / catch / finally

    #[test]
    fn test_try_catch_basic() {
        with_cfg("try { f(); } catch (Exception e) { g(); }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::TryEntry), 1);
            assert_eq!(count_kind(cfg, NodeKind::Handler), 1);
            assert!(count_label(cfg, EdgeLabel::Except) >= 1);
        });
    }

    #[test]
    fn test_try_catch_finally() {
        with_cfg(
            "try { f(); } catch (Exception e) { g(); } finally { h(); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Finally), 1);
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_multiple_catch_clauses() {
        with_cfg(
            "try { f(); } catch (System.IO.IOException e) { g(); } catch (Exception e2) { h(); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Handler), 2);
            },
        );
    }

    #[test]
    fn test_throw_routes_to_handler() {
        with_cfg(
            "try { throw new Exception(); } catch (Exception e) { handle(e); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::RaiseSite), 1);
                assert!(count_label(cfg, EdgeLabel::Except) >= 1);
            },
        );
    }

    #[test]
    fn test_throw_without_handler_escapes() {
        with_cfg("throw new Exception();", |cfg| {
            let escape_edges: Vec<_> = cfg
                .edges
                .iter()
                .filter(|e| e.label == EdgeLabel::Escape)
                .collect();
            assert_eq!(escape_edges.len(), 1);
            assert_eq!(escape_edges[0].dst, cfg.exit);
        });
    }

    #[test]
    fn test_nested_try() {
        with_cfg(
            "try { try { f(); } catch (System.IO.IOException e) { g(); } } catch (Exception e2) { h(); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::TryEntry), 2);
            },
        );
    }

    // ----------------------------------------- using (disposal) / lock

    #[test]
    fn test_using_statement_is_distinct_from_using_directive() {
        // `using_directive` (import, outside a method body) and
        // `using_statement` (disposal) must NEVER be confused —
        // verified by parsing both in the same file.
        let tree =
            parse_csharp("using System; class C { void M() { using (var x = Open()) { f(x); } } }");
        assert!(!tree.root_node().has_error());
        assert!(find_first(tree.root_node(), "using_directive").is_some());
        assert!(find_first(tree.root_node(), "using_statement").is_some());
    }

    #[test]
    fn test_using_statement_descends_into_body() {
        with_cfg("using (var x = Open()) { if (c) { f(x); } }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Branch), 1);
        });
    }

    #[test]
    fn test_using_statement_resource_appended_before_body() {
        // The resource declaration is appended to the head of the
        // BasicBlock reached from the entry — like any sequential
        // statement, a single body statement then merges into it (the
        // same generic merging that `append_to_basic` applies
        // everywhere else; also verified on the Python side:
        // `_visit_block` of the body descends into the same
        // `entry_cursor`).
        with_cfg("using (var x = Open()) { f(x); }", |cfg| {
            let first_succ = cfg.successors(cfg.entry)[0].dst;
            let bb = &cfg.nodes[&first_succ];
            assert_eq!(bb.kind, NodeKind::Basic);
            assert_eq!(bb.statements.len(), 2);
            assert_eq!(bb.statements[0].kind(), "variable_declaration");
        });
    }

    #[test]
    fn test_try_with_nested_using_no_separate_statement_type() {
        // No separate "try-with-resources" form: `using_statement`
        // nested in the `body` of an ordinary `try_statement`.
        with_cfg(
            "try { using (var x = Open()) { f(x); } } catch (Exception e) { g(); } finally { h(); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::TryEntry), 1);
                assert_eq!(count_kind(cfg, NodeKind::Handler), 1);
                assert_eq!(count_kind(cfg, NodeKind::Finally), 1);
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_lock_statement_descends_into_body() {
        with_cfg("lock (obj) { if (c) { f(); } }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Branch), 1);
        });
    }

    #[test]
    fn test_lock_statement_return_terminates() {
        with_cfg("lock (obj) { return; } y = 1;", |cfg| {
            assert!(cfg.successors(cfg.exit).is_empty());
        });
    }

    // ----------------------------------------------------------- switch

    #[test]
    fn test_switch_colon_basic() {
        with_cfg(
            r#"switch (x) { case 1: y = 1; break; default: y = 2; break; }"#,
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Branch), 2);
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_switch_fallthrough_empty_case_flows_to_next() {
        with_cfg(
            r#"switch (x) { case 1: return 1; case 2: case 3: return 2; default: return 3; }"#,
            |cfg| {
                let mut body_nodes: Vec<_> = cfg
                    .nodes
                    .values()
                    .filter(|n| n.label.starts_with("switch_body"))
                    .collect();
                body_nodes.sort_unstable_by_key(|n| n.id);
                let (body_2, body_3) = (body_nodes[1], body_nodes[2]);
                assert!(cfg.edges.iter().any(|e| e.src == body_2.id
                    && e.dst == body_3.id
                    && e.label == EdgeLabel::Flow));
            },
        );
    }

    #[test]
    fn test_switch_no_default_falls_to_exit() {
        with_cfg(
            r#"int r = 0; switch (x) { case 1: r = 1; break; } r = r + 1;"#,
            |cfg| {
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_switch_break_reaches_switch_end() {
        with_cfg(
            r#"switch (x) { case 1: y = 1; break; default: y = 2; break; }"#,
            |cfg| {
                let switch_end = cfg
                    .nodes
                    .values()
                    .find(|n| n.label.starts_with("switch_end"))
                    .unwrap()
                    .id;
                assert!(has_path(cfg, cfg.entry, switch_end));
            },
        );
    }

    #[test]
    fn test_switch_case_condition_set_for_single_literal_label() {
        with_cfg(r#"switch (x) { case 1: y = 1; break; }"#, |cfg| {
            let branch = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Branch)
                .unwrap();
            assert!(branch.condition.is_some());
            assert!(branch.switch_case_label.is_some());
        });
    }

    #[test]
    fn test_switch_case_condition_none_for_default() {
        with_cfg(r#"switch (x) { default: y = 2; break; }"#, |cfg| {
            let branch = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Branch)
                .unwrap();
            assert!(branch.switch_case_label.is_none());
        });
    }

    #[test]
    fn test_switch_case_condition_none_for_non_literal_pattern() {
        // Verified empirically (cf. module doc): contrary to what one
        // might assume, `case 1: case 2:` produces TWO distinct
        // `switch_section`s (one per label), never a single
        // multi-label group — so `labels.len() != 1` never triggers
        // through this path. The real non-literal-pattern case is a
        // `var_pattern` (`case var y:`), which still has `labels.len()
        // == 1` but a type other than `constant_pattern` — must stay
        // opaque.
        with_cfg(r#"switch (x) { case var y: f(y); break; }"#, |cfg| {
            let branch = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Branch)
                .unwrap();
            assert!(branch.switch_case_label.is_none());
        });
    }

    // -------------------------------------------------------- return/throw

    #[test]
    fn test_return_terminates_path() {
        with_cfg("if (x) { return; } y = 1;", |cfg| {
            assert!(has_path(cfg, cfg.entry, cfg.exit));
        });
    }

    #[test]
    fn test_multiple_returns() {
        with_cfg("if (x) { return 1; } else { return 2; }", |cfg| {
            let return_edges_to_exit = cfg.edges.iter().filter(|e| e.dst == cfg.exit).count();
            assert_eq!(return_edges_to_exit, 2);
        });
    }

    // ---------------------------------------------------- constructor body

    #[test]
    fn test_constructor_body_uses_plain_block() {
        // No separate `constructor_body` type in this grammar
        // (unlike Java) — the constructor body is an ordinary `block`,
        // directly consumable by `build_csharp_cfg` without special
        // handling.
        let src = "class C { C(int x) { this.x = x; } }";
        let tree = parse_csharp(src);
        assert!(!tree.root_node().has_error());
        let ctor = find_first(tree.root_node(), "constructor_declaration").unwrap();
        let body = ctor.child_by_field_name("body").unwrap();
        assert_eq!(body.kind(), "block");
        let cfg = build_csharp_cfg(body, src.as_bytes());
        assert_eq!(count_kind(&cfg, NodeKind::Basic), 1);
        assert!(has_path(&cfg, cfg.entry, cfg.exit));
    }

    // ------------------------------------------- preprocessor (Juliet)

    #[test]
    fn test_flatten_preproc_members_single_level() {
        let src = "class C { #if (!OMITBAD)\nvoid M() { f(); }\n#endif\n }";
        let tree = parse_csharp(src);
        assert!(!tree.root_node().has_error());
        let class_decl = find_first(tree.root_node(), "class_declaration").unwrap();
        let body = class_decl.child_by_field_name("body").unwrap();

        // Without flattening: no `method_declaration` as a direct
        // named child (documented bug, cf. module doc) — proof that
        // the test below does exercise a real case, not a no-op.
        let mut w = body.walk();
        assert!(
            !body
                .named_children(&mut w)
                .any(|c| c.kind() == "method_declaration"),
            "sans aplatissement, la méthode devrait rester invisible (nichée dans preproc_if)"
        );

        let flattened = flatten_preproc_members(body);
        assert!(
            flattened.iter().any(|m| m.kind() == "method_declaration"),
            "la méthode doit être découverte après aplatissement du preproc_if"
        );
    }

    #[test]
    fn test_flatten_preproc_members_nested_elif() {
        let src = "class C { \
            #if (A)\nvoid M1() { f(); }\n\
            #elif (B)\nvoid M2() { g(); }\n\
            #else\nvoid M3() { h(); }\n\
            #endif\n }";
        let tree = parse_csharp(src);
        assert!(!tree.root_node().has_error());
        let class_decl = find_first(tree.root_node(), "class_declaration").unwrap();
        let body = class_decl.child_by_field_name("body").unwrap();
        let flattened = flatten_preproc_members(body);
        let methods: Vec<&str> = flattened
            .iter()
            .filter(|m| m.kind() == "method_declaration")
            .map(|m| {
                m.child_by_field_name("name")
                    .unwrap()
                    .utf8_text(src.as_bytes())
                    .unwrap()
            })
            .collect();
        assert_eq!(methods, vec!["M1", "M2", "M3"]);
    }

    #[test]
    fn test_flatten_preproc_members_no_wrapper_is_identity() {
        let src = "class C { void M1() { f(); } void M2() { g(); } }";
        let tree = parse_csharp(src);
        assert!(!tree.root_node().has_error());
        let class_decl = find_first(tree.root_node(), "class_declaration").unwrap();
        let body = class_decl.child_by_field_name("body").unwrap();
        let flattened = flatten_preproc_members(body);
        let methods = flattened
            .iter()
            .filter(|m| m.kind() == "method_declaration")
            .count();
        assert_eq!(methods, 2);
    }
}
