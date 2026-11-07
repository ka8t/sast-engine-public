//! CFG (Control Flow Graph) construction for Java — tree-sitter
//! front-end. Faithful port of `Audit/sca/dataflow/java_cfg.py`.
//!
//! Fully reuses the language-neutral structures from `cfg.rs`
//! (`Cfg`/`CfgNode`/`NodeKind`/`EdgeLabel`/`prune_unreachable`/
//! `field_children`) — the same general contract as a language
//! front-end for the dataflow engine (see the `dataflow/mod.rs` doc).
//!
//! Structural difference from Python: `ast.Module` carries a list
//! of top-level statements, which doesn't exist in Java — all
//! executable code lives in a method/constructor body (`block`).
//! This builder's entry unit is therefore a tree-sitter `block`
//! node (or `constructor_body`), not an entire `.java` file. Discovering
//! a file's methods (the equivalent of
//! `summary.rs::collect_functions`) is a separate problem, not
//! handled here (upcoming work in `java_summary.rs`).
//!
//! Dispatch on `node.kind()` (tree-sitter string). The node kinds
//! used here were **verified empirically** (actual parsing with
//! the `tree-sitter-java` crate, not inferred from memory or blindly
//! copied from the Python docstring) — in particular:
//!   - `try_statement` and `try_with_resources_statement` are two
//!     DISTINCT kinds (not a single `try_statement` with optional
//!     resources).
//!   - `catch_clause`/`finally_clause` are NOT exposed as
//!     named fields on `try_statement` — the children must be scanned
//!     positionally by kind.
//!   - `switch_expression` covers the classic switch (`case:`), the
//!     arrow switch (`case ->`) AND the switch-expression in the
//!     strict sense — there is no distinct `switch_statement` in this
//!     grammar.
//!   - Classic fall-through (`case "b": case "c": return 2;`)
//!     produces ONE `switch_block_statement_group` PER label — not a
//!     shared group (the group for label "b" has an empty body, the
//!     flow must fall through into the next group's body).
//!
//! Java's `break`/`continue` differ from Python's: an (unlabeled)
//! `break` exits the `switch` OR the enclosing loop, whichever is
//! syntactically closest (Python has no switch `break`). Hence a
//! unified `break_stack` (loops AND switches), instead of Python's
//! single `loop_stack` (`cfg.rs`). `continue` only targets
//! loops (never a switch): the search skips over switch
//! entries even when they are closer.

use super::cfg::{Cfg, EdgeLabel, NodeKind, field_children, prune_unreachable};
use tree_sitter::Node;

/// Java tree-sitter node accepted as an executable entry point for
/// `build_java_cfg` (method/constructor body, static block).
const BODY_NODE_KINDS: [&str; 2] = ["block", "constructor_body"];

/// `break_stack` entry — a loop or switch reachable via
/// `break`.
struct BreakTarget {
    exit_id: usize,
    is_loop: bool,
    label: Option<String>,
    /// Used only if `is_loop` (target of `continue`).
    loop_head_id: Option<usize>,
}

struct JavaCfgBuilder<'tree, 'src> {
    cfg: Cfg<'tree>,
    break_stack: Vec<BreakTarget>,
    /// Label pending association with the next `BreakTarget`
    /// pushed (set right before visiting the loop/switch it
    /// labels).
    pending_label: Option<String>,
    /// Stack of active `catch` handler lists (HANDLER node
    /// ids), used to link a `throw` to its closest
    /// handler(s).
    try_handler_stack: Vec<Vec<usize>>,
    source: &'src [u8],
}

/// Builds a CFG from a Java method body (tree-sitter
/// `block` or `constructor_body` node — NOT the whole file,
/// see the module doc).
pub fn build_java_cfg<'tree>(body: Node<'tree>, source: &[u8]) -> Cfg<'tree> {
    debug_assert!(
        BODY_NODE_KINDS.contains(&body.kind()),
        "build_java_cfg attend un nœud block/constructor_body, reçu {:?}",
        body.kind()
    );
    let mut builder = JavaCfgBuilder {
        cfg: Cfg::new(),
        break_stack: Vec::new(),
        pending_label: None,
        try_handler_stack: Vec::new(),
        source,
    };
    builder.cfg.entry = builder.cfg.add_node(NodeKind::Entry, "entry");
    builder.cfg.exit = builder.cfg.add_node(NodeKind::Exit, "exit");

    let mut w = body.walk();
    let stmts: Vec<Node<'tree>> = body.named_children(&mut w).collect();
    let cursor = builder.visit_stmts(&stmts, Some(builder.cfg.entry));
    if let Some(c) = cursor {
        builder.cfg.add_edge(c, builder.cfg.exit, EdgeLabel::Flow);
    }
    prune_unreachable(&mut builder.cfg);
    builder.cfg
}

const LITERAL_LABEL_KINDS: [&str; 9] = [
    "character_literal",
    "string_literal",
    "decimal_integer_literal",
    "hex_integer_literal",
    "octal_integer_literal",
    "binary_integer_literal",
    "true",
    "false",
    "null_literal",
];

impl<'tree, 'src> JavaCfgBuilder<'tree, 'src> {
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
            "for_statement" => self.visit_for(stmt, cursor),
            "enhanced_for_statement" => self.visit_enhanced_for(stmt, cursor),
            "try_statement" => self.visit_try_like(stmt, cursor, None),
            "try_with_resources_statement" => {
                let resources = stmt.child_by_field_name("resources");
                self.visit_try_like(stmt, cursor, resources)
            }
            "synchronized_statement" => self.visit_synchronized(stmt, cursor),
            "labeled_statement" => self.visit_labeled(stmt, cursor),
            "switch_expression" => self.visit_switch(stmt, cursor),
            // Catch-all: linear statement (or unmodeled
            // construct, e.g. a nested method_declaration/class_declaration,
            // an isolated lambda body) → opaque append to the
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

    // Bare block (`{ ... }` in statement position, not a method
    // body): descends into its content, unlike
    // method/class which remain opaque.
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

    // Throw — the equivalent of Python's `raise`.

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

    // Break / Continue — unified loop+switch stack (see the module doc).

    fn visit_break(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        if self.break_stack.is_empty() {
            return Some(cursor); // source code error; conservative, no-op
        }
        let label_node = stmt.named_children(&mut stmt.walk()).next();
        let exit_id = self
            .find_break_target(label_node)
            .unwrap_or_else(|| self.break_stack.last().unwrap().exit_id);
        self.cfg.add_edge(cursor, exit_id, EdgeLabel::Flow);
        None
    }

    fn visit_continue(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let label_node = stmt.named_children(&mut stmt.walk()).next();
        let Some(loop_head_id) = self.find_continue_target(label_node) else {
            return Some(cursor); // no enclosing loop; conservative, no-op
        };
        self.cfg.add_edge(cursor, loop_head_id, EdgeLabel::Back);
        None
    }

    /// Resolves the target `exit_id` of a `break` — the matching label
    /// (loop or switch), or the closest entry if unlabeled.
    fn find_break_target(&self, label_node: Option<Node<'tree>>) -> Option<usize> {
        let Some(label_node) = label_node else {
            return self.break_stack.last().map(|t| t.exit_id);
        };
        let label_text = self.text(label_node);
        self.break_stack
            .iter()
            .rev()
            .find(|t| t.label.as_deref() == Some(label_text.as_str()))
            .or_else(|| self.break_stack.last())
            .map(|t| t.exit_id)
    }

    /// Resolves the target loop head of a `continue` — loops
    /// only (switch entries are skipped even if
    /// closer), matching label if one is given.
    fn find_continue_target(&self, label_node: Option<Node<'tree>>) -> Option<usize> {
        let loops: Vec<&BreakTarget> = self.break_stack.iter().filter(|t| t.is_loop).collect();
        let Some(label_node) = label_node else {
            return loops.last().and_then(|t| t.loop_head_id);
        };
        let label_text = self.text(label_node);
        loops
            .iter()
            .rev()
            .find(|t| t.label.as_deref() == Some(label_text.as_str()))
            .or_else(|| loops.last())
            .and_then(|t| t.loop_head_id)
    }

    fn text(&self, node: Node<'tree>) -> String {
        node.utf8_text(self.source).unwrap_or_default().to_string()
    }

    // If / else-if / else — direct recursion via `visit_stmt`: the
    // `alternative` field is either another `if_statement` (else-if)
    // or a `block` (else), both dispatch naturally with no
    // special case (unlike Python, where `elif`/`else` are
    // distinct sibling fields `elif_clause`/`else_clause`, see cfg.rs).

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

        let target = self.new_loop_target(exit_join, loop_head);
        self.break_stack.push(target);

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

    // For (classique)

    fn visit_for(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let pre_cursor = match stmt.child_by_field_name("init") {
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

        let target = self.new_loop_target(exit_join, loop_head);
        self.break_stack.push(target);

        let body_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("for_body_{lineno}"));
        self.cfg.add_edge(loop_head, body_seed, EdgeLabel::True);
        let body_end = match stmt.child_by_field_name("body") {
            Some(b) => self.visit_stmt(b, body_seed),
            None => Some(body_seed),
        };

        // update (i++, etc.) — one or several, executed after the
        // body, before looping back to the condition. tree-sitter can
        // expose several `update` (repeated field, e.g.
        // `for (;; i++, j--)`) — we collect them all via
        // `field_children`, not just the first `field()`.
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

    // For-each (`for (T x : coll)`)

    fn visit_enhanced_for(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let value = stmt.child_by_field_name("value"); // collection/iterable
        let loop_head = self
            .cfg
            .add_node(NodeKind::Loop, format!("foreach_{lineno}"));
        {
            let n = self.cfg.nodes.get_mut(&loop_head).unwrap();
            n.condition = value;
            n.for_target = stmt.child_by_field_name("name");
        }
        self.cfg.add_edge(cursor, loop_head, EdgeLabel::Flow);
        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("foreach_end_{lineno}"));

        let target = self.new_loop_target(exit_join, loop_head);
        self.break_stack.push(target);

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

    // Try / try-with-resources — same modeling, resources
    // treated as an opaque statement before the body (like the
    // items of a Python `with`, see cfg.rs::visit_with).

    fn visit_try_like(
        &mut self,
        stmt: Node<'tree>,
        cursor: usize,
        resources: Option<Node<'tree>>,
    ) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let try_entry = self
            .cfg
            .add_node(NodeKind::TryEntry, format!("try_{lineno}"));
        self.cfg.add_edge(cursor, try_entry, EdgeLabel::Flow);

        let entry_cursor = match resources {
            Some(r) => self.append_to_basic(r, try_entry),
            None => try_entry,
        };

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
            let param = h
                .children(&mut h.walk())
                .find(|c| c.kind() == "catch_formal_parameter");
            let hid = self.cfg.add_node(
                NodeKind::Handler,
                format!("catch_{}", h.start_position().row),
            );
            self.cfg.nodes.get_mut(&hid).unwrap().handler_type = param;
            handler_ids.push(hid);
        }

        self.try_handler_stack.push(handler_ids.clone());
        let body_cursor = match stmt.child_by_field_name("body") {
            Some(b) => self.visit_stmt(b, entry_cursor),
            None => Some(entry_cursor),
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

    // Synchronized — like a Python `with`: opaque wrapper, then
    // descends into the body.

    fn visit_synchronized(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let sync_bb = self.cfg.add_node(
            NodeKind::Basic,
            format!("sync_{}", stmt.start_position().row),
        );
        self.cfg
            .nodes
            .get_mut(&sync_bb)
            .unwrap()
            .statements
            .push(stmt);
        self.cfg.add_edge(cursor, sync_bb, EdgeLabel::Flow);
        match stmt.child_by_field_name("body") {
            Some(b) => self.visit_stmt(b, sync_bb),
            None => Some(sync_bb),
        }
    }

    // Labeled statement — unwraps + labels the next break_stack
    // target.

    fn visit_labeled(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let named: Vec<Node<'tree>> = stmt.named_children(&mut stmt.walk()).collect();
        if named.len() < 2 {
            return Some(cursor);
        }
        let (label_node, inner) = (named[0], named[1]);
        self.pending_label = Some(self.text(label_node));
        let result = self.visit_stmt(inner, cursor);
        self.pending_label = None;
        result
    }

    fn new_loop_target(&mut self, exit_id: usize, loop_head_id: usize) -> BreakTarget {
        let label = self.pending_label.take();
        BreakTarget {
            exit_id,
            is_loop: true,
            label,
            loop_head_id: Some(loop_head_id),
        }
    }

    // Switch (colon form with fall-through + arrow form without
    // fall-through) — see the module doc for the empirical
    // verification of the fall-through behavior.

    fn visit_switch(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let subject = stmt.child_by_field_name("condition");
        let Some(body) = stmt.child_by_field_name("body") else {
            return Some(cursor);
        };
        let mut w = body.walk();
        let groups: Vec<Node<'tree>> = body
            .named_children(&mut w)
            .filter(|c| c.kind() == "switch_block_statement_group" || c.kind() == "switch_rule")
            .collect();
        if groups.is_empty() {
            return Some(cursor);
        }

        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("switch_end_{lineno}"));
        let label = self.pending_label.take();
        self.break_stack.push(BreakTarget {
            exit_id: exit_join,
            is_loop: false,
            label,
            loop_head_id: None,
        });

        let mut prev_false = cursor;
        // `None` = no colon group processed yet (or the last one
        // was an arrow form); `Some(None)` = the last colon
        // group ended unreachable; `Some(Some(id))` =
        // reachable, to be linked to the next group (fall-through).
        let mut fallthrough_cursor: Option<Option<usize>> = None;

        for (i, grp) in groups.iter().enumerate() {
            let labels: Vec<Node<'tree>> = grp
                .named_children(&mut grp.walk())
                .filter(|c| c.kind() == "switch_label")
                .collect();
            let branch = self
                .cfg
                .add_node(NodeKind::Branch, format!("switch_case_{lineno}_{i}"));
            {
                let n = self.cfg.nodes.get_mut(&branch).unwrap();
                n.condition = subject;
                n.switch_case_label = Self::switch_case_condition(&labels);
            }
            self.cfg.add_edge(prev_false, branch, EdgeLabel::Flow);

            let body_seed = self
                .cfg
                .add_node(NodeKind::Join, format!("switch_body_{lineno}_{i}"));
            self.cfg.add_edge(branch, body_seed, EdgeLabel::True);
            if let Some(Some(fc)) = fallthrough_cursor {
                self.cfg.add_edge(fc, body_seed, EdgeLabel::Flow);
            }

            if grp.kind() == "switch_rule" {
                let arm_body: Vec<Node<'tree>> = grp
                    .named_children(&mut grp.walk())
                    .filter(|c| c.kind() != "switch_label")
                    .collect();
                let body_end = self.visit_stmts(&arm_body, Some(body_seed));
                if let Some(be) = body_end {
                    self.cfg.add_edge(be, exit_join, EdgeLabel::Flow);
                }
                fallthrough_cursor = None;
            } else {
                let stmts: Vec<Node<'tree>> = grp
                    .named_children(&mut grp.walk())
                    .filter(|c| c.kind() != "switch_label")
                    .collect();
                let body_end = self.visit_stmts(&stmts, Some(body_seed));
                fallthrough_cursor = Some(body_end);
            }

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

    /// Simple literal label of a single `case` (`case 1:`), to
    /// let `eval_const` statically determine which `case` is
    /// active (see the `CfgNode::switch_case_label` field doc). For
    /// `default` (no value), a multi-label group
    /// (fall-through), or a non-literal label (enum constant,
    /// symbol resolution out of scope): `None` (opaque,
    /// conservative) — the same strategy as Python's
    /// `_match_case_condition` (`cfg.rs`) for complex patterns.
    fn switch_case_condition(labels: &[Node<'tree>]) -> Option<Node<'tree>> {
        if labels.len() != 1 {
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
// Tests — mirror of `Audit/tests/dataflow/test_cfg_java.py` (same
// invariants, same suite structure).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tree_sitter::Parser;

    fn parse_java(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
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

    /// Parses a Java method body (wrapped in a class/method),
    /// builds its CFG, and exposes it to `f` — avoids letting
    /// a `Cfg<'tree>` escape the scope of the tree it depends on
    /// (a self-reference not directly representable in safe Rust).
    fn with_cfg<R>(method_body_src: &str, f: impl FnOnce(&Cfg) -> R) -> R {
        let src = format!("class Foo {{ void t() {{ {method_body_src} }} }}");
        let tree = parse_java(&src);
        assert!(
            !tree.root_node().has_error(),
            "syntaxe Java invalide : {method_body_src:?}"
        );
        let method = find_first(tree.root_node(), "method_declaration").unwrap();
        let body = method.child_by_field_name("body").unwrap();
        let cfg = build_java_cfg(body, src.as_bytes());
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
            "for (String s : items) { doIt(s); }",
            "try { f(); } catch (Exception e) { g(); } finally { h(); }",
            "switch (x) { case 1: y = 1; break; default: y = 2; }",
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
        with_cfg(
            "int x = 1; int y = 2; int z = x + y; System.out.println(z);",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Basic), 1);
                let bb = cfg
                    .nodes
                    .values()
                    .find(|n| n.kind == NodeKind::Basic)
                    .unwrap();
                assert_eq!(bb.statements.len(), 4);
            },
        );
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
    fn test_enhanced_for() {
        with_cfg("for (String s : items) { System.out.println(s); }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Loop), 1);
            assert!(count_label(cfg, EdgeLabel::Back) >= 1);
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
    fn test_labeled_continue_skips_nearer_unlabeled_loop() {
        with_cfg(
            "outer: for (int i = 0; i < 10; i++) { \
               for (int j = 0; j < 10; j++) { \
                 if (j == 3) { continue outer; } \
               } \
             }",
            |cfg| {
                let mut loops: Vec<usize> = cfg
                    .nodes
                    .values()
                    .filter(|n| n.kind == NodeKind::Loop)
                    .map(|n| n.id)
                    .collect();
                loops.sort_unstable();
                let outer_head = loops[0];
                let n_back_to_outer = cfg
                    .edges
                    .iter()
                    .filter(|e| e.label == EdgeLabel::Back && e.dst == outer_head)
                    .count();
                // natural back edge of the outer loop + the explicit `continue outer`.
                assert!(n_back_to_outer >= 2);
            },
        );
    }

    #[test]
    fn test_labeled_break_targets_correct_loop() {
        with_cfg(
            "outer: for (int i = 0; i < 10; i++) { \
               for (int j = 0; j < 10; j++) { \
                 if (j == 5) { break outer; } \
               } \
             }",
            |cfg| {
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
                 default: doIt(); \
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
            "try { f(); } catch (IOException e) { g(); } catch (RuntimeException e2) { h(); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Handler), 2);
            },
        );
    }

    #[test]
    fn test_multi_catch_type() {
        with_cfg(
            "try { f(); } catch (RuntimeException | Error e) { g(); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Handler), 1);
            },
        );
    }

    #[test]
    fn test_try_with_resources() {
        with_cfg(
            "try (AutoCloseable c = open()) { f(); } catch (Exception e) { g(); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::TryEntry), 1);
                assert_eq!(count_kind(cfg, NodeKind::Handler), 1);
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_try_with_multiple_resources() {
        with_cfg(
            "try (AutoCloseable c = open(); AutoCloseable d = open2()) { f(); } catch (Exception e) { g(); }",
            |cfg| {
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_throw_routes_to_handler() {
        with_cfg(
            "try { throw new RuntimeException(); } catch (RuntimeException e) { handle(e); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::RaiseSite), 1);
                assert!(count_label(cfg, EdgeLabel::Except) >= 1);
            },
        );
    }

    #[test]
    fn test_throw_without_handler_escapes() {
        with_cfg("throw new RuntimeException();", |cfg| {
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
            "try { try { f(); } catch (IOException e) { g(); } } catch (Exception e2) { h(); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::TryEntry), 2);
            },
        );
    }

    // ----------------------------------------------------------- switch

    #[test]
    fn test_switch_colon_basic() {
        with_cfg(
            r#"switch (x) { case "a": y = 1; break; default: y = 2; }"#,
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Branch), 2);
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_switch_fallthrough_empty_case_flows_to_next() {
        with_cfg(
            r#"switch (x) { case "a": return 1; case "b": case "c": return 2; default: return 3; }"#,
            |cfg| {
                let mut body_nodes: Vec<_> = cfg
                    .nodes
                    .values()
                    .filter(|n| n.label.starts_with("switch_body"))
                    .collect();
                body_nodes.sort_unstable_by_key(|n| n.id);
                let (body_b, body_c) = (body_nodes[1], body_nodes[2]);
                assert!(cfg.edges.iter().any(|e| e.src == body_b.id
                    && e.dst == body_c.id
                    && e.label == EdgeLabel::Flow));
            },
        );
    }

    #[test]
    fn test_switch_arrow_form_no_fallthrough() {
        with_cfg(
            r#"switch (x) { case "a" -> foo(); case "b", "c" -> bar(); default -> baz(); }"#,
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Branch), 3);
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_switch_no_default_falls_to_exit() {
        with_cfg(
            r#"int r = 0; switch (x) { case "a": r = 1; break; } r = r + 1;"#,
            |cfg| {
                assert!(has_path(cfg, cfg.entry, cfg.exit));
            },
        );
    }

    #[test]
    fn test_switch_break_reaches_switch_end() {
        with_cfg(
            r#"switch (x) { case "a": y = 1; break; default: y = 2; }"#,
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

    // ------------------------------------------------------ synchronized

    #[test]
    fn test_synchronized_descends_into_body() {
        with_cfg("synchronized (lock) { if (x) { y = 1; } }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Branch), 1);
        });
    }

    #[test]
    fn test_synchronized_return_terminates() {
        with_cfg("synchronized (lock) { return; } y = 1;", |cfg| {
            assert!(cfg.successors(cfg.exit).is_empty());
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

    // ---------------------------------------- constructeur (constructor_body)

    #[test]
    fn test_constructor_body_is_valid_entry_point() {
        let src = "class C { C(int x) { this.x = x; } }";
        let tree = parse_java(src);
        assert!(!tree.root_node().has_error());
        let ctor = find_first(tree.root_node(), "constructor_declaration").unwrap();
        let body = ctor.child_by_field_name("body").unwrap();
        assert_eq!(body.kind(), "constructor_body");
        let cfg = build_java_cfg(body, src.as_bytes());
        assert_eq!(count_kind(&cfg, NodeKind::Basic), 1);
        assert!(has_path(&cfg, cfg.entry, cfg.exit));
    }
}
