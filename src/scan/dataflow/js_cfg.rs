//! CFG (Control Flow Graph) construction for JavaScript — tree-sitter
//! front-end. Direct template of `java_cfg.rs` — same general contract
//! as a language front-end for the dataflow engine (see the doc of
//! `dataflow/mod.rs`), fully reuses the language-neutral structures
//! from `cfg.rs`.
//!
//! Entry point: a tree-sitter `statement_block` node (body of
//! `function_declaration`/`function_expression`/`arrow_function`/
//! `method_definition`/`generator_function_declaration`), same contract
//! as Java (`block`/`constructor_body`) — **or** `program` (root of an
//! entire file), for top-module-level analysis (mirrors
//! `cfg::build_cfg`, Python: `build_cfg_from_block(source,
//! tree.root_node())`) wired into `js_taint_scan.rs` on 08/30 — JS code
//! outside any function (invisible before this fix, found while
//! validating on real code). Both forms share the same algorithm:
//! `visit_stmts` only walks the direct named children of the node it
//! receives, without any assumption about its kind beyond the
//! `debug_assert!` guard below; a `function_declaration` encountered at
//! module level falls into the catch-all `append_to_basic` (opaque
//! statement, no descent into its body) — exactly like a function
//! nested inside another function today, no double counting. An
//! `arrow_function` with an expression-only body (`x => x + 1`, no
//! `{ ... }`) is not a `statement_block` — handled separately by
//! `js_summary.rs` (implicit return), not here.
//!
//! Node shapes verified empirically (real parsing with
//! `tree-sitter-javascript`, following the discipline established in
//! `js_lowering.rs`):
//!   - `try_statement` ALWAYS covers body + handler (optional,
//!     `catch_clause`) + finalizer (optional, `finally_clause`) as
//!     singular NAMED fields — unlike Java, no need to scan positional
//!     children nor to handle multiple `catch` clauses (JS allows only
//!     one `catch` block per `try`).
//!   - `switch_case`/`switch_default` are two SEPARATE kinds, already
//!     one per label (no multi-label grouping as in Java, where
//!     several `switch_label`s share a single
//!     `switch_block_statement_group`) — each `case`/`default` of
//!     `switch_body` has its own node, with a `body` field repeated per
//!     statement (like `update` in Java, collected via
//!     `field_children`). Classic JS fall-through is therefore simpler
//!     to model than the Java form with two syntaxes (colon + arrow):
//!     only one syntax here.
//!   - `for_in_statement` covers both `for...in` AND `for...of` (see
//!     the doc of `js_lowering.rs`) — treated as the JS equivalent of
//!     `enhanced_for_statement` (Java), `for_target`/`condition`
//!     carried by the same `Loop` node mechanism.
//!   - `do_statement` (do/while) — no direct equivalent in the
//!     `java_cfg.rs` dispatch used as a template (not covered on the
//!     Java side as of today); modeled here as `while_statement` but
//!     with the body executed before the first condition test (direct
//!     `Flow` edge loop-head → body, no initial `True` branch).

use super::cfg::{Cfg, EdgeLabel, NodeKind, field_children, prune_unreachable};
use tree_sitter::Node;

const BODY_NODE_KINDS: [&str; 2] = ["statement_block", "program"];

/// Entry of `break_stack` — a loop or switch reachable via `break`.
/// Mirrors `java_cfg::BreakTarget`.
struct BreakTarget {
    exit_id: usize,
    is_loop: bool,
    label: Option<String>,
    loop_head_id: Option<usize>,
}

struct JsCfgBuilder<'tree, 'src> {
    cfg: Cfg<'tree>,
    break_stack: Vec<BreakTarget>,
    pending_label: Option<String>,
    /// Stack of active `catch` handler lists (unique HANDLER node id per
    /// `try`, since JS allows only one `catch`), used to link a `throw`
    /// to its nearest handler.
    try_handler_stack: Vec<Vec<usize>>,
    source: &'src [u8],
}

/// Builds a CFG from a JS function body (tree-sitter `statement_block`
/// node) OR from the `program` root of an entire file (top-module-level
/// analysis, see module doc).
pub fn build_js_cfg<'tree>(body: Node<'tree>, source: &[u8]) -> Cfg<'tree> {
    debug_assert!(
        BODY_NODE_KINDS.contains(&body.kind()),
        "build_js_cfg expects a statement_block or program node, got {:?}",
        body.kind()
    );
    let mut builder = JsCfgBuilder {
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

impl<'tree, 'src> JsCfgBuilder<'tree, 'src> {
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
            "statement_block" => self.visit_block(stmt, cursor),
            "return_statement" => self.visit_return(stmt, cursor),
            "throw_statement" => self.visit_throw(stmt, cursor),
            "break_statement" => self.visit_break(stmt, cursor),
            "continue_statement" => self.visit_continue(stmt, cursor),
            "if_statement" => self.visit_if(stmt, cursor),
            "while_statement" => self.visit_while(stmt, cursor),
            "do_statement" => self.visit_do(stmt, cursor),
            "for_statement" => self.visit_for(stmt, cursor),
            "for_in_statement" => self.visit_for_in(stmt, cursor),
            "try_statement" => self.visit_try(stmt, cursor),
            "labeled_statement" => self.visit_labeled(stmt, cursor),
            "switch_statement" => self.visit_switch(stmt, cursor),
            "empty_statement" => Some(cursor),
            // Catch-all: linear statement (or unmodeled construct, e.g. a
            // nested function_declaration/class_declaration) → opaque
            // append to the current BasicBlock. Conservative by
            // construction, same strategy as Java.
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

    // Break / Continue — unified loop+switch stack (see module doc,
    // same strategy as Java: an unlabeled `break` targets the nearest
    // loop OR switch, `continue` only targets loops).

    fn visit_break(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        if self.break_stack.is_empty() {
            return Some(cursor);
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
            return Some(cursor);
        };
        self.cfg.add_edge(cursor, loop_head_id, EdgeLabel::Back);
        None
    }

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

    // If / else-if / else — `alternative` is either another
    // `if_statement` (else-if), or an `else_clause` wrapping the body —
    // unwrapped before recursion (unlike Java where `alternative` is
    // directly the `block`/`if_statement`, with no wrapper).

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
        let alternative = stmt.child_by_field_name("alternative").and_then(|alt| {
            if alt.kind() == "else_clause" {
                alt.named_children(&mut alt.walk()).next()
            } else {
                Some(alt)
            }
        });
        let f_end = match alternative {
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

    // Do-while — body executed before the first test (see module doc):
    // the cursor enters the body directly, the loop head (condition) is
    // only reached AFTER the first execution. `continue` must loop back
    // to the CONDITION (not directly to the body), so `loop_head_id`
    // points to the Loop node as usual.

    fn visit_do(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let condition = stmt.child_by_field_name("condition");
        let loop_head = self.cfg.add_node(NodeKind::Loop, format!("do_{lineno}"));
        self.cfg.nodes.get_mut(&loop_head).unwrap().condition = condition;
        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("do_end_{lineno}"));

        let target = self.new_loop_target(exit_join, loop_head);
        self.break_stack.push(target);

        // The body is executed first, before any test.
        let body_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("do_body_{lineno}"));
        self.cfg.add_edge(cursor, body_seed, EdgeLabel::Flow);
        let body_end = match stmt.child_by_field_name("body") {
            Some(b) => self.visit_stmt(b, body_seed),
            None => Some(body_seed),
        };
        // After the body, we reach the loop head (condition).
        if let Some(be) = body_end {
            self.cfg.add_edge(be, loop_head, EdgeLabel::Flow);
        }
        self.cfg.add_edge(loop_head, body_seed, EdgeLabel::True);
        self.cfg.add_edge(loop_head, exit_join, EdgeLabel::False);

        self.break_stack.pop();
        Some(exit_join)
    }

    // For (classic)

    fn visit_for(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let pre_cursor = match stmt.child_by_field_name("initializer") {
            Some(init) if init.kind() != "empty_statement" => self.visit_stmt(init, cursor),
            _ => Some(cursor),
        }?;

        let condition = stmt
            .child_by_field_name("condition")
            .filter(|c| c.kind() != "empty_statement");
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

        // increment (i++, etc.) — `increment` field, only one in JS
        // (unlike Java, which allows a list `i++, j--` via a repeated
        // `update` field); collected via `field_children` anyway for
        // consistency/robustness.
        let update_nodes = field_children(stmt, "increment");
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

    // For-in / for-of (`for (x in obj)`/`for (x of arr)`) — same kind
    // `for_in_statement`, see module doc.

    fn visit_for_in(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let iterable = stmt.child_by_field_name("right");
        let loop_head = self.cfg.add_node(NodeKind::Loop, format!("forin_{lineno}"));
        {
            let n = self.cfg.nodes.get_mut(&loop_head).unwrap();
            n.condition = iterable;
            n.for_target = stmt.child_by_field_name("left");
        }
        self.cfg.add_edge(cursor, loop_head, EdgeLabel::Flow);
        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("forin_end_{lineno}"));

        let target = self.new_loop_target(exit_join, loop_head);
        self.break_stack.push(target);

        let body_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("forin_body_{lineno}"));
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

    // Try / catch / finally — a single handler and a single finalizer,
    // both optional, see module doc.

    fn visit_try(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let try_entry = self
            .cfg
            .add_node(NodeKind::TryEntry, format!("try_{lineno}"));
        self.cfg.add_edge(cursor, try_entry, EdgeLabel::Flow);

        let handler = stmt.child_by_field_name("handler"); // catch_clause
        let hid = handler.map(|h| {
            let param = h.child_by_field_name("parameter");
            let id = self
                .cfg
                .add_node(NodeKind::Handler, format!("catch_{lineno}"));
            self.cfg.nodes.get_mut(&id).unwrap().handler_type = param;
            (id, h)
        });
        let handler_ids: Vec<usize> = hid.iter().map(|(id, _)| *id).collect();

        self.try_handler_stack.push(handler_ids.clone());
        let body_cursor = match stmt.child_by_field_name("body") {
            Some(b) => self.visit_stmt(b, try_entry),
            None => Some(try_entry),
        };
        self.try_handler_stack.pop();

        let handler_end_cursor = if let Some((id, h)) = hid {
            self.cfg.add_edge(try_entry, id, EdgeLabel::Except);
            match h.child_by_field_name("body") {
                Some(b) => self.visit_stmt(b, id),
                None => Some(id),
            }
        } else {
            None
        };

        let finalizer = stmt.child_by_field_name("finalizer"); // finally_clause
        let fin = if let Some(fc) = finalizer {
            let fin_id = self
                .cfg
                .add_node(NodeKind::Finally, format!("finally_{lineno}"));
            if let Some(block) = fc.child_by_field_name("body") {
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
        if let Some(hc) = handler_end_cursor {
            self.cfg.add_edge(hc, fin, EdgeLabel::Flow);
        }

        Some(fin)
    }

    // Labeled statement — unwraps + labels the next break_stack target.
    // Exact mirror of Java.

    fn visit_labeled(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let label_node = stmt.child_by_field_name("label");
        let body_node = stmt.child_by_field_name("body");
        let (Some(label_node), Some(inner)) = (label_node, body_node) else {
            return Some(cursor);
        };
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

    // Switch — one `switch_case`/`switch_default` node PER label (no
    // multi-label grouping as in Java), classic fall-through only (no
    // Java 14+ arrow form). See module doc.

    fn visit_switch(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let subject = stmt.child_by_field_name("value");
        let Some(body) = stmt.child_by_field_name("body") else {
            return Some(cursor);
        };
        let mut w = body.walk();
        let groups: Vec<Node<'tree>> = body
            .named_children(&mut w)
            .filter(|c| c.kind() == "switch_case" || c.kind() == "switch_default")
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
        let mut fallthrough_cursor: Option<Option<usize>> = None;

        for (i, grp) in groups.iter().enumerate() {
            let branch = self
                .cfg
                .add_node(NodeKind::Branch, format!("switch_case_{lineno}_{i}"));
            {
                let n = self.cfg.nodes.get_mut(&branch).unwrap();
                n.condition = subject;
                n.switch_case_label = if grp.kind() == "switch_case" {
                    Self::switch_case_condition(*grp)
                } else {
                    None // switch_default: always opaque, conservative
                };
            }
            self.cfg.add_edge(prev_false, branch, EdgeLabel::Flow);

            let body_seed = self
                .cfg
                .add_node(NodeKind::Join, format!("switch_body_{lineno}_{i}"));
            self.cfg.add_edge(branch, body_seed, EdgeLabel::True);
            if let Some(Some(fc)) = fallthrough_cursor {
                self.cfg.add_edge(fc, body_seed, EdgeLabel::Flow);
            }

            let stmts = field_children(*grp, "body");
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

    /// Simple literal label of a `case` (`case 1:`), letting `eval_const`
    /// statically determine which `case` is active. A non-literal label
    /// (variable, expression): `None` (opaque, conservative) — same
    /// strategy as Java.
    fn switch_case_condition(case_node: Node<'tree>) -> Option<Node<'tree>> {
        let value = case_node.child_by_field_name("value")?;
        const LITERAL_KINDS: [&str; 6] = ["number", "string", "true", "false", "null", "undefined"];
        if LITERAL_KINDS.contains(&value.kind()) {
            Some(value)
        } else {
            None
        }
    }
}

// ============================================================================
// Tests — mirror of the `java_cfg.rs` suite (same invariants, analogous
// structure, JS syntax).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tree_sitter::Parser;

    fn parse_js(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
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

    /// Parses a JS function body, builds its CFG, and exposes it to `f`
    /// — avoids letting a `Cfg<'tree>` escape the scope of the tree it
    /// depends on.
    fn with_cfg<R>(body_src: &str, f: impl FnOnce(&Cfg) -> R) -> R {
        let src = format!("function t() {{ {body_src} }}");
        let tree = parse_js(&src);
        assert!(
            !tree.root_node().has_error(),
            "invalid JS syntax: {body_src:?}"
        );
        let func = find_first(tree.root_node(), "function_declaration").unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let cfg = build_js_cfg(body, src.as_bytes());
        f(&cfg)
    }

    fn count_kind(cfg: &Cfg, kind: NodeKind) -> usize {
        cfg.nodes.values().filter(|n| n.kind == kind).count()
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
            "let x = 1;",
            "let x = 1; let y = 2; let z = 3;",
            "if (x) { y = 1; }",
            "if (x) { y = 1; } else { y = 2; }",
            "while (x) { x = x - 1; }",
            "do { x = x - 1; } while (x);",
            "for (let i = 0; i < 10; i++) { doIt(); }",
            "for (const k in obj) { doIt(k); }",
            "for (const v of arr) { doIt(v); }",
            "try { f(); } catch (e) { }",
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
            "let x = 1;",
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
        for src in ["let x = 1;", "if (x) { y = 1; } else { y = 2; }", "return;"] {
            with_cfg(src, |cfg| {
                assert!(cfg.successors(cfg.exit).is_empty(), "src={src:?}");
            });
        }
    }

    #[test]
    fn test_all_nodes_reachable_from_entry() {
        for src in [
            "let x = 1;",
            "if (x) { y = 1; } else { y = 2; }",
            "while (x) { x = x - 1; }",
            "for (const v of items) { doIt(v); }",
            "try { f(); } catch (e) { g(); } finally { h(); }",
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
            assert_eq!(cfg.nodes.len(), 2);
            assert_eq!(cfg.edges.len(), 1);
            assert_eq!(cfg.edges[0].label, EdgeLabel::Flow);
        });
    }

    #[test]
    fn test_linear_statements_share_one_basic_block() {
        with_cfg("let a = 1; let b = 2; let c = 3;", |cfg| {
            let basics: Vec<_> = cfg
                .nodes
                .values()
                .filter(|n| n.kind == NodeKind::Basic)
                .collect();
            assert_eq!(basics.len(), 1);
            assert_eq!(basics[0].statements.len(), 3);
        });
    }

    // --------------------------------------------------------------- if

    #[test]
    fn test_if_else_has_true_and_false_edges() {
        with_cfg("if (x) { y = 1; } else { y = 2; }", |cfg| {
            let branch = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Branch)
                .unwrap();
            assert!(
                cfg.successors(branch.id)
                    .iter()
                    .any(|e| e.label == EdgeLabel::True)
            );
            assert!(
                cfg.successors(branch.id)
                    .iter()
                    .any(|e| e.label == EdgeLabel::False)
            );
        });
    }

    #[test]
    fn test_if_else_if_chain() {
        with_cfg(
            "if (x) { y = 1; } else if (z) { y = 2; } else { y = 3; }",
            |cfg| {
                let branches = cfg
                    .nodes
                    .values()
                    .filter(|n| n.kind == NodeKind::Branch)
                    .count();
                assert_eq!(branches, 2, "one Branch per if/else-if");
            },
        );
    }

    #[test]
    fn test_if_without_else_both_paths_reach_join() {
        with_cfg("if (x) { y = 1; } z = 2;", |cfg| {
            assert!(all_reachable_from_entry(cfg));
        });
    }

    // ------------------------------------------------------------ while/do

    #[test]
    fn test_while_has_back_edge() {
        with_cfg("while (x) { x = x - 1; }", |cfg| {
            assert!(
                cfg.edges.iter().any(|e| e.label == EdgeLabel::Back),
                "expected a Back edge (returning to the loop head)"
            );
        });
    }

    #[test]
    fn test_do_while_body_executes_before_condition() {
        with_cfg("do { x = x - 1; } while (x);", |cfg| {
            // The body must be reachable directly from the entry, BEFORE
            // the loop head (condition) — no initial Branch.
            assert!(all_reachable_from_entry(cfg));
            assert!(
                cfg.edges
                    .iter()
                    .any(|e| e.label == EdgeLabel::Back || e.label == EdgeLabel::True),
                "correctly formed loop"
            );
        });
    }

    #[test]
    fn test_break_exits_while_loop() {
        with_cfg("while (x) { if (y) { break; } z = 1; }", |cfg| {
            assert!(all_reachable_from_entry(cfg));
        });
    }

    #[test]
    fn test_continue_targets_loop_head() {
        with_cfg("while (x) { if (y) { continue; } z = 1; }", |cfg| {
            let loop_head = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Loop)
                .unwrap();
            assert!(
                cfg.predecessors(loop_head.id)
                    .iter()
                    .any(|e| e.label == EdgeLabel::Back)
            );
        });
    }

    // -------------------------------------------------------------- for

    #[test]
    fn test_for_classic_has_loop_node() {
        with_cfg("for (let i = 0; i < 10; i++) { doIt(); }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Loop), 1);
        });
    }

    #[test]
    fn test_for_in_sets_for_target() {
        with_cfg("for (const k in obj) { doIt(k); }", |cfg| {
            let loop_node = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Loop)
                .unwrap();
            assert!(loop_node.for_target.is_some());
            assert!(loop_node.condition.is_some());
        });
    }

    #[test]
    fn test_for_of_sets_for_target() {
        with_cfg("for (const v of arr) { doIt(v); }", |cfg| {
            let loop_node = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Loop)
                .unwrap();
            assert!(loop_node.for_target.is_some());
        });
    }

    #[test]
    fn test_for_empty_clauses() {
        with_cfg("for (;;) { break; }", |cfg| {
            assert!(all_reachable_from_entry(cfg));
        });
    }

    // -------------------------------------------------------------- try

    #[test]
    fn test_try_catch_links_throw_to_handler() {
        with_cfg("try { throw x; } catch (e) { g(); }", |cfg| {
            let handler = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Handler)
                .unwrap();
            let raise = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::RaiseSite)
                .unwrap();
            assert!(has_path(cfg, raise.id, handler.id));
        });
    }

    #[test]
    fn test_try_finally_always_reached() {
        with_cfg("try { f(); } catch (e) { g(); } finally { h(); }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Finally), 1);
        });
    }

    #[test]
    fn test_throw_without_handler_escapes_to_exit() {
        with_cfg("throw x;", |cfg| {
            let raise = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::RaiseSite)
                .unwrap();
            assert!(
                cfg.successors(raise.id)
                    .iter()
                    .any(|e| e.label == EdgeLabel::Escape)
            );
        });
    }

    // ---------------------------------------------------------- switch

    #[test]
    fn test_switch_case_branch_per_case() {
        with_cfg(
            "switch (x) { case 1: y = 1; break; case 2: y = 2; break; default: y = 0; }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Branch), 3);
            },
        );
    }

    #[test]
    fn test_switch_fallthrough_reaches_next_case_body() {
        // case 1 without break -> falls into the body of case 2.
        with_cfg(
            "switch (x) { case 1: y = 1; case 2: y = 2; break; }",
            |cfg| {
                assert!(all_reachable_from_entry(cfg));
            },
        );
    }

    #[test]
    fn test_switch_break_exits_to_join() {
        with_cfg("switch (x) { case 1: y = 1; break; }", |cfg| {
            assert!(all_reachable_from_entry(cfg));
        });
    }

    #[test]
    fn test_switch_case_literal_label_captured() {
        with_cfg("switch (x) { case 1: y = 1; break; }", |cfg| {
            let branch = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Branch)
                .unwrap();
            assert!(branch.switch_case_label.is_some());
        });
    }

    #[test]
    fn test_switch_default_label_is_none() {
        with_cfg("switch (x) { default: y = 0; }", |cfg| {
            let branch = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Branch)
                .unwrap();
            assert!(branch.switch_case_label.is_none());
        });
    }

    // ------------------------------------------------------------ labeled

    #[test]
    fn test_labeled_break_targets_labeled_loop() {
        with_cfg(
            "outer: for (let i = 0; i < 10; i++) { for (let j = 0; j < 10; j++) { break outer; } }",
            |cfg| {
                assert!(all_reachable_from_entry(cfg));
            },
        );
    }
}
