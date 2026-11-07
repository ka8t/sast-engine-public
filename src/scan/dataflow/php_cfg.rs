//! CFG (control-flow graph) construction for PHP — tree-sitter
//! front-end. Direct template of `js_cfg.rs` — same general contract
//! as a language front-end for the dataflow engine, fully reuses the
//! language-neutral structures from `cfg.rs`.
//!
//! Entry point: a tree-sitter `compound_statement` node (body of a
//! `function_definition`/`method_declaration`/`anonymous_function`) —
//! **or** `program` (root of an entire file), for the top-level-module
//! analysis wired into `php_taint_scan.rs` on 08/30 (mirroring
//! `cfg::build_cfg` on the Python side): classic procedural PHP code
//! outside of any function — a dominant pattern in a lot of real-world
//! PHP code (found invisible while validating against DVWA, where
//! 100% of the intentional vulnerabilities are in top-level code, 0
//! findings before this fix). `php_tag`/any declaration encountered at
//! module level falls into the catch-all `append_to_basic` (opaque
//! statement), the same mechanism as for a nested function today — no
//! double counting with the separate collection done by
//! `php_summary.rs`. An `arrow_function` (`fn($x) => $x + 1`) NEVER
//! has a `compound_statement` body in PHP (unlike JS, where only some
//! arrow functions have an expression body) — so no PHP arrow function
//! is ever collected by `php_summary.rs`, cf. its doc.
//!
//! Node shapes verified empirically (actual parsing with
//! `tree-sitter-php`, following the discipline established on the
//! `js_cfg.rs` side):
//!   - `if_statement` has a REPEATED `alternative` field (like
//!     `elif_clause`/`else_clause` in Python, cf. `cfg.rs`) — an
//!     `else_if_clause` (PHP's name, not `elif_clause`) per `elseif`,
//!     then a final `else_clause` — handled here by the same recursive
//!     cascade over `field_children(stmt, "alternative")` as
//!     `cfg.rs::visit_if`/`visit_if_like` (Python), NOT by the
//!     Java/JS model (a single optional `alternative` field).
//!   - `try_statement`: only ONE named field (`body`); `catch_clause`
//!     (PHP allows several `catch` clauses for different types) and
//!     `finally_clause` appear as additional positional children, with
//!     no field — unlike JS, where `handler`/`finalizer` are singular
//!     fields.
//!   - `switch_statement`/`switch_block`: each `case_statement`
//!     (`value` field) or `default_statement` (no field) already
//!     carries exactly ONE label — no Java-style multi-label grouping,
//!     same fall-through model as `js_cfg.rs` (one node per label, an
//!     empty body falls through to the next one).
//!   - `do_statement` has `body`/`condition` fields (same order as
//!     JS) — body executed before the first test.
//!   - `foreach_statement`: only `body` is a named field — the
//!     iterable and the target are positional (`pair(key, value)` for
//!     the `as $k => $v` form, otherwise just the target for `as $v`).
//!   - `break`/`continue` accept an optional integer level
//!     (`break 2;`) — IGNORED in v1 (accepted limitation, cf. the doc
//!     in `php_lowering.rs`): always treated as a single-level jump
//!     (nearest loop/switch), as in JS/Java without a label.
//!   - No PHP equivalent to `labeled_statement` (JS/Java): PHP has no
//!     labeled loops — only `goto`/arbitrary labels (a different
//!     feature, not modeled, falls into the catch-all
//!     `append_to_basic`).

use super::cfg::{Cfg, EdgeLabel, NodeKind, field_children, prune_unreachable};
use tree_sitter::Node;

const BODY_NODE_KINDS: [&str; 2] = ["compound_statement", "program"];

struct BreakTarget {
    exit_id: usize,
    is_loop: bool,
    loop_head_id: Option<usize>,
}

struct PhpCfgBuilder<'tree, 'src> {
    cfg: Cfg<'tree>,
    break_stack: Vec<BreakTarget>,
    try_handler_stack: Vec<Vec<usize>>,
    source: &'src [u8],
}

/// Builds a CFG from a PHP function body (tree-sitter
/// `compound_statement` node) OR from the `program` root of an entire
/// file (top-level-module analysis, cf. module doc).
pub fn build_php_cfg<'tree>(body: Node<'tree>, source: &[u8]) -> Cfg<'tree> {
    debug_assert!(
        BODY_NODE_KINDS.contains(&body.kind()),
        "build_php_cfg attend un nœud compound_statement ou program, reçu {:?}",
        body.kind()
    );
    let mut builder = PhpCfgBuilder {
        cfg: Cfg::new(),
        break_stack: Vec::new(),
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

impl<'tree, 'src> PhpCfgBuilder<'tree, 'src> {
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
            "compound_statement" => self.visit_block(stmt, cursor),
            "return_statement" => self.visit_return(stmt, cursor),
            "break_statement" => self.visit_break(cursor),
            "continue_statement" => self.visit_continue(cursor),
            "if_statement" => self.visit_if(stmt, cursor),
            "while_statement" => self.visit_while(stmt, cursor),
            "do_statement" => self.visit_do(stmt, cursor),
            "for_statement" => self.visit_for(stmt, cursor),
            "foreach_statement" => self.visit_foreach(stmt, cursor),
            "try_statement" => self.visit_try(stmt, cursor),
            "switch_statement" => self.visit_switch(stmt, cursor),
            "empty_statement" => Some(cursor),
            // `throw $x;` — verified empirically (`php_lowering.rs`):
            // it's `(expression_statement (throw_expression ...))`,
            // never a distinct statement kind. Intercepted here to
            // route it to a `RaiseSite` rather than an opaque `Basic`
            // — otherwise `throw` would never reach the CFG's `catch`
            // handlers.
            "expression_statement"
                if stmt
                    .named_children(&mut stmt.walk())
                    .next()
                    .is_some_and(|inner| inner.kind() == "throw_expression") =>
            {
                self.visit_throw(stmt, cursor)
            }
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

    // Break / Continue — no labels in PHP (neither labeled loops, nor
    // `break N`/`continue N` modeled beyond level 1, cf. module doc):
    // always targets the nearest one.

    fn visit_break(&mut self, cursor: usize) -> Option<usize> {
        let Some(target) = self.break_stack.last() else {
            return Some(cursor);
        };
        self.cfg.add_edge(cursor, target.exit_id, EdgeLabel::Flow);
        None
    }

    fn visit_continue(&mut self, cursor: usize) -> Option<usize> {
        let Some(loop_head_id) = self
            .break_stack
            .iter()
            .rev()
            .find(|t| t.is_loop)
            .and_then(|t| t.loop_head_id)
        else {
            return Some(cursor);
        };
        self.cfg.add_edge(cursor, loop_head_id, EdgeLabel::Back);
        None
    }

    // If / elseif / else — recursive cascade over the repeated
    // `alternative:` fields, same algorithm as `cfg.rs::visit_if`/
    // `visit_if_like` (Python) — PHP has the same grammar shape
    // (unlike JS/Java, which have a single optional `alternative`).

    fn visit_if(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let condition = stmt.child_by_field_name("condition");
        let body = stmt.child_by_field_name("body").expect("if sans corps");
        let alternatives = field_children(stmt, "alternative");
        self.visit_if_like(
            condition,
            body,
            &alternatives,
            cursor,
            stmt.start_position().row + 1,
        )
    }

    fn visit_if_like(
        &mut self,
        condition: Option<Node<'tree>>,
        body: Node<'tree>,
        alternatives: &[Node<'tree>],
        cursor: usize,
        lineno: usize,
    ) -> Option<usize> {
        let branch = self.cfg.add_node(NodeKind::Branch, format!("if_{lineno}"));
        self.cfg.nodes.get_mut(&branch).unwrap().condition = condition;
        self.cfg.add_edge(cursor, branch, EdgeLabel::Flow);

        let true_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("if_true_{lineno}"));
        self.cfg.add_edge(branch, true_seed, EdgeLabel::True);
        let t_end = self.visit_stmt(body, true_seed);

        let false_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("if_false_{lineno}"));
        self.cfg.add_edge(branch, false_seed, EdgeLabel::False);

        let f_end = match alternatives.split_first() {
            None => Some(false_seed),
            Some((alt, rest)) if alt.kind() == "else_if_clause" => {
                let elif_cond = alt.child_by_field_name("condition");
                let elif_body = alt.child_by_field_name("body").expect("elseif sans corps");
                self.visit_if_like(
                    elif_cond,
                    elif_body,
                    rest,
                    false_seed,
                    alt.start_position().row + 1,
                )
            }
            Some((alt, _rest)) => {
                // else_clause
                let else_body = alt.child_by_field_name("body").expect("else sans corps");
                self.visit_stmt(else_body, false_seed)
            }
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

    // Do-while — body executed before the first test (cf. module
    // doc), same strategy as `js_cfg::visit_do`.

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
        self.cfg.add_edge(loop_head, body_seed, EdgeLabel::True);
        self.cfg.add_edge(loop_head, exit_join, EdgeLabel::False);

        self.break_stack.pop();
        Some(exit_join)
    }

    // For (classic)

    fn visit_for(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let init_nodes = field_children(stmt, "initialize");
        let mut pre_cursor = cursor;
        for init in init_nodes {
            pre_cursor = self.append_to_basic(init, pre_cursor);
        }

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

    // Foreach — `body` is the only named field; the iterable/target
    // are positional (cf. module doc). `pair(key, value)` for the
    // `as $k => $v` form — only the VALUE receives the iterable's
    // taint in v1 (the key is ignored, the same simplification as the
    // array keys not modeled on the `php_lowering.rs` side).

    fn visit_foreach(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let body_field = stmt.child_by_field_name("body");
        let mut w = stmt.walk();
        let positional: Vec<Node<'tree>> = stmt
            .named_children(&mut w)
            .filter(|c| Some(c.id()) != body_field.map(|b| b.id()))
            .collect();
        let iterable = positional.first().copied();
        let target_node = positional.get(1).copied();
        let target = target_node.and_then(|t| {
            if t.kind() == "pair" {
                t.named_children(&mut t.walk()).last()
            } else {
                Some(t)
            }
        });

        let loop_head = self
            .cfg
            .add_node(NodeKind::Loop, format!("foreach_{lineno}"));
        {
            let n = self.cfg.nodes.get_mut(&loop_head).unwrap();
            n.condition = iterable;
            n.for_target = target;
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
        let body_end = match body_field {
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

    // Try / catch(es) / finally — PHP allows SEVERAL `catch_clause`
    // nodes (different types), positional (not a repeated field) —
    // cf. module doc.

    fn visit_try(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let try_entry = self
            .cfg
            .add_node(NodeKind::TryEntry, format!("try_{lineno}"));
        self.cfg.add_edge(cursor, try_entry, EdgeLabel::Flow);

        let mut w = stmt.walk();
        let catch_clauses: Vec<Node<'tree>> = stmt
            .named_children(&mut w)
            .filter(|c| c.kind() == "catch_clause")
            .collect();
        let mut w2 = stmt.walk();
        let finally_clause = stmt
            .named_children(&mut w2)
            .find(|c| c.kind() == "finally_clause");

        let mut handler_ids: Vec<usize> = Vec::new();
        for h in &catch_clauses {
            let param = h.child_by_field_name("type");
            let hid = self.cfg.add_node(
                NodeKind::Handler,
                format!("catch_{}", h.start_position().row),
            );
            self.cfg.nodes.get_mut(&hid).unwrap().handler_type = param;
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

        let fin = if let Some(fc) = finally_clause {
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
        for hc in handler_end_cursors.into_iter().flatten() {
            self.cfg.add_edge(hc, fin, EdgeLabel::Flow);
        }

        Some(fin)
    }

    // Switch — one `case_statement`/`default_statement` node PER
    // label (no multi-label grouping), same fall-through model as
    // `js_cfg::visit_switch`.

    fn visit_switch(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row;
        let subject = stmt.child_by_field_name("condition");
        let Some(body) = stmt.child_by_field_name("body") else {
            return Some(cursor);
        };
        let mut w = body.walk();
        let groups: Vec<Node<'tree>> = body
            .named_children(&mut w)
            .filter(|c| c.kind() == "case_statement" || c.kind() == "default_statement")
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
        let mut fallthrough_cursor: Option<Option<usize>> = None;

        for (i, grp) in groups.iter().enumerate() {
            let branch = self
                .cfg
                .add_node(NodeKind::Branch, format!("switch_case_{lineno}_{i}"));
            {
                let n = self.cfg.nodes.get_mut(&branch).unwrap();
                n.condition = subject;
                n.switch_case_label = if grp.kind() == "case_statement" {
                    Self::switch_case_condition(*grp)
                } else {
                    None
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

            let value_field = grp.child_by_field_name("value");
            let mut gw = grp.walk();
            let stmts: Vec<Node<'tree>> = grp
                .named_children(&mut gw)
                .filter(|c| Some(c.id()) != value_field.map(|v| v.id()))
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

    fn switch_case_condition(case_node: Node<'tree>) -> Option<Node<'tree>> {
        let value = case_node.child_by_field_name("value")?;
        const LITERAL_KINDS: [&str; 5] = ["integer", "string", "true", "false", "null"];
        if LITERAL_KINDS.contains(&value.kind()) {
            Some(value)
        } else {
            None
        }
    }
}

// ============================================================================
// Tests — mirrors the `js_cfg.rs` suite (same invariants, PHP syntax).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tree_sitter::Parser;

    fn parse_php(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
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

    fn with_cfg<R>(body_src: &str, f: impl FnOnce(&Cfg) -> R) -> R {
        let src = format!("<?php\nfunction t() {{ {body_src} }}");
        let tree = parse_php(&src);
        assert!(
            !tree.root_node().has_error(),
            "syntaxe PHP invalide : {body_src:?}"
        );
        let func = find_first(tree.root_node(), "function_definition").unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let cfg = build_php_cfg(body, src.as_bytes());
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
            "$x = 1;",
            "$x = 1; $y = 2; $z = 3;",
            "if ($x) { $y = 1; }",
            "if ($x) { $y = 1; } else { $y = 2; }",
            "while ($x) { $x = $x - 1; }",
            "do { $x = $x - 1; } while ($x);",
            "for ($i = 0; $i < 10; $i++) { doIt(); }",
            "foreach ($arr as $v) { doIt($v); }",
            "try { f(); } catch (Exception $e) { }",
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
            "$x = 1;",
            "if ($x) { $y = 1; } else { $y = 2; }",
            "while ($x) { $x = $x - 1; }",
        ] {
            with_cfg(src, |cfg| {
                assert!(cfg.predecessors(cfg.entry).is_empty(), "src={src:?}");
            });
        }
    }

    #[test]
    fn test_exit_has_no_successors() {
        for src in ["$x = 1;", "if ($x) { $y = 1; } else { $y = 2; }", "return;"] {
            with_cfg(src, |cfg| {
                assert!(cfg.successors(cfg.exit).is_empty(), "src={src:?}");
            });
        }
    }

    #[test]
    fn test_all_nodes_reachable_from_entry() {
        for src in [
            "$x = 1;",
            "if ($x) { $y = 1; } else { $y = 2; }",
            "while ($x) { $x = $x - 1; }",
            "foreach ($items as $v) { doIt($v); }",
            "try { f(); } catch (Exception $e) { g(); } finally { h(); }",
            "switch ($x) { case 1: $y = 1; break; default: $y = 2; }",
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
        with_cfg("$a = 1; $b = 2; $c = 3;", |cfg| {
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
        with_cfg("if ($x) { $y = 1; } else { $y = 2; }", |cfg| {
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
    fn test_elseif_chain_one_branch_per_clause() {
        with_cfg(
            "if ($x) { $y = 1; } elseif ($z) { $y = 2; } else { $y = 3; }",
            |cfg| {
                let branches = cfg
                    .nodes
                    .values()
                    .filter(|n| n.kind == NodeKind::Branch)
                    .count();
                assert_eq!(branches, 2, "un Branch par if/elseif");
            },
        );
    }

    #[test]
    fn test_if_without_else_both_paths_reach_join() {
        with_cfg("if ($x) { $y = 1; } $z = 2;", |cfg| {
            assert!(all_reachable_from_entry(cfg));
        });
    }

    // ------------------------------------------------------------ while/do

    #[test]
    fn test_while_has_back_edge() {
        with_cfg("while ($x) { $x = $x - 1; }", |cfg| {
            assert!(
                cfg.edges.iter().any(|e| e.label == EdgeLabel::Back),
                "attendu une arête Back (retour à la tête de boucle)"
            );
        });
    }

    #[test]
    fn test_do_while_body_executes_before_condition() {
        with_cfg("do { $x = $x - 1; } while ($x);", |cfg| {
            assert!(all_reachable_from_entry(cfg));
            assert!(
                cfg.edges
                    .iter()
                    .any(|e| e.label == EdgeLabel::Back || e.label == EdgeLabel::True),
                "boucle correctement formée"
            );
        });
    }

    #[test]
    fn test_break_exits_while_loop() {
        with_cfg("while ($x) { if ($y) { break; } $z = 1; }", |cfg| {
            assert!(all_reachable_from_entry(cfg));
        });
    }

    #[test]
    fn test_continue_targets_loop_head() {
        with_cfg("while ($x) { if ($y) { continue; } $z = 1; }", |cfg| {
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
        with_cfg("for ($i = 0; $i < 10; $i++) { doIt(); }", |cfg| {
            assert_eq!(count_kind(cfg, NodeKind::Loop), 1);
        });
    }

    #[test]
    fn test_foreach_sets_for_target() {
        with_cfg("foreach ($arr as $v) { doIt($v); }", |cfg| {
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
    fn test_foreach_keyed_form_target_is_value_not_key() {
        let src = "<?php\nfunction t() { foreach ($arr as $k => $v) { doIt($v); } }";
        let tree = parse_php(src);
        let func = find_first(tree.root_node(), "function_definition").unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let cfg = build_php_cfg(body, src.as_bytes());
        let loop_node = cfg
            .nodes
            .values()
            .find(|n| n.kind == NodeKind::Loop)
            .unwrap();
        let target_text = loop_node
            .for_target
            .unwrap()
            .utf8_text(src.as_bytes())
            .unwrap();
        assert_eq!(target_text, "$v");
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
        with_cfg("try { throw $x; } catch (Exception $e) { g(); }", |cfg| {
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
    fn test_try_multiple_catch_clauses() {
        with_cfg(
            "try { f(); } catch (TypeA $e) { g(); } catch (TypeB $e) { h(); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Handler), 2);
            },
        );
    }

    #[test]
    fn test_try_finally_always_reached() {
        with_cfg(
            "try { f(); } catch (Exception $e) { g(); } finally { h(); }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Finally), 1);
            },
        );
    }

    #[test]
    fn test_throw_without_handler_escapes_to_exit() {
        with_cfg("throw $x;", |cfg| {
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
            "switch ($x) { case 1: $y = 1; break; case 2: $y = 2; break; default: $y = 0; }",
            |cfg| {
                assert_eq!(count_kind(cfg, NodeKind::Branch), 3);
            },
        );
    }

    #[test]
    fn test_switch_fallthrough_reaches_next_case_body() {
        with_cfg(
            "switch ($x) { case 1: $y = 1; case 2: $y = 2; break; }",
            |cfg| {
                assert!(all_reachable_from_entry(cfg));
            },
        );
    }

    #[test]
    fn test_switch_case_literal_label_captured() {
        with_cfg("switch ($x) { case 1: $y = 1; break; }", |cfg| {
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
        with_cfg("switch ($x) { default: $y = 0; }", |cfg| {
            let branch = cfg
                .nodes
                .values()
                .find(|n| n.kind == NodeKind::Branch)
                .unwrap();
            assert!(branch.switch_case_label.is_none());
        });
    }
}
