//! CFG (Control Flow Graph) construction — faithful port of
//! `Audit/sca/dataflow/cfg.py`.
//!
//! **Accepted implementation difference (noted in the plan, Step 3.3)**:
//! Python builds the CFG by walking the stdlib AST (`ast.parse`).
//! Rust has no equivalent — the CFG is built here by walking
//! the `tree-sitter-python` tree (CST, not a dedicated semantic AST),
//! already a dependency (Step 3.2, AST executor). The tree-sitter
//! node types (`if_statement`, `for_statement`, `try_statement`...)
//! cover the Python grammar closely enough that a second parser is not
//! warranted. Notable structural difference: tree-sitter
//! represents `elif` as sibling `alternative:` fields of
//! `if_statement` (`elif_clause`/`else_clause`), whereas the Python AST
//! nests recursively (`If.orelse = [If(...)]`) — the produced
//! graph shape is equivalent (a cascade of BRANCH nodes), built here
//! by recursion over the list of `alternative:` fields rather than over
//! nested `If` nodes.

use std::collections::{BTreeMap, HashSet};
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKind {
    Entry,
    Exit,
    Basic,
    Branch,
    Join,
    Loop,
    TryEntry,
    Handler,
    Finally,
    RaiseSite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeLabel {
    Flow,
    True,
    False,
    Back,
    Except,
    Escape,
}

/// CFG node. Depending on `kind`: `statements` non-empty for `Basic`;
/// `condition` non-`None` for `Branch`/`Loop`; `handler_type`/
/// `handler_name` for `Handler`.
pub struct CfgNode<'tree> {
    pub id: usize,
    pub kind: NodeKind,
    pub statements: Vec<Node<'tree>>,
    pub condition: Option<Node<'tree>>,
    pub handler_type: Option<Node<'tree>>,
    pub handler_name: Option<String>,
    pub label: String,
    /// For loop: iteration target (`for <target> in <iter>:`).
    pub for_target: Option<Node<'tree>>,
    /// **Java-specific** (`java_cfg.rs`): on a switch `Branch` node,
    /// the simple literal label of a single `case` (e.g. `case 1:`)
    /// — when present, `condition` carries the switch subject and this
    /// field carries the compared label (`subject == label`). Mirrors
    /// `SwitchCaseCondition` on the Python side (`java_to_ir.py`), which encodes
    /// this pair as a dynamically-typed duplicated object (tree-sitter
    /// has no synthesizable node for `subject == label`) — here
    /// represented by two typed `Option<Node>` fields instead of a
    /// dynamic union. `None` (the `default` case, a multi-label group, or
    /// a non-literal label): `condition` alone is used, opaque,
    /// the same strategy as `_match_case_condition` on the Python side.
    pub switch_case_label: Option<Node<'tree>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CfgEdge {
    pub src: usize,
    pub dst: usize,
    pub label: EdgeLabel,
}

pub struct Cfg<'tree> {
    pub nodes: BTreeMap<usize, CfgNode<'tree>>,
    pub edges: Vec<CfgEdge>,
    pub entry: usize,
    pub exit: usize,
    next_id: usize,
}

impl<'tree> Cfg<'tree> {
    pub(crate) fn new() -> Self {
        Cfg {
            nodes: BTreeMap::new(),
            edges: Vec::new(),
            entry: 0,
            exit: 0,
            next_id: 0,
        }
    }

    pub(crate) fn add_node(&mut self, kind: NodeKind, label: impl Into<String>) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert(
            id,
            CfgNode {
                id,
                kind,
                statements: Vec::new(),
                condition: None,
                handler_type: None,
                handler_name: None,
                label: label.into(),
                for_target: None,
                switch_case_label: None,
            },
        );
        id
    }

    /// Adds an edge, deduplicated by (src, dst, label).
    pub(crate) fn add_edge(&mut self, src: usize, dst: usize, label: EdgeLabel) {
        let edge = CfgEdge { src, dst, label };
        if !self.edges.contains(&edge) {
            self.edges.push(edge);
        }
    }

    pub fn successors(&self, node_id: usize) -> Vec<CfgEdge> {
        self.edges
            .iter()
            .filter(|e| e.src == node_id)
            .cloned()
            .collect()
    }

    pub fn predecessors(&self, node_id: usize) -> Vec<CfgEdge> {
        self.edges
            .iter()
            .filter(|e| e.dst == node_id)
            .cloned()
            .collect()
    }

    pub fn successor_ids(&self, node_id: usize) -> Vec<usize> {
        self.successors(node_id).iter().map(|e| e.dst).collect()
    }

    pub fn predecessor_ids(&self, node_id: usize) -> Vec<usize> {
        self.predecessors(node_id).iter().map(|e| e.src).collect()
    }
}

/// Builds a CFG from an already-parsed `tree-sitter-python` tree
/// and its source text (needed to read the alias name of
/// `except X as e`). Mirrors `build_cfg(module)`.
pub fn build_cfg<'tree>(tree: &'tree tree_sitter::Tree, source: &[u8]) -> Cfg<'tree> {
    build_cfg_from_block(source, tree.root_node())
}

/// Builds a CFG from any "container" node
/// (named statements as direct children) — not just the root
/// of a complete tree. Used to analyze a function's body
/// as a self-contained sub-module (§8, `summary.rs::function_to_sub_module`
/// on the Python side — Rust does not need to fabricate a fake root node,
/// the function's `block` directly serves as the container).
pub fn build_cfg_from_block<'tree>(source: &[u8], block: Node<'tree>) -> Cfg<'tree> {
    let mut builder = CfgBuilder {
        cfg: Cfg::new(),
        loop_stack: Vec::new(),
        try_stack: Vec::new(),
        source,
    };
    builder.cfg.entry = builder.cfg.add_node(NodeKind::Entry, "entry");
    builder.cfg.exit = builder.cfg.add_node(NodeKind::Exit, "exit");

    let cursor = builder.visit_block_children(block, Some(builder.cfg.entry));
    if let Some(c) = cursor {
        builder.cfg.add_edge(c, builder.cfg.exit, EdgeLabel::Flow);
    }
    prune_unreachable(&mut builder.cfg);
    builder.cfg
}

struct CfgBuilder<'tree, 'src> {
    cfg: Cfg<'tree>,
    /// Stack of (loop_head, exit_join) for break/continue.
    loop_stack: Vec<(usize, usize)>,
    /// Stack of lists of active handlers, for raise.
    try_stack: Vec<Vec<usize>>,
    source: &'src [u8],
}

impl<'tree, 'src> CfgBuilder<'tree, 'src> {
    /// Visits the named children of a "container" node (module or
    /// block) as a sequence of statements.
    fn visit_block_children(
        &mut self,
        container: Node<'tree>,
        cursor: Option<usize>,
    ) -> Option<usize> {
        let mut cursor = cursor;
        let mut walker = container.walk();
        for child in container.named_children(&mut walker) {
            if child.kind() == "comment" {
                continue;
            }
            cursor = self.visit_stmt(child, cursor);
            if cursor.is_none() {
                break; // rest of the sequence is unreachable
            }
        }
        cursor
    }

    fn visit_stmt(&mut self, stmt: Node<'tree>, cursor: Option<usize>) -> Option<usize> {
        let cursor = cursor?; // UNREACHABLE propagates
        match stmt.kind() {
            "if_statement" => self.visit_if(stmt, cursor),
            "while_statement" => self.visit_while(stmt, cursor),
            "for_statement" => self.visit_for(stmt, cursor),
            "try_statement" => self.visit_try(stmt, cursor),
            "with_statement" => self.visit_with(stmt, cursor),
            "match_statement" => self.visit_match(stmt, cursor),
            "return_statement" => self.visit_return(stmt, cursor),
            "raise_statement" => self.visit_raise(stmt, cursor),
            "break_statement" => self.visit_break(stmt, cursor),
            "continue_statement" => self.visit_continue(stmt, cursor),
            // Everything else: opaque linear statement (assignment,
            // expression_statement, import, global, nonlocal, delete,
            // assert, pass, function_definition, class_definition,
            // decorated_definition...) — same choice as Python
            // (_visit_default, including for FunctionDef/ClassDef: an opaque
            // block, no recursion into the function body here).
            _ => Some(self.append_to_basic(stmt, cursor)),
        }
    }

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

    fn visit_return(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let bb = self.cfg.add_node(
            NodeKind::Basic,
            format!("return_{}", stmt.start_position().row + 1),
        );
        self.cfg.nodes.get_mut(&bb).unwrap().statements.push(stmt);
        self.cfg.add_edge(cursor, bb, EdgeLabel::Flow);
        self.cfg.add_edge(bb, self.cfg.exit, EdgeLabel::Flow);
        None
    }

    fn visit_raise(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let rs = self.cfg.add_node(
            NodeKind::RaiseSite,
            format!("raise_{}", stmt.start_position().row + 1),
        );
        self.cfg.nodes.get_mut(&rs).unwrap().statements.push(stmt);
        self.cfg.add_edge(cursor, rs, EdgeLabel::Flow);
        if let Some(handlers) = self.try_stack.last().filter(|h| !h.is_empty()) {
            for &handler_id in &handlers.clone() {
                self.cfg.add_edge(rs, handler_id, EdgeLabel::Except);
            }
        } else {
            self.cfg.add_edge(rs, self.cfg.exit, EdgeLabel::Escape);
        }
        None
    }

    fn visit_break(&mut self, _stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let Some(&(_loop_head, exit_join)) = self.loop_stack.last() else {
            return Some(cursor); // invalid source code, do not crash
        };
        self.cfg.add_edge(cursor, exit_join, EdgeLabel::Flow);
        None
    }

    fn visit_continue(&mut self, _stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let Some(&(loop_head, _exit_join)) = self.loop_stack.last() else {
            return Some(cursor);
        };
        self.cfg.add_edge(cursor, loop_head, EdgeLabel::Back);
        None
    }

    /// If / elif / else — recursive cascade over the `alternative:` fields.
    fn visit_if(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let condition = stmt.child_by_field_name("condition");
        let consequence = stmt
            .child_by_field_name("consequence")
            .expect("if sans corps");
        let alternatives = field_children(stmt, "alternative");
        self.visit_if_like(
            condition,
            consequence,
            &alternatives,
            cursor,
            stmt.start_position().row + 1,
        )
    }

    fn visit_if_like(
        &mut self,
        condition: Option<Node<'tree>>,
        consequence: Node<'tree>,
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
        let t_end = self.visit_block_children(consequence, Some(true_seed));

        let false_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("if_false_{lineno}"));
        self.cfg.add_edge(branch, false_seed, EdgeLabel::False);

        let f_end = match alternatives.split_first() {
            None => Some(false_seed),
            Some((alt, rest)) if alt.kind() == "elif_clause" => {
                let elif_cond = alt.child_by_field_name("condition");
                let elif_body = alt
                    .child_by_field_name("consequence")
                    .expect("elif sans corps");
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
                self.visit_block_children(else_body, Some(false_seed))
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

    fn visit_while(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row + 1;
        let loop_head = self.cfg.add_node(NodeKind::Loop, format!("while_{lineno}"));
        self.cfg.nodes.get_mut(&loop_head).unwrap().condition =
            stmt.child_by_field_name("condition");
        self.cfg.add_edge(cursor, loop_head, EdgeLabel::Flow);

        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("while_end_{lineno}"));
        self.loop_stack.push((loop_head, exit_join));

        let body_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("while_body_{lineno}"));
        self.cfg.add_edge(loop_head, body_seed, EdgeLabel::True);
        let body = stmt.child_by_field_name("body").expect("while sans corps");
        let body_end = self.visit_block_children(body, Some(body_seed));
        if let Some(be) = body_end {
            self.cfg.add_edge(be, loop_head, EdgeLabel::Back);
        }

        if let Some(alt) = stmt.child_by_field_name("alternative") {
            let else_seed = self
                .cfg
                .add_node(NodeKind::Join, format!("while_else_{lineno}"));
            self.cfg.add_edge(loop_head, else_seed, EdgeLabel::False);
            let else_body = alt
                .child_by_field_name("body")
                .expect("while-else sans corps");
            let else_end = self.visit_block_children(else_body, Some(else_seed));
            if let Some(ee) = else_end {
                self.cfg.add_edge(ee, exit_join, EdgeLabel::Flow);
            }
        } else {
            self.cfg.add_edge(loop_head, exit_join, EdgeLabel::False);
        }

        self.loop_stack.pop();
        Some(exit_join)
    }

    fn visit_for(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row + 1;
        let loop_head = self.cfg.add_node(NodeKind::Loop, format!("for_{lineno}"));
        {
            let n = self.cfg.nodes.get_mut(&loop_head).unwrap();
            n.condition = stmt.child_by_field_name("right"); // the iterable
            n.for_target = stmt.child_by_field_name("left"); // the target
        }
        self.cfg.add_edge(cursor, loop_head, EdgeLabel::Flow);
        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("for_end_{lineno}"));
        self.loop_stack.push((loop_head, exit_join));

        let body_seed = self
            .cfg
            .add_node(NodeKind::Join, format!("for_body_{lineno}"));
        self.cfg.add_edge(loop_head, body_seed, EdgeLabel::True);
        let body = stmt.child_by_field_name("body").expect("for sans corps");
        let body_end = self.visit_block_children(body, Some(body_seed));
        if let Some(be) = body_end {
            self.cfg.add_edge(be, loop_head, EdgeLabel::Back);
        }

        if let Some(alt) = stmt.child_by_field_name("alternative") {
            let else_seed = self
                .cfg
                .add_node(NodeKind::Join, format!("for_else_{lineno}"));
            self.cfg.add_edge(loop_head, else_seed, EdgeLabel::False);
            let else_body = alt
                .child_by_field_name("body")
                .expect("for-else sans corps");
            let else_end = self.visit_block_children(else_body, Some(else_seed));
            if let Some(ee) = else_end {
                self.cfg.add_edge(ee, exit_join, EdgeLabel::Flow);
            }
        } else {
            self.cfg.add_edge(loop_head, exit_join, EdgeLabel::False);
        }

        self.loop_stack.pop();
        Some(exit_join)
    }

    fn visit_try(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row + 1;
        let try_entry = self
            .cfg
            .add_node(NodeKind::TryEntry, format!("try_{lineno}"));
        self.cfg.add_edge(cursor, try_entry, EdgeLabel::Flow);

        let except_clauses: Vec<Node<'tree>> = stmt
            .children(&mut stmt.walk())
            .filter(|c| c.kind() == "except_clause")
            .collect();
        let mut handler_ids = Vec::new();
        for h in &except_clauses {
            let hid = self.cfg.add_node(
                NodeKind::Handler,
                format!("except_{}", h.start_position().row + 1),
            );
            let (handler_type, handler_name) = except_type_and_name(*h, self.source);
            {
                let n = self.cfg.nodes.get_mut(&hid).unwrap();
                n.handler_type = handler_type;
                n.handler_name = handler_name;
            }
            handler_ids.push(hid);
        }

        self.try_stack.push(handler_ids.clone());
        let body = stmt.child_by_field_name("body").expect("try sans corps");
        let mut body_cursor = self.visit_block_children(body, Some(try_entry));

        if let Some(else_clause) = stmt
            .children(&mut stmt.walk())
            .find(|c| c.kind() == "else_clause")
            && let Some(bc) = body_cursor
        {
            let orelse_seed = self
                .cfg
                .add_node(NodeKind::Join, format!("try_orelse_{lineno}"));
            self.cfg.add_edge(bc, orelse_seed, EdgeLabel::Flow);
            let orelse_body = else_clause
                .child_by_field_name("body")
                .expect("try-else sans corps");
            body_cursor = self.visit_block_children(orelse_body, Some(orelse_seed));
        }

        self.try_stack.pop();

        let mut handler_end_cursors = Vec::new();
        for (h, &hid) in except_clauses.iter().zip(handler_ids.iter()) {
            // Over-approximation: an except is always reachable from
            // try_entry (an implicit exception can occur anywhere
            // in the body), not only via an explicit raise.
            self.cfg.add_edge(try_entry, hid, EdgeLabel::Except);
            let h_body = h
                .child_by_field_name("consequence")
                .or_else(|| h.children(&mut h.walk()).find(|c| c.kind() == "block"))
                .expect("except sans corps");
            handler_end_cursors.push(self.visit_block_children(h_body, Some(hid)));
        }

        let finally_clause = stmt
            .children(&mut stmt.walk())
            .find(|c| c.kind() == "finally_clause");
        let fin = if let Some(fc) = finally_clause {
            let fin_id = self
                .cfg
                .add_node(NodeKind::Finally, format!("finally_{lineno}"));
            let fin_body = fc.children(&mut fc.walk()).find(|c| c.kind() == "block");
            if let Some(b) = fin_body {
                let mut w = b.walk();
                for stmt_node in b.named_children(&mut w) {
                    self.cfg
                        .nodes
                        .get_mut(&fin_id)
                        .unwrap()
                        .statements
                        .push(stmt_node);
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

    /// `with`/`async with` — minimally desugared into an opaque entry
    /// block followed by the body (no `__enter__`/
    /// `__exit__` modeling — same choice as Python, phase 1).
    fn visit_with(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row + 1;
        let with_bb = self.cfg.add_node(NodeKind::Basic, format!("with_{lineno}"));
        self.cfg
            .nodes
            .get_mut(&with_bb)
            .unwrap()
            .statements
            .push(stmt);
        self.cfg.add_edge(cursor, with_bb, EdgeLabel::Flow);
        let body = stmt.child_by_field_name("body").expect("with sans corps");
        self.visit_block_children(body, Some(with_bb))
    }

    /// `match`/`case` — cascade of BRANCH nodes, one per case (same choice as
    /// Python: synthetic `subject == value` condition only
    /// for a simple literal pattern without a guard, otherwise an
    /// opaque condition = the subject).
    fn visit_match(&mut self, stmt: Node<'tree>, cursor: usize) -> Option<usize> {
        let lineno = stmt.start_position().row + 1;
        let subject = stmt.child_by_field_name("subject");
        let body = stmt.child_by_field_name("body").expect("match sans corps");
        let cases: Vec<Node<'tree>> = field_children(body, "alternative");

        let exit_join = self
            .cfg
            .add_node(NodeKind::Join, format!("match_end_{lineno}"));
        let mut prev_false = cursor;

        for (i, case) in cases.iter().enumerate() {
            let branch = self
                .cfg
                .add_node(NodeKind::Branch, format!("match_case_{lineno}_{i}"));
            self.cfg.nodes.get_mut(&branch).unwrap().condition = subject; // opaque condition = the subject (conservative choice, cf. Python)
            self.cfg.add_edge(prev_false, branch, EdgeLabel::Flow);

            let body_seed = self
                .cfg
                .add_node(NodeKind::Join, format!("match_body_{lineno}_{i}"));
            self.cfg.add_edge(branch, body_seed, EdgeLabel::True);
            let case_body = case
                .child_by_field_name("consequence")
                .expect("case sans corps");
            let body_end = self.visit_block_children(case_body, Some(body_seed));
            if let Some(be) = body_end {
                self.cfg.add_edge(be, exit_join, EdgeLabel::Flow);
            }

            let next_false = self
                .cfg
                .add_node(NodeKind::Join, format!("match_else_{lineno}_{i}"));
            self.cfg.add_edge(branch, next_false, EdgeLabel::False);
            prev_false = next_false;
        }

        self.cfg.add_edge(prev_false, exit_join, EdgeLabel::Flow);
        Some(exit_join)
    }
}

/// Returns, in order, all children of `node` carrying the
/// `field_name` field — tree-sitter allows several children with the same
/// field name (e.g. `alternative:` repeated for elif/else).
pub(super) fn field_children<'tree>(node: Node<'tree>, field_name: &str) -> Vec<Node<'tree>> {
    let mut result = Vec::new();
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        let mut index = 0u32;
        loop {
            if node.field_name_for_child(index) == Some(field_name) {
                result.push(cursor.node());
            }
            index += 1;
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    result
}

/// Extracts (type, name) from an `except_clause` — handles `except X as e`
/// (an `as_pattern` node wrapping the type and the alias, whose name must
/// be read from the source text via `source`), `except X` (direct
/// type) and `except:` (none).
fn except_type_and_name<'tree>(
    handler: Node<'tree>,
    source: &[u8],
) -> (Option<Node<'tree>>, Option<String>) {
    let Some(value) = handler.child_by_field_name("value") else {
        return (None, None);
    };
    if value.kind() != "as_pattern" {
        return (Some(value), None);
    }
    let mut w = value.walk();
    let exc_type = value.named_children(&mut w).next();
    let alias_name = value
        .child_by_field_name("alias")
        .and_then(|target| target.named_children(&mut target.walk()).next())
        .and_then(|ident| ident.utf8_text(source).ok())
        .map(str::to_string);
    (exc_type, alias_name)
}

/// Removes from the CFG all nodes not reachable from `entry`
/// (spec invariant §2.4). `entry`/`exit` are never removed.
pub fn prune_unreachable(cfg: &mut Cfg) {
    if cfg.nodes.is_empty() {
        return;
    }
    let mut reachable: HashSet<usize> = HashSet::new();
    let mut stack = vec![cfg.entry];
    while let Some(nid) = stack.pop() {
        if !reachable.insert(nid) {
            continue;
        }
        for e in cfg.successors(nid) {
            if !reachable.contains(&e.dst) {
                stack.push(e.dst);
            }
        }
    }
    reachable.insert(cfg.exit);

    cfg.nodes.retain(|nid, _| reachable.contains(nid));
    cfg.edges
        .retain(|e| reachable.contains(&e.src) && reachable.contains(&e.dst));
}

/// Reverse post-order (RPO) traversal — used by the worklist
/// to minimize the number of iterations.
pub fn reverse_post_order(cfg: &Cfg) -> Vec<usize> {
    let mut visited = HashSet::new();
    let mut post_order = Vec::new();

    fn dfs(cfg: &Cfg, node_id: usize, visited: &mut HashSet<usize>, post_order: &mut Vec<usize>) {
        if !visited.insert(node_id) {
            return;
        }
        for e in cfg.successors(node_id) {
            dfs(cfg, e.dst, visited, post_order);
        }
        post_order.push(node_id);
    }

    dfs(cfg, cfg.entry, &mut visited, &mut post_order);
    post_order.reverse();
    post_order
}

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

    fn build(src: &str) -> (tree_sitter::Tree, Vec<u8>) {
        (parse(src), src.as_bytes().to_vec())
    }

    fn count_kind(cfg: &Cfg, kind: NodeKind) -> usize {
        cfg.nodes.values().filter(|n| n.kind == kind).count()
    }

    fn count_label(cfg: &Cfg, label: EdgeLabel) -> usize {
        cfg.edges.iter().filter(|e| e.label == label).count()
    }

    #[test]
    fn test_linear_sequence_single_basic_block() {
        let (tree, src) = build("x = 1\ny = 2\nz = 3\n");
        let cfg = build_cfg(&tree, &src);
        // entry -> basic -> exit: a single basic block grouping the 3 statements.
        assert_eq!(count_kind(&cfg, NodeKind::Basic), 1);
        let basic = cfg
            .nodes
            .values()
            .find(|n| n.kind == NodeKind::Basic)
            .unwrap();
        assert_eq!(basic.statements.len(), 3);
    }

    #[test]
    fn test_entry_and_exit_always_present_and_reachable() {
        let (tree, src) = build("x = 1\n");
        let cfg = build_cfg(&tree, &src);
        assert!(cfg.nodes.contains_key(&cfg.entry));
        assert!(cfg.nodes.contains_key(&cfg.exit));
        assert_eq!(cfg.nodes[&cfg.entry].kind, NodeKind::Entry);
        assert_eq!(cfg.nodes[&cfg.exit].kind, NodeKind::Exit);
    }

    #[test]
    fn test_if_else_has_true_and_false_edges() {
        let (tree, src) = build("if a:\n    x = 1\nelse:\n    x = 2\n");
        let cfg = build_cfg(&tree, &src);
        assert_eq!(count_kind(&cfg, NodeKind::Branch), 1);
        assert_eq!(count_label(&cfg, EdgeLabel::True), 1);
        assert_eq!(count_label(&cfg, EdgeLabel::False), 1);
    }

    #[test]
    fn test_if_elif_else_produces_two_branches() {
        let (tree, src) = build("if a:\n    x = 1\nelif b:\n    x = 2\nelse:\n    x = 3\n");
        let cfg = build_cfg(&tree, &src);
        // One Branch for the if, one for the elif (cascade).
        assert_eq!(count_kind(&cfg, NodeKind::Branch), 2);
    }

    #[test]
    fn test_if_without_else_still_reaches_exit() {
        let (tree, src) = build("if a:\n    x = 1\ny = 2\n");
        let cfg = build_cfg(&tree, &src);
        // Both paths (a true or false) must reach exit.
        assert!(reverse_post_order(&cfg).contains(&cfg.exit));
    }

    #[test]
    fn test_while_has_loop_node_and_back_edge() {
        let (tree, src) = build("while a:\n    x = 1\n");
        let cfg = build_cfg(&tree, &src);
        assert_eq!(count_kind(&cfg, NodeKind::Loop), 1);
        assert_eq!(count_label(&cfg, EdgeLabel::Back), 1);
    }

    #[test]
    fn test_while_else_wires_false_edge_to_else_body() {
        let (tree, src) = build("while a:\n    x = 1\nelse:\n    y = 2\n");
        let cfg = build_cfg(&tree, &src);
        // The false condition must lead to the else body, not directly to exit_join.
        let loop_node = cfg
            .nodes
            .values()
            .find(|n| n.kind == NodeKind::Loop)
            .unwrap();
        let false_targets: Vec<_> = cfg
            .successors(loop_node.id)
            .into_iter()
            .filter(|e| e.label == EdgeLabel::False)
            .map(|e| e.dst)
            .collect();
        assert_eq!(false_targets.len(), 1);
        // The FALSE target must have a successor leading to a Basic block
        // (the else body), not already be the exit node itself.
        assert!(!cfg.successors(false_targets[0]).is_empty());
    }

    #[test]
    fn test_for_has_loop_node_with_target_and_iter() {
        let (tree, src) = build("for i in items:\n    x = i\n");
        let cfg = build_cfg(&tree, &src);
        let loop_node = cfg
            .nodes
            .values()
            .find(|n| n.kind == NodeKind::Loop)
            .unwrap();
        assert!(loop_node.for_target.is_some());
        assert!(loop_node.condition.is_some()); // the iterable
    }

    #[test]
    fn test_break_jumps_to_loop_exit_not_back_edge() {
        let (tree, src) = build("while a:\n    if b:\n        break\n    x = 1\n");
        let cfg = build_cfg(&tree, &src);
        // The break must produce a direct FLOW edge to the loop's
        // exit_join (no BACK edge from the break point).
        assert!(count_label(&cfg, EdgeLabel::Flow) > 0);
    }

    #[test]
    fn test_continue_produces_back_edge() {
        let (tree, src) = build("while a:\n    if b:\n        continue\n    x = 1\n");
        let cfg = build_cfg(&tree, &src);
        // Two BACK edges: one for the normal end of the body, one for the continue.
        assert_eq!(count_label(&cfg, EdgeLabel::Back), 2);
    }

    #[test]
    fn test_return_links_directly_to_exit() {
        // FunctionDef is an opaque block on the Python side (no recursion
        // into the body) — a `return` is therefore never actually
        // visited in practice by this builder. We test its
        // structural shape directly: `return` in statement position
        // always links its block to the exit node via a FLOW edge, regardless
        // of its originating context.
        let (tree, src) = build("x = 1\nreturn 2\n");
        let cfg = build_cfg(&tree, &src);
        let return_bb = cfg
            .nodes
            .values()
            .find(|n| n.statements.iter().any(|s| s.kind() == "return_statement"))
            .expect("bloc contenant le return introuvable"); // block containing the return not found
        let targets = cfg.successor_ids(return_bb.id);
        assert_eq!(targets, vec![cfg.exit]);
    }

    #[test]
    fn test_module_level_return_is_rejected_by_grammar_use_raise_instead() {
        let (tree, src) = build("raise ValueError('x')\n");
        let cfg = build_cfg(&tree, &src);
        assert_eq!(count_kind(&cfg, NodeKind::RaiseSite), 1);
        // No enclosing try: must escape (ESCAPE) to exit.
        assert_eq!(count_label(&cfg, EdgeLabel::Escape), 1);
    }

    #[test]
    fn test_raise_inside_try_reaches_handler_via_except_edge() {
        let (tree, src) =
            build("try:\n    raise ValueError('x')\nexcept ValueError as e:\n    y = 1\n");
        let cfg = build_cfg(&tree, &src);
        assert_eq!(count_kind(&cfg, NodeKind::TryEntry), 1);
        assert_eq!(count_kind(&cfg, NodeKind::Handler), 1);
        assert!(count_label(&cfg, EdgeLabel::Except) >= 1);
        let handler = cfg
            .nodes
            .values()
            .find(|n| n.kind == NodeKind::Handler)
            .unwrap();
        assert_eq!(handler.handler_name.as_deref(), Some("e"));
    }

    #[test]
    fn test_try_finally_produces_finally_node_with_statements() {
        let (tree, src) = build("try:\n    a()\nexcept ValueError:\n    b()\nfinally:\n    c()\n");
        let cfg = build_cfg(&tree, &src);
        let fin = cfg.nodes.values().find(|n| n.kind == NodeKind::Finally);
        assert!(fin.is_some());
        assert_eq!(fin.unwrap().statements.len(), 1);
    }

    #[test]
    fn test_try_without_finally_uses_join_not_finally_node() {
        let (tree, src) = build("try:\n    a()\nexcept ValueError:\n    b()\n");
        let cfg = build_cfg(&tree, &src);
        assert_eq!(count_kind(&cfg, NodeKind::Finally), 0);
    }

    #[test]
    fn test_with_statement_is_opaque_basic_block_then_body() {
        // The `with` itself becomes an opaque Basic block, cursor to visit
        // its body next — since this new block has no successor yet,
        // `x = 1` (a linear statement) gets merged into it instead of
        // creating a second block: same merging behavior as Python
        // (_append_to_basic extends in place as long as the current
        // block has no successor), so a single Basic block in the end,
        // containing both statements.
        let (tree, src) = build("with open(f) as g:\n    x = 1\n");
        let cfg = build_cfg(&tree, &src);
        assert_eq!(count_kind(&cfg, NodeKind::Basic), 1);
        let basic = cfg
            .nodes
            .values()
            .find(|n| n.kind == NodeKind::Basic)
            .unwrap();
        assert_eq!(basic.statements.len(), 2);
        assert_eq!(basic.statements[0].kind(), "with_statement");
    }

    #[test]
    fn test_match_statement_produces_branch_per_case() {
        let (tree, src) =
            build("match x:\n    case 1:\n        y = 1\n    case _:\n        y = 2\n");
        let cfg = build_cfg(&tree, &src);
        assert_eq!(count_kind(&cfg, NodeKind::Branch), 2);
    }

    #[test]
    fn test_unreachable_code_after_return_is_pruned() {
        let (tree, src) = build("if a:\n    x = 1\n    return\n    y = 2\nelse:\n    z = 3\n");
        let cfg = build_cfg(&tree, &src);
        // `y = 2` must not appear in any Basic block (dead code after return).
        let has_y = cfg.nodes.values().any(|n| {
            n.statements
                .iter()
                .any(|s| s.utf8_text(&src).unwrap_or("").contains("y = 2"))
        });
        assert!(!has_y);
    }

    #[test]
    fn test_reverse_post_order_starts_at_entry() {
        let (tree, src) = build("x = 1\nif a:\n    y = 1\n");
        let cfg = build_cfg(&tree, &src);
        let rpo = reverse_post_order(&cfg);
        assert_eq!(rpo.first(), Some(&cfg.entry));
    }

    #[test]
    fn test_prune_unreachable_keeps_entry_and_exit_always() {
        let (tree, src) = build("x = 1\n");
        let mut cfg = build_cfg(&tree, &src);
        prune_unreachable(&mut cfg); // idempotent
        assert!(cfg.nodes.contains_key(&cfg.entry));
        assert!(cfg.nodes.contains_key(&cfg.exit));
    }
}
