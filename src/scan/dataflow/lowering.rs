//! Lowering `tree-sitter-python` → IR — equivalent of
//! `Audit/sca/parsers/python_to_ir.py`, adapted to the tree-sitter tree
//! rather than the Python stdlib AST (cf. `cfg.rs` architecture
//! decision).
//!
//! **Deliberately narrow scope**: only statements reachable inside a
//! `Basic`/`Finally`/`RaiseSite` CFG node are covered (cf. `cfg.rs`:
//! control statements — if/while/for/try/match — have their own CFG
//! node type and never appear in the `.statements` lists of a `Basic`
//! block). The `_lower_If`/`_lower_While`/etc. handlers from
//! `python_to_ir.py` exist on the Python side for a different use case
//! (flat function summaries, Step 5 — `summary.rs`, not yet tackled)
//! and are therefore not ported here.
//!
//! **Constructs not covered in this pass**:
//! comprehensions (list/set/dict/generator), `match` as a standalone
//! statement (only its branch condition is lowered, via `lower_expr`
//! on the CFG condition node — covered), `yield`/`await` propagated
//! as-is like in Python, lambda bodies never lowered (opaque, like
//! Python).

use super::cfg::field_children;
use super::ir::{ConstValue, IrStmt, Lhs, Rhs};
use tree_sitter::Node;

pub struct Lowerer<'src> {
    source: &'src [u8],
    output: Vec<IrStmt>,
    temp_counter: u32,
}

impl<'src> Lowerer<'src> {
    pub fn new(source: &'src [u8]) -> Self {
        Lowerer {
            source,
            output: Vec::new(),
            temp_counter: 0,
        }
    }

    fn fresh_temp(&mut self) -> String {
        let name = format!("__t{}", self.temp_counter);
        self.temp_counter += 1;
        name
    }

    fn emit(&mut self, stmt: IrStmt) {
        self.output.push(stmt);
    }

    fn text(&self, node: Node) -> String {
        node.utf8_text(self.source).unwrap_or("").to_string()
    }

    fn line(&self, node: Node) -> usize {
        node.start_position().row + 1
    }

    // ------------------------------------------------------------ RHS

    /// Lowers an expression into an `Rhs`, emitting along the way the
    /// intermediate statements needed (compound forms → temporary
    /// variable `__tN`).
    pub fn lower_expr(&mut self, node: Node<'src>) -> Rhs {
        match node.kind() {
            "integer" => {
                let t = self.text(node).replace('_', "");
                let v = parse_python_int(&t).unwrap_or(0);
                Rhs::Const(ConstValue::Int(v))
            }
            "float" => Rhs::Const(ConstValue::Float(self.text(node).parse().unwrap_or(0.0))),
            "true" => Rhs::Const(ConstValue::Bool(true)),
            "false" => Rhs::Const(ConstValue::Bool(false)),
            "none" => Rhs::Const(ConstValue::None),
            "string" => self.lower_string(node),
            "identifier" => Rhs::VarRef(self.text(node)),
            "attribute" => {
                let base = node
                    .child_by_field_name("object")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let attr = node
                    .child_by_field_name("attribute")
                    .map(|n| self.text(n))
                    .unwrap_or_default();
                Rhs::AttrRef {
                    base: Box::new(base),
                    attr,
                }
            }
            "subscript" => {
                let base = node
                    .child_by_field_name("value")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let key = node
                    .child_by_field_name("subscript")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                Rhs::SubscriptRef {
                    base: Box::new(base),
                    key: Box::new(key),
                }
            }
            "parenthesized_expression" => {
                let mut w = node.walk();
                node.named_children(&mut w)
                    .next()
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None))
            }
            "binary_operator" => {
                let left = node
                    .child_by_field_name("left")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let right = node
                    .child_by_field_name("right")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let op = node
                    .child_by_field_name("operator")
                    .map(|n| self.text(n))
                    .unwrap_or_default();
                let tmp = self.fresh_temp();
                self.emit(IrStmt::Assign {
                    lhs: Lhs::VarLhs(tmp.clone()),
                    rhs: Rhs::BinOp {
                        op,
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    lineno: self.line(node),
                });
                Rhs::VarRef(tmp)
            }
            "unary_operator" => {
                let operand = node
                    .child_by_field_name("argument")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let op = node
                    .child_by_field_name("operator")
                    .map(|n| self.text(n))
                    .unwrap_or_default();
                let tmp = self.fresh_temp();
                self.emit(IrStmt::Assign {
                    lhs: Lhs::VarLhs(tmp.clone()),
                    rhs: Rhs::UnaryOp {
                        op,
                        operand: Box::new(operand),
                    },
                    lineno: self.line(node),
                });
                Rhs::VarRef(tmp)
            }
            "not_operator" => {
                let operand = node
                    .child_by_field_name("argument")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let tmp = self.fresh_temp();
                self.emit(IrStmt::Assign {
                    lhs: Lhs::VarLhs(tmp.clone()),
                    rhs: Rhs::UnaryOp {
                        op: "not".to_string(),
                        operand: Box::new(operand),
                    },
                    lineno: self.line(node),
                });
                Rhs::VarRef(tmp)
            }
            "comparison_operator" => self.lower_comparison(node),
            "boolean_operator" => {
                let left = node
                    .child_by_field_name("left")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let right = node
                    .child_by_field_name("right")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let op = node
                    .child_by_field_name("operator")
                    .map(|n| self.text(n))
                    .unwrap_or_default();
                let tmp = self.fresh_temp();
                self.emit(IrStmt::Assign {
                    lhs: Lhs::VarLhs(tmp.clone()),
                    rhs: Rhs::Bool {
                        op,
                        operands: vec![left, right],
                    },
                    lineno: self.line(node),
                });
                Rhs::VarRef(tmp)
            }
            "call" => self.lower_call_expr(node),
            "tuple" => {
                let elements = self.lower_named_children(node);
                Rhs::TupleRef(elements)
            }
            "list" => Rhs::ListRef(self.lower_named_children(node)),
            "set" => Rhs::SetRef(self.lower_named_children(node)),
            "dictionary" => {
                let mut items = Vec::new();
                let mut w = node.walk();
                for child in node.named_children(&mut w) {
                    if child.kind() == "pair" {
                        let k = child
                            .child_by_field_name("key")
                            .map(|n| self.lower_expr(n))
                            .unwrap_or(Rhs::Const(ConstValue::None));
                        let v = child
                            .child_by_field_name("value")
                            .map(|n| self.lower_expr(n))
                            .unwrap_or(Rhs::Const(ConstValue::None));
                        items.push((k, v));
                    } else if child.kind() == "dictionary_splat" {
                        let mut cw = child.walk();
                        if let Some(inner) = child.named_children(&mut cw).next() {
                            let v = self.lower_expr(inner);
                            items.push((Rhs::Const(ConstValue::None), v));
                        }
                    }
                }
                Rhs::DictRef(items)
            }
            "conditional_expression" => {
                let mut w = node.walk();
                let parts: Vec<Node> = node.named_children(&mut w).collect();
                // Grammar order: then, cond, orelse (`then if cond else orelse`).
                let then_rhs = parts
                    .first()
                    .map(|n| self.lower_expr(*n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let cond_rhs = parts
                    .get(1)
                    .map(|n| self.lower_expr(*n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let orelse_rhs = parts
                    .get(2)
                    .map(|n| self.lower_expr(*n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let tmp = self.fresh_temp();
                self.emit(IrStmt::Assign {
                    lhs: Lhs::VarLhs(tmp.clone()),
                    rhs: Rhs::IfExp {
                        cond: Box::new(cond_rhs),
                        then: Box::new(then_rhs),
                        orelse: Box::new(orelse_rhs),
                    },
                    lineno: self.line(node),
                });
                Rhs::VarRef(tmp)
            }
            "named_expression" => {
                // Walrus `x := expr`.
                let value = node
                    .child_by_field_name("value")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let name = node
                    .child_by_field_name("name")
                    .map(|n| self.text(n))
                    .unwrap_or_else(|| self.fresh_temp());
                self.emit(IrStmt::Assign {
                    lhs: Lhs::VarLhs(name.clone()),
                    rhs: value,
                    lineno: self.line(node),
                });
                Rhs::VarRef(name)
            }
            "lambda" => {
                let arg_names = node
                    .child_by_field_name("parameters")
                    .map(|params| {
                        let mut w = params.walk();
                        params
                            .named_children(&mut w)
                            .map(|p| self.text(p))
                            .collect()
                    })
                    .unwrap_or_default();
                Rhs::LambdaRef { arg_names }
            }
            "list_splat" => {
                let mut w = node.walk();
                let inner = node
                    .named_children(&mut w)
                    .next()
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                Rhs::Star {
                    inner: Box::new(inner),
                    double: false,
                }
            }
            "dictionary_splat" => {
                let mut w = node.walk();
                let inner = node
                    .named_children(&mut w)
                    .next()
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                Rhs::Star {
                    inner: Box::new(inner),
                    double: true,
                }
            }
            "await" => {
                let mut w = node.walk();
                node.named_children(&mut w)
                    .next()
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None))
            }
            // Comprehensions, yield, other rare forms: safe opaque
            // fallback (does not propagate taint) — not covered in
            // this pass, cf. module docstring.
            _ => Rhs::Const(ConstValue::None),
        }
    }

    fn lower_named_children(&mut self, node: Node<'src>) -> Vec<Rhs> {
        let mut w = node.walk();
        let children: Vec<Node> = node.named_children(&mut w).collect();
        children.into_iter().map(|n| self.lower_expr(n)).collect()
    }

    /// `a < b <= c` — Python models a chained comparison as
    /// `(a<b) and (b<=c)`. tree-sitter places the operands as
    /// positional unnamed children and the operators under the
    /// repeated `operators` field.
    fn lower_comparison(&mut self, node: Node<'src>) -> Rhs {
        let mut operands: Vec<Node> = Vec::new();
        let mut operators: Vec<Node> = Vec::new();
        let mut w = node.walk();
        if w.goto_first_child() {
            let mut idx = 0u32;
            loop {
                let child = w.node();
                if node.field_name_for_child(idx) == Some("operators") {
                    operators.push(child);
                } else if child.is_named() {
                    operands.push(child);
                }
                idx += 1;
                if !w.goto_next_sibling() {
                    break;
                }
            }
        }

        if operands.len() < 2 || operators.is_empty() {
            return Rhs::Const(ConstValue::None);
        }

        let lowered_operands: Vec<Rhs> = operands.iter().map(|n| self.lower_expr(*n)).collect();
        let ops: Vec<String> = operators.iter().map(|n| self.text(*n)).collect();

        if lowered_operands.len() == 2 {
            let tmp = self.fresh_temp();
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs: Rhs::Cmp {
                    op: ops[0].clone(),
                    left: Box::new(lowered_operands[0].clone()),
                    right: Box::new(lowered_operands[1].clone()),
                },
                lineno: self.line(node),
            });
            return Rhs::VarRef(tmp);
        }

        let mut cmps = Vec::new();
        for i in 0..ops.len() {
            cmps.push(Rhs::Cmp {
                op: ops[i].clone(),
                left: Box::new(lowered_operands[i].clone()),
                right: Box::new(lowered_operands[i + 1].clone()),
            });
        }
        let tmp = self.fresh_temp();
        self.emit(IrStmt::Assign {
            lhs: Lhs::VarLhs(tmp.clone()),
            rhs: Rhs::Bool {
                op: "and".to_string(),
                operands: cmps,
            },
            lineno: self.line(node),
        });
        Rhs::VarRef(tmp)
    }

    /// f-string: passthrough on each interpolation (Python SCA-5
    /// choice), modeled as `Call(__format__, [hole1, hole2, ...])`.
    /// A string with no interpolation stays a plain constant.
    fn lower_string(&mut self, node: Node<'src>) -> Rhs {
        let mut w = node.walk();
        let has_interpolation = node
            .named_children(&mut w)
            .any(|c| c.kind() == "interpolation");
        if !has_interpolation {
            return Rhs::Const(ConstValue::Str(self.text(node)));
        }
        let mut w2 = node.walk();
        let mut args = Vec::new();
        for child in node.named_children(&mut w2) {
            if child.kind() == "interpolation"
                && let Some(expr) = child.child_by_field_name("expression")
            {
                args.push(self.lower_expr(expr));
            }
        }
        let tmp = self.fresh_temp();
        self.emit(IrStmt::Assign {
            lhs: Lhs::VarLhs(tmp.clone()),
            rhs: Rhs::CallRef {
                callee: Box::new(Rhs::VarRef("__format__".to_string())),
                args,
                kwargs: vec![],
            },
            lineno: self.line(node),
        });
        Rhs::VarRef(tmp)
    }

    fn lower_call_expr(&mut self, node: Node<'src>) -> Rhs {
        let callee = node
            .child_by_field_name("function")
            .map(|n| self.lower_expr(n))
            .unwrap_or(Rhs::Const(ConstValue::None));
        let (args, kwargs) = self.lower_call_arguments(node);
        let tmp = self.fresh_temp();
        self.emit(IrStmt::Assign {
            lhs: Lhs::VarLhs(tmp.clone()),
            rhs: Rhs::CallRef {
                callee: Box::new(callee),
                args,
                kwargs,
            },
            lineno: self.line(node),
        });
        Rhs::VarRef(tmp)
    }

    fn lower_call_arguments(&mut self, call_node: Node<'src>) -> (Vec<Rhs>, Vec<(String, Rhs)>) {
        let mut args = Vec::new();
        let mut kwargs = Vec::new();
        if let Some(arg_list) = call_node.child_by_field_name("arguments") {
            let mut w = arg_list.walk();
            for child in arg_list.named_children(&mut w) {
                match child.kind() {
                    "keyword_argument" => {
                        let name = child
                            .child_by_field_name("name")
                            .map(|n| self.text(n))
                            .unwrap_or_default();
                        let value = child
                            .child_by_field_name("value")
                            .map(|n| self.lower_expr(n))
                            .unwrap_or(Rhs::Const(ConstValue::None));
                        kwargs.push((name, value));
                    }
                    "dictionary_splat" => {
                        let v = self.lower_expr(child);
                        kwargs.push(("**".to_string(), v));
                    }
                    _ => args.push(self.lower_expr(child)),
                }
            }
        }
        (args, kwargs)
    }

    // -------------------------------------------------------------- LHS

    pub fn lower_target(&mut self, node: Node<'src>) -> Lhs {
        match node.kind() {
            "identifier" => Lhs::VarLhs(self.text(node)),
            "attribute" => {
                let base = node
                    .child_by_field_name("object")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let attr = node
                    .child_by_field_name("attribute")
                    .map(|n| self.text(n))
                    .unwrap_or_default();
                Lhs::AttrLhs {
                    base: Box::new(base),
                    attr,
                }
            }
            "subscript" => {
                let base = node
                    .child_by_field_name("value")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let key = node
                    .child_by_field_name("subscript")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                Lhs::SubscriptLhs {
                    base: Box::new(base),
                    key: Box::new(key),
                }
            }
            "pattern_list" | "tuple" | "list_pattern" => {
                let mut w = node.walk();
                let elements: Vec<Node> = node.named_children(&mut w).collect();
                Lhs::TupleLhs(elements.into_iter().map(|n| self.lower_target(n)).collect())
            }
            "list_splat_pattern" => {
                let mut w = node.walk();
                let inner = node
                    .named_children(&mut w)
                    .next()
                    .map(|n| self.lower_target(n))
                    .unwrap_or(Lhs::VarLhs(String::new()));
                Lhs::StarLhs(Box::new(inner))
            }
            _ => Lhs::VarLhs(format!("__unknown_target_{}", node.id())),
        }
    }

    // ------------------------------------------------------------- stmt

    /// Lowers a statement reachable inside a Basic/Finally/RaiseSite
    /// block (cf. module docstring — no control flow here, already
    /// handled by the CFG).
    pub fn lower_stmt(&mut self, node: Node<'src>) {
        match node.kind() {
            "expression_statement" => self.lower_expression_statement(node),
            "import_statement" => self.lower_import(node),
            "import_from_statement" => self.lower_import_from(node),
            "global_statement" | "nonlocal_statement" => self.emit(IrStmt::Noop {
                lineno: self.line(node),
            }),
            "delete_statement" => self.lower_delete(node),
            "assert_statement" => {
                let mut w = node.walk();
                for child in node.named_children(&mut w) {
                    self.lower_expr(child);
                }
                self.emit(IrStmt::Noop {
                    lineno: self.line(node),
                });
            }
            "pass_statement" => self.emit(IrStmt::Noop {
                lineno: self.line(node),
            }),
            "function_definition" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| self.text(n))
                    .unwrap_or_default();
                let arg_names = node
                    .child_by_field_name("parameters")
                    .map(|params| {
                        let mut w = params.walk();
                        params
                            .named_children(&mut w)
                            .map(|p| self.text(p))
                            .collect()
                    })
                    .unwrap_or_default();
                self.emit(IrStmt::Assign {
                    lhs: Lhs::VarLhs(name),
                    rhs: Rhs::LambdaRef { arg_names },
                    lineno: self.line(node),
                });
            }
            "class_definition" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| self.text(n))
                    .unwrap_or_default();
                self.emit(IrStmt::Assign {
                    lhs: Lhs::VarLhs(name),
                    rhs: Rhs::LambdaRef { arg_names: vec![] },
                    lineno: self.line(node),
                });
            }
            "decorated_definition" => {
                if let Some(def) = node.child_by_field_name("definition") {
                    self.lower_stmt(def);
                }
            }
            "with_statement" => self.lower_with(node),
            "raise_statement" => self.lower_raise(node),
            "return_statement" => self.lower_return(node),
            _ => self.emit(IrStmt::Noop {
                lineno: self.line(node),
            }),
        }
    }

    fn lower_expression_statement(&mut self, node: Node<'src>) {
        let mut w = node.walk();
        let Some(inner) = node.named_children(&mut w).next() else {
            return;
        };
        match inner.kind() {
            "assignment" => self.lower_assignment(inner),
            "augmented_assignment" => self.lower_aug_assignment(inner),
            "call" => {
                let callee = inner
                    .child_by_field_name("function")
                    .map(|n| self.lower_expr(n))
                    .unwrap_or(Rhs::Const(ConstValue::None));
                let (args, kwargs) = self.lower_call_arguments(inner);
                self.emit(IrStmt::Call {
                    callee,
                    args,
                    kwargs,
                    lineno: self.line(inner),
                });
            }
            _ => {
                self.lower_expr(inner);
            }
        }
    }

    /// `a = b = expr` and destructuring `a, b = expr` (spec §3.4:
    /// `__t := expr; a := __t[0]; b := __t[1]`).
    fn lower_assignment(&mut self, node: Node<'src>) {
        // Chain `a = b = expr`: right can itself be a nested
        // "assignment" node.
        let mut targets = Vec::new();
        let mut cur = node;
        while let Some(left) = cur.child_by_field_name("left") {
            targets.push(left);
            let Some(right) = cur.child_by_field_name("right") else {
                return;
            };
            if right.kind() == "assignment" {
                cur = right;
                continue;
            }
            let rhs = self.lower_expr(right);
            let lineno = self.line(node);
            for target in &targets {
                self.emit_assign_target(*target, rhs.clone(), lineno);
            }
            return;
        }
    }

    fn emit_assign_target(&mut self, target: Node<'src>, rhs: Rhs, lineno: usize) {
        match target.kind() {
            "pattern_list" | "tuple" | "list_pattern" => {
                let tmp = self.fresh_temp();
                self.emit(IrStmt::Assign {
                    lhs: Lhs::VarLhs(tmp.clone()),
                    rhs,
                    lineno,
                });
                let tmp_ref = Rhs::VarRef(tmp);
                let mut w = target.walk();
                let elements: Vec<Node> = target.named_children(&mut w).collect();
                for (i, sub_target) in elements.into_iter().enumerate() {
                    if sub_target.kind() == "list_splat_pattern" {
                        let mut sw = sub_target.walk();
                        if let Some(inner) = sub_target.named_children(&mut sw).next() {
                            let lhs = Lhs::StarLhs(Box::new(self.lower_target(inner)));
                            self.emit(IrStmt::Assign {
                                lhs,
                                rhs: tmp_ref.clone(),
                                lineno,
                            });
                        }
                    } else {
                        let sub_rhs = Rhs::SubscriptRef {
                            base: Box::new(tmp_ref.clone()),
                            key: Box::new(Rhs::Const(ConstValue::Int(i as i64))),
                        };
                        self.emit_assign_target(sub_target, sub_rhs, lineno);
                    }
                }
            }
            _ => {
                let lhs = self.lower_target(target);
                self.emit(IrStmt::Assign { lhs, rhs, lineno });
            }
        }
    }

    /// `a += expr` → `a := BinOp(+, a, expr)` (spec §3.4).
    fn lower_aug_assignment(&mut self, node: Node<'src>) {
        let target = node.child_by_field_name("left");
        let right = node
            .child_by_field_name("right")
            .map(|n| self.lower_expr(n))
            .unwrap_or(Rhs::Const(ConstValue::None));
        let op_full = node
            .child_by_field_name("operator")
            .map(|n| self.text(n))
            .unwrap_or_default();
        let op = op_full.strip_suffix('=').unwrap_or(&op_full).to_string();
        let Some(target) = target else { return };
        let read_target = self.target_as_rvalue(target);
        let lhs = self.lower_target(target);
        self.emit(IrStmt::Assign {
            lhs,
            rhs: Rhs::BinOp {
                op,
                left: Box::new(read_target),
                right: Box::new(right),
            },
            lineno: self.line(node),
        });
    }

    fn target_as_rvalue(&mut self, target: Node<'src>) -> Rhs {
        match target.kind() {
            "identifier" => Rhs::VarRef(self.text(target)),
            "attribute" | "subscript" => self.lower_expr(target),
            _ => Rhs::Const(ConstValue::None),
        }
    }

    fn lower_import(&mut self, node: Node<'src>) {
        let lineno = self.line(node);
        let mut w = node.walk();
        for child in node.named_children(&mut w) {
            let (module_path, local_name) = match child.kind() {
                "aliased_import" => {
                    let name_node = child.child_by_field_name("name");
                    let alias_node = child.child_by_field_name("alias");
                    let path = name_node.map(|n| self.text(n)).unwrap_or_default();
                    let local = alias_node
                        .map(|n| self.text(n))
                        .unwrap_or_else(|| path.clone());
                    (path, local)
                }
                "dotted_name" => {
                    let path = self.text(child);
                    let local = path.split('.').next().unwrap_or(&path).to_string();
                    (path, local)
                }
                _ => continue,
            };
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(local_name),
                rhs: Rhs::CallRef {
                    callee: Box::new(Rhs::VarRef("__import__".to_string())),
                    args: vec![Rhs::Const(ConstValue::Str(module_path))],
                    kwargs: vec![],
                },
                lineno,
            });
        }
    }

    fn lower_import_from(&mut self, node: Node<'src>) {
        let lineno = self.line(node);
        let module = node
            .child_by_field_name("module_name")
            .map(|n| self.text(n))
            .unwrap_or_default();
        // Only children carrying the `name:` field are imported
        // symbols — `module_name:` is also a `dotted_name` and must
        // not be confused with an import (bug found via test:
        // iterating all named_children() without filtering by field
        // treated the module itself as an imported symbol).
        let imported = field_children(node, "name");
        for child in imported {
            match child.kind() {
                "wildcard_import" => self.emit(IrStmt::Noop { lineno }),
                "dotted_name" => {
                    let name = self.text(child);
                    self.emit(IrStmt::Assign {
                        lhs: Lhs::VarLhs(name.clone()),
                        rhs: Rhs::AttrRef {
                            base: Box::new(Rhs::CallRef {
                                callee: Box::new(Rhs::VarRef("__import__".to_string())),
                                args: vec![Rhs::Const(ConstValue::Str(module.clone()))],
                                kwargs: vec![],
                            }),
                            attr: name,
                        },
                        lineno,
                    });
                }
                "aliased_import" => {
                    let orig = child
                        .child_by_field_name("name")
                        .map(|n| self.text(n))
                        .unwrap_or_default();
                    let alias = child
                        .child_by_field_name("alias")
                        .map(|n| self.text(n))
                        .unwrap_or_else(|| orig.clone());
                    self.emit(IrStmt::Assign {
                        lhs: Lhs::VarLhs(alias),
                        rhs: Rhs::AttrRef {
                            base: Box::new(Rhs::CallRef {
                                callee: Box::new(Rhs::VarRef("__import__".to_string())),
                                args: vec![Rhs::Const(ConstValue::Str(module.clone()))],
                                kwargs: vec![],
                            }),
                            attr: orig,
                        },
                        lineno,
                    });
                }
                _ => {}
            }
        }
    }

    fn lower_delete(&mut self, node: Node<'src>) {
        let lineno = self.line(node);
        let mut w = node.walk();
        let named: Vec<Node> = node.named_children(&mut w).collect();
        let targets: Vec<Node> = if named.len() == 1 && named[0].kind() == "expression_list" {
            let mut ew = named[0].walk();
            named[0].named_children(&mut ew).collect()
        } else {
            named
        };
        for target in targets {
            let lhs = self.lower_target(target);
            self.emit(IrStmt::Assign {
                lhs,
                rhs: Rhs::Const(ConstValue::None),
                lineno,
            });
        }
    }

    /// `with ctx as x: body` → `x := ctx.__enter__(); body; ctx.__exit__(...)`
    /// (spec §3.4), `__exit__` in reverse order for multiple context
    /// managers.
    fn lower_with(&mut self, node: Node<'src>) {
        let lineno = self.line(node);
        let mut ctx_temps = Vec::new();

        if let Some(clause) = node
            .children(&mut node.walk())
            .find(|c| c.kind() == "with_clause")
        {
            let mut w = clause.walk();
            for item in clause.named_children(&mut w) {
                if item.kind() != "with_item" {
                    continue;
                }
                let Some(value) = item.child_by_field_name("value") else {
                    continue;
                };
                let (ctx_expr_node, alias) = if value.kind() == "as_pattern" {
                    let mut vw = value.walk();
                    let expr = value.named_children(&mut vw).next();
                    let alias = value
                        .child_by_field_name("alias")
                        .and_then(|a| a.named_children(&mut a.walk()).next())
                        .map(|n| self.text(n));
                    (expr, alias)
                } else {
                    (Some(value), None)
                };
                let Some(ctx_expr_node) = ctx_expr_node else {
                    continue;
                };
                let ctx_rhs = self.lower_expr(ctx_expr_node);
                let tmp_ctx = self.fresh_temp();
                self.emit(IrStmt::Assign {
                    lhs: Lhs::VarLhs(tmp_ctx.clone()),
                    rhs: ctx_rhs,
                    lineno,
                });
                ctx_temps.push(tmp_ctx.clone());

                let enter_call = Rhs::CallRef {
                    callee: Box::new(Rhs::AttrRef {
                        base: Box::new(Rhs::VarRef(tmp_ctx.clone())),
                        attr: "__enter__".to_string(),
                    }),
                    args: vec![],
                    kwargs: vec![],
                };
                if let Some(alias_name) = alias {
                    self.emit(IrStmt::Assign {
                        lhs: Lhs::VarLhs(alias_name),
                        rhs: enter_call,
                        lineno,
                    });
                } else {
                    self.emit(IrStmt::Call {
                        callee: Rhs::AttrRef {
                            base: Box::new(Rhs::VarRef(tmp_ctx)),
                            attr: "__enter__".to_string(),
                        },
                        args: vec![],
                        kwargs: vec![],
                        lineno,
                    });
                }
            }
        }

        for tmp_ctx in ctx_temps.into_iter().rev() {
            self.emit(IrStmt::Call {
                callee: Rhs::AttrRef {
                    base: Box::new(Rhs::VarRef(tmp_ctx)),
                    attr: "__exit__".to_string(),
                },
                args: vec![
                    Rhs::Const(ConstValue::None),
                    Rhs::Const(ConstValue::None),
                    Rhs::Const(ConstValue::None),
                ],
                kwargs: vec![],
                lineno,
            });
        }
    }

    fn lower_raise(&mut self, node: Node<'src>) {
        let lineno = self.line(node);
        let mut w = node.walk();
        let value = node
            .named_children(&mut w)
            .next()
            .map(|n| self.lower_expr(n));
        self.emit(IrStmt::Raise { value, lineno });
    }

    fn lower_return(&mut self, node: Node<'src>) {
        let lineno = self.line(node);
        let mut w = node.walk();
        let value = node
            .named_children(&mut w)
            .next()
            .map(|n| self.lower_expr(n));
        self.emit(IrStmt::Return { value, lineno });
    }
}

/// Converts a pair of statements (the with node itself, then the
/// statements of its body — cf. `cfg.rs::visit_with`, which merges
/// them into the same Basic block) or any other raw sequence of
/// statements into IR — entry point used by the future `worklist.rs`
/// to lower the contents of a Basic/Finally/RaiseSite CFG node.
pub fn lower_stmts<'src>(source: &'src [u8], stmts: &[Node<'src>]) -> Vec<IrStmt> {
    let mut lowerer = Lowerer::new(source);
    for stmt in stmts {
        lowerer.lower_stmt(*stmt);
    }
    lowerer.output
}

/// Lowers a standalone expression (condition of a Branch/Loop node)
/// into an `Rhs` — mirrors `lower_expr` (public function on the
/// Python side); the intermediate statements generated are ignored by
/// the caller (only the final result matters for `eval_const`).
pub fn lower_expr_standalone<'src>(source: &'src [u8], expr: Node<'src>) -> (Rhs, Vec<IrStmt>) {
    let mut lowerer = Lowerer::new(source);
    let rhs = lowerer.lower_expr(expr);
    (rhs, lowerer.output)
}

/// Lowers the synthetic assignment `target := iter` of a CFG LOOP
/// node (`for target in iter:`) — mirrors the synthetic `ast.Assign`
/// built on the Python side in
/// `worklist.py::_lower_node_to_ir_python` (without it, taint from
/// `iter` does not propagate to `target`, cf. Python comment
/// "for/break bug"). `iter` (rhs) is lowered before `target` (lhs),
/// same order as `_lower_Assign`.
pub fn lower_for_target_assign<'src>(
    source: &'src [u8],
    target: Node<'src>,
    iter_expr: Node<'src>,
) -> Vec<IrStmt> {
    let mut lowerer = Lowerer::new(source);
    let rhs = lowerer.lower_expr(iter_expr);
    let lhs = lowerer.lower_target(target);
    let lineno = lowerer.line(target);
    lowerer.emit(IrStmt::Assign { lhs, rhs, lineno });
    lowerer.output
}

/// Parses a Python integer literal (accepts hex/oct/bin prefixes).
fn parse_python_int(s: &str) -> Option<i64> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(rest, 16).ok()
    } else if let Some(rest) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        i64::from_str_radix(rest, 8).ok()
    } else if let Some(rest) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        i64::from_str_radix(rest, 2).ok()
    } else {
        s.parse().ok()
    }
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

    fn lower_module(src: &str) -> Vec<IrStmt> {
        let tree = parse(src);
        let src_bytes = src.as_bytes();
        let root = tree.root_node();
        let mut w = root.walk();
        let stmts: Vec<Node> = root.named_children(&mut w).collect();
        lower_stmts(src_bytes, &stmts)
    }

    #[test]
    fn test_simple_assign() {
        let ir = lower_module("x = 1\n");
        assert_eq!(ir.len(), 1);
        assert!(
            matches!(&ir[0], IrStmt::Assign { lhs: Lhs::VarLhs(n), rhs: Rhs::Const(ConstValue::Int(1)), .. } if n == "x")
        );
    }

    #[test]
    fn test_binop_uses_temp() {
        let ir = lower_module("x = a + b\n");
        // __t0 := a + b ; x := __t0
        assert_eq!(ir.len(), 2);
        assert!(matches!(&ir[1], IrStmt::Assign { rhs: Rhs::VarRef(n), .. } if n == "__t0"));
    }

    #[test]
    fn test_call_statement() {
        let ir = lower_module("f(x)\n");
        assert_eq!(ir.len(), 1);
        assert!(matches!(&ir[0], IrStmt::Call { .. }));
    }

    #[test]
    fn test_call_as_rhs_uses_temp() {
        let ir = lower_module("y = f(x)\n");
        assert_eq!(ir.len(), 2);
        assert!(matches!(
            &ir[0],
            IrStmt::Assign {
                rhs: Rhs::CallRef { .. },
                ..
            }
        ));
    }

    #[test]
    fn test_attribute_chain() {
        let ir = lower_module("y = request.GET\n");
        assert!(matches!(
            &ir[0],
            IrStmt::Assign { rhs: Rhs::AttrRef { attr, .. }, .. } if attr == "GET"
        ));
    }

    #[test]
    fn test_subscript() {
        let ir = lower_module("y = request.GET['q']\n");
        // The last assignment must have a SubscriptRef as RHS.
        assert!(ir.iter().any(|s| matches!(
            s,
            IrStmt::Assign {
                rhs: Rhs::SubscriptRef { .. },
                ..
            }
        )));
    }

    #[test]
    fn test_call_with_kwargs_and_splat() {
        let ir = lower_module("f(a, *b, c=1, **d)\n");
        let IrStmt::Call { args, kwargs, .. } = &ir[0] else {
            panic!("attendu Call")
        };
        assert_eq!(args.len(), 2); // a, *b
        assert!(matches!(&args[1], Rhs::Star { double: false, .. }));
        assert_eq!(kwargs.len(), 2); // c=1, **d
    }

    #[test]
    fn test_augmented_assignment_expands_to_binop() {
        let ir = lower_module("x += 1\n");
        assert_eq!(ir.len(), 1);
        assert!(matches!(&ir[0], IrStmt::Assign { rhs: Rhs::BinOp { op, .. }, .. } if op == "+"));
    }

    #[test]
    fn test_chained_assignment() {
        let ir = lower_module("a = b = 1\n");
        assert_eq!(ir.len(), 2);
        assert!(matches!(&ir[0], IrStmt::Assign { lhs: Lhs::VarLhs(n), .. } if n == "a"));
        assert!(matches!(&ir[1], IrStmt::Assign { lhs: Lhs::VarLhs(n), .. } if n == "b"));
    }

    #[test]
    fn test_tuple_destructuring() {
        let ir = lower_module("a, b = f()\n");
        // __t0 := f() ; a := __t0[0] ; b := __t0[1] — we just check
        // that one of the final assignments targets 'a' and another 'b'.
        let targets: Vec<&str> = ir
            .iter()
            .filter_map(|s| match s {
                IrStmt::Assign {
                    lhs: Lhs::VarLhs(n),
                    ..
                } => Some(n.as_str()),
                _ => None,
            })
            .collect();
        assert!(targets.contains(&"a"));
        assert!(targets.contains(&"b"));
    }

    #[test]
    fn test_comparison_simple() {
        let ir = lower_module("x = a < b\n");
        assert!(matches!(&ir[0], IrStmt::Assign { rhs: Rhs::Cmp { op, .. }, .. } if op == "<"));
    }

    #[test]
    fn test_comparison_chain_becomes_and_of_cmps() {
        let ir = lower_module("x = a < b <= c\n");
        assert!(
            matches!(&ir[0], IrStmt::Assign { rhs: Rhs::Bool { op, operands }, .. } if op == "and" && operands.len() == 2)
        );
    }

    #[test]
    fn test_boolean_operator() {
        let ir = lower_module("x = a and b\n");
        assert!(matches!(&ir[0], IrStmt::Assign { rhs: Rhs::Bool { op, .. }, .. } if op == "and"));
    }

    #[test]
    fn test_not_operator() {
        let ir = lower_module("x = not a\n");
        assert!(
            matches!(&ir[0], IrStmt::Assign { rhs: Rhs::UnaryOp { op, .. }, .. } if op == "not")
        );
    }

    #[test]
    fn test_ternary() {
        let ir = lower_module("x = a if b else c\n");
        assert!(matches!(
            &ir[0],
            IrStmt::Assign {
                rhs: Rhs::IfExp { .. },
                ..
            }
        ));
    }

    #[test]
    fn test_fstring_produces_format_call() {
        let ir = lower_module("x = f'hello {name}'\n");
        assert!(ir.iter().any(|s| matches!(
            s,
            IrStmt::Assign { rhs: Rhs::CallRef { callee, .. }, .. }
                if matches!(callee.as_ref(), Rhs::VarRef(n) if n == "__format__")
        )));
    }

    #[test]
    fn test_plain_string_is_const() {
        let ir = lower_module("x = 'hello'\n");
        assert!(
            matches!(&ir[0], IrStmt::Assign { rhs: Rhs::Const(ConstValue::Str(s)), .. } if s == "'hello'")
        );
    }

    #[test]
    fn test_import_statement() {
        let ir = lower_module("import os\n");
        assert!(matches!(&ir[0], IrStmt::Assign { lhs: Lhs::VarLhs(n), .. } if n == "os"));
    }

    #[test]
    fn test_import_from_statement() {
        let ir = lower_module("from os import path\n");
        assert!(matches!(&ir[0], IrStmt::Assign { lhs: Lhs::VarLhs(n), .. } if n == "path"));
    }

    #[test]
    fn test_delete_statement_clears_taint() {
        let ir = lower_module("del a\n");
        assert!(
            matches!(&ir[0], IrStmt::Assign { lhs: Lhs::VarLhs(n), rhs: Rhs::Const(ConstValue::None), .. } if n == "a")
        );
    }

    #[test]
    fn test_pass_and_assert_are_noop() {
        let ir = lower_module("pass\n");
        assert!(matches!(&ir[0], IrStmt::Noop { .. }));
    }

    #[test]
    fn test_function_def_is_opaque_lambda_binding() {
        let ir = lower_module("def f(x, y):\n    return x\n");
        assert!(
            matches!(&ir[0], IrStmt::Assign { lhs: Lhs::VarLhs(n), rhs: Rhs::LambdaRef { arg_names }, .. } if n == "f" && arg_names.len() == 2)
        );
    }

    #[test]
    fn test_with_statement_desugars_enter_exit() {
        let ir = lower_module("with open(f) as g:\n    pass\n");
        // __t_ctx := open(f) ; g := __t_ctx.__enter__() ; pass ; __t_ctx.__exit__(...)
        assert!(ir.iter().any(|s| matches!(
            s,
            IrStmt::Assign { rhs: Rhs::CallRef { callee, .. }, .. }
                if matches!(callee.as_ref(), Rhs::AttrRef { attr, .. } if attr == "__enter__")
        )));
        assert!(ir.iter().any(|s| matches!(
            s,
            IrStmt::Call { callee: Rhs::AttrRef { attr, .. }, .. } if attr == "__exit__"
        )));
    }

    #[test]
    fn test_raise_with_value() {
        // `ValueError('x')` is a call: raising it goes through a temp
        // (__t0 := ValueError('x')) emitted before the Raise itself —
        // so the Raise is not necessarily the first element.
        let ir = lower_module("raise ValueError('x')\n");
        assert!(
            ir.iter()
                .any(|s| matches!(s, IrStmt::Raise { value: Some(_), .. }))
        );
    }

    #[test]
    fn test_return_with_value() {
        // Bug found via summary.rs (§8 — return_taint): return_statement
        // had no dedicated arm in lower_stmt and fell into the
        // catch-all Noop, so no IrStmt::Return was ever produced.
        let ir = lower_module("return x\n");
        assert!(matches!(
            &ir[0],
            IrStmt::Return { value: Some(Rhs::VarRef(n)), .. } if n == "x"
        ));
    }

    #[test]
    fn test_return_bare_has_no_value() {
        let ir = lower_module("return\n");
        assert!(matches!(&ir[0], IrStmt::Return { value: None, .. }));
    }
}
