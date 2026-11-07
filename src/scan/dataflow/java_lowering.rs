//! `tree-sitter-java` → IR lowering — faithful port of
//! `Audit/sca/parsers/java_to_ir.py`. Direct template of `lowering.rs`
//! (Python) — same layout (temporaries `__t0, __t1, ...`,
//! 3-address linearization), same shared, language-neutral IR
//! (`ir.rs`).
//!
//! **Scope difference from `lowering.rs`**: this module
//! only lowers the statements that `java_cfg.rs::JavaCfgBuilder`
//! actually stores in a CFG node (`Basic`/`Finally`
//! `.statements`, or the condition of a `Branch`/`Loop`).
//! `JavaCfgBuilder` fully intercepts if/while/for/try/switch/
//! break/continue/labeled — they never land in a
//! `.statements` list — so this module has **no** equivalent to
//! `lowering.rs`'s control handlers (which exist on the
//! Python side for a different purpose, flat function summaries, not
//! yet tackled on the Java side).
//!
//! Statements actually lowered here: `local_variable_declaration`,
//! `expression_statement` (internal dispatch on the wrapped
//! expression), `return_statement`, `throw_statement`,
//! `resource_specification` (try-with-resources resources),
//! `synchronized_statement` (lock expression only — the body
//! is visited separately by the CFG, unlike the choice made for
//! Python's `with`, which descends into the body during lowering;
//! this choice avoids double processing).
//!
//! Tree-sitter node shapes verified empirically before writing
//! this code (not assumed) — in particular:
//!   - `update_expression` (`i++`/`--i`) does NOT expose `operand`/
//!     `operator` as named fields — extracted via
//!     `named_children[0]` (the operand is the sole named child) plus
//!     text inspection for `++`/`--`.
//!   - `string_literal` is not a terminal node: its sub-parts
//!     (`string_fragment`, `escape_sequence`) must be concatenated.
//!   - `method_invocation` has an optional `object` field (`None` for
//!     a call with no receiver, e.g. `doIt()` in a lambda body).

use super::cfg::{Cfg, NodeKind};
use super::ir::{ConstValue, IrStmt, Lhs, Rhs};
use std::collections::BTreeMap;
use tree_sitter::Node;

// Binary arithmetic/bitwise operators → BinOp
const ARITH_OPS: [&str; 10] = ["+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"];
// (">>>": unsigned shift, added separately since it's 3 characters — the same
// logical set as Python, the list above is just used as a quick
// membership test, see `is_arith_op`.)
const CMP_OPS: [&str; 6] = ["==", "!=", "<", "<=", ">", ">="];

fn is_arith_op(op: &str) -> bool {
    ARITH_OPS.contains(&op) || op == ">>>"
}

fn bool_op_name(op: &str) -> Option<&'static str> {
    match op {
        "&&" => Some("and"),
        "||" => Some("or"),
        _ => None,
    }
}

const LITERAL_KINDS: [&str; 6] = [
    "decimal_integer_literal",
    "hex_integer_literal",
    "octal_integer_literal",
    "binary_integer_literal",
    "decimal_floating_point_literal",
    "hex_floating_point_literal",
];

const LIST_CONSTRUCTOR_NAMES: [&str; 4] = ["ArrayList", "LinkedList", "Vector", "Stack"];

pub struct JavaLowerer<'src> {
    source: &'src [u8],
    output: Vec<IrStmt>,
    temp_counter: u32,
}

impl<'src> JavaLowerer<'src> {
    pub fn new(source: &'src [u8]) -> Self {
        JavaLowerer {
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

    fn text(&self, node: Node<'src>) -> String {
        node.utf8_text(self.source).unwrap_or("").to_string()
    }

    fn line(&self, node: Node<'src>) -> usize {
        node.start_position().row + 1
    }

    // ------------------------------------------------------------ RHS

    /// Lowers a Java expression into a canonical `Rhs`, emitting
    /// the necessary intermediate statements along the way
    /// (compound sub-expressions, side effects of an assignment/
    /// increment used as an expression).
    pub fn lower_expr(&mut self, expr: Option<Node<'src>>) -> Rhs {
        let Some(expr) = expr else {
            return Rhs::Const(ConstValue::None);
        };
        let t = expr.kind();

        if t == "identifier" || t == "this" || t == "super" {
            return Rhs::VarRef(self.text(expr));
        }

        if LITERAL_KINDS.contains(&t) {
            return Rhs::Const(parse_java_numeric(&self.text(expr)));
        }

        if t == "string_literal" {
            return Rhs::Const(ConstValue::Str(self.string_literal_value(expr)));
        }

        if t == "character_literal" {
            let raw = self.text(expr);
            let inner = if raw.chars().count() >= 2 {
                let mut chars = raw.chars();
                chars.next();
                chars.next_back();
                chars.as_str().to_string()
            } else {
                raw
            };
            return Rhs::Const(ConstValue::Str(inner));
        }

        if t == "true" {
            return Rhs::Const(ConstValue::Bool(true));
        }
        if t == "false" {
            return Rhs::Const(ConstValue::Bool(false));
        }
        if t == "null_literal" {
            return Rhs::Const(ConstValue::None);
        }

        if t == "parenthesized_expression" {
            let inner = expr.named_children(&mut expr.walk()).next();
            return self.lower_expr(inner);
        }

        if t == "field_access" {
            let base = self.lower_expr(expr.child_by_field_name("object"));
            let attr = expr
                .child_by_field_name("field")
                .map(|f| self.text(f))
                .unwrap_or_else(|| "?".to_string());
            return Rhs::AttrRef {
                base: Box::new(base),
                attr,
            };
        }

        if t == "array_access" {
            let base = self.lower_expr(expr.child_by_field_name("array"));
            let key = self.lower_expr(expr.child_by_field_name("index"));
            return Rhs::SubscriptRef {
                base: Box::new(base),
                key: Box::new(key),
            };
        }

        if t == "method_invocation" {
            return self.lower_method_invocation(expr);
        }

        if t == "object_creation_expression" {
            let type_node = expr.child_by_field_name("type");
            let args = self.lower_arg_list(expr.child_by_field_name("arguments"));
            if args.is_empty() && self.is_list_constructor(type_node) {
                // `new ArrayList<>()`/`new ArrayList<String>()` — recognized
                // as an empty list (ListRef) rather than an opaque
                // CallRef, so that constant tracking (const_eval.rs)
                // starts from a known state — the same strategy as a
                // `[]` literal on the Python side.
                return Rhs::ListRef(Vec::new());
            }
            let callee = self.type_to_rhs(type_node);
            let tmp = self.fresh_temp();
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs: Rhs::CallRef {
                    callee: Box::new(callee),
                    args,
                    kwargs: Vec::new(),
                },
                lineno: self.line(expr),
            });
            return Rhs::VarRef(tmp);
        }

        if t == "array_creation_expression" {
            let init = expr
                .named_children(&mut expr.walk())
                .find(|c| c.kind() == "array_initializer");
            return match init {
                Some(i) => self.lower_expr(Some(i)),
                None => Rhs::ListRef(Vec::new()),
            };
        }

        if t == "array_initializer" {
            let elements: Vec<Rhs> = expr
                .named_children(&mut expr.walk())
                .map(|e| self.lower_expr(Some(e)))
                .collect();
            return Rhs::ListRef(elements);
        }

        if t == "cast_expression" {
            return self.lower_expr(expr.child_by_field_name("value"));
        }

        if t == "ternary_expression" {
            let cond = self.lower_expr(expr.child_by_field_name("condition"));
            let then = self.lower_expr(expr.child_by_field_name("consequence"));
            let orelse = self.lower_expr(expr.child_by_field_name("alternative"));
            let tmp = self.fresh_temp();
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs: Rhs::IfExp {
                    cond: Box::new(cond),
                    then: Box::new(then),
                    orelse: Box::new(orelse),
                },
                lineno: self.line(expr),
            });
            return Rhs::VarRef(tmp);
        }

        if t == "lambda_expression" {
            let params = expr.child_by_field_name("parameters");
            return Rhs::LambdaRef {
                arg_names: self.lambda_param_names(params),
            };
        }

        if t == "method_reference" {
            // `Foo::bar` — opaque, rare in a taint-sensitive position.
            return Rhs::LambdaRef {
                arg_names: Vec::new(),
            };
        }

        if t == "binary_expression" {
            let op = self.binary_op_text(expr);
            let left = self.lower_expr(expr.child_by_field_name("left"));
            let right = self.lower_expr(expr.child_by_field_name("right"));
            let tmp = self.fresh_temp();
            let rhs = if let Some(bool_op) = bool_op_name(&op) {
                Rhs::Bool {
                    op: bool_op.to_string(),
                    operands: vec![left, right],
                }
            } else if CMP_OPS.contains(&op.as_str()) {
                Rhs::Cmp {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                }
            } else {
                let _ = is_arith_op(&op); // documents the expected membership, not enforced at runtime
                Rhs::BinOp {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                }
            };
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs,
                lineno: self.line(expr),
            });
            return Rhs::VarRef(tmp);
        }

        if t == "unary_expression" {
            let op = self.unary_op_text(expr);
            let operand = self.lower_expr(expr.child_by_field_name("operand"));
            let tmp = self.fresh_temp();
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs: Rhs::UnaryOp {
                    op,
                    operand: Box::new(operand),
                },
                lineno: self.line(expr),
            });
            return Rhs::VarRef(tmp);
        }

        if t == "instanceof_expression" {
            let left = self.lower_expr(expr.child_by_field_name("left"));
            let type_text = expr
                .child_by_field_name("right")
                .map(|n| self.text(n))
                .unwrap_or_else(|| "?".to_string());
            let tmp = self.fresh_temp();
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs: Rhs::Cmp {
                    op: "instanceof".to_string(),
                    left: Box::new(left),
                    right: Box::new(Rhs::Const(ConstValue::Str(type_text))),
                },
                lineno: self.line(expr),
            });
            return Rhs::VarRef(tmp);
        }

        if t == "update_expression" {
            return self.lower_update_expression(expr);
        }

        if t == "assignment_expression" {
            return self.lower_assignment_expression(expr);
        }

        // Fallback: unknown expression → Const(None), safe (propagates nothing).
        Rhs::Const(ConstValue::None)
    }

    /// `new Test().doSomething(...)` — a call chained directly on a
    /// constructor (a frequent OWASP pattern with inner classes).
    /// Going through `lower_expr(obj)` would produce an opaque
    /// temporary `VarRef` (`AttrRef(VarRef(__t0), "doSomething")`) that loses the
    /// class name. Instead, the constructor's `CallRef` is inlined
    /// as the base of the `AttrRef` — `eval_call` (`transfer.rs`) knows
    /// how to recover "Test" via `callee.base.callee` to resolve the
    /// `Test.doSomething` summary. The constructor's arguments are
    /// still evaluated (taint/effects) via `lower_expr`'s normal
    /// recursion on a nested `CallRef`.
    fn lower_method_invocation(&mut self, expr: Node<'src>) -> Rhs {
        let obj = expr.child_by_field_name("object");
        let name_node = expr.child_by_field_name("name");
        let name = name_node
            .map(|n| self.text(n))
            .unwrap_or_else(|| "?".to_string());

        let is_ctor_chain = obj.is_some_and(|o| {
            o.kind() == "object_creation_expression"
                && !self.is_list_constructor(o.child_by_field_name("type"))
        });

        let callee: Rhs = if is_ctor_chain {
            let ctor = obj.unwrap();
            let ctor_type = ctor.child_by_field_name("type");
            let ctor_args = self.lower_arg_list(ctor.child_by_field_name("arguments"));
            let ctor_callee = self.type_to_rhs(ctor_type);
            Rhs::AttrRef {
                base: Box::new(Rhs::CallRef {
                    callee: Box::new(ctor_callee),
                    args: ctor_args,
                    kwargs: Vec::new(),
                }),
                attr: name.clone(),
            }
        } else if let Some(o) = obj {
            let base = self.lower_expr(Some(o));
            Rhs::AttrRef {
                base: Box::new(base),
                attr: name.clone(),
            }
        } else {
            Rhs::VarRef(name.clone())
        };

        let args = self.lower_arg_list(expr.child_by_field_name("arguments"));
        let tmp = self.fresh_temp();
        // Line of the CALL (the method name), not of the whole
        // `method_invocation`: for a chain spread over several lines
        // (`xp.compile(expr)\n.evaluate(...)`), the enclosing node
        // starts at the receiver (potentially several lines
        // above) — this improves reporting precision (the finding's
        // line), an exact mirror of `python_java_to_ir.py::_lower_expr`
        // (Round 8, OWASP BenchmarkJava calibration).
        let call_lineno = name_node.map(|n| self.line(n)).unwrap_or(self.line(expr));
        self.emit(IrStmt::Assign {
            lhs: Lhs::VarLhs(tmp.clone()),
            rhs: Rhs::CallRef {
                callee: Box::new(callee),
                args,
                kwargs: Vec::new(),
            },
            lineno: call_lineno,
        });
        Rhs::VarRef(tmp)
    }

    fn lower_arg_list(&mut self, arg_list: Option<Node<'src>>) -> Vec<Rhs> {
        let Some(arg_list) = arg_list else {
            return Vec::new();
        };
        arg_list
            .named_children(&mut arg_list.walk())
            .map(|a| self.lower_expr(Some(a)))
            .collect()
    }

    fn lambda_param_names(&self, params: Option<Node<'src>>) -> Vec<String> {
        let Some(params) = params else {
            return Vec::new();
        };
        if params.kind() == "identifier" {
            // `x -> ...` — single parameter without parentheses.
            return vec![self.text(params)];
        }
        let mut names = Vec::new();
        let mut w = params.walk();
        for p in params.named_children(&mut w) {
            if p.kind() == "formal_parameter" || p.kind() == "inferred_parameters" {
                if let Some(name_node) = p.child_by_field_name("name") {
                    names.push(self.text(name_node));
                }
            } else if p.kind() == "identifier" {
                names.push(self.text(p));
            }
        }
        names
    }

    /// Converts a type node (`type_identifier`/
    /// `scoped_type_identifier`) into a chain of `AttrRef` to
    /// match "dotted" patterns (e.g. `java.io.File` →
    /// `AttrRef(AttrRef(VarRef("java"), "io"), "File")`).
    fn type_to_rhs(&self, type_node: Option<Node<'src>>) -> Rhs {
        let Some(type_node) = type_node else {
            return Rhs::VarRef("?".to_string());
        };
        let text = self.text(type_node);
        let mut parts = text.split('.');
        let Some(first) = parts.next() else {
            return Rhs::VarRef("?".to_string());
        };
        let mut rhs = Rhs::VarRef(first.to_string());
        for part in parts {
            rhs = Rhs::AttrRef {
                base: Box::new(rhs),
                attr: part.to_string(),
            };
        }
        rhs
    }

    /// Does a type node name a list constructor
    /// (`new ArrayList<>()`/`new java.util.ArrayList<String>()`) — the
    /// `type` node of an `object_creation_expression` carries the
    /// generic parameters in its text (`generic_type` →
    /// `"ArrayList<String>"`), stripped before comparing the simple name.
    fn is_list_constructor(&self, type_node: Option<Node<'src>>) -> bool {
        let Some(type_node) = type_node else {
            return false;
        };
        let text = self.text(type_node);
        let before_generic = text.split('<').next().unwrap_or(&text);
        let simple_name = before_generic.rsplit('.').next().unwrap_or(before_generic);
        LIST_CONSTRUCTOR_NAMES.contains(&simple_name)
    }

    /// Lowers `i++`/`--i` into an emitted `+1`/`-1` assignment,
    /// returning the pre-increment value of the operand.
    fn lower_update_expression(&mut self, expr: Node<'src>) -> Rhs {
        let operand_node = expr.named_children(&mut expr.walk()).next();
        let Some(operand_node) = operand_node else {
            return Rhs::Const(ConstValue::None);
        };
        let op_symbol = if self.text(expr).contains("++") {
            "+"
        } else {
            "-"
        };
        let operand_rhs = self.lower_expr(Some(operand_node));
        let lhs = self.lower_target(Some(operand_node));
        self.emit(IrStmt::Assign {
            lhs,
            rhs: Rhs::BinOp {
                op: op_symbol.to_string(),
                left: Box::new(operand_rhs.clone()),
                right: Box::new(Rhs::Const(ConstValue::Int(1))),
            },
            lineno: self.line(expr),
        });
        operand_rhs
    }

    /// Lowers `target = expr` (and the compound forms `+=`, `-=`...)
    /// into an emitted `Assign`, returning the assigned `Rhs`.
    fn lower_assignment_expression(&mut self, expr: Node<'src>) -> Rhs {
        let left_node = expr.child_by_field_name("left");
        let right_node = expr.child_by_field_name("right");
        let op_text = expr
            .child_by_field_name("operator")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "=".to_string());

        let mut rhs = self.lower_expr(right_node);
        if op_text != "=" {
            // Compound assignment (`+=`, `-=`...): reads the target as an rvalue.
            let base_op = &op_text[..op_text.len() - 1]; // "+=" -> "+"
            let read_target = self.lower_expr(left_node);
            rhs = Rhs::BinOp {
                op: base_op.to_string(),
                left: Box::new(read_target),
                right: Box::new(rhs),
            };
        }

        let lhs = self.lower_target(left_node);
        self.emit(IrStmt::Assign {
            lhs,
            rhs: rhs.clone(),
            lineno: self.line(expr),
        });
        rhs
    }

    // --- lowering the target (LHS) --------------------------------------

    fn lower_target(&mut self, target: Option<Node<'src>>) -> Lhs {
        let Some(target) = target else {
            return Lhs::VarLhs("__unknown_target".to_string());
        };
        match target.kind() {
            "identifier" | "this" => Lhs::VarLhs(self.text(target)),
            "field_access" => {
                let base = self.lower_expr(target.child_by_field_name("object"));
                let attr = target
                    .child_by_field_name("field")
                    .map(|f| self.text(f))
                    .unwrap_or_else(|| "?".to_string());
                Lhs::AttrLhs {
                    base: Box::new(base),
                    attr,
                }
            }
            "array_access" => {
                let base = self.lower_expr(target.child_by_field_name("array"));
                let key = self.lower_expr(target.child_by_field_name("index"));
                Lhs::SubscriptLhs {
                    base: Box::new(base),
                    key: Box::new(key),
                }
            }
            // Fallback: synthetic name so we never panic.
            _ => Lhs::VarLhs("__unknown_target".to_string()),
        }
    }

    // --- operator text extraction -------------------------------------

    fn binary_op_text(&self, expr: Node<'src>) -> String {
        expr.child_by_field_name("operator")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "?".to_string())
    }

    fn unary_op_text(&self, expr: Node<'src>) -> String {
        expr.child_by_field_name("operator")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "?".to_string())
    }

    // --- literal reading --------------------------------------------------

    fn string_literal_value(&self, node: Node<'src>) -> String {
        let mut parts = String::new();
        let mut w = node.walk();
        for c in node.children(&mut w) {
            if c.kind() == "string_fragment" || c.kind() == "escape_sequence" {
                parts.push_str(&self.text(c));
            }
        }
        parts
    }

    // --- statement lowering ---------------------------------------------

    fn lower_stmt(&mut self, stmt: Node<'src>) {
        match stmt.kind() {
            "local_variable_declaration" => self.lower_local_variable_declaration(stmt),
            "expression_statement" => self.lower_expression_statement(stmt),
            "return_statement" => self.lower_return_statement(stmt),
            "throw_statement" => self.lower_throw_statement(stmt),
            "resource_specification" => self.lower_resource_specification(stmt),
            "synchronized_statement" => self.lower_synchronized_statement(stmt),
            _ => self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            }),
        }
    }

    fn lower_local_variable_declaration(&mut self, stmt: Node<'src>) {
        let mut w = stmt.walk();
        let decls: Vec<Node<'src>> = stmt
            .named_children(&mut w)
            .filter(|c| c.kind() == "variable_declarator")
            .collect();
        for decl in decls {
            let Some(name_node) = decl.child_by_field_name("name") else {
                continue;
            };
            let name = self.text(name_node);
            let value_node = decl.child_by_field_name("value");
            match value_node {
                None => self.emit(IrStmt::Noop {
                    lineno: self.line(stmt),
                }),
                Some(v) => {
                    let rhs = self.lower_expr(Some(v));
                    self.emit(IrStmt::Assign {
                        lhs: Lhs::VarLhs(name),
                        rhs,
                        lineno: self.line(stmt),
                    });
                }
            }
        }
    }

    fn lower_expression_statement(&mut self, stmt: Node<'src>) {
        let inner = stmt.named_children(&mut stmt.walk()).next();
        let Some(inner) = inner else {
            self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            });
            return;
        };
        if inner.kind() == "method_invocation" {
            self.lower_call_as_statement(inner);
            return;
        }
        // assignment_expression / update_expression already emit their
        // Assign via lower_expr (side effect); any other expression
        // is lowered for its side effects, the final result discarded.
        self.lower_expr(Some(inner));
    }

    /// Emits an IR `Call` node (no Assign+temporary) for a call
    /// used as a statement — directly visible to the taint
    /// engine as a potential sink. Shared between
    /// `lower_expression_statement` and `lower_condition` (this module,
    /// Branch/Loop condition that is a direct call, e.g.
    /// `if (isValid(input))`).
    fn lower_call_as_statement(&mut self, call_node: Node<'src>) {
        let obj = call_node.child_by_field_name("object");
        let name = call_node
            .child_by_field_name("name")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "?".to_string());
        let callee: Rhs = if let Some(o) = obj {
            let base = self.lower_expr(Some(o));
            Rhs::AttrRef {
                base: Box::new(base),
                attr: name,
            }
        } else {
            Rhs::VarRef(name)
        };
        let args = self.lower_arg_list(call_node.child_by_field_name("arguments"));
        self.emit(IrStmt::Call {
            callee,
            args,
            kwargs: Vec::new(),
            lineno: self.line(call_node),
        });
    }

    fn lower_return_statement(&mut self, stmt: Node<'src>) {
        let value_node = stmt.named_children(&mut stmt.walk()).next();
        let value = value_node.map(|v| self.lower_expr(Some(v)));
        self.emit(IrStmt::Return {
            value,
            lineno: self.line(stmt),
        });
    }

    fn lower_throw_statement(&mut self, stmt: Node<'src>) {
        let value_node = stmt.named_children(&mut stmt.walk()).next();
        let value = value_node.map(|v| self.lower_expr(Some(v)));
        self.emit(IrStmt::Raise {
            value,
            lineno: self.line(stmt),
        });
    }

    fn lower_resource_specification(&mut self, stmt: Node<'src>) {
        let mut w = stmt.walk();
        let resources: Vec<Node<'src>> = stmt
            .named_children(&mut w)
            .filter(|c| c.kind() == "resource")
            .collect();
        for res in resources {
            let Some(name_node) = res.child_by_field_name("name") else {
                continue;
            };
            let name = self.text(name_node);
            let value_node = res.child_by_field_name("value");
            let rhs = match value_node {
                Some(v) => self.lower_expr(Some(v)),
                None => Rhs::Const(ConstValue::None),
            };
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(name),
                rhs,
                lineno: self.line(stmt),
            });
        }
    }

    /// Lowers only the lock expression of a
    /// `synchronized (lock) {...}`. The body is visited separately by
    /// `JavaCfgBuilder` (its own CFG nodes) — do NOT descend
    /// into it here, to avoid double processing (unlike
    /// Python's `lower_with`).
    fn lower_synchronized_statement(&mut self, stmt: Node<'src>) {
        let mut w = stmt.walk();
        let lock = stmt
            .children(&mut w)
            .find(|c| c.kind() == "parenthesized_expression");
        match lock {
            Some(l) => {
                self.lower_expr(Some(l));
            }
            None => self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            }),
        }
    }
}

/// Parses a Java numeric literal (hex/binary/octal/float, with
/// `l`/`f`/`d` suffixes and `_` separators) into a `ConstValue`. Falls
/// back to `Str(text)` (the ORIGINAL, uncleaned text) if the cleanup
/// produces an unparsable form — the same behavior as
/// Python's `_parse_numeric` (`except ValueError: return text`).
fn parse_java_numeric(text: &str) -> ConstValue {
    let cleaned = text
        .trim_end_matches(['l', 'L', 'f', 'F', 'd', 'D'])
        .replace('_', "");
    let lower = cleaned.to_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        let hex_digits = &cleaned[cleaned.len() - hex.len()..];
        return match i64::from_str_radix(hex_digits, 16) {
            Ok(v) => ConstValue::Int(v),
            Err(_) => ConstValue::Str(text.to_string()),
        };
    }
    if let Some(bin) = lower.strip_prefix("0b") {
        let bin_digits = &cleaned[cleaned.len() - bin.len()..];
        return match i64::from_str_radix(bin_digits, 2) {
            Ok(v) => ConstValue::Int(v),
            Err(_) => ConstValue::Str(text.to_string()),
        };
    }
    if cleaned.contains('.') || lower.contains('e') {
        return match cleaned.parse::<f64>() {
            Ok(v) => ConstValue::Float(v),
            Err(_) => ConstValue::Str(text.to_string()),
        };
    }
    let is_octal =
        cleaned.starts_with('0') && cleaned != "0" && cleaned.chars().all(|c| c.is_ascii_digit());
    let parsed = if is_octal {
        i64::from_str_radix(&cleaned, 8)
    } else {
        cleaned.parse::<i64>()
    };
    match parsed {
        Ok(v) => ConstValue::Int(v),
        Err(_) => ConstValue::Str(text.to_string()),
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Lowers an isolated Java expression into an `Rhs` (the auxiliary
/// statements generated along the way — sub-expression
/// temporaries — are discarded here, only the final `Rhs` counts).
/// Reserved for a compile-time-constant-evaluation style of use
/// (e.g. `const_eval`, mirroring the use of `lower_expr` on the
/// `python_to_ir.py` side). **Do not use for taint propagation
/// of a Branch/Loop condition** — the discarded temporaries are
/// precisely what carries the taint information; use
/// `lower_condition` instead (see its doc for why).
pub fn lower_expr<'src>(source: &'src [u8], expr: Node<'src>) -> Rhs {
    JavaLowerer::new(source).lower_expr(Some(expr))
}

/// Variant of [`lower_expr`] for the synthetic condition of a
/// switch `case` with a simple literal label (`case 1:`) — a **typed**
/// mirror of Python's `SwitchCaseCondition` branch of `lower_expr`
/// (which takes a `Union[TSNode, SwitchCaseCondition]` union type
/// — not directly representable in Rust; `subject`/`label` are
/// already two separate `Option<Node>` fields on `CfgNode`, see
/// `cfg.rs::CfgNode::switch_case_label`). Emits `subject == label`.
pub fn lower_expr_switch_case<'src>(
    source: &'src [u8],
    subject: Node<'src>,
    label: Node<'src>,
) -> Rhs {
    let mut lowerer = JavaLowerer::new(source);
    let left = lowerer.lower_expr(Some(subject));
    let right = lowerer.lower_expr(Some(label));
    Rhs::Cmp {
        op: "==".to_string(),
        left: Box::new(left),
        right: Box::new(right),
    }
}

/// Lowers an expression used as a condition (Branch/Loop) into
/// a list of IR statements — for taint propagation, not
/// just its value.
///
/// Equivalent to the "wrap in a synthetic `ast.Expr` then
/// `lower_stmt`" workaround that `worklist.rs::lower_node_to_ir` applies on
/// the Python side (a tree-sitter node cannot be synthesized, hence this
/// dedicated function on the Java side). If the expression is a direct
/// call (`method_invocation`, e.g. `if (isValid(input))`), emits a `Call` —
/// visible as a potential sink to the taint engine — rather than a
/// buried Assign+temporary. Otherwise, lowers the expression and keeps
/// the auxiliary statements (temporaries) emitted along the way; the
/// final top-level `Rhs` is discarded (the true/false branch
/// itself is already handled by the CFG's edges, not by the IR).
pub fn lower_condition<'src>(source: &'src [u8], expr: Node<'src>) -> Vec<IrStmt> {
    let mut lowerer = JavaLowerer::new(source);
    // if_statement/while_statement expose their condition wrapped
    // in a `parenthesized_expression` (`if (x)`) — unlike
    // Python's `ast.If.test`, which is the bare expression. We
    // unwrap before testing the `method_invocation` case, otherwise
    // `if (isValid(input))` would never match and would fall through to
    // the buried Assign+temporary.
    let mut unwrapped = expr;
    loop {
        if unwrapped.kind() != "parenthesized_expression" {
            break;
        }
        let Some(inner) = unwrapped.named_children(&mut unwrapped.walk()).next() else {
            break;
        };
        unwrapped = inner;
    }
    if unwrapped.kind() == "method_invocation" {
        lowerer.lower_call_as_statement(unwrapped);
    } else {
        lowerer.lower_expr(Some(expr));
    }
    lowerer.output
}

/// Variant of [`lower_condition`] for a switch `case`'s synthetic
/// condition (`SwitchCaseCondition` on the Python side): emits
/// `__tN := (subject == label)`.
pub fn lower_condition_switch_case<'src>(
    source: &'src [u8],
    subject: Node<'src>,
    label: Node<'src>,
) -> Vec<IrStmt> {
    let mut lowerer = JavaLowerer::new(source);
    let left = lowerer.lower_expr(Some(subject));
    let right = lowerer.lower_expr(Some(label));
    let tmp = lowerer.fresh_temp();
    lowerer.emit(IrStmt::Assign {
        lhs: Lhs::VarLhs(tmp),
        rhs: Rhs::Cmp {
            op: "==".to_string(),
            left: Box::new(left),
            right: Box::new(right),
        },
        lineno: lowerer.line(subject),
    });
    lowerer.output
}

/// Synthesizes `target := iterable` for a Java for-each loop
/// (`for (Type target : iterable)`).
///
/// The same strategy as the handling of `for_target` in
/// Python's `worklist.rs`/`lowering.rs`: without this explicit
/// assignment, the taint of the iterated collection never propagates to
/// the loop variable (a for-each LOOP CFG node's `condition`
/// is the iterable, not a boolean comparison — `lower_condition`
/// alone is not enough here).
pub fn lower_for_target_assign<'src>(
    source: &'src [u8],
    target: Node<'src>,
    iterable: Node<'src>,
) -> Vec<IrStmt> {
    let mut lowerer = JavaLowerer::new(source);
    let rhs = lowerer.lower_expr(Some(iterable));
    let lhs = lowerer.lower_target(Some(target));
    lowerer.emit(IrStmt::Assign {
        lhs,
        rhs,
        lineno: lowerer.line(iterable),
    });
    lowerer.output
}

/// Lowers a list of Java statements (the content of a
/// Basic/Finally CFG node) into IR.
pub fn lower_stmts<'src>(source: &'src [u8], stmts: &[Node<'src>]) -> Vec<IrStmt> {
    let mut lowerer = JavaLowerer::new(source);
    for &stmt in stmts {
        lowerer.lower_stmt(stmt);
    }
    lowerer.output
}

/// Lowers a single Java statement into IR (can produce several
/// `IrStmt`).
pub fn lower_stmt<'src>(source: &'src [u8], stmt: Node<'src>) -> Vec<IrStmt> {
    let mut lowerer = JavaLowerer::new(source);
    lowerer.lower_stmt(stmt);
    lowerer.output
}

// ============================================================================
// Lowering a CFG node into IR — Java mirror of
// `worklist.rs::lower_node_to_ir`/`lower_all_nodes`, the entry point
// consumed by `worklist::analyze_generic` (the `lower_all` parameter)
// to instantiate `worklist::analyze_java`.
// ============================================================================

/// Lowers the statements/condition of a Java CFG node into IR.
///
/// Switch `case` condition (`CfgNode::switch_case_label`
/// present): lowered here via `lower_condition_switch_case` for the
/// main taint fixed point. The §9 pre-pass
/// (`worklist.rs::eval_branch_condition`, dead-edge pruning)
/// builds `subject == label` itself by calling `lower_expr`
/// (below) twice — on `cond` (the subject) and on
/// `switch_case_label` (the label) — no need for a dedicated function
/// on the pruning side, see the comment on `eval_branch_condition`.
pub fn lower_node_to_ir<'tree>(cfg: &Cfg<'tree>, node_id: usize, source: &[u8]) -> Vec<IrStmt> {
    let node = &cfg.nodes[&node_id];
    match node.kind {
        NodeKind::Basic | NodeKind::Finally | NodeKind::RaiseSite => {
            if node.statements.is_empty() {
                Vec::new()
            } else {
                lower_stmts(source, &node.statements)
            }
        }
        NodeKind::Branch | NodeKind::Loop => {
            let Some(cond) = node.condition else {
                return Vec::new();
            };
            // For-each loop: emits the synthetic assignment
            // `target := iter` (without it the taint of the iterable does not
            // propagate to the loop variable).
            if node.kind == NodeKind::Loop
                && let Some(target) = node.for_target
            {
                return lower_for_target_assign(source, target, cond);
            }
            if let Some(label) = node.switch_case_label {
                return lower_condition_switch_case(source, cond, label);
            }
            lower_condition(source, cond)
        }
        _ => Vec::new(),
    }
}

/// Lowers all nodes of a Java CFG into IR, in a single pass.
pub fn lower_all_nodes<'tree>(cfg: &Cfg<'tree>, source: &[u8]) -> BTreeMap<usize, Vec<IrStmt>> {
    cfg.nodes
        .keys()
        .map(|&nid| (nid, lower_node_to_ir(cfg, nid, source)))
        .collect()
}

/// Lowers an isolated expression (a Branch/Loop node's condition) into
/// an `Rhs` — Java mirror of `lowering::lower_expr_standalone`, consumed
/// by `worklist::compute_dead_edges_generic` (the §9 pre-pass,
/// dead-edge pruning). The intermediate statements generated
/// are returned (as on the Python side) for future use; a
/// `switch_case_label`'s subject is NOT taken into account here (see the doc of
/// [`lower_node_to_ir`]).
pub fn lower_expr_standalone<'src>(source: &'src [u8], expr: Node<'src>) -> (Rhs, Vec<IrStmt>) {
    let mut lowerer = JavaLowerer::new(source);
    let rhs = lowerer.lower_expr(Some(expr));
    (rhs, lowerer.output)
}

// ============================================================================
// Tests — mirror of `Audit/tests/dataflow/test_ir_java.py`.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

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

    fn parse_java(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    /// Parses a Java method body and exposes `(source, body_stmts)`
    /// to `f`.
    fn with_body_stmts<R>(method_body_src: &str, f: impl FnOnce(&str, &[Node]) -> R) -> R {
        let src = format!("class Foo {{ void t(String input, int n) {{ {method_body_src} }} }}");
        let tree = parse_java(&src);
        assert!(
            !tree.root_node().has_error(),
            "syntaxe Java invalide : {method_body_src:?}"
        );
        let method = find_first(tree.root_node(), "method_declaration").unwrap();
        let body = method.child_by_field_name("body").unwrap();
        let stmts: Vec<Node> = body.named_children(&mut body.walk()).collect();
        f(&src, &stmts)
    }

    fn lower(method_body_src: &str) -> Vec<IrStmt> {
        with_body_stmts(method_body_src, |src, stmts| {
            lower_stmts(src.as_bytes(), stmts)
        })
    }

    fn assigns(ir: &[IrStmt]) -> Vec<&IrStmt> {
        ir.iter()
            .filter(|s| matches!(s, IrStmt::Assign { .. }))
            .collect()
    }

    fn calls(ir: &[IrStmt]) -> Vec<&IrStmt> {
        ir.iter()
            .filter(|s| matches!(s, IrStmt::Call { .. }))
            .collect()
    }

    fn var(name: &str) -> Rhs {
        Rhs::VarRef(name.to_string())
    }

    fn attr(base: Rhs, name: &str) -> Rhs {
        Rhs::AttrRef {
            base: Box::new(base),
            attr: name.to_string(),
        }
    }

    // ------------------------------------------------- assignations simples

    #[test]
    fn test_var_assign_constant() {
        let ir = lower("int x = 1;");
        assert_eq!(
            ir,
            vec![IrStmt::Assign {
                lhs: Lhs::VarLhs("x".to_string()),
                rhs: Rhs::Const(ConstValue::Int(1)),
                lineno: 1,
            }]
        );
    }

    #[test]
    fn test_var_assign_var() {
        let ir = lower("int x = n;");
        let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        assert_eq!(*lhs, Lhs::VarLhs("x".to_string()));
        assert_eq!(*rhs, var("n"));
    }

    #[test]
    fn test_field_assign() {
        let ir = lower("this.field = input;");
        let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        assert_eq!(
            *lhs,
            Lhs::AttrLhs {
                base: Box::new(var("this")),
                attr: "field".to_string(),
            }
        );
        assert_eq!(*rhs, var("input"));
    }

    #[test]
    fn test_array_assign() {
        let ir = lower("arr[0] = input;");
        let IrStmt::Assign { lhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        let Lhs::SubscriptLhs { base, key } = lhs else {
            panic!("expected SubscriptLhs")
        };
        assert_eq!(**base, var("arr"));
        assert_eq!(**key, Rhs::Const(ConstValue::Int(0)));
    }

    #[test]
    fn test_multi_declarator() {
        let ir = lower("int x = 1, y = 2;");
        let a = assigns(&ir);
        assert_eq!(a.len(), 2);
        let IrStmt::Assign { lhs: lhs0, .. } = a[0] else {
            panic!()
        };
        let IrStmt::Assign { lhs: lhs1, .. } = a[1] else {
            panic!()
        };
        assert_eq!(*lhs0, Lhs::VarLhs("x".to_string()));
        assert_eq!(*lhs1, Lhs::VarLhs("y".to_string()));
    }

    #[test]
    fn test_declaration_without_initializer() {
        let ir = lower("int x;");
        assert!(matches!(ir[0], IrStmt::Noop { .. }));
    }

    // ------------------------------------------------------------ operators

    #[test]
    fn test_binary_arith() {
        let ir = lower("int z = x + y;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::BinOp { op, .. } = rhs else {
            panic!("expected BinOp")
        };
        assert_eq!(op, "+");
    }

    #[test]
    fn test_comparison() {
        let ir = lower("boolean b = x > 0;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::Cmp { op, .. } = rhs else {
            panic!("expected Cmp")
        };
        assert_eq!(op, ">");
    }

    #[test]
    fn test_boolean_and() {
        let ir = lower("boolean b = x > 0 && y < 10;");
        let a = assigns(&ir);
        let bool_assign = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::Bool { op, operands } = rhs {
                Some((op, operands))
            } else {
                None
            }
        });
        let (op, operands) = bool_assign.unwrap();
        assert_eq!(op, "and");
        assert_eq!(operands.len(), 2);
    }

    #[test]
    fn test_boolean_or() {
        let ir = lower("boolean b = x > 0 || y < 10;");
        let a = assigns(&ir);
        let op = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::Bool { op, .. } = rhs {
                Some(op)
            } else {
                None
            }
        });
        assert_eq!(op.unwrap(), "or");
    }

    #[test]
    fn test_unary_negation() {
        let ir = lower("int x = -n;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::UnaryOp { op, .. } = rhs else {
            panic!("expected UnaryOp")
        };
        assert_eq!(op, "-");
    }

    #[test]
    fn test_instanceof() {
        let ir = lower("boolean chk = input instanceof String;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::Cmp { op, left, .. } = rhs else {
            panic!("expected Cmp")
        };
        assert_eq!(op, "instanceof");
        assert_eq!(**left, var("input"));
    }

    // ------------------------------------------ update/assign (side effects)

    #[test]
    fn test_postfix_increment() {
        let ir = lower("x++;");
        let a = assigns(&ir);
        let IrStmt::Assign { lhs, rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("x".to_string()));
        let Rhs::BinOp { op, .. } = rhs else {
            panic!("expected BinOp")
        };
        assert_eq!(op, "+");
    }

    #[test]
    fn test_prefix_decrement() {
        let ir = lower("--x;");
        let a = assigns(&ir);
        let IrStmt::Assign { lhs, rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("x".to_string()));
        let Rhs::BinOp { op, .. } = rhs else {
            panic!("expected BinOp")
        };
        assert_eq!(op, "-");
    }

    #[test]
    fn test_chained_assignment() {
        let ir = lower("x = y = 5;");
        let a = assigns(&ir);
        assert_eq!(a.len(), 2);
        let IrStmt::Assign { lhs: lhs0, .. } = a[0] else {
            panic!()
        };
        let IrStmt::Assign { lhs: lhs1, .. } = a[1] else {
            panic!()
        };
        assert_eq!(*lhs0, Lhs::VarLhs("y".to_string()));
        assert_eq!(*lhs1, Lhs::VarLhs("x".to_string()));
    }

    #[test]
    fn test_compound_assignment() {
        let ir = lower("z += 5;");
        let a = assigns(&ir);
        let IrStmt::Assign { lhs, rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("z".to_string()));
        let Rhs::BinOp { op, left, right } = rhs else {
            panic!("expected BinOp")
        };
        assert_eq!(op, "+");
        assert_eq!(**left, var("z"));
        assert_eq!(**right, Rhs::Const(ConstValue::Int(5)));
    }

    // --------------------------- appels — statement vs sous-expression

    #[test]
    fn test_call_as_statement() {
        let ir = lower("obj.method(input);");
        let c = calls(&ir);
        assert_eq!(c.len(), 1);
        let IrStmt::Call { callee, args, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*callee, attr(var("obj"), "method"));
        assert_eq!(*args, vec![var("input")]);
    }

    #[test]
    fn test_call_without_receiver() {
        let ir = lower("doIt(input);");
        let c = calls(&ir);
        let IrStmt::Call { callee, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*callee, var("doIt"));
    }

    #[test]
    fn test_call_as_subexpression_produces_assign_temp() {
        let ir = lower("String s = getInput(input);");
        let a = assigns(&ir);
        let call_assign = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, args, .. } = rhs {
                Some((callee, args))
            } else {
                None
            }
        });
        let (callee, args) = call_assign.unwrap();
        assert_eq!(**callee, var("getInput"));
        assert_eq!(*args, vec![var("input")]);
        let IrStmt::Assign { lhs, .. } = a[a.len() - 1] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("s".to_string()));
    }

    #[test]
    fn test_object_creation() {
        let ir = lower("Object o = new Foo(input);");
        let a = assigns(&ir);
        let creation = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, args, .. } = rhs {
                Some((callee, args))
            } else {
                None
            }
        });
        let (callee, args) = creation.unwrap();
        assert_eq!(**callee, var("Foo"));
        assert_eq!(*args, vec![var("input")]);
    }

    #[test]
    fn test_qualified_object_creation() {
        let ir = lower("Object o = new java.io.File(input);");
        let a = assigns(&ir);
        let callee = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, .. } = rhs {
                Some(callee)
            } else {
                None
            }
        });
        assert_eq!(**callee.unwrap(), attr(attr(var("java"), "io"), "File"));
    }

    // ------------------------------------------- containers / compound expr

    #[test]
    fn test_array_initializer() {
        let ir = lower("int[] arr = {1, 2, 3};");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(
            *rhs,
            Rhs::ListRef(vec![
                Rhs::Const(ConstValue::Int(1)),
                Rhs::Const(ConstValue::Int(2)),
                Rhs::Const(ConstValue::Int(3)),
            ])
        );
    }

    #[test]
    fn test_ternary() {
        let ir = lower(r#"String a = cond ? input : "safe";"#);
        let a = assigns(&ir);
        let ternary = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::IfExp { cond, then, orelse } = rhs {
                Some((cond, then, orelse))
            } else {
                None
            }
        });
        let (cond, then, orelse) = ternary.unwrap();
        assert_eq!(**cond, var("cond"));
        assert_eq!(**then, var("input"));
        assert_eq!(**orelse, Rhs::Const(ConstValue::Str("safe".to_string())));
    }

    #[test]
    fn test_cast_passthrough() {
        let ir = lower("String r = (String) input;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, var("input"));
    }

    #[test]
    fn test_lambda_no_params() {
        let ir = lower("Runnable lam = () -> doIt();");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(
            *rhs,
            Rhs::LambdaRef {
                arg_names: Vec::new()
            }
        );
    }

    #[test]
    fn test_lambda_single_param_no_parens() {
        let ir = lower("java.util.function.Function<String,String> f = x -> x;");
        let a = assigns(&ir);
        let names = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::LambdaRef { arg_names } = rhs {
                Some(arg_names)
            } else {
                None
            }
        });
        assert_eq!(*names.unwrap(), vec!["x".to_string()]);
    }

    // ------------------------------------------------------------- literals

    #[test]
    fn test_string_literal_simple() {
        let ir = lower(r#"String s = "hello";"#);
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Str("hello".to_string())));
    }

    #[test]
    fn test_string_literal_with_space() {
        let ir = lower(r#"String s = "hello world";"#);
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Str("hello world".to_string())));
    }

    #[test]
    fn test_boolean_literals() {
        let ir = lower("boolean a = true; boolean b = false;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs: r0, .. } = a[0] else {
            panic!()
        };
        let IrStmt::Assign { rhs: r1, .. } = a[1] else {
            panic!()
        };
        assert_eq!(*r0, Rhs::Const(ConstValue::Bool(true)));
        assert_eq!(*r1, Rhs::Const(ConstValue::Bool(false)));
    }

    #[test]
    fn test_null_literal() {
        let ir = lower("Object o = null;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::None));
    }

    #[test]
    fn test_integer_literal() {
        let ir = lower("int x = 42;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Int(42)));
    }

    #[test]
    fn test_long_literal_suffix_stripped() {
        let ir = lower("long l = 10L;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Int(10)));
    }

    #[test]
    fn test_float_literal() {
        let ir = lower("double d = 2.5;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Float(2.5)));
    }

    // -------------------------------------------------------- return / throw

    #[test]
    fn test_return_value() {
        let ir = lower("return input;");
        let IrStmt::Return { value, .. } = &ir[0] else {
            panic!("expected Return")
        };
        assert_eq!(*value, Some(var("input")));
    }

    #[test]
    fn test_return_void() {
        let ir = lower("return;");
        let IrStmt::Return { value, .. } = &ir[0] else {
            panic!("expected Return")
        };
        assert_eq!(*value, None);
    }

    #[test]
    fn test_throw() {
        let ir = lower("throw new RuntimeException(input);");
        let raises: Vec<&IrStmt> = ir
            .iter()
            .filter(|s| matches!(s, IrStmt::Raise { .. }))
            .collect();
        assert_eq!(raises.len(), 1);
        let IrStmt::Raise { value, .. } = raises[0] else {
            panic!()
        };
        assert!(value.is_some());
    }

    // ------------------------------------------- try-with-resources / synchronized

    #[test]
    fn test_resource_specification() {
        with_body_stmts(
            "try (AutoCloseable c = open(input)) { use(c); } catch (Exception e) {}",
            |src, stmts| {
                let mut root = stmts[0];
                while let Some(p) = root.parent() {
                    root = p;
                }
                let rs = find_first(root, "resource_specification").unwrap();
                let ir = lower_stmt(src.as_bytes(), rs);
                let a = assigns(&ir);
                let IrStmt::Assign { lhs, .. } = a[a.len() - 1] else {
                    panic!()
                };
                assert_eq!(*lhs, Lhs::VarLhs("c".to_string()));
            },
        );
    }

    #[test]
    fn test_synchronized_lowers_lock_not_body() {
        with_body_stmts("synchronized (lock) { doIt(input); }", |src, stmts| {
            let ir = lower_stmt(src.as_bytes(), stmts[0]);
            let c = calls(&ir);
            assert!(!c.iter().any(|s| {
                let IrStmt::Call { callee, .. } = s else {
                    return false;
                };
                *callee == var("doIt")
            }));
        });
    }

    // -------------------- lower_condition / lower_for_target_assign

    #[test]
    fn test_condition_call_unwraps_parenthesized() {
        with_body_stmts("if (isValid(input)) { doIt(); }", |src, stmts| {
            let cond = stmts[0].child_by_field_name("condition").unwrap();
            let ir = lower_condition(src.as_bytes(), cond);
            assert_eq!(ir.len(), 1);
            let IrStmt::Call { callee, .. } = &ir[0] else {
                panic!("expected Call")
            };
            assert_eq!(*callee, var("isValid"));
        });
    }

    #[test]
    fn test_condition_comparison_keeps_temp() {
        with_body_stmts("if (x > 0) { doIt(); }", |src, stmts| {
            let cond = stmts[0].child_by_field_name("condition").unwrap();
            let ir = lower_condition(src.as_bytes(), cond);
            assert!(ir.iter().any(|s| matches!(
                s,
                IrStmt::Assign {
                    rhs: Rhs::Cmp { .. },
                    ..
                }
            )));
        });
    }

    #[test]
    fn test_for_target_assign() {
        with_body_stmts("for (String s : items) { use(s); }", |src, stmts| {
            let for_stmt = stmts[0];
            let target = for_stmt.child_by_field_name("name").unwrap();
            let iterable = for_stmt.child_by_field_name("value").unwrap();
            let ir = lower_for_target_assign(src.as_bytes(), target, iterable);
            assert_eq!(ir.len(), 1);
            let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
                panic!("expected Assign")
            };
            assert_eq!(*lhs, Lhs::VarLhs("s".to_string()));
            assert_eq!(*rhs, var("items"));
        });
    }

    // ------------------------------------------------------- repli conservateur

    #[test]
    fn test_unknown_statement_type_is_noop() {
        let ir = lower("assert x > 0;");
        assert!(matches!(ir[0], IrStmt::Noop { .. }));
    }
}
