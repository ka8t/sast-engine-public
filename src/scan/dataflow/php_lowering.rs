//! `tree-sitter-php` → IR lowering — direct template of
//! `js_lowering.rs`/`java_lowering.rs` (same `__t0, __t1, ...`
//! temporaries, same shared language-neutral IR, `ir.rs`). No
//! equivalent Python source (`lexical_taint.py` is a line-by-line
//! engine with no AST, dropped for PHP as it was for JS),
//! this module goes beyond Python parity.
//!
//! **Scope difference from `lowering.rs`/`java_lowering.rs`/
//! `js_lowering.rs`**: this module lowers ONLY the statements that
//! `php_cfg.rs::PhpCfgBuilder` actually stores in a CFG node.
//!
//! Node shapes verified empirically before writing this code
//! (`tree-sitter-php`, never assumed, following the discipline
//! established on the `java_lowering.rs`/`js_lowering.rs` side) —
//! notable deviations from JS:
//!   - `variable_name` (`$foo`) — its own text already includes the
//!     `$`, used as-is as the canonical variable name.
//!   - `object_creation_expression` (`new Foo($x)`) and
//!     `subscript_expression` (`$arr[$i]`) have NO named field (unlike
//!     JS) — positional extraction via `named_children()`.
//!   - Call arguments are wrapped in an intermediate `argument` node
//!     (`(arguments (argument (expr)))`) — one level deeper than JS,
//!     unwrapped here.
//!   - `unary_op_expression` (not `unary_expression` as in JS).
//!   - `member_call_expression` (`$obj->method()`) combines the
//!     receiver + name + arguments into a SINGLE node with
//!     `object`/`name`/`arguments` fields — no `member_expression`
//!     nested inside a separate `call_expression` as in JS.
//!   - String: `string` (single quotes, never interpolated) vs.
//!     `encapsed_string` (double quotes/heredoc, interpolable —
//!     `"hello $x"` AND `"hello {$x}"` produce the SAME shape,
//!     alternating `string_content`/`variable_name`) — lowered as a
//!     concatenation of `BinOp("+", ...)`, the same strategy as the JS
//!     `template_string`.
//!   - `echo`/`print` are LANGUAGE CONSTRUCTS, not function calls —
//!     lowered to a synthetic `IrStmt::Call`
//!     (`callee = VarRef("echo")`/`VarRef("print")`) so they stay
//!     visible to the sink engine like any other call (`echo $input`
//!     is a classic XSS sink). `echo $a, $b;` (multiple arguments)
//!     wraps its operands in a `sequence_expression` (comma operator)
//!     — unwrapped into several arguments of the synthetic `Call`.
//!
//! Not handled in v1 (accepted limitation, same spirit as
//! `js_lowering.rs`): array destructuring in target position
//! (`[$a, $b] = $arr`) — opaque synthetic target; `break N`/`continue
//! N` (jumping N nested levels) — treated as a single-level
//! break/continue (cf. `php_cfg.rs`); a closure's `use ($x)` — the
//! captured variable is NOT re-seeded as tainted in the closure's
//! isolated CFG (the same limitation already accepted on the JS side
//! for an arrow function's implicit lexical capture).

use super::cfg::{Cfg, NodeKind};
use super::ir::{ConstValue, IrStmt, Lhs, Rhs};
use std::collections::BTreeMap;
use tree_sitter::Node;

const CMP_OPS: [&str; 9] = ["==", "!=", "===", "!==", "<", "<=", ">", ">=", "<=>"];

fn bool_op_name(op: &str) -> Option<&'static str> {
    match op {
        "&&" | "and" => Some("and"),
        "||" | "or" => Some("or"),
        "??" => Some("or"), // null coalescing — treated as an OR for taint propagation
        _ => None,
    }
}

/// Tree-sitter kind → synthetic call name mapping for the 4 PHP file
/// inclusion language constructs (no named field, a single positional
/// child — the path, possibly wrapped in `parenthesized_expression`,
/// already handled generically by `lower_expr`). Used both in
/// statement position (`lower_include_like_statement`) and expression
/// position (`lower_expr`) — before this mapping,
/// `include($file)`/`require($file)`/etc. fell into `lower_expr`'s
/// "unknown expression" fallback (`Const(None)`), invisible to the
/// sink engine: no LFI/RFI sink (CWE-98) could ever fire, no matter
/// which `.sca` rule was written — found on 08/30 while covering
/// DVWA's "File Inclusion" category (`vulnerabilities/fi/`,
/// `include($file)` where `$file` comes from `$_GET['page']`). Mirrors
/// the strategy already applied to `echo`/`print` (language
/// constructs, not calls, lowered to a synthetic `Call` to stay
/// visible).
fn include_like_callee_name(kind: &str) -> Option<&'static str> {
    match kind {
        "include_expression" => Some("include"),
        "include_once_expression" => Some("include_once"),
        "require_expression" => Some("require"),
        "require_once_expression" => Some("require_once"),
        _ => None,
    }
}

pub struct PhpLowerer<'src> {
    source: &'src [u8],
    output: Vec<IrStmt>,
    temp_counter: u32,
}

impl<'src> PhpLowerer<'src> {
    pub fn new(source: &'src [u8]) -> Self {
        PhpLowerer {
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

    /// Lowers a PHP expression to a canonical `Rhs` — mirrors
    /// `JsLowerer::lower_expr`.
    pub fn lower_expr(&mut self, expr: Option<Node<'src>>) -> Rhs {
        let Some(expr) = expr else {
            return Rhs::Const(ConstValue::None);
        };
        let t = expr.kind();

        if t == "variable_name" {
            return Rhs::VarRef(self.text(expr));
        }
        if t == "name" {
            // Bare identifier (function/class/constant name).
            return Rhs::VarRef(self.text(expr));
        }

        if t == "integer" || t == "float" {
            return Rhs::Const(parse_php_numeric(&self.text(expr)));
        }
        if t == "true" {
            return Rhs::Const(ConstValue::Bool(true));
        }
        if t == "false" {
            return Rhs::Const(ConstValue::Bool(false));
        }
        if t == "null" {
            return Rhs::Const(ConstValue::None);
        }
        if t == "string" {
            return Rhs::Const(ConstValue::Str(self.string_literal_value(expr)));
        }
        if t == "encapsed_string" || t == "heredoc" {
            return self.lower_encapsed_string(expr);
        }

        if t == "parenthesized_expression" {
            let inner = expr.named_children(&mut expr.walk()).next();
            return self.lower_expr(inner);
        }

        // `$arr[$i]` — positional, no named field (verified empirically).
        if t == "subscript_expression" {
            let mut w = expr.walk();
            let mut children = expr.named_children(&mut w);
            let base = self.lower_expr(children.next());
            let key = self.lower_expr(children.next());
            return Rhs::SubscriptRef {
                base: Box::new(base),
                key: Box::new(key),
            };
        }

        // `$obj->prop` — property access without a call.
        if t == "member_access_expression" {
            let base = self.lower_expr(expr.child_by_field_name("object"));
            let attr = expr
                .child_by_field_name("name")
                .map(|f| self.text(f))
                .unwrap_or_else(|| "?".to_string());
            return Rhs::AttrRef {
                base: Box::new(base),
                attr,
            };
        }

        if t == "member_call_expression" {
            return self.lower_member_call(expr);
        }

        if t == "function_call_expression" {
            let callee = self.lower_expr(expr.child_by_field_name("function"));
            let args = self.lower_arg_list(expr.child_by_field_name("arguments"));
            return self.emit_call(callee, args, expr);
        }

        if let Some(callee_name) = include_like_callee_name(t) {
            let arg = self.lower_expr(expr.named_children(&mut expr.walk()).next());
            return self.emit_call(Rhs::VarRef(callee_name.to_string()), vec![arg], expr);
        }

        // `new Foo($x)` — positional, no named field.
        if t == "object_creation_expression" {
            let mut w = expr.walk();
            let mut children = expr.named_children(&mut w);
            let class_node = children.next();
            let callee = match class_node {
                Some(c) if c.kind() == "name" => Rhs::VarRef(self.text(c)),
                Some(c) => self.lower_expr(Some(c)),
                None => Rhs::VarRef("?".to_string()),
            };
            let args_node = children.find(|c| c.kind() == "arguments");
            let args = self.lower_arg_list(args_node);
            return self.emit_call(callee, args, expr);
        }

        if t == "array_creation_expression" {
            let elements: Vec<Rhs> = expr
                .named_children(&mut expr.walk())
                .map(|e| self.lower_array_element(e))
                .collect();
            return Rhs::ListRef(elements);
        }

        if t == "conditional_expression" {
            let cond = self.lower_expr(expr.child_by_field_name("condition"));
            let then = self.lower_expr(expr.child_by_field_name("body"));
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

        // `fn($x) => $x + 1` — ALWAYS an expression body (never a
        // block in PHP, unlike JS): opaque, like a lambda.
        if t == "arrow_function" || t == "anonymous_function" {
            let params = expr.child_by_field_name("parameters");
            return Rhs::LambdaRef {
                arg_names: self.param_names(params),
            };
        }

        if t == "binary_expression" {
            let op = self.operator_text(expr);
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

        if t == "unary_op_expression" {
            let op = self.operator_text(expr);
            let operand = self.lower_expr(expr.child_by_field_name("argument"));
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

        if t == "update_expression" {
            return self.lower_update_expression(expr);
        }

        if t == "assignment_expression" {
            return self.lower_assignment_expression(expr, "=");
        }

        if t == "augmented_assignment_expression" {
            let op = self.operator_text(expr);
            let base_op = op.strip_suffix('=').unwrap_or(&op).to_string();
            return self.lower_assignment_expression(expr, &base_op);
        }

        // Fallback: unknown expression → Const(None), safe (propagates nothing).
        Rhs::Const(ConstValue::None)
    }

    fn emit_call(&mut self, callee: Rhs, args: Vec<Rhs>, at: Node<'src>) -> Rhs {
        let tmp = self.fresh_temp();
        self.emit(IrStmt::Assign {
            lhs: Lhs::VarLhs(tmp.clone()),
            rhs: Rhs::CallRef {
                callee: Box::new(callee),
                args,
                kwargs: Vec::new(),
            },
            lineno: self.line(at),
        });
        Rhs::VarRef(tmp)
    }

    fn lower_member_call(&mut self, expr: Node<'src>) -> Rhs {
        let base = self.lower_expr(expr.child_by_field_name("object"));
        let name = expr
            .child_by_field_name("name")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "?".to_string());
        let callee = Rhs::AttrRef {
            base: Box::new(base),
            attr: name,
        };
        let args = self.lower_arg_list(expr.child_by_field_name("arguments"));
        self.emit_call(callee, args, expr)
    }

    /// An `arguments` entry is wrapped in an intermediate `argument`
    /// node (`(arguments (argument (expr)))`) — unwrapped here
    /// (verified empirically, absent in JS).
    fn lower_arg_list(&mut self, arg_list: Option<Node<'src>>) -> Vec<Rhs> {
        let Some(arg_list) = arg_list else {
            return Vec::new();
        };
        arg_list
            .named_children(&mut arg_list.walk())
            .map(|a| {
                let inner = if a.kind() == "argument" {
                    a.named_children(&mut a.walk()).next()
                } else {
                    Some(a)
                };
                self.lower_expr(inner)
            })
            .collect()
    }

    /// Array literal element (`array_element_initializer`) — the key
    /// in a `key => value` form is ignored in v1 (only the value is
    /// lowered, the same simplification as `DictRef` not being
    /// modeled for PHP associative arrays — an array remains a
    /// `ListRef` of its values, the value's taint is what matters).
    fn lower_array_element(&mut self, node: Node<'src>) -> Rhs {
        let inner = if node.kind() == "array_element_initializer" {
            // Last named child = the value (the `key => value` form
            // has 2 children, the plain form has 1 — the value is
            // always in last position).
            let mut w = node.walk();
            node.named_children(&mut w).last()
        } else {
            Some(node)
        };
        self.lower_expr(inner)
    }

    fn lower_encapsed_string(&mut self, expr: Node<'src>) -> Rhs {
        let mut parts: Vec<Rhs> = Vec::new();
        let mut w = expr.walk();
        for child in expr.children(&mut w) {
            match child.kind() {
                "string_content" | "escape_sequence" => {
                    parts.push(Rhs::Const(ConstValue::Str(self.text(child))))
                }
                "\"" | "'" | "<<<" | ">>>" => {}
                _ if child.is_named() => parts.push(self.lower_expr(Some(child))),
                _ => {}
            }
        }
        if parts.is_empty() {
            return Rhs::Const(ConstValue::Str(String::new()));
        }
        let mut iter = parts.into_iter();
        let mut acc = iter.next().unwrap();
        for part in iter {
            let tmp = self.fresh_temp();
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs: Rhs::BinOp {
                    op: "+".to_string(),
                    left: Box::new(acc),
                    right: Box::new(part),
                },
                lineno: self.line(expr),
            });
            acc = Rhs::VarRef(tmp);
        }
        acc
    }

    fn param_names(&self, params: Option<Node<'src>>) -> Vec<String> {
        let Some(params) = params else {
            return Vec::new();
        };
        let mut names = Vec::new();
        let mut w = params.walk();
        for p in params.named_children(&mut w) {
            match p.kind() {
                "simple_parameter" | "variadic_parameter" | "property_promotion_parameter" => {
                    if let Some(name_node) = p.child_by_field_name("name") {
                        names.push(self.text(name_node));
                    }
                }
                "variable_name" => names.push(self.text(p)),
                _ => {}
            }
        }
        names
    }

    /// Lowers `$i++`/`--$i` into an emitted `+1`/`-1` assignment,
    /// returning the pre-increment value of the operand.
    fn lower_update_expression(&mut self, expr: Node<'src>) -> Rhs {
        let operand_node = expr.child_by_field_name("argument");
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

    fn lower_assignment_expression(&mut self, expr: Node<'src>, base_op: &str) -> Rhs {
        let left_node = expr.child_by_field_name("left");
        let right_node = expr.child_by_field_name("right");

        let mut rhs = self.lower_expr(right_node);
        if base_op != "=" {
            let read_target = self.lower_expr(left_node);
            rhs = if let Some(bool_op) = bool_op_name(base_op) {
                Rhs::Bool {
                    op: bool_op.to_string(),
                    operands: vec![read_target, rhs],
                }
            } else {
                Rhs::BinOp {
                    op: base_op.to_string(),
                    left: Box::new(read_target),
                    right: Box::new(rhs),
                }
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
            "variable_name" => Lhs::VarLhs(self.text(target)),
            "member_access_expression" => {
                let base = self.lower_expr(target.child_by_field_name("object"));
                let attr = target
                    .child_by_field_name("name")
                    .map(|f| self.text(f))
                    .unwrap_or_else(|| "?".to_string());
                Lhs::AttrLhs {
                    base: Box::new(base),
                    attr,
                }
            }
            "subscript_expression" => {
                let mut w = target.walk();
                let mut children = target.named_children(&mut w);
                let base = self.lower_expr(children.next());
                let key = self.lower_expr(children.next());
                Lhs::SubscriptLhs {
                    base: Box::new(base),
                    key: Box::new(key),
                }
            }
            // Destructuring (`list(...)`/`[$a, $b] = ...`): opaque
            // synthetic target in v1 (accepted limitation, see module
            // doc).
            _ => Lhs::VarLhs("__unknown_target".to_string()),
        }
    }

    // --- operator text extraction -------------------------------------

    fn operator_text(&self, expr: Node<'src>) -> String {
        expr.child_by_field_name("operator")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "?".to_string())
    }

    // --- literal reading --------------------------------------------------

    fn string_literal_value(&self, node: Node<'src>) -> String {
        let mut parts = String::new();
        let mut w = node.walk();
        for c in node.children(&mut w) {
            if c.kind() == "string_content" || c.kind() == "escape_sequence" {
                parts.push_str(&self.text(c));
            }
        }
        parts
    }

    // --- statement lowering ---------------------------------------------

    fn lower_stmt(&mut self, stmt: Node<'src>) {
        match stmt.kind() {
            "expression_statement" => self.lower_expression_statement(stmt),
            "return_statement" => self.lower_return_statement(stmt),
            "echo_statement" => self.lower_echo_statement(stmt),
            _ => self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            }),
        }
    }

    /// `print`/`throw` are NOT standalone PHP statements — verified
    /// empirically: `print $x;` parses as
    /// `(expression_statement (print_intrinsic ...))`, and `throw $x;`
    /// (PHP 8+, `throw` is an EXPRESSION) as `(expression_statement
    /// (throw_expression ...))` — both dispatched here, not in
    /// `lower_stmt`.
    fn lower_expression_statement(&mut self, stmt: Node<'src>) {
        let inner = stmt.named_children(&mut stmt.walk()).next();
        let Some(inner) = inner else {
            self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            });
            return;
        };
        match inner.kind() {
            "function_call_expression" | "member_call_expression" => {
                self.lower_call_as_statement(inner);
            }
            "print_intrinsic" => self.lower_print_statement(inner),
            "throw_expression" => self.lower_throw_expression(inner),
            _ if include_like_callee_name(inner.kind()).is_some() => {
                self.lower_include_like_statement(inner);
            }
            // assignment_expression / augmented_assignment_expression /
            // update_expression already emit their Assign via
            // lower_expr (side effect); any other expression is
            // lowered for its side effects, the final result discarded.
            _ => {
                self.lower_expr(Some(inner));
            }
        }
    }

    /// Emits an IR `Call` node (no Assign+temporary) for a call used
    /// as a statement — directly visible to the taint engine as a
    /// potential sink. Mirrors `JsLowerer::lower_call_as_statement`.
    fn lower_call_as_statement(&mut self, call_node: Node<'src>) {
        let (callee, args) = if call_node.kind() == "member_call_expression" {
            let base = self.lower_expr(call_node.child_by_field_name("object"));
            let name = call_node
                .child_by_field_name("name")
                .map(|n| self.text(n))
                .unwrap_or_else(|| "?".to_string());
            let callee = Rhs::AttrRef {
                base: Box::new(base),
                attr: name,
            };
            let args = self.lower_arg_list(call_node.child_by_field_name("arguments"));
            (callee, args)
        } else {
            let callee = self.lower_expr(call_node.child_by_field_name("function"));
            let args = self.lower_arg_list(call_node.child_by_field_name("arguments"));
            (callee, args)
        };
        self.emit(IrStmt::Call {
            callee,
            args,
            kwargs: Vec::new(),
            lineno: self.line(call_node),
        });
    }

    /// `include`/`include_once`/`require`/`require_once` in statement
    /// position — same strategy as `echo`/`print` just below (direct
    /// synthetic `Call`, no useless temporary): mirrors
    /// `lower_call_as_statement` for these language constructs.
    /// See `include_like_callee_name` for the kind → synthetic name
    /// mapping and full context (found on 08/30, LFI/RFI gap on
    /// DVWA).
    fn lower_include_like_statement(&mut self, stmt: Node<'src>) {
        let Some(callee_name) = include_like_callee_name(stmt.kind()) else {
            return;
        };
        let arg = self.lower_expr(stmt.named_children(&mut stmt.walk()).next());
        self.emit(IrStmt::Call {
            callee: Rhs::VarRef(callee_name.to_string()),
            args: vec![arg],
            kwargs: Vec::new(),
            lineno: self.line(stmt),
        });
    }

    /// `echo`/`print` are language constructs, not calls — lowered
    /// into a synthetic `Call` to stay visible as a sink (see module
    /// doc). `echo $a, $b;` wraps its operands in a
    /// `sequence_expression` (unwrapped here).
    fn lower_echo_statement(&mut self, stmt: Node<'src>) {
        let args = self.lower_echo_print_args(stmt);
        self.emit(IrStmt::Call {
            callee: Rhs::VarRef("echo".to_string()),
            args,
            kwargs: Vec::new(),
            lineno: self.line(stmt),
        });
    }

    fn lower_print_statement(&mut self, stmt: Node<'src>) {
        let args = self.lower_echo_print_args(stmt);
        self.emit(IrStmt::Call {
            callee: Rhs::VarRef("print".to_string()),
            args,
            kwargs: Vec::new(),
            lineno: self.line(stmt),
        });
    }

    fn lower_echo_print_args(&mut self, stmt: Node<'src>) -> Vec<Rhs> {
        let mut w = stmt.walk();
        let named: Vec<Node<'src>> = stmt.named_children(&mut w).collect();
        if named.len() == 1 && named[0].kind() == "sequence_expression" {
            let seq = named[0];
            return seq
                .named_children(&mut seq.walk())
                .map(|e| self.lower_expr(Some(e)))
                .collect();
        }
        named
            .into_iter()
            .map(|e| self.lower_expr(Some(e)))
            .collect()
    }

    fn lower_return_statement(&mut self, stmt: Node<'src>) {
        let value_node = stmt.named_children(&mut stmt.walk()).next();
        let value = value_node.map(|v| self.lower_expr(Some(v)));
        self.emit(IrStmt::Return {
            value,
            lineno: self.line(stmt),
        });
    }

    fn lower_throw_expression(&mut self, expr: Node<'src>) {
        let value_node = expr.named_children(&mut expr.walk()).next();
        let value = value_node.map(|v| self.lower_expr(Some(v)));
        self.emit(IrStmt::Raise {
            value,
            lineno: self.line(expr),
        });
    }
}

/// Parses a PHP numeric literal (hex/binary/octal/float, with `_`
/// separators) into a `ConstValue`. Falls back to `Str(text)` if
/// cleanup produces an unparsable form — same strategy as
/// `parse_js_numeric`.
fn parse_php_numeric(text: &str) -> ConstValue {
    let cleaned = text.replace('_', "");
    let lower = cleaned.to_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        return match i64::from_str_radix(hex, 16) {
            Ok(v) => ConstValue::Int(v),
            Err(_) => ConstValue::Str(text.to_string()),
        };
    }
    if let Some(oct) = lower.strip_prefix("0o") {
        return match i64::from_str_radix(oct, 8) {
            Ok(v) => ConstValue::Int(v),
            Err(_) => ConstValue::Str(text.to_string()),
        };
    }
    if let Some(bin) = lower.strip_prefix("0b") {
        return match i64::from_str_radix(bin, 2) {
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
    match cleaned.parse::<i64>() {
        Ok(v) => ConstValue::Int(v),
        Err(_) => ConstValue::Str(text.to_string()),
    }
}

// ============================================================================
// API publique
// ============================================================================

pub fn lower_expr<'src>(source: &'src [u8], expr: Node<'src>) -> Rhs {
    PhpLowerer::new(source).lower_expr(Some(expr))
}

/// Lowers an expression used as a condition (Branch/Loop) into a
/// list of IR statements — for taint propagation, not just its
/// value. Mirrors `js_lowering::lower_condition`.
pub fn lower_condition<'src>(source: &'src [u8], expr: Node<'src>) -> Vec<IrStmt> {
    let mut lowerer = PhpLowerer::new(source);
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
    if unwrapped.kind() == "function_call_expression"
        || unwrapped.kind() == "member_call_expression"
    {
        lowerer.lower_call_as_statement(unwrapped);
    } else {
        lowerer.lower_expr(Some(expr));
    }
    lowerer.output
}

/// Synthesizes `target := iterable` for a PHP `foreach` loop —
/// without this explicit assignment, the taint of the iterated
/// collection would never propagate to the loop variable. Mirrors
/// `js_lowering::lower_for_target_assign`.
pub fn lower_for_target_assign<'src>(
    source: &'src [u8],
    target: Node<'src>,
    iterable: Node<'src>,
) -> Vec<IrStmt> {
    let mut lowerer = PhpLowerer::new(source);
    let rhs = lowerer.lower_expr(Some(iterable));
    let lhs = lowerer.lower_target(Some(target));
    lowerer.emit(IrStmt::Assign {
        lhs,
        rhs,
        lineno: lowerer.line(iterable),
    });
    lowerer.output
}

/// Variant of [`lower_condition`] for a synthetic `case` condition
/// of a switch. Emits `subject === label`.
pub fn lower_expr_switch_case<'src>(
    source: &'src [u8],
    subject: Node<'src>,
    label: Node<'src>,
) -> Rhs {
    let mut lowerer = PhpLowerer::new(source);
    let left = lowerer.lower_expr(Some(subject));
    let right = lowerer.lower_expr(Some(label));
    Rhs::Cmp {
        op: "===".to_string(),
        left: Box::new(left),
        right: Box::new(right),
    }
}

pub fn lower_condition_switch_case<'src>(
    source: &'src [u8],
    subject: Node<'src>,
    label: Node<'src>,
) -> Vec<IrStmt> {
    let mut lowerer = PhpLowerer::new(source);
    let left = lowerer.lower_expr(Some(subject));
    let right = lowerer.lower_expr(Some(label));
    let tmp = lowerer.fresh_temp();
    lowerer.emit(IrStmt::Assign {
        lhs: Lhs::VarLhs(tmp),
        rhs: Rhs::Cmp {
            op: "===".to_string(),
            left: Box::new(left),
            right: Box::new(right),
        },
        lineno: lowerer.line(subject),
    });
    lowerer.output
}

pub fn lower_stmts<'src>(source: &'src [u8], stmts: &[Node<'src>]) -> Vec<IrStmt> {
    let mut lowerer = PhpLowerer::new(source);
    for &stmt in stmts {
        lowerer.lower_stmt(stmt);
    }
    lowerer.output
}

pub fn lower_stmt<'src>(source: &'src [u8], stmt: Node<'src>) -> Vec<IrStmt> {
    let mut lowerer = PhpLowerer::new(source);
    lowerer.lower_stmt(stmt);
    lowerer.output
}

// ============================================================================
// Lowering a CFG node into IR — PHP mirror of
// `js_lowering::lower_node_to_ir`.
// ============================================================================

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

pub fn lower_all_nodes<'tree>(cfg: &Cfg<'tree>, source: &[u8]) -> BTreeMap<usize, Vec<IrStmt>> {
    cfg.nodes
        .keys()
        .map(|&nid| (nid, lower_node_to_ir(cfg, nid, source)))
        .collect()
}

pub fn lower_expr_standalone<'src>(source: &'src [u8], expr: Node<'src>) -> (Rhs, Vec<IrStmt>) {
    let mut lowerer = PhpLowerer::new(source);
    let rhs = lowerer.lower_expr(Some(expr));
    (rhs, lowerer.output)
}

// ============================================================================
// Tests
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

    fn parse_php(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    /// Parses a PHP function body and exposes `(source, body_stmts)` to `f`.
    fn with_body_stmts<R>(body_src: &str, f: impl FnOnce(&str, &[Node]) -> R) -> R {
        let src = format!("<?php\nfunction t($input, $n) {{ {body_src} }}");
        let tree = parse_php(&src);
        assert!(
            !tree.root_node().has_error(),
            "syntaxe PHP invalide : {body_src:?}"
        );
        let func = find_first(tree.root_node(), "function_definition").unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let stmts: Vec<Node> = body.named_children(&mut body.walk()).collect();
        f(&src, &stmts)
    }

    fn lower(body_src: &str) -> Vec<IrStmt> {
        with_body_stmts(body_src, |src, stmts| lower_stmts(src.as_bytes(), stmts))
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

    // ------------------------------------------------- assignations simples

    #[test]
    fn test_assign_constant() {
        let ir = lower("$x = 1;");
        assert_eq!(
            ir,
            vec![IrStmt::Assign {
                lhs: Lhs::VarLhs("$x".to_string()),
                rhs: Rhs::Const(ConstValue::Int(1)),
                lineno: 2,
            }]
        );
    }

    #[test]
    fn test_assign_var() {
        let ir = lower("$x = $n;");
        let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        assert_eq!(*lhs, Lhs::VarLhs("$x".to_string()));
        assert_eq!(*rhs, var("$n"));
    }

    #[test]
    fn test_member_access_assign() {
        let ir = lower("$this->field = $input;");
        let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        assert_eq!(
            *lhs,
            Lhs::AttrLhs {
                base: Box::new(var("$this")),
                attr: "field".to_string(),
            }
        );
        assert_eq!(*rhs, var("$input"));
    }

    #[test]
    fn test_subscript_assign_positional_no_field_names() {
        let ir = lower("$arr[0] = $input;");
        let IrStmt::Assign { lhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        let Lhs::SubscriptLhs { base, key } = lhs else {
            panic!("expected SubscriptLhs")
        };
        assert_eq!(**base, var("$arr"));
        assert_eq!(**key, Rhs::Const(ConstValue::Int(0)));
    }

    // ------------------------------------------------------------ operators

    #[test]
    fn test_binary_arith() {
        let ir = lower("$z = $x + $y;");
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
        let ir = lower("$b = $x > 0;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert!(matches!(rhs, Rhs::Cmp { .. }));
    }

    #[test]
    fn test_spaceship_is_cmp() {
        let ir = lower("$b = $x <=> $y;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert!(matches!(rhs, Rhs::Cmp { .. }));
    }

    #[test]
    fn test_boolean_and() {
        let ir = lower("$b = $x && $y;");
        let a = assigns(&ir);
        let bool_assign = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::Bool { op, .. } = rhs {
                Some(op)
            } else {
                None
            }
        });
        assert_eq!(bool_assign.map(|s| s.as_str()), Some("and"));
    }

    #[test]
    fn test_null_coalescing_is_bool_or() {
        let ir = lower("$b = $x ?? $y;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(
            rhs,
            &Rhs::Bool {
                op: "or".to_string(),
                operands: vec![var("$x"), var("$y")],
            }
        );
    }

    #[test]
    fn test_unary_not() {
        let ir = lower("$b = !$x;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::UnaryOp { op, .. } = rhs else {
            panic!("expected UnaryOp (unary_op_expression en PHP)")
        };
        assert_eq!(op, "!");
    }

    #[test]
    fn test_update_expression_increment() {
        let ir = lower("$n++;");
        let a = assigns(&ir);
        assert_eq!(a.len(), 1);
        let IrStmt::Assign { lhs, rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("$n".to_string()));
        assert_eq!(
            *rhs,
            Rhs::BinOp {
                op: "+".to_string(),
                left: Box::new(var("$n")),
                right: Box::new(Rhs::Const(ConstValue::Int(1))),
            }
        );
    }

    #[test]
    fn test_augmented_assignment_plus_equal() {
        let ir = lower("$n += $input;");
        let a = assigns(&ir);
        let IrStmt::Assign { lhs, rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("$n".to_string()));
        assert_eq!(
            *rhs,
            Rhs::BinOp {
                op: "+".to_string(),
                left: Box::new(var("$n")),
                right: Box::new(var("$input")),
            }
        );
    }

    #[test]
    fn test_augmented_assignment_dot_concat() {
        let ir = lower(r#"$n .= $input;"#);
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::BinOp { op, .. } = rhs else {
            panic!("expected BinOp")
        };
        assert_eq!(op, ".");
    }

    #[test]
    fn test_ternary() {
        let ir = lower("$z = $cond ? $input : $safe;");
        let a = assigns(&ir);
        let has_ifexp = a.iter().any(|s| {
            matches!(
                s,
                IrStmt::Assign {
                    rhs: Rhs::IfExp { .. },
                    ..
                }
            )
        });
        assert!(has_ifexp);
    }

    // ------------------------------------------------------------- appels

    #[test]
    fn test_call_as_statement_emits_call_node() {
        let ir = lower("doSomething($input);");
        let c = calls(&ir);
        assert_eq!(c.len(), 1);
        let IrStmt::Call { callee, args, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*callee, var("doSomething"));
        assert_eq!(*args, vec![var("$input")]);
    }

    #[test]
    fn test_member_call_captures_receiver() {
        let ir = lower("$r = $obj->method($input);");
        let a = assigns(&ir);
        let call_assign = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, .. } = rhs {
                Some(callee)
            } else {
                None
            }
        });
        let callee = call_assign.expect("un CallRef attendu");
        assert_eq!(
            **callee,
            Rhs::AttrRef {
                base: Box::new(var("$obj")),
                attr: "method".to_string(),
            }
        );
    }

    #[test]
    fn test_object_creation_positional_no_field_names() {
        let ir = lower("$r = new Foo($input);");
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
        let (callee, args) = call_assign.expect("un CallRef attendu");
        assert_eq!(**callee, var("Foo"));
        assert_eq!(*args, vec![var("$input")]);
    }

    #[test]
    fn test_argument_wrapper_node_unwrapped() {
        // PHP arguments are wrapped in an intermediate `argument`
        // node — verifies that lower_arg_list unwraps it.
        let ir = lower("doSomething($a, $b);");
        let c = calls(&ir);
        let IrStmt::Call { args, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*args, vec![var("$a"), var("$b")]);
    }

    // --------------------------------------------------------- literals

    #[test]
    fn test_single_quoted_string_never_interpolated() {
        let ir = lower(r#"$s = 'hello';"#);
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Str("hello".to_string())));
    }

    #[test]
    fn test_encapsed_string_bare_interpolation_propagates_taint() {
        let ir = lower(r#"$s = "foo $input bar";"#);
        let a = assigns(&ir);
        let has_binop_with_var = a.iter().any(|s| {
            if let IrStmt::Assign {
                rhs: Rhs::BinOp { left, right, .. },
                ..
            } = s
            {
                **left == var("$input") || **right == var("$input")
            } else {
                false
            }
        });
        assert!(has_binop_with_var);
    }

    #[test]
    fn test_encapsed_string_curly_interpolation_propagates_taint() {
        let ir = lower(r#"$s = "foo {$input} bar";"#);
        let a = assigns(&ir);
        let has_binop_with_var = a.iter().any(|s| {
            if let IrStmt::Assign {
                rhs: Rhs::BinOp { left, right, .. },
                ..
            } = s
            {
                **left == var("$input") || **right == var("$input")
            } else {
                false
            }
        });
        assert!(has_binop_with_var);
    }

    #[test]
    fn test_hex_numeric_literal() {
        let ir = lower("$x = 0x1F;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Int(31)));
    }

    #[test]
    fn test_array_literal() {
        let ir = lower("$a = [1, $input];");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(
            *rhs,
            Rhs::ListRef(vec![Rhs::Const(ConstValue::Int(1)), var("$input")])
        );
    }

    #[test]
    fn test_array_literal_keyed_value_still_propagates() {
        let ir = lower(r#"$a = ["k" => $input];"#);
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::ListRef(vec![var("$input")]));
    }

    #[test]
    fn test_arrow_function_always_opaque_lambda() {
        // fn() => ... NEVER has a block body in PHP — always an opaque
        // lambda, never collected by the js_summary equivalent.
        let ir = lower("$f = fn($a) => $a + 1;");
        let a = assigns(&ir);
        let has_lambda = a.iter().any(|s| {
            matches!(
                s,
                IrStmt::Assign {
                    rhs: Rhs::LambdaRef { .. },
                    ..
                }
            )
        });
        assert!(has_lambda);
    }

    // ------------------------------------------------------ echo/print/return

    #[test]
    fn test_echo_single_arg_is_synthetic_call() {
        let ir = lower("echo $input;");
        let c = calls(&ir);
        assert_eq!(c.len(), 1);
        let IrStmt::Call { callee, args, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*callee, var("echo"));
        assert_eq!(*args, vec![var("$input")]);
    }

    #[test]
    fn test_echo_multiple_args_sequence_unwrapped() {
        let ir = lower("echo $a, $b;");
        let c = calls(&ir);
        let IrStmt::Call { callee, args, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*callee, var("echo"));
        assert_eq!(*args, vec![var("$a"), var("$b")]);
    }

    #[test]
    fn test_print_is_synthetic_call() {
        let ir = lower("print $input;");
        let c = calls(&ir);
        assert_eq!(c.len(), 1);
        let IrStmt::Call { callee, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*callee, var("print"));
    }

    #[test]
    fn test_return_with_value() {
        let ir = lower("return $input;");
        assert_eq!(
            ir.last(),
            Some(&IrStmt::Return {
                value: Some(var("$input")),
                lineno: 2,
            })
        );
    }

    #[test]
    fn test_throw_with_value() {
        let ir = lower("throw $input;");
        assert_eq!(
            ir.last(),
            Some(&IrStmt::Raise {
                value: Some(var("$input")),
                lineno: 2,
            })
        );
    }

    // --------------------------------------------------------- lower_condition

    #[test]
    fn test_lower_condition_unwraps_parens_for_call() {
        let src = "<?php\nfunction t($input) { if (isValid($input)) { $x = 1; } }";
        let tree = parse_php(src);
        let if_stmt = find_first(tree.root_node(), "if_statement").unwrap();
        let cond = if_stmt.child_by_field_name("condition").unwrap();
        let ir = lower_condition(src.as_bytes(), cond);
        let c = calls(&ir);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn test_lower_for_target_assign_foreach() {
        let src = "<?php\nfunction t($arr) { foreach ($arr as $v) { $x = $v; } }";
        let tree = parse_php(src);
        let foreach_stmt = find_first(tree.root_node(), "foreach_statement").unwrap();
        let mut w = foreach_stmt.walk();
        let named: Vec<Node> = foreach_stmt.named_children(&mut w).collect();
        // named[0] = iterable ($arr), named[1] = target ($v), body exclu (champ).
        let iterable = named[0];
        let target = named[1];
        let ir = lower_for_target_assign(src.as_bytes(), target, iterable);
        assert_eq!(
            ir,
            vec![IrStmt::Assign {
                lhs: Lhs::VarLhs("$v".to_string()),
                rhs: var("$arr"),
                lineno: 2,
            }]
        );
    }
}
