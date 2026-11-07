//! `tree-sitter-javascript` → IR lowering — direct template of
//! `java_lowering.rs` (same layout: `__t0, __t1, ...` temporaries,
//! 3-address linearization), same shared, language-neutral IR
//! (`ir.rs`). No equivalent Python source (`lexical_taint.py` is a
//! line-by-line engine without an AST, discarded)
//! — this module goes beyond Python parity, as `java_lowering.rs` did
//! in its time.
//!
//! **Reused as-is for TypeScript** (`.ts`, not yet `.tsx`/JSX):
//! `tree-sitter-typescript` produces the SAME node kinds as
//! `tree-sitter-javascript` for the entire ordinary JS subset (verified
//! empirically — `function_declaration`/`if_statement`/
//! `binary_expression`/`call_expression`/etc. are identical), so this
//! module has no separate `ts_lowering.rs` variant. The only addition
//! needed: three transparent wrappers specific to TS (`as_expression`,
//! `type_assertion`, `non_null_expression`), which can simply never
//! appear in a pure JS tree.
//!
//! **Scope difference vs `lowering.rs`/`java_lowering.rs`**: this
//! module only lowers the statements that `js_cfg.rs::JsCfgBuilder`
//! actually stores in a CFG node (`Basic`/`Finally` `.statements`, or
//! the condition of a `Branch`/`Loop`) — same split as Java.
//!
//! Tree-sitter node shapes verified empirically before writing this
//! code (not assumed, following the discipline established for
//! `java_lowering.rs`):
//!   - `for_in_statement` covers BOTH `for...in` AND `for...of` (same
//!     kind, distinguished only by the `operator` field = "in"/"of") —
//!     treated identically here (target assignment := iterable), taint
//!     propagates the same way in both cases.
//!   - `augmented_assignment_expression` (`+=`, `??=`, `||=`, `&&=`...)
//!     is a SEPARATE kind from `assignment_expression` (`=`) — unlike
//!     Java where both forms share the same node distinguished by its
//!     `operator` field.
//!   - `member_expression`/`call_expression` with optional chaining
//!     (`a?.b`, `a?.()`) just carry an extra `optional_chain` field —
//!     `object`/`property`/`function`/`arguments` remain the same
//!     fields, no special handling required.
//!   - `new_expression` (`new Foo(x)`) is a separate kind from
//!     `call_expression`, with `constructor`/`arguments` fields.
//!   - Strings: `string` wraps `string_fragment` nodes (like Java);
//!     `template_string` wraps `string_fragment` +
//!     `template_substitution` (the interpolated expression) — lowered
//!     into a concatenation of `BinOp("+", ...)` to propagate the taint
//!     of the interpolated parts, not just the fragments' literal
//!     value.
//!   - `var`/`let`/`const` are two different kinds
//!     (`variable_declaration`/`lexical_declaration`) but share the
//!     same internal shape (`variable_declarator{name, value}`).
//!
//! Not handled in v1 (accepted limitation, see the JS onboarding plan):
//! destructuring (`array_pattern`/`object_pattern` in target position)
//! — lowered to an opaque synthetic target rather than distributing
//! taint element by element (same fallback as Java for an unrecognized
//! target node); spread (`...x`) in call or literal position — lowered
//! as a normal sub-expression, the `...` marker is simply ignored (the
//! taint of `x` keeps propagating, only the expansion semantics is
//! lost); generators (`yield`)/`async`/`await` treated as transparent
//! wrappers around their operand (taint passes through, no async
//! semantics modeled — consistent with the absence of any concurrency
//! model in the rest of the engine).

use super::cfg::{Cfg, NodeKind};
use super::ir::{ConstValue, IrStmt, Lhs, Rhs};
use std::collections::BTreeMap;
use tree_sitter::Node;

const CMP_OPS: [&str; 8] = ["==", "!=", "===", "!==", "<", "<=", ">", ">="];

fn bool_op_name(op: &str) -> Option<&'static str> {
    match op {
        "&&" => Some("and"),
        "||" => Some("or"),
        "??" => Some("or"), // nullish coalescing — treated as an OR for taint propagation
        _ => None,
    }
}

pub struct JsLowerer<'src> {
    source: &'src [u8],
    output: Vec<IrStmt>,
    temp_counter: u32,
}

impl<'src> JsLowerer<'src> {
    pub fn new(source: &'src [u8]) -> Self {
        JsLowerer {
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

    /// Lowers a JS expression into a canonical `Rhs` — mirrors
    /// `JavaLowerer::lower_expr`.
    pub fn lower_expr(&mut self, expr: Option<Node<'src>>) -> Rhs {
        let Some(expr) = expr else {
            return Rhs::Const(ConstValue::None);
        };
        let t = expr.kind();

        if t == "identifier" || t == "this" || t == "super" || t == "property_identifier" {
            return Rhs::VarRef(self.text(expr));
        }

        if t == "number" {
            return Rhs::Const(parse_js_numeric(&self.text(expr)));
        }
        if t == "true" {
            return Rhs::Const(ConstValue::Bool(true));
        }
        if t == "false" {
            return Rhs::Const(ConstValue::Bool(false));
        }
        if t == "null" || t == "undefined" {
            return Rhs::Const(ConstValue::None);
        }
        if t == "string" {
            return Rhs::Const(ConstValue::Str(self.string_literal_value(expr)));
        }
        if t == "template_string" {
            return self.lower_template_string(expr);
        }

        if t == "parenthesized_expression" {
            let inner = expr.named_children(&mut expr.walk()).next();
            return self.lower_expr(inner);
        }

        if t == "member_expression" {
            let base = self.lower_expr(expr.child_by_field_name("object"));
            let attr = expr
                .child_by_field_name("property")
                .map(|f| self.text(f))
                .unwrap_or_else(|| "?".to_string());
            return Rhs::AttrRef {
                base: Box::new(base),
                attr,
            };
        }

        if t == "subscript_expression" {
            let base = self.lower_expr(expr.child_by_field_name("object"));
            let key = self.lower_expr(expr.child_by_field_name("index"));
            return Rhs::SubscriptRef {
                base: Box::new(base),
                key: Box::new(key),
            };
        }

        if t == "call_expression" {
            return self.lower_call_expression(expr);
        }

        if t == "new_expression" {
            let callee = self.lower_expr(expr.child_by_field_name("constructor"));
            let args = self.lower_arg_list(expr.child_by_field_name("arguments"));
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

        if t == "array" {
            let elements: Vec<Rhs> = expr
                .named_children(&mut expr.walk())
                .map(|e| self.lower_spreadable(e))
                .collect();
            return Rhs::ListRef(elements);
        }

        if t == "object" {
            return self.lower_object(expr);
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

        if t == "arrow_function" || t == "function_expression" || t == "function" {
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

        if t == "unary_expression" {
            let op = self.operator_text(expr);
            let operand = self.lower_expr(expr.child_by_field_name("argument"));
            // `typeof`/`void`/`delete` don't carry useful taint as such,
            // but the operand can be a sink (e.g. `delete
            // obj[tainted]`) — lowered normally, like any unary
            // operator.
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
            // "+=" -> "+", "??=" -> "??", etc.
            let base_op = op.strip_suffix('=').unwrap_or(&op).to_string();
            return self.lower_assignment_expression(expr, &base_op);
        }

        if t == "await_expression" || t == "yield_expression" {
            // Transparent wrapper: the operand's taint passes through,
            // no async/generator semantics modeled (see module doc).
            let inner = expr.named_children(&mut expr.walk()).next();
            return self.lower_expr(inner);
        }

        if t == "spread_element" {
            let inner = expr.named_children(&mut expr.walk()).next();
            return self.lower_expr(inner);
        }

        // --- TypeScript: transparent wrappers around an ordinary JS
        // expression (see module doc, added when extending to
        // TypeScript) — taint passes through, the type annotation is
        // ignored. Verified empirically (`tree-sitter-typescript`):
        //   - `x as Type` (as_expression): the expression is the FIRST
        //     named child, the type the second (source text order).
        //   - `<Type>x` (type_assertion): REVERSE order — the type is
        //     the first named child, the expression the LAST.
        //   - `x!` (non_null_expression): a single named child, the
        //     expression itself.
        if t == "as_expression" || t == "non_null_expression" {
            let inner = expr.named_children(&mut expr.walk()).next();
            return self.lower_expr(inner);
        }
        if t == "type_assertion" {
            let inner = expr.named_children(&mut expr.walk()).last();
            return self.lower_expr(inner);
        }

        // Fallback: unknown expression → Const(None), safe (propagates nothing).
        Rhs::Const(ConstValue::None)
    }

    /// Array literal element, with or without `...spread`.
    fn lower_spreadable(&mut self, node: Node<'src>) -> Rhs {
        self.lower_expr(Some(node))
    }

    fn lower_object(&mut self, expr: Node<'src>) -> Rhs {
        let mut pairs = Vec::new();
        let mut w = expr.walk();
        for child in expr.named_children(&mut w) {
            match child.kind() {
                "pair" => {
                    let key = child
                        .child_by_field_name("key")
                        .map(|k| self.text(k))
                        .unwrap_or_else(|| "?".to_string());
                    let value = self.lower_expr(child.child_by_field_name("value"));
                    pairs.push((Rhs::Const(ConstValue::Str(key)), value));
                }
                "shorthand_property_identifier" => {
                    let name = self.text(child);
                    pairs.push((Rhs::Const(ConstValue::Str(name.clone())), Rhs::VarRef(name)));
                }
                "spread_element" => {
                    let inner = child.named_children(&mut child.walk()).next();
                    let value = self.lower_expr(inner);
                    pairs.push((Rhs::Const(ConstValue::Str("...".to_string())), value));
                }
                "method_definition" => {
                    // Object method — body not lowered here (same scope
                    // as `lambda_expression` on the Java side: opaque,
                    // the body is never visited outside its own CFG
                    // unit).
                    let name = child
                        .child_by_field_name("name")
                        .map(|n| self.text(n))
                        .unwrap_or_else(|| "?".to_string());
                    pairs.push((
                        Rhs::Const(ConstValue::Str(name)),
                        Rhs::LambdaRef {
                            arg_names: Vec::new(),
                        },
                    ));
                }
                _ => {}
            }
        }
        Rhs::DictRef(pairs)
    }

    fn lower_template_string(&mut self, expr: Node<'src>) -> Rhs {
        let mut parts: Vec<Rhs> = Vec::new();
        let mut w = expr.walk();
        for child in expr.children(&mut w) {
            match child.kind() {
                "string_fragment" => parts.push(Rhs::Const(ConstValue::Str(self.text(child)))),
                "template_substitution" => {
                    let inner = child.named_children(&mut child.walk()).next();
                    parts.push(self.lower_expr(inner));
                }
                _ => {}
            }
        }
        if parts.is_empty() {
            return Rhs::Const(ConstValue::Str(String::new()));
        }
        // Left-associative concatenation into BinOp("+", ...) —
        // propagates the taint of each interpolated part, like a Python
        // f-string (see `lowering.rs::lower_fstring`, same strategy).
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

    fn lower_call_expression(&mut self, expr: Node<'src>) -> Rhs {
        let callee = self.lower_expr(expr.child_by_field_name("function"));
        let args = self.lower_arg_list(expr.child_by_field_name("arguments"));
        let tmp = self.fresh_temp();
        let call_lineno = expr
            .child_by_field_name("function")
            .map(|f| self.line(f))
            .unwrap_or_else(|| self.line(expr));
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

    fn param_names(&self, params: Option<Node<'src>>) -> Vec<String> {
        let Some(params) = params else {
            return Vec::new();
        };
        if params.kind() == "identifier" {
            // `x => ...` — single parameter without parentheses.
            return vec![self.text(params)];
        }
        let mut names = Vec::new();
        let mut w = params.walk();
        for p in params.named_children(&mut w) {
            match p.kind() {
                "identifier" => names.push(self.text(p)),
                "required_parameter" | "optional_parameter" => {
                    if let Some(pat) = p.named_children(&mut p.walk()).next()
                        && pat.kind() == "identifier"
                    {
                        names.push(self.text(pat));
                    }
                }
                "assignment_pattern" => {
                    if let Some(left) = p.child_by_field_name("left")
                        && left.kind() == "identifier"
                    {
                        names.push(self.text(left));
                    }
                }
                "rest_pattern" => {
                    if let Some(inner) = p.named_children(&mut p.walk()).next() {
                        names.push(self.text(inner));
                    }
                }
                _ => {}
            }
        }
        names
    }

    /// Lowers `i++`/`--i` into an emitted `+1`/`-1` assignment, returning
    /// the pre-increment value of the operand — exact mirror of Java.
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

    /// Lowers `target = expr` / `target OP= expr` into an emitted
    /// `Assign`, returning the assigned `Rhs`. `base_op` = "=" for a
    /// plain assignment (`assignment_expression`), otherwise the base
    /// operator of a compound form (`augmented_assignment_expression`,
    /// e.g. "+" for "+=", "??" for "??=").
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

    // --- target (LHS) lowering ------------------------------------------

    fn lower_target(&mut self, target: Option<Node<'src>>) -> Lhs {
        let Some(target) = target else {
            return Lhs::VarLhs("__unknown_target".to_string());
        };
        match target.kind() {
            "identifier" | "this" => Lhs::VarLhs(self.text(target)),
            "member_expression" => {
                let base = self.lower_expr(target.child_by_field_name("object"));
                let attr = target
                    .child_by_field_name("property")
                    .map(|f| self.text(f))
                    .unwrap_or_else(|| "?".to_string());
                Lhs::AttrLhs {
                    base: Box::new(base),
                    attr,
                }
            }
            "subscript_expression" => {
                let base = self.lower_expr(target.child_by_field_name("object"));
                let key = self.lower_expr(target.child_by_field_name("index"));
                Lhs::SubscriptLhs {
                    base: Box::new(base),
                    key: Box::new(key),
                }
            }
            // Destructuring (`array_pattern`/`object_pattern`): opaque
            // synthetic target in v1 (accepted limitation, see module
            // doc) — no element-by-element taint distribution.
            _ => Lhs::VarLhs("__unknown_target".to_string()),
        }
    }

    // --- operator text extraction ---------------------------------------

    fn operator_text(&self, expr: Node<'src>) -> String {
        expr.child_by_field_name("operator")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "?".to_string())
    }

    // --- literal reading -------------------------------------------------

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

    // --- statement lowering ------------------------------------------------

    fn lower_stmt(&mut self, stmt: Node<'src>) {
        match stmt.kind() {
            "lexical_declaration" | "variable_declaration" => self.lower_variable_declaration(stmt),
            "expression_statement" => self.lower_expression_statement(stmt),
            "return_statement" => self.lower_return_statement(stmt),
            "throw_statement" => self.lower_throw_statement(stmt),
            _ => self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            }),
        }
    }

    fn lower_variable_declaration(&mut self, stmt: Node<'src>) {
        let mut w = stmt.walk();
        let decls: Vec<Node<'src>> = stmt
            .named_children(&mut w)
            .filter(|c| c.kind() == "variable_declarator")
            .collect();
        for decl in decls {
            let Some(name_node) = decl.child_by_field_name("name") else {
                continue;
            };
            let value_node = decl.child_by_field_name("value");
            // Destructuring in declaration position
            // (`const {a, b} = obj`/`const [a, b] = arr]`): accepted
            // limitation in v1, opaque target rather than
            // element-by-element distribution (see module doc).
            if name_node.kind() != "identifier" {
                self.emit(IrStmt::Noop {
                    lineno: self.line(stmt),
                });
                continue;
            }
            let name = self.text(name_node);
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
        if inner.kind() == "call_expression" {
            self.lower_call_as_statement(inner);
            return;
        }
        // assignment_expression / augmented_assignment_expression /
        // update_expression already emit their Assign via lower_expr
        // (side effect); any other expression is lowered for its
        // side effects, the final result discarded.
        self.lower_expr(Some(inner));
    }

    /// Emits an IR `Call` node (no Assign+temporary) for a call used as
    /// a statement — directly visible to the taint engine as a
    /// potential sink. Exact mirror of
    /// `JavaLowerer::lower_call_as_statement`.
    fn lower_call_as_statement(&mut self, call_node: Node<'src>) {
        let callee = self.lower_expr(call_node.child_by_field_name("function"));
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
}

/// Parses a JS numeric literal (hex/binary/octal/float/exponential
/// notation, with `_` separators) into a `ConstValue`. Falls back to
/// `Str(text)` (the ORIGINAL text, not cleaned) if the cleaning
/// produces an unparsable form — same strategy as `parse_java_numeric`.
fn parse_js_numeric(text: &str) -> ConstValue {
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
        return match cleaned.trim_end_matches('n').parse::<f64>() {
            Ok(v) => ConstValue::Float(v),
            Err(_) => ConstValue::Str(text.to_string()),
        };
    }
    // BigInt: `n` suffix (e.g. `123n`) — stripped before integer parsing.
    match cleaned.trim_end_matches('n').parse::<i64>() {
        Ok(v) => ConstValue::Int(v),
        Err(_) => ConstValue::Str(text.to_string()),
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Lowers a standalone JS expression into an `Rhs` — reserved for
/// constant-folding-at-compile-time-style usage. See the warning on
/// [`crate::scan::dataflow::java_lowering::lower_expr`]: do not use for taint
/// propagation of a Branch/Loop condition, use [`lower_condition`]
/// instead.
pub fn lower_expr<'src>(source: &'src [u8], expr: Node<'src>) -> Rhs {
    JsLowerer::new(source).lower_expr(Some(expr))
}

/// Lowers an expression used as a condition (Branch/Loop) into a list of
/// IR statements — for taint propagation, not just its value. Mirrors
/// `java_lowering::lower_condition`.
pub fn lower_condition<'src>(source: &'src [u8], expr: Node<'src>) -> Vec<IrStmt> {
    let mut lowerer = JsLowerer::new(source);
    // if_statement/while_statement expose their condition wrapped in a
    // `parenthesized_expression` — unwrapped before testing the
    // `call_expression` case, otherwise `if (isValid(input))` would
    // never match.
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
    if unwrapped.kind() == "call_expression" {
        lowerer.lower_call_as_statement(unwrapped);
    } else {
        lowerer.lower_expr(Some(expr));
    }
    lowerer.output
}

/// Synthesizes `target := iterable` for a JS `for...in`/`for...of` loop
/// (same kind `for_in_statement`, see module doc) — without this
/// explicit assignment, the taint of the iterated collection/object
/// never propagates to the loop variable. Mirrors
/// `java_lowering::lower_for_target_assign`.
pub fn lower_for_target_assign<'src>(
    source: &'src [u8],
    target: Node<'src>,
    iterable: Node<'src>,
) -> Vec<IrStmt> {
    let mut lowerer = JsLowerer::new(source);
    let rhs = lowerer.lower_expr(Some(iterable));
    let lhs = lowerer.lower_target(Some(target));
    lowerer.emit(IrStmt::Assign {
        lhs,
        rhs,
        lineno: lowerer.line(iterable),
    });
    lowerer.output
}

/// Lowers a list of JS statements (contents of a CFG Basic/Finally node)
/// into IR.
pub fn lower_stmts<'src>(source: &'src [u8], stmts: &[Node<'src>]) -> Vec<IrStmt> {
    let mut lowerer = JsLowerer::new(source);
    for &stmt in stmts {
        lowerer.lower_stmt(stmt);
    }
    lowerer.output
}

/// Lowers a single JS statement into IR (may produce several
/// `IrStmt`s).
pub fn lower_stmt<'src>(source: &'src [u8], stmt: Node<'src>) -> Vec<IrStmt> {
    let mut lowerer = JsLowerer::new(source);
    lowerer.lower_stmt(stmt);
    lowerer.output
}

/// Variant of [`lower_expr`] for the synthetic condition of a switch
/// `case` with a simple literal label (`case 1:`). Emits `subject ===
/// label`. Mirrors `java_lowering::lower_expr_switch_case`.
pub fn lower_expr_switch_case<'src>(
    source: &'src [u8],
    subject: Node<'src>,
    label: Node<'src>,
) -> Rhs {
    let mut lowerer = JsLowerer::new(source);
    let left = lowerer.lower_expr(Some(subject));
    let right = lowerer.lower_expr(Some(label));
    Rhs::Cmp {
        op: "===".to_string(),
        left: Box::new(left),
        right: Box::new(right),
    }
}

/// Variant of [`lower_condition`] for a synthetic switch `case`
/// condition: emits `__tN := (subject === label)`. Mirrors
/// `java_lowering::lower_condition_switch_case`.
pub fn lower_condition_switch_case<'src>(
    source: &'src [u8],
    subject: Node<'src>,
    label: Node<'src>,
) -> Vec<IrStmt> {
    let mut lowerer = JsLowerer::new(source);
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

// ============================================================================
// Lowering a CFG node into IR — JS mirror of
// `java_lowering::lower_node_to_ir`, entry point consumed by
// `worklist::analyze_generic` to instantiate a future
// `worklist::analyze_js`.
// ============================================================================

/// Lowers the statements/condition of a JS CFG node into IR.
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
            // for-in/for-of loop: emits the synthetic `target := iter`
            // assignment (without it, the taint of the
            // iterable/object doesn't propagate to the loop variable).
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

/// Lowers all nodes of a JS CFG into IR, in one pass.
pub fn lower_all_nodes<'tree>(cfg: &Cfg<'tree>, source: &[u8]) -> BTreeMap<usize, Vec<IrStmt>> {
    cfg.nodes
        .keys()
        .map(|&nid| (nid, lower_node_to_ir(cfg, nid, source)))
        .collect()
}

/// Lowers a standalone expression (condition of a Branch/Loop node)
/// into `Rhs` — consumed by `worklist::compute_dead_edges_generic`
/// (pre-pass §9, dead edge pruning).
pub fn lower_expr_standalone<'src>(source: &'src [u8], expr: Node<'src>) -> (Rhs, Vec<IrStmt>) {
    let mut lowerer = JsLowerer::new(source);
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

    fn parse_js(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    /// Parses a JS function body and exposes `(source, body_stmts)` to `f`.
    fn with_body_stmts<R>(body_src: &str, f: impl FnOnce(&str, &[Node]) -> R) -> R {
        let src = format!("function t(input, n) {{ {body_src} }}");
        let tree = parse_js(&src);
        assert!(
            !tree.root_node().has_error(),
            "invalid JS syntax: {body_src:?}"
        );
        let func = find_first(tree.root_node(), "function_declaration").unwrap();
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

    // ------------------------------------------------- simple assignments

    #[test]
    fn test_const_assign_constant() {
        let ir = lower("const x = 1;");
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
    fn test_let_assign_var() {
        let ir = lower("let x = n;");
        let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        assert_eq!(*lhs, Lhs::VarLhs("x".to_string()));
        assert_eq!(*rhs, var("n"));
    }

    #[test]
    fn test_var_declaration_also_handled() {
        let ir = lower("var x = 1;");
        assert!(matches!(ir[0], IrStmt::Assign { .. }));
    }

    #[test]
    fn test_member_assign() {
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
    fn test_subscript_assign() {
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
        let ir = lower("let x = 1, y = 2;");
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
        let ir = lower("let x;");
        assert!(matches!(ir[0], IrStmt::Noop { .. }));
    }

    #[test]
    fn test_destructuring_target_is_opaque_noop_when_no_value_lost() {
        // Accepted v1 limitation: no taint distribution, but must not
        // panic/crash on a valid and common form.
        let ir = lower("const {a, b} = input;");
        assert!(!ir.is_empty());
    }

    // ------------------------------------------------------------ operators

    #[test]
    fn test_binary_arith() {
        let ir = lower("let z = x + y;");
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
        let ir = lower("let b = x > 0;");
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
    fn test_strict_equality_is_cmp() {
        let ir = lower("let b = x === 0;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert!(matches!(rhs, Rhs::Cmp { .. }));
    }

    #[test]
    fn test_boolean_and() {
        let ir = lower("let b = x && y;");
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
    fn test_nullish_coalescing_is_bool_or() {
        let ir = lower("let b = x ?? y;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(
            rhs,
            &Rhs::Bool {
                op: "or".to_string(),
                operands: vec![var("x"), var("y")],
            }
        );
    }

    #[test]
    fn test_unary_not() {
        let ir = lower("let b = !x;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::UnaryOp { op, operand } = rhs else {
            panic!("expected UnaryOp")
        };
        assert_eq!(op, "!");
        assert_eq!(**operand, var("x"));
    }

    #[test]
    fn test_update_expression_increment() {
        let ir = lower("n++;");
        // n++ lowers to Assign(n, n + 1).
        let a = assigns(&ir);
        assert_eq!(a.len(), 1);
        let IrStmt::Assign { lhs, rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("n".to_string()));
        assert_eq!(
            *rhs,
            Rhs::BinOp {
                op: "+".to_string(),
                left: Box::new(var("n")),
                right: Box::new(Rhs::Const(ConstValue::Int(1))),
            }
        );
    }

    #[test]
    fn test_augmented_assignment_plus_equal() {
        let ir = lower("n += input;");
        let a = assigns(&ir);
        let IrStmt::Assign { lhs, rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("n".to_string()));
        assert_eq!(
            *rhs,
            Rhs::BinOp {
                op: "+".to_string(),
                left: Box::new(var("n")),
                right: Box::new(var("input")),
            }
        );
    }

    #[test]
    fn test_augmented_assignment_nullish() {
        let ir = lower("n ??= input;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert!(matches!(rhs, Rhs::Bool { .. }));
    }

    #[test]
    fn test_ternary() {
        let ir = lower("let z = cond ? input : safe;");
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

    // ------------------------------------------------------------- calls

    #[test]
    fn test_call_as_statement_emits_call_node() {
        let ir = lower("doSomething(input);");
        let c = calls(&ir);
        assert_eq!(c.len(), 1);
        let IrStmt::Call { callee, args, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*callee, var("doSomething"));
        assert_eq!(*args, vec![var("input")]);
    }

    #[test]
    fn test_member_call_captures_receiver() {
        let ir = lower("let r = obj.method(input);");
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
        let callee = call_assign.expect("expected a CallRef");
        assert_eq!(
            **callee,
            Rhs::AttrRef {
                base: Box::new(var("obj")),
                attr: "method".to_string(),
            }
        );
    }

    #[test]
    fn test_new_expression_is_call_ref() {
        let ir = lower("let r = new Foo(input);");
        let a = assigns(&ir);
        let has_call = a.iter().any(|s| {
            matches!(
                s,
                IrStmt::Assign {
                    rhs: Rhs::CallRef { .. },
                    ..
                }
            )
        });
        assert!(has_call);
    }

    #[test]
    fn test_optional_chaining_member_still_lowers() {
        let ir = lower("let r = obj?.field;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(
            *rhs,
            Rhs::AttrRef {
                base: Box::new(var("obj")),
                attr: "field".to_string(),
            }
        );
    }

    // --------------------------------------------------------- literals

    #[test]
    fn test_string_literal() {
        let ir = lower(r#"let s = "hello";"#);
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Str("hello".to_string())));
    }

    #[test]
    fn test_template_string_concatenates_interpolation() {
        // `foo${input}bar` must propagate the taint of `input` — lowered
        // into BinOp("+", ...) rather than a plain constant.
        let ir = lower("let s = `foo${input}bar`;");
        let a = assigns(&ir);
        let has_binop_with_var = a.iter().any(|s| {
            if let IrStmt::Assign {
                rhs: Rhs::BinOp { left, right, .. },
                ..
            } = s
            {
                **left == var("input") || **right == var("input")
            } else {
                false
            }
        });
        assert!(has_binop_with_var);
    }

    #[test]
    fn test_hex_numeric_literal() {
        let ir = lower("let x = 0x1F;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Int(31)));
    }

    #[test]
    fn test_array_literal() {
        let ir = lower("let a = [1, input];");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(
            *rhs,
            Rhs::ListRef(vec![Rhs::Const(ConstValue::Int(1)), var("input")])
        );
    }

    #[test]
    fn test_object_literal_pair() {
        let ir = lower("let o = { key: input };");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::DictRef(pairs) = rhs else {
            panic!("expected DictRef")
        };
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, Rhs::Const(ConstValue::Str("key".to_string())));
        assert_eq!(pairs[0].1, var("input"));
    }

    #[test]
    fn test_arrow_function_is_opaque_lambda() {
        let ir = lower("let f = (a) => a + 1;");
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

    // ------------------------------------------------------ return/throw

    #[test]
    fn test_return_with_value() {
        let ir = lower("return input;");
        assert_eq!(
            ir.last(),
            Some(&IrStmt::Return {
                value: Some(var("input")),
                lineno: 1,
            })
        );
    }

    #[test]
    fn test_throw_with_value() {
        let ir = lower("throw input;");
        assert_eq!(
            ir.last(),
            Some(&IrStmt::Raise {
                value: Some(var("input")),
                lineno: 1,
            })
        );
    }

    // --------------------------------------------------------------- TypeScript
    // Transparent wrappers (as/type_assertion/non_null) — invalid syntax
    // in pure JS, parsed here with `tree-sitter-typescript`.

    fn parse_ts(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn lower_ts(body_src: &str) -> Vec<IrStmt> {
        let src = format!("function t(input) {{ {body_src} }}");
        let tree = parse_ts(&src);
        assert!(
            !tree.root_node().has_error(),
            "invalid TS syntax: {body_src:?}"
        );
        let func = find_first(tree.root_node(), "function_declaration").unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let stmts: Vec<Node> = body.named_children(&mut body.walk()).collect();
        lower_stmts(src.as_bytes(), &stmts)
    }

    #[test]
    fn test_as_expression_propagates_taint() {
        let ir = lower_ts("const q = input as string;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, var("input"));
    }

    #[test]
    fn test_type_assertion_propagates_taint() {
        let ir = lower_ts("const q = <string>input;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, var("input"));
    }

    #[test]
    fn test_non_null_assertion_propagates_taint() {
        let ir = lower_ts("const q = input!;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, var("input"));
    }

    // --------------------------------------------------------- lower_condition

    #[test]
    fn test_lower_condition_unwraps_parens_for_call() {
        let src = "function t(input) { if (isValid(input)) { x = 1; } }";
        let tree = parse_js(src);
        let if_stmt = find_first(tree.root_node(), "if_statement").unwrap();
        let cond = if_stmt.child_by_field_name("condition").unwrap();
        let ir = lower_condition(src.as_bytes(), cond);
        let c = calls(&ir);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn test_lower_for_target_assign_for_of() {
        let src = "function t(arr) { for (const v of arr) { x = v; } }";
        let tree = parse_js(src);
        let for_stmt = find_first(tree.root_node(), "for_in_statement").unwrap();
        let target = for_stmt.child_by_field_name("left").unwrap();
        let iterable = for_stmt.child_by_field_name("right").unwrap();
        let ir = lower_for_target_assign(src.as_bytes(), target, iterable);
        assert_eq!(
            ir,
            vec![IrStmt::Assign {
                lhs: Lhs::VarLhs("v".to_string()),
                rhs: var("arr"),
                lineno: 1,
            }]
        );
    }
}
