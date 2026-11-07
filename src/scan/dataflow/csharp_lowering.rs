//! `tree-sitter-c-sharp` → IR lowering — mirrors `java_lowering.rs`,
//! a faithful port of `Audit/sca/parsers/csharp_to_ir.py` (ticket #79, spec
//! #77). Same template as `java_lowering.rs`: temporaries
//! `__t0, __t1, ...`, three-address linearization, same shared,
//! language-neutral IR (`ir.rs`).
//!
//! **Scope difference vs `lowering.rs`/`java_lowering.rs`**:
//! this module lowers ONLY the statements that
//! `csharp_cfg.rs::CSharpCfgBuilder` actually stores in a CFG
//! (control-flow graph) node (`Basic`/`Finally`/`RaiseSite` `.statements`, or
//! the condition of a `Branch`/`Loop`) — if/while/do/for/foreach/try/switch/break/
//! continue are entirely intercepted by the CFG builder and
//! never land in a `.statements` list.
//!
//! Tree-sitter node shapes verified empirically (real parsing
//! with `tree-sitter-c-sharp` 0.23.5, never assumed from the
//! Java grammar nor blindly copied from the Python docstring — an
//! actual deviation was in fact found and fixed, see below):
//!   - `variable_declarator` does NOT expose a named `value` field —
//!     the initializer, if present, is the SECOND named child
//!     (`[name]` alone if absent).
//!   - `prefix_unary_expression`/`postfix_unary_expression` are two
//!     DISTINCT types (unlike Java's single `update_expression`,
//!     which also covers unary `-`/`!` via a separate
//!     `unary_expression`) — this grammar has NO `unary_expression` type:
//!     `-x`/`!x`/`~x`/`++x`/`--x` are all `prefix_unary_expression`,
//!     `x++`/`x--` are `postfix_unary_expression`. Neither
//!     exposes a field name — operator/operand distinguished by
//!     position (operator first for prefix, last for
//!     postfix); a single named child (the operand) in both cases.
//!   - `invocation_expression` has `function`/`arguments` fields (not
//!     Java's separate `object`+`name` fields) — the receiver,
//!     if present, is itself a nested `member_access_expression`
//!     reached via `function`, never split off at the call level.
//!   - Each element of an `argument_list` is wrapped in an
//!     `argument` node (unlike Java, whose `argument_list` named
//!     children ARE directly the expressions) — unwrapped
//!     to its single named child.
//!   - `string_literal` fragments are typed
//!     `string_literal_content` (not Java's `string_fragment`);
//!     `character_literal` likewise wraps a
//!     `character_literal_content`. `verbatim_string_literal` (`@"..."`)
//!     is a LEAF with no child — text sliced directly.
//!   - `interpolated_string_expression` (`$"...{expr}..."`, with no
//!     Java equivalent) mixes `string_content` children (literal
//!     text) and `interpolation` children (each wrapping the nested
//!     expression as its single named child, between two anonymous
//!     `interpolation_brace` tokens) — lowered into a chain of
//!     `BinOp("+", ...)` over strings so that the taint of every
//!     `{expr}` propagates to the result, just like ordinary
//!     string concatenation.
//!   - `element_access_expression`: **actual deviation from the Python
//!     docstring** (which handles it via positional/by-type scanning, for
//!     lack of named fields in its grammar version) — this version of
//!     the crate (`tree-sitter-c-sharp` 0.23.5) does expose named
//!     fields `expression`/`subscript` (verified by a real dump of
//!     the tree), used directly here rather than reproducing the
//!     now-unnecessary positional workaround.
//!   - `conditional_access_expression` (`x?.y`/`x?.y()`, the
//!     null-conditional operator, with no Java equivalent): `condition` field for
//!     the base (verified as named, unlike a positional scan),
//!     nested `member_binding_expression` (no field name, scanned by
//!     type) wrapping the `.name` part the same way
//!     `member_access_expression` wraps `name`. Treated as an
//!     ordinary member access for taint purposes — the `?.` short-circuit
//!     itself carries no information relevant to this engine.
//!   - `cast_expression` exposes `type`/`value` fields (like Java).
//!   - `is_expression` (`x is Foo`, the `instanceof` equivalent) exposes
//!     `left`/`right` fields (same naming as Java's
//!     `instanceof_expression` despite the different node name).
//!   - `conditional_expression` (ternary, NOT Java's `ternary_expression`)
//!     exposes `condition`/`consequence`/
//!     `alternative` fields, as in Java.
//!   - `lambda_expression`: `parameters` field is either a `parameter_list`
//!     (typed/parenthesized form) or an `implicit_parameter` (bare
//!     single-identifier form, `p => p`) — the latter has no
//!     Java equivalent (which uses a bare `identifier`).

use super::cfg::{Cfg, NodeKind};
use super::ir::{ConstValue, IrStmt, Lhs, Rhs};
use std::collections::BTreeMap;
use tree_sitter::Node;

const CMP_OPS: [&str; 6] = ["==", "!=", "<", "<=", ">", ">="];

fn bool_op_name(op: &str) -> Option<&'static str> {
    match op {
        "&&" => Some("and"),
        "||" => Some("or"),
        _ => None,
    }
}

const LITERAL_KINDS: [&str; 2] = ["integer_literal", "real_literal"];

pub struct CSharpLowerer<'src> {
    source: &'src [u8],
    output: Vec<IrStmt>,
    temp_counter: u32,
}

impl<'src> CSharpLowerer<'src> {
    pub fn new(source: &'src [u8]) -> Self {
        CSharpLowerer {
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

    /// Lowers a C# expression into a canonical `Rhs`, emitting
    /// any necessary intermediate statements along the way.
    pub fn lower_expr(&mut self, expr: Option<Node<'src>>) -> Rhs {
        let Some(expr) = expr else {
            return Rhs::Const(ConstValue::None);
        };
        let t = expr.kind();

        if t == "identifier" || t == "this" || t == "base" {
            return Rhs::VarRef(self.text(expr));
        }

        if LITERAL_KINDS.contains(&t) {
            return Rhs::Const(parse_csharp_numeric(&self.text(expr)));
        }

        if t == "string_literal" {
            return Rhs::Const(ConstValue::Str(self.string_literal_value(expr)));
        }

        if t == "verbatim_string_literal" {
            // Leaf with no child — strip the `@"` prefix/`"` suffix and
            // unescape doubled quotes (`""` -> `"`, the only
            // escape mechanism for this literal form).
            let raw = self.text(expr);
            let inner =
                if let Some(stripped) = raw.strip_prefix("@\"").and_then(|s| s.strip_suffix('"')) {
                    stripped
                } else {
                    raw.as_str()
                };
            return Rhs::Const(ConstValue::Str(inner.replace("\"\"", "\"")));
        }

        if t == "character_literal" {
            let mut w = expr.walk();
            let content = expr
                .children(&mut w)
                .find(|c| c.kind() == "character_literal_content");
            let value = content.map(|c| self.text(c)).unwrap_or_default();
            return Rhs::Const(ConstValue::Str(value));
        }

        if t == "boolean_literal" {
            return Rhs::Const(ConstValue::Bool(self.text(expr) == "true"));
        }
        if t == "null_literal" {
            return Rhs::Const(ConstValue::None);
        }

        if t == "interpolated_string_expression" {
            return self.lower_interpolated_string(expr);
        }

        if t == "parenthesized_expression" {
            let inner = expr.named_children(&mut expr.walk()).next();
            return self.lower_expr(inner);
        }

        if t == "member_access_expression" {
            let base = self.lower_expr(expr.child_by_field_name("expression"));
            let attr = expr
                .child_by_field_name("name")
                .map(|f| self.text(f))
                .unwrap_or_else(|| "?".to_string());
            return Rhs::AttrRef {
                base: Box::new(base),
                attr,
            };
        }

        if t == "conditional_access_expression" {
            let base = self.lower_expr(expr.child_by_field_name("condition"));
            let mut w = expr.walk();
            let binding = expr
                .children(&mut w)
                .find(|c| c.kind() == "member_binding_expression");
            if let Some(binding) = binding {
                let attr = binding
                    .child_by_field_name("name")
                    .map(|f| self.text(f))
                    .unwrap_or_else(|| "?".to_string());
                return Rhs::AttrRef {
                    base: Box::new(base),
                    attr,
                };
            }
            return base;
        }

        if t == "element_access_expression" {
            let base = self.lower_expr(expr.child_by_field_name("expression"));
            let key = self.lower_bracketed_argument(expr.child_by_field_name("subscript"));
            return Rhs::SubscriptRef {
                base: Box::new(base),
                key: Box::new(key),
            };
        }

        if t == "invocation_expression" {
            return self.lower_invocation(expr);
        }

        if t == "object_creation_expression" {
            let type_node = expr.child_by_field_name("type");
            let args = self.lower_arg_list(expr.child_by_field_name("arguments"));
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

        if t == "array_creation_expression" || t == "implicit_array_creation_expression" {
            let mut w = expr.walk();
            let init = expr
                .children(&mut w)
                .find(|c| c.kind() == "initializer_expression");
            return match init {
                Some(i) => self.lower_expr(Some(i)),
                None => Rhs::ListRef(Vec::new()),
            };
        }

        if t == "initializer_expression" {
            let elements: Vec<Rhs> = expr
                .named_children(&mut expr.walk())
                .map(|e| self.lower_expr(Some(e)))
                .collect();
            return Rhs::ListRef(elements);
        }

        if t == "cast_expression" {
            return self.lower_expr(expr.child_by_field_name("value"));
        }

        if t == "conditional_expression" {
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

        if t == "anonymous_method_expression" {
            // `delegate(int x) { ... }` — legacy pre-lambda syntax,
            // rare. Opaque: no value-producing form is modeled
            // here.
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
                // Covers arithmetic/bitwise operators AND `??`
                // (null coalescing) — the latter has no dedicated IR
                // form, but BinOp already propagates the taint of both
                // operands unconditionally, which is exactly the
                // correct over-approximation for `a ?? b` (the result
                // is one operand or the other depending on execution).
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

        if t == "prefix_unary_expression" {
            return self.lower_prefix_unary(expr);
        }

        if t == "postfix_unary_expression" {
            return self.lower_postfix_unary(expr);
        }

        if t == "is_expression" {
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

        if t == "as_expression" {
            // `x as Foo` — a cast that yields null instead of throwing. For
            // taint purposes: identical to a cast, propagates the operand.
            return self.lower_expr(expr.child_by_field_name("left"));
        }

        if t == "assignment_expression" {
            return self.lower_assignment_expression(expr);
        }

        // Fallback: unknown expression → Const(None), safe (propagates nothing).
        Rhs::Const(ConstValue::None)
    }

    fn lower_invocation(&mut self, expr: Node<'src>) -> Rhs {
        let function = expr.child_by_field_name("function");
        let args = self.lower_arg_list(expr.child_by_field_name("arguments"));
        let callee = self.lower_expr(function);
        // Call line: for a `member_access_expression` receiver,
        // prefer the line of the `.name` part (mirrors the
        // Java round-8 fix for call chains spread over
        // several lines) — falls back to the line of the whole invocation
        // otherwise.
        let mut call_lineno = self.line(expr);
        if let Some(f) = function
            && f.kind() == "member_access_expression"
            && let Some(name_node) = f.child_by_field_name("name")
        {
            call_lineno = self.line(name_node);
        }
        let tmp = self.fresh_temp();
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

    /// Lowers each element of an `argument_list`, unwrapped from its
    /// `argument` node (unlike Java, see module doc).
    fn lower_arg_list(&mut self, arg_list: Option<Node<'src>>) -> Vec<Rhs> {
        let Some(arg_list) = arg_list else {
            return Vec::new();
        };
        let mut w = arg_list.walk();
        arg_list
            .named_children(&mut w)
            .map(|a| self.lower_wrapped_argument(a))
            .collect()
    }

    /// Lowers a `bracketed_argument_list` (indexer, `arr[i]`) — same
    /// `argument` wrapper as a call's `argument_list`, a single
    /// element expected.
    fn lower_bracketed_argument(&mut self, arg_list: Option<Node<'src>>) -> Rhs {
        let Some(arg_list) = arg_list else {
            return Rhs::Const(ConstValue::None);
        };
        let first = arg_list.named_children(&mut arg_list.walk()).next();
        match first {
            Some(a) => self.lower_wrapped_argument(a),
            None => Rhs::Const(ConstValue::None),
        }
    }

    fn lower_wrapped_argument(&mut self, a: Node<'src>) -> Rhs {
        if a.kind() == "argument" {
            let inner = a.named_children(&mut a.walk()).next();
            self.lower_expr(inner)
        } else {
            self.lower_expr(Some(a))
        }
    }

    fn lambda_param_names(&self, params: Option<Node<'src>>) -> Vec<String> {
        let Some(params) = params else {
            return Vec::new();
        };
        if params.kind() == "implicit_parameter" {
            // `p => ...` — single parameter with no parentheses or type,
            // with no Java equivalent (which uses a bare `identifier`).
            return vec![self.text(params)];
        }
        let mut names = Vec::new();
        let mut w = params.walk();
        for p in params.named_children(&mut w) {
            if p.kind() == "parameter" {
                if let Some(name_node) = p.child_by_field_name("name") {
                    names.push(self.text(name_node));
                }
            } else if p.kind() == "identifier" {
                names.push(self.text(p));
            }
        }
        names
    }

    /// Converts a type node into a chain of `AttrRef` to
    /// match "dotted" patterns (e.g.
    /// `System.Data.SqlClient.SqlCommand` →
    /// `AttrRef(AttrRef(AttrRef(VarRef("System"), "Data"), "SqlClient"), "SqlCommand")`).
    /// Generic arguments (`List<string>` → text `List<string>`)
    /// are stripped before splitting on dots.
    fn type_to_rhs(&self, type_node: Option<Node<'src>>) -> Rhs {
        let Some(type_node) = type_node else {
            return Rhs::VarRef("?".to_string());
        };
        let text = self.text(type_node);
        let before_generic = text.split('<').next().unwrap_or(&text).trim();
        let mut parts = before_generic.split('.');
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

    /// Lowers `-x`/`!x`/`~x`/`++x`/`--x`. No field name on this
    /// node (verified): `children[0]` is the anonymous operator token,
    /// `named_children[0]` the single named operand.
    fn lower_prefix_unary(&mut self, expr: Node<'src>) -> Rhs {
        let operand_node = expr.named_children(&mut expr.walk()).next();
        let Some(operand_node) = operand_node else {
            return Rhs::Const(ConstValue::None);
        };
        let Some(op_child) = expr.child(0) else {
            return Rhs::Const(ConstValue::None);
        };
        let op_text = self.text(op_child);
        if op_text == "++" || op_text == "--" {
            let symbol = &op_text[..1];
            return self.lower_increment(operand_node, symbol, expr);
        }
        let operand = self.lower_expr(Some(operand_node));
        let tmp = self.fresh_temp();
        self.emit(IrStmt::Assign {
            lhs: Lhs::VarLhs(tmp.clone()),
            rhs: Rhs::UnaryOp {
                op: op_text,
                operand: Box::new(operand),
            },
            lineno: self.line(expr),
        });
        Rhs::VarRef(tmp)
    }

    /// Lowers `x++`/`x--`. No field name (verified):
    /// `named_children[0]` the single named operand, the LAST raw
    /// child the anonymous operator token (reverse order from prefix).
    fn lower_postfix_unary(&mut self, expr: Node<'src>) -> Rhs {
        let operand_node = expr.named_children(&mut expr.walk()).next();
        let Some(operand_node) = operand_node else {
            return Rhs::Const(ConstValue::None);
        };
        let last_child = {
            let count = expr.child_count();
            if count == 0 {
                None
            } else {
                expr.child((count - 1) as u32)
            }
        };
        let Some(op_child) = last_child else {
            return Rhs::Const(ConstValue::None);
        };
        let op_text = self.text(op_child);
        let symbol = if op_text.starts_with("++") { "+" } else { "-" };
        self.lower_increment(operand_node, symbol, expr)
    }

    /// Shared lowering for `++`/`--`: emits the update assignment,
    /// returns the value BEFORE the increment (an accepted
    /// approximation for both pre AND post, mirroring
    /// `java_lowering.rs::lower_update_expression` — the distinction
    /// only matters if the expression's VALUE itself feeds a sink in
    /// the same statement, a rare idiom).
    fn lower_increment(
        &mut self,
        operand_node: Node<'src>,
        op_symbol: &str,
        expr: Node<'src>,
    ) -> Rhs {
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

    /// Lowers `target = expr` (and compound forms `+=`, `??=`...) into
    /// an emitted `Assign`, returning the assigned `Rhs`.
    fn lower_assignment_expression(&mut self, expr: Node<'src>) -> Rhs {
        let left_node = expr.child_by_field_name("left");
        let right_node = expr.child_by_field_name("right");
        let op_text = expr
            .child_by_field_name("operator")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "=".to_string());

        let mut rhs = self.lower_expr(right_node);
        if op_text != "=" {
            let base_op = &op_text[..op_text.len() - 1]; // "+=" -> "+", "??=" -> "??"
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

    // --- target (LHS) lowering ------------------------------------------------

    fn lower_target(&mut self, target: Option<Node<'src>>) -> Lhs {
        let Some(target) = target else {
            return Lhs::VarLhs("__unknown_target".to_string());
        };
        match target.kind() {
            "identifier" | "this" => Lhs::VarLhs(self.text(target)),
            "member_access_expression" => {
                let base = self.lower_expr(target.child_by_field_name("expression"));
                let attr = target
                    .child_by_field_name("name")
                    .map(|f| self.text(f))
                    .unwrap_or_else(|| "?".to_string());
                Lhs::AttrLhs {
                    base: Box::new(base),
                    attr,
                }
            }
            "element_access_expression" => {
                let base = self.lower_expr(target.child_by_field_name("expression"));
                let key = self.lower_bracketed_argument(target.child_by_field_name("subscript"));
                Lhs::SubscriptLhs {
                    base: Box::new(base),
                    key: Box::new(key),
                }
            }
            // Fallback: synthetic name to avoid panicking.
            _ => Lhs::VarLhs("__unknown_target".to_string()),
        }
    }

    // --- operator text extraction ---------------------------------------------

    fn binary_op_text(&self, expr: Node<'src>) -> String {
        expr.child_by_field_name("operator")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "?".to_string())
    }

    // --- literal reading -------------------------------------------------------

    fn string_literal_value(&self, node: Node<'src>) -> String {
        let mut parts = String::new();
        let mut w = node.walk();
        for c in node.children(&mut w) {
            if c.kind() == "string_literal_content" || c.kind() == "escape_sequence" {
                parts.push_str(&self.text(c));
            }
        }
        parts
    }

    /// Lowers `$"...{expr}..."` into a chain of `BinOp("+", ...)` over
    /// strings, so that the taint of every nested `{expr}` propagates
    /// to the result.
    fn lower_interpolated_string(&mut self, expr: Node<'src>) -> Rhs {
        let mut parts: Vec<Rhs> = Vec::new();
        let mut w = expr.walk();
        for c in expr.children(&mut w) {
            if c.kind() == "string_content" {
                parts.push(Rhs::Const(ConstValue::Str(self.text(c))));
            } else if c.kind() == "interpolation" {
                let inner = c.named_children(&mut c.walk()).next();
                parts.push(self.lower_expr(inner));
            }
        }
        let Some(first) = parts.first().cloned() else {
            return Rhs::Const(ConstValue::Str(String::new()));
        };
        let mut acc = first;
        for part in parts.into_iter().skip(1) {
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

    // --- statement lowering ----------------------------------------------------

    fn lower_stmt(&mut self, stmt: Node<'src>) {
        match stmt.kind() {
            "local_declaration_statement" => self.lower_local_declaration_statement(stmt),
            "variable_declaration" => self.lower_variable_declaration(stmt),
            "expression_statement" => self.lower_expression_statement(stmt),
            "return_statement" => self.lower_return_statement(stmt),
            // Expression body (`=> expr`) of a method/constructor: same
            // IR as `return expr;` (ticket #123, see `csharp_cfg.rs`).
            // Its single named child is the expression, exactly like a
            // `return_statement`. For a `void` method the returned value
            // is simply never read; calls inside are still lowered, so
            // sinks are seen.
            "arrow_expression_clause" => self.lower_return_statement(stmt),
            "throw_statement" => self.lower_throw_statement(stmt),
            "lock_statement" => self.lower_lock_statement(stmt),
            _ => self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            }),
        }
    }

    fn lower_local_declaration_statement(&mut self, stmt: Node<'src>) {
        let mut w = stmt.walk();
        let decl = stmt
            .named_children(&mut w)
            .find(|c| c.kind() == "variable_declaration");
        match decl {
            Some(d) => self.lower_declarators(d, stmt),
            None => self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            }),
        }
    }

    /// Lowers a BARE `variable_declaration` — reached when a
    /// `using (var x = ...)` resource is appended directly to a BASIC
    /// CFG node by `CSharpCfgBuilder::visit_using` (the resource clause
    /// has no `local_declaration_statement` wrapper there, unlike an
    /// ordinary top-level declaration).
    fn lower_variable_declaration(&mut self, stmt: Node<'src>) {
        self.lower_declarators(stmt, stmt);
    }

    fn lower_declarators(&mut self, decl: Node<'src>, lineno_src: Node<'src>) {
        let mut w = decl.walk();
        let declarators: Vec<Node<'src>> = decl
            .named_children(&mut w)
            .filter(|c| c.kind() == "variable_declarator")
            .collect();
        for declarator in declarators {
            let Some(name_node) = declarator.child_by_field_name("name") else {
                continue;
            };
            let name = self.text(name_node);
            // No named `value` field (verified) — the initializer, if
            // present, is the SECOND named child.
            let named: Vec<Node<'src>> =
                declarator.named_children(&mut declarator.walk()).collect();
            let value_node = named.get(1).copied();
            match value_node {
                None => self.emit(IrStmt::Noop {
                    lineno: self.line(lineno_src),
                }),
                Some(v) => {
                    let rhs = self.lower_expr(Some(v));
                    self.emit(IrStmt::Assign {
                        lhs: Lhs::VarLhs(name),
                        rhs,
                        lineno: self.line(lineno_src),
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
        if inner.kind() == "invocation_expression" {
            self.lower_call_as_statement(inner);
            return;
        }
        // assignment_expression / postfix|prefix_unary_expression
        // already emit their Assign via lower_expr (side effect);
        // any other expression is lowered for its side effects, the
        // final result discarded.
        self.lower_expr(Some(inner));
    }

    /// Emits an IR `Call` node (no Assign+temporary) for a call used
    /// as a statement — directly visible to the taint engine as a
    /// potential sink. Shared between `lower_expression_statement` and
    /// `lower_condition` (a Branch/Loop condition that is a direct
    /// call, e.g. `if (IsValid(input))`).
    fn lower_call_as_statement(&mut self, call_node: Node<'src>) {
        let function = call_node.child_by_field_name("function");
        let callee = self.lower_expr(function);
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

    /// Lowers only the lock expression of a `lock (obj) {...}`. The
    /// body is visited separately by `CSharpCfgBuilder` (its own CFG
    /// nodes) — do NOT descend into it here to avoid double
    /// processing, mirroring
    /// `java_lowering.rs::lower_synchronized_statement`.
    fn lower_lock_statement(&mut self, stmt: Node<'src>) {
        let mut w = stmt.walk();
        let lock_expr = stmt.named_children(&mut w).find(|c| c.kind() != "block");
        match lock_expr {
            Some(l) => {
                self.lower_expr(Some(l));
            }
            None => self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            }),
        }
    }
}

/// Parses a C# numeric literal (hex/binary, with `l`/`u`/`f`/`d`/`m`
/// suffixes and `_` separators) into a `ConstValue`. Falls back to
/// `Str(text)` (the ORIGINAL, uncleaned text) if the cleanup produces
/// an unparsable form — same behavior as `_parse_numeric` on the
/// Python side. Unlike `parse_java_numeric`, no octal heuristic
/// (Python `int("0123")` == 123, no C-style ambiguity here).
fn parse_csharp_numeric(text: &str) -> ConstValue {
    let cleaned = text
        .trim_end_matches(['l', 'L', 'u', 'U', 'f', 'F', 'd', 'D', 'm', 'M'])
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
    match cleaned.parse::<i64>() {
        Ok(v) => ConstValue::Int(v),
        Err(_) => ConstValue::Str(text.to_string()),
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Lowers a standalone C# expression into an `Rhs` (the auxiliary
/// statements generated along the way are discarded, only the final
/// `Rhs` counts). **Do not use for taint propagation of a Branch/Loop
/// condition** — use `lower_condition` instead.
pub fn lower_expr<'src>(source: &'src [u8], expr: Node<'src>) -> Rhs {
    CSharpLowerer::new(source).lower_expr(Some(expr))
}

/// Variant of [`lower_expr`] for the synthetic condition of a switch
/// `case` with a single literal label (`case 6:`) — typed mirror of
/// `SwitchCaseCondition` on the Python side. Emits `subject == label`.
pub fn lower_expr_switch_case<'src>(
    source: &'src [u8],
    subject: Node<'src>,
    label: Node<'src>,
) -> Rhs {
    let mut lowerer = CSharpLowerer::new(source);
    let left = lowerer.lower_expr(Some(subject));
    let right = lowerer.lower_expr(Some(label));
    Rhs::Cmp {
        op: "==".to_string(),
        left: Box::new(left),
        right: Box::new(right),
    }
}

/// Lowers an expression used as a condition (Branch/Loop) into a list
/// of IR statements — for taint propagation, not just its value. If
/// the expression is a direct call (`invocation_expression`, e.g.
/// `if (IsValid(input))`), emits a `Call` rather than a buried
/// Assign+temporary.
pub fn lower_condition<'src>(source: &'src [u8], expr: Node<'src>) -> Vec<IrStmt> {
    let mut lowerer = CSharpLowerer::new(source);
    // if/while expose their condition wrapped in a
    // `parenthesized_expression` (`if (x)`) — unwrapped before testing
    // for the `invocation_expression` case, otherwise
    // `if (IsValid(input))` would never match.
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
    if unwrapped.kind() == "invocation_expression" {
        lowerer.lower_call_as_statement(unwrapped);
    } else {
        lowerer.lower_expr(Some(expr));
    }
    lowerer.output
}

/// Variant of [`lower_condition`] for a switch `case`'s synthetic
/// condition: emits `__tN := (subject == label)`.
pub fn lower_condition_switch_case<'src>(
    source: &'src [u8],
    subject: Node<'src>,
    label: Node<'src>,
) -> Vec<IrStmt> {
    let mut lowerer = CSharpLowerer::new(source);
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

/// Synthesizes `target := iterable` for a C# for-each loop
/// (`foreach (T target in iterable)`). Without this explicit
/// assignment, the taint of the iterated collection never propagates
/// to the loop variable.
pub fn lower_for_target_assign<'src>(
    source: &'src [u8],
    target: Node<'src>,
    iterable: Node<'src>,
) -> Vec<IrStmt> {
    let mut lowerer = CSharpLowerer::new(source);
    let rhs = lowerer.lower_expr(Some(iterable));
    let lhs = lowerer.lower_target(Some(target));
    lowerer.emit(IrStmt::Assign {
        lhs,
        rhs,
        lineno: lowerer.line(iterable),
    });
    lowerer.output
}

/// Lowers a list of C# statements (the content of a Basic/Finally CFG
/// node) into IR.
pub fn lower_stmts<'src>(source: &'src [u8], stmts: &[Node<'src>]) -> Vec<IrStmt> {
    let mut lowerer = CSharpLowerer::new(source);
    for &stmt in stmts {
        lowerer.lower_stmt(stmt);
    }
    lowerer.output
}

/// Lowers a single C# statement into IR (may produce several `IrStmt`s).
pub fn lower_stmt<'src>(source: &'src [u8], stmt: Node<'src>) -> Vec<IrStmt> {
    let mut lowerer = CSharpLowerer::new(source);
    lowerer.lower_stmt(stmt);
    lowerer.output
}

// ============================================================================
// Lowering a CFG node into IR — C# mirror of
// `java_lowering.rs::lower_node_to_ir`/`lower_all_nodes`, the entry
// point consumed by `worklist::analyze_generic` to instantiate
// `worklist::analyze_csharp`.
// ============================================================================

/// Lowers the statements/condition of a C# CFG node into IR.
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
            // `target := iter` (without it the iterable's taint would
            // not propagate to the loop variable).
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

/// Lowers all nodes of a C# CFG into IR, in a single pass.
pub fn lower_all_nodes<'tree>(cfg: &Cfg<'tree>, source: &[u8]) -> BTreeMap<usize, Vec<IrStmt>> {
    cfg.nodes
        .keys()
        .map(|&nid| (nid, lower_node_to_ir(cfg, nid, source)))
        .collect()
}

/// Lowers a standalone expression (a Branch/Loop node's condition)
/// into `Rhs` — consumed by `worklist::compute_dead_edges_generic`
/// (dead-edge pruning pre-pass).
pub fn lower_expr_standalone<'src>(source: &'src [u8], expr: Node<'src>) -> (Rhs, Vec<IrStmt>) {
    let mut lowerer = CSharpLowerer::new(source);
    let rhs = lowerer.lower_expr(Some(expr));
    (rhs, lowerer.output)
}

// ============================================================================
// Tests — mirrors `Audit/tests/parsers/test_csharp_to_ir.py` (same
// invariants), with density equivalent to `java_lowering.rs::tests`.
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

    fn parse_csharp(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_c_sharp::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    /// Parses a C# method body and exposes `(source, body_stmts)` to `f`.
    fn with_body_stmts<R>(method_body_src: &str, f: impl FnOnce(&str, &[Node]) -> R) -> R {
        let src = format!("class Foo {{ void t(string input, int n) {{ {method_body_src} }} }}");
        let tree = parse_csharp(&src);
        assert!(
            !tree.root_node().has_error(),
            "syntaxe C# invalide : {method_body_src:?}"
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
    fn test_implicit_type_var_declaration() {
        let ir = lower("var x = n;");
        let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        assert_eq!(*lhs, Lhs::VarLhs("x".to_string()));
        assert_eq!(*rhs, var("n"));
    }

    #[test]
    fn test_declaration_without_initializer() {
        let ir = lower("int x;");
        assert!(matches!(ir[0], IrStmt::Noop { .. }));
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
    fn test_element_access_assign() {
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
    fn test_element_access_read() {
        let ir = lower("var y = arr[i];");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(
            *rhs,
            Rhs::SubscriptRef {
                base: Box::new(var("arr")),
                key: Box::new(var("i")),
            }
        );
    }

    // ------------------------------------------------------------- operators

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
    fn test_null_coalescing_is_binop() {
        let ir = lower("var z = x ?? y;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::BinOp { op, .. } = rhs else {
            panic!("expected BinOp")
        };
        assert_eq!(op, "??");
    }

    #[test]
    fn test_comparison() {
        let ir = lower("bool b = x > 0;");
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
        let ir = lower("bool b = x > 0 && y < 10;");
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
    fn test_is_expression() {
        let ir = lower("bool chk = input is string;");
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

    #[test]
    fn test_as_expression_passthrough() {
        let ir = lower("var r = input as string;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, var("input"));
    }

    // -------------------------------- prefix/postfix unary (distinct types)

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
    fn test_prefix_negation_is_unary_not_increment() {
        let ir = lower("var y = -x;");
        let a = assigns(&ir);
        let unary = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::UnaryOp { op, .. } = rhs {
                Some(op)
            } else {
                None
            }
        });
        assert_eq!(unary.unwrap(), "-");
    }

    #[test]
    fn test_prefix_logical_not() {
        let ir = lower("bool y = !x;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::UnaryOp { op, .. } = rhs else {
            panic!("expected UnaryOp")
        };
        assert_eq!(op, "!");
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

    // --------------------------- calls — statement vs sub-expression

    #[test]
    fn test_call_as_statement() {
        let ir = lower("obj.Method(input);");
        let c = calls(&ir);
        assert_eq!(c.len(), 1);
        let IrStmt::Call { callee, args, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*callee, attr(var("obj"), "Method"));
        assert_eq!(*args, vec![var("input")]);
    }

    #[test]
    fn test_call_without_receiver() {
        let ir = lower("DoIt(input);");
        let c = calls(&ir);
        let IrStmt::Call { callee, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*callee, var("DoIt"));
    }

    #[test]
    fn test_call_as_subexpression_produces_assign_temp() {
        let ir = lower("string s = GetInput(input);");
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
        assert_eq!(**callee, var("GetInput"));
        assert_eq!(*args, vec![var("input")]);
        let IrStmt::Assign { lhs, .. } = a[a.len() - 1] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("s".to_string()));
    }

    #[test]
    fn test_object_creation() {
        let ir = lower("var o = new Foo(input);");
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
        let ir = lower("var o = new System.IO.FileStream(input);");
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
        assert_eq!(
            **callee.unwrap(),
            attr(attr(var("System"), "IO"), "FileStream")
        );
    }

    #[test]
    fn test_member_access_chained_call() {
        let ir = lower("var r = obj.Method(a, b);");
        let a = assigns(&ir);
        let call = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, args, .. } = rhs {
                Some((callee, args))
            } else {
                None
            }
        });
        let (callee, args) = call.unwrap();
        assert_eq!(**callee, attr(var("obj"), "Method"));
        assert_eq!(*args, vec![var("a"), var("b")]);
    }

    // ---------------------------------------------- conditional access (?.)

    #[test]
    fn test_conditional_access_member() {
        let ir = lower("var y = obj?.field;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, attr(var("obj"), "field"));
    }

    #[test]
    fn test_conditional_access_call() {
        let ir = lower("var z = obj?.Method();");
        let a = assigns(&ir);
        let call = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, .. } = rhs {
                Some(callee)
            } else {
                None
            }
        });
        assert_eq!(**call.unwrap(), attr(var("obj"), "Method"));
    }

    // ------------------------------------------------------------- literals

    #[test]
    fn test_string_literal_simple() {
        let ir = lower(r#"string s = "hello";"#);
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Str("hello".to_string())));
    }

    #[test]
    fn test_verbatim_string_literal_unescapes_quotes() {
        let ir = lower(r#"string s = @"a""b";"#);
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Str("a\"b".to_string())));
    }

    #[test]
    fn test_interpolated_string_propagates_taint_via_binop_chain() {
        let ir = lower(r#"string s = $"a{x}b{y}c";"#);
        let a = assigns(&ir);
        // At least two chained BinOp("+", ...) to concatenate 3
        // literal fragments and 2 interpolations.
        let plus_count = a
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    IrStmt::Assign {
                        rhs: Rhs::BinOp { op, .. },
                        ..
                    } if op == "+"
                )
            })
            .count();
        assert!(plus_count >= 2, "plus_count={plus_count}");
    }

    #[test]
    fn test_boolean_literals() {
        let ir = lower("bool a = true; bool b = false;");
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
        let ir = lower("object o = null;");
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

    // ------------------------------------------- containers / composite exprs

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
    fn test_ternary_conditional_expression() {
        let ir = lower(r#"string a = cond ? input : "safe";"#);
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
        let ir = lower("string r = (string)input;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, var("input"));
    }

    #[test]
    fn test_lambda_parenthesized_no_params() {
        let ir = lower("Action lam = () => DoIt();");
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
    fn test_lambda_implicit_single_param_no_parens() {
        let ir = lower("Action<int> f = p => DoIt(p);");
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
        assert_eq!(*names.unwrap(), vec!["p".to_string()]);
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
        let ir = lower("throw new Exception(input);");
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

    // ---------------------------------------------------------- using / lock

    #[test]
    fn test_using_resource_bare_variable_declaration() {
        with_body_stmts("using (var x = Open(input)) { Use(x); }", |src, stmts| {
            let using_stmt = stmts[0];
            let resource = using_stmt
                .named_children(&mut using_stmt.walk())
                .find(|c| c.kind() == "variable_declaration")
                .unwrap();
            let ir = lower_stmt(src.as_bytes(), resource);
            let a = assigns(&ir);
            // Two Assigns: the CallRef temporary for `Open(input)`,
            // then the declarator's actual assignment `x := __t0`.
            let IrStmt::Assign { lhs, .. } = a[a.len() - 1] else {
                panic!()
            };
            assert_eq!(*lhs, Lhs::VarLhs("x".to_string()));
        });
    }

    #[test]
    fn test_lock_lowers_lock_expr_not_body() {
        with_body_stmts("lock (obj) { DoIt(input); }", |src, stmts| {
            let ir = lower_stmt(src.as_bytes(), stmts[0]);
            let c = calls(&ir);
            assert!(!c.iter().any(|s| {
                let IrStmt::Call { callee, .. } = s else {
                    return false;
                };
                *callee == var("DoIt")
            }));
        });
    }

    // -------------------- lower_condition / lower_for_target_assign

    #[test]
    fn test_condition_call_unwraps_parenthesized() {
        with_body_stmts("if (IsValid(input)) { DoIt(); }", |src, stmts| {
            let cond = stmts[0].child_by_field_name("condition").unwrap();
            let ir = lower_condition(src.as_bytes(), cond);
            assert_eq!(ir.len(), 1);
            let IrStmt::Call { callee, .. } = &ir[0] else {
                panic!("expected Call")
            };
            assert_eq!(*callee, var("IsValid"));
        });
    }

    #[test]
    fn test_condition_comparison_keeps_temp() {
        with_body_stmts("if (x > 0) { DoIt(); }", |src, stmts| {
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
        with_body_stmts("foreach (var s in items) { Use(s); }", |src, stmts| {
            let for_stmt = stmts[0];
            let target = for_stmt.child_by_field_name("left").unwrap();
            let iterable = for_stmt.child_by_field_name("right").unwrap();
            let ir = lower_for_target_assign(src.as_bytes(), target, iterable);
            assert_eq!(ir.len(), 1);
            let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
                panic!("expected Assign")
            };
            assert_eq!(*lhs, Lhs::VarLhs("s".to_string()));
            assert_eq!(*rhs, var("items"));
        });
    }

    // ------------------------------------------------------- conservative fallback

    #[test]
    fn test_unknown_statement_type_is_noop() {
        // `goto` is not handled by `lower_stmt` (unmodeled construct,
        // cf. module doc) — Noop fallback.
        let ir = lower("goto done; done: ;");
        assert!(matches!(ir[0], IrStmt::Noop { .. }));
    }
}
