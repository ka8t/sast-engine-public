//! Intermediate representation (IR) of the dataflow engine — faithful port
//! of `Audit/sca/dataflow/ir.py`. Normalized 3-address form,
//! independent of the source language (§3 of the Python spec — the
//! Rust scope remains Python-only, Decision #10, but the IR
//! itself is already designed language-neutral on the Python side).

/// Literal constant value (int, str, bool, None, float).
#[derive(Debug, Clone, PartialEq)]
pub enum ConstValue {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    None,
}

/// RHS (Right-Hand Side) — expressions whose value is read.
#[derive(Debug, Clone, PartialEq)]
pub enum Rhs {
    Const(ConstValue),
    VarRef(String),
    AttrRef {
        base: Box<Rhs>,
        attr: String,
    },
    SubscriptRef {
        base: Box<Rhs>,
        key: Box<Rhs>,
    },
    /// Call used as a value.
    CallRef {
        callee: Box<Rhs>,
        args: Vec<Rhs>,
        kwargs: Vec<(String, Rhs)>,
    },
    BinOp {
        op: String,
        left: Box<Rhs>,
        right: Box<Rhs>,
    },
    UnaryOp {
        op: String,
        operand: Box<Rhs>,
    },
    Cmp {
        op: String,
        left: Box<Rhs>,
        right: Box<Rhs>,
    },
    /// Short-circuited boolean operation: and/or.
    Bool {
        op: String,
        operands: Vec<Rhs>,
    },
    TupleRef(Vec<Rhs>),
    ListRef(Vec<Rhs>),
    DictRef(Vec<(Rhs, Rhs)>),
    SetRef(Vec<Rhs>),
    /// Lambda — opaque (the body is handled separately, out of scope here).
    LambdaRef {
        arg_names: Vec<String>,
    },
    /// Starred argument: *args or **kwargs (on the call side).
    Star {
        inner: Box<Rhs>,
        double: bool,
    },
    /// Ternary expression: `then if cond else orelse`. Kept as a
    /// distinct node (not desugared into `Bool`) so constant
    /// propagation can mark a branch as dead.
    IfExp {
        cond: Box<Rhs>,
        then: Box<Rhs>,
        orelse: Box<Rhs>,
    },
}

/// LHS (Left-Hand Side) — assignable locations.
#[derive(Debug, Clone, PartialEq)]
pub enum Lhs {
    VarLhs(String),
    AttrLhs {
        base: Box<Rhs>,
        attr: String,
    },
    SubscriptLhs {
        base: Box<Rhs>,
        key: Box<Rhs>,
    },
    /// Tuple target: `a, b = ...` (destructuring).
    TupleLhs(Vec<Lhs>),
    /// Starred target in a destructuring: `*rest = ...`.
    StarLhs(Box<Lhs>),
}

/// Statement IR.
#[derive(Debug, Clone, PartialEq)]
pub enum IrStmt {
    /// `lhs := rhs` — the fundamental dataflow statement.
    Assign {
        lhs: Lhs,
        rhs: Rhs,
        lineno: usize,
    },
    /// Call used as a statement (return value not captured).
    Call {
        callee: Rhs,
        args: Vec<Rhs>,
        kwargs: Vec<(String, Rhs)>,
        lineno: usize,
    },
    Return {
        value: Option<Rhs>,
        lineno: usize,
    },
    Raise {
        value: Option<Rhs>,
        lineno: usize,
    },
    /// Condition of a branch (if, while...) — present only
    /// in CFG Branch/Loop nodes, never in the linear flow
    /// of a Basic block.
    Branch {
        condition: Rhs,
        lineno: usize,
    },
    /// No-op (for `pass` and ignored statements).
    Noop {
        lineno: usize,
    },
}

// ============================================================================
// Canonicalization — state keys for the dataflow (spec §4.4)
// ============================================================================

/// Converts an LHS into its canonical key for the dataflow state. A
/// sub-attribute/subscript access with a non-constant key is aggregated
/// under `[*]`.
pub fn canon_lhs(lhs: &Lhs) -> String {
    match lhs {
        Lhs::VarLhs(name) => name.clone(),
        Lhs::AttrLhs { base, attr } => format!("{}.{attr}", canon_rhs(base)),
        Lhs::SubscriptLhs { base, key } => {
            format!("{}[{}]", canon_rhs(base), canon_subscript_key(key))
        }
        Lhs::TupleLhs(elements) => {
            format!(
                "({})",
                elements
                    .iter()
                    .map(canon_lhs)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        Lhs::StarLhs(inner) => format!("*{}", canon_lhs(inner)),
    }
}

/// Converts an RHS into a canonical string, used to build the
/// state keys.
pub fn canon_rhs(rhs: &Rhs) -> String {
    match rhs {
        Rhs::VarRef(name) => name.clone(),
        Rhs::AttrRef { base, attr } => format!("{}.{attr}", canon_rhs(base)),
        Rhs::SubscriptRef { base, key } => {
            format!("{}[{}]", canon_rhs(base), canon_subscript_key(key))
        }
        Rhs::Const(v) => repr_const(v),
        // For the other RHS types, no canonical key is possible
        // (they are not lvalues) — a readable representation is
        // returned instead.
        other => format!("<{}>", rhs_variant_name(other)),
    }
}

/// `pub(super)`: reused by `transfer.rs::_key_repr` (same
/// convention for the canonical representation of an indexed access key).
pub(super) fn canon_subscript_key(key: &Rhs) -> String {
    match key {
        Rhs::Const(v) => repr_const(v),
        _ => "*".to_string(),
    }
}

/// Converts a callee expression into a dotted name, for resolving
/// the specs (source/sink/sanitizer, §7.1).
pub fn canon_callee(rhs: &Rhs) -> String {
    match rhs {
        Rhs::VarRef(name) => name.clone(),
        Rhs::AttrRef { base, attr } => format!("{}.{attr}", canon_callee(base)),
        Rhs::CallRef { .. } => "<call>".to_string(),
        Rhs::SubscriptRef { base, key } => {
            format!("{}[{}]", canon_callee(base), canon_subscript_key(key))
        }
        _ => "<unknown>".to_string(),
    }
}

/// Equivalent of Python's `repr(value)` for a constant — used
/// as a canonical key (e.g. `repr(0)` = `"0"`, `repr("a")` = `"'a'"`).
fn repr_const(v: &ConstValue) -> String {
    match v {
        ConstValue::Int(i) => i.to_string(),
        ConstValue::Float(f) => f.to_string(),
        ConstValue::Str(s) => format!("'{s}'"),
        ConstValue::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        ConstValue::None => "None".to_string(),
    }
}

fn rhs_variant_name(rhs: &Rhs) -> &'static str {
    match rhs {
        Rhs::Const(_) => "Const",
        Rhs::VarRef(_) => "VarRef",
        Rhs::AttrRef { .. } => "AttrRef",
        Rhs::SubscriptRef { .. } => "SubscriptRef",
        Rhs::CallRef { .. } => "CallRef",
        Rhs::BinOp { .. } => "BinOp",
        Rhs::UnaryOp { .. } => "UnaryOp",
        Rhs::Cmp { .. } => "Cmp",
        Rhs::Bool { .. } => "Bool",
        Rhs::TupleRef(_) => "TupleRef",
        Rhs::ListRef(_) => "ListRef",
        Rhs::DictRef(_) => "DictRef",
        Rhs::SetRef(_) => "SetRef",
        Rhs::LambdaRef { .. } => "LambdaRef",
        Rhs::Star { .. } => "Star",
        Rhs::IfExp { .. } => "IfExp",
    }
}

// ============================================================================
// Readable display (debug)
// ============================================================================

pub fn pretty_rhs(rhs: &Rhs) -> String {
    match rhs {
        Rhs::Const(v) => repr_const(v),
        Rhs::VarRef(name) => name.clone(),
        Rhs::AttrRef { base, attr } => format!("{}.{attr}", pretty_rhs(base)),
        Rhs::SubscriptRef { base, key } => format!("{}[{}]", pretty_rhs(base), pretty_rhs(key)),
        Rhs::CallRef {
            callee,
            args,
            kwargs,
        } => {
            let mut parts: Vec<String> = args.iter().map(pretty_rhs).collect();
            parts.extend(kwargs.iter().map(|(n, v)| format!("{n}={}", pretty_rhs(v))));
            format!("{}({})", pretty_rhs(callee), parts.join(", "))
        }
        Rhs::BinOp { op, left, right } => {
            format!("({} {op} {})", pretty_rhs(left), pretty_rhs(right))
        }
        Rhs::UnaryOp { op, operand } => format!("({op}{})", pretty_rhs(operand)),
        Rhs::Cmp { op, left, right } => {
            format!("({} {op} {})", pretty_rhs(left), pretty_rhs(right))
        }
        Rhs::Bool { op, operands } => {
            format!(
                "({})",
                operands
                    .iter()
                    .map(pretty_rhs)
                    .collect::<Vec<_>>()
                    .join(&format!(" {op} "))
            )
        }
        Rhs::TupleRef(elements) => format!(
            "({},)",
            elements
                .iter()
                .map(pretty_rhs)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Rhs::ListRef(elements) => format!(
            "[{}]",
            elements
                .iter()
                .map(pretty_rhs)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Rhs::DictRef(items) => {
            let rendered: Vec<String> = items
                .iter()
                .map(|(k, v)| format!("{}: {}", pretty_rhs(k), pretty_rhs(v)))
                .collect();
            format!("{{{}}}", rendered.join(", "))
        }
        Rhs::SetRef(elements) => format!(
            "{{{}}}",
            elements
                .iter()
                .map(pretty_rhs)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Rhs::LambdaRef { arg_names } => format!("lambda {}: ...", arg_names.join(", ")),
        Rhs::Star { inner, double } => {
            format!("{}{}", if *double { "**" } else { "*" }, pretty_rhs(inner))
        }
        Rhs::IfExp { cond, then, orelse } => {
            format!(
                "({} if {} else {})",
                pretty_rhs(then),
                pretty_rhs(cond),
                pretty_rhs(orelse)
            )
        }
    }
}

pub fn pretty_lhs(lhs: &Lhs) -> String {
    match lhs {
        Lhs::VarLhs(name) => name.clone(),
        Lhs::AttrLhs { base, attr } => format!("{}.{attr}", pretty_rhs(base)),
        Lhs::SubscriptLhs { base, key } => format!("{}[{}]", pretty_rhs(base), pretty_rhs(key)),
        Lhs::TupleLhs(elements) => {
            format!(
                "({})",
                elements
                    .iter()
                    .map(pretty_lhs)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        Lhs::StarLhs(inner) => format!("*{}", pretty_lhs(inner)),
    }
}

pub fn pretty_stmt(stmt: &IrStmt) -> String {
    match stmt {
        IrStmt::Assign { lhs, rhs, .. } => format!("{} := {}", pretty_lhs(lhs), pretty_rhs(rhs)),
        IrStmt::Call {
            callee,
            args,
            kwargs,
            ..
        } => {
            let mut parts: Vec<String> = args.iter().map(pretty_rhs).collect();
            parts.extend(kwargs.iter().map(|(n, v)| format!("{n}={}", pretty_rhs(v))));
            format!("{}({})", pretty_rhs(callee), parts.join(", "))
        }
        IrStmt::Return { value, .. } => match value {
            Some(v) => format!("return {}", pretty_rhs(v)),
            None => "return".to_string(),
        },
        IrStmt::Raise { value, .. } => match value {
            Some(v) => format!("raise {}", pretty_rhs(v)),
            None => "raise".to_string(),
        },
        IrStmt::Branch { condition, .. } => format!("branch {}", pretty_rhs(condition)),
        IrStmt::Noop { .. } => "noop".to_string(),
    }
}

pub fn pretty_stmts(stmts: &[IrStmt]) -> String {
    stmts.iter().map(pretty_stmt).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(name: &str) -> Rhs {
        Rhs::VarRef(name.to_string())
    }

    #[test]
    fn test_canon_lhs_simple_var() {
        assert_eq!(canon_lhs(&Lhs::VarLhs("x".to_string())), "x");
    }

    #[test]
    fn test_canon_lhs_attr_chain() {
        let lhs = Lhs::AttrLhs {
            base: Box::new(Rhs::AttrRef {
                base: Box::new(var("a")),
                attr: "b".to_string(),
            }),
            attr: "c".to_string(),
        };
        assert_eq!(canon_lhs(&lhs), "a.b.c");
    }

    #[test]
    fn test_canon_lhs_subscript_const_key() {
        let lhs = Lhs::SubscriptLhs {
            base: Box::new(var("a")),
            key: Box::new(Rhs::Const(ConstValue::Int(0))),
        };
        assert_eq!(canon_lhs(&lhs), "a[0]");
    }

    #[test]
    fn test_canon_lhs_subscript_dynamic_key_is_star() {
        let lhs = Lhs::SubscriptLhs {
            base: Box::new(var("a")),
            key: Box::new(var("k")),
        };
        assert_eq!(canon_lhs(&lhs), "a[*]");
    }

    #[test]
    fn test_canon_rhs_opaque_binop() {
        let rhs = Rhs::BinOp {
            op: "+".to_string(),
            left: Box::new(var("a")),
            right: Box::new(var("b")),
        };
        assert_eq!(canon_rhs(&rhs), "<BinOp>");
    }

    #[test]
    fn test_canon_callee_dotted_name() {
        let rhs = Rhs::AttrRef {
            base: Box::new(Rhs::AttrRef {
                base: Box::new(var("subprocess")),
                attr: "run".to_string(),
            }),
            attr: "extra".to_string(),
        };
        assert_eq!(canon_callee(&rhs), "subprocess.run.extra");
    }

    #[test]
    fn test_canon_callee_call_is_call_marker() {
        let rhs = Rhs::CallRef {
            callee: Box::new(var("f")),
            args: vec![],
            kwargs: vec![],
        };
        assert_eq!(canon_callee(&rhs), "<call>");
    }

    #[test]
    fn test_pretty_rhs_call_with_args_and_kwargs() {
        let rhs = Rhs::CallRef {
            callee: Box::new(var("f")),
            args: vec![Rhs::Const(ConstValue::Int(1))],
            kwargs: vec![("x".to_string(), Rhs::Const(ConstValue::Bool(true)))],
        };
        assert_eq!(pretty_rhs(&rhs), "f(1, x=True)");
    }

    #[test]
    fn test_pretty_stmt_assign() {
        let stmt = IrStmt::Assign {
            lhs: Lhs::VarLhs("x".to_string()),
            rhs: Rhs::Const(ConstValue::Int(42)),
            lineno: 1,
        };
        assert_eq!(pretty_stmt(&stmt), "x := 42");
    }

    #[test]
    fn test_pretty_stmt_return_none() {
        let stmt = IrStmt::Return {
            value: None,
            lineno: 1,
        };
        assert_eq!(pretty_stmt(&stmt), "return");
    }

    #[test]
    fn test_pretty_ifexp() {
        let rhs = Rhs::IfExp {
            cond: Box::new(var("c")),
            then: Box::new(Rhs::Const(ConstValue::Int(1))),
            orelse: Box::new(Rhs::Const(ConstValue::Int(2))),
        };
        assert_eq!(pretty_rhs(&rhs), "(1 if c else 2)");
    }
}
