//! Dataflow engine (taint analysis, Step 3.3). Scope: Python + Java (Decision #10, extended
//! on 2026-08-25).
//!
//! Built brick by brick, like the DSL parser (Step 2): the lattice
//! (`lattice`) first — the most self-contained and best-specified
//! piece (§1) — then the CFG, the worklist, the transfer functions,
//! the function summaries and the call graph. These layers are
//! **language-neutral** (lattice/ir/const_eval/worklist/transfer core);
//! only the CFG, the AST→IR lowering, the summaries and the call
//! graph are CST-specific — `cfg`/`lowering`/`summary`/
//! `call_graph` carry the Python front-end, `java_cfg` (and the
//! upcoming Java equivalents) the Java front-end, both reusing
//! the same `Cfg`/`NodeKind`/`EdgeLabel` structures from `cfg.rs`.
#![allow(dead_code)]

pub mod call_graph;
pub mod cfg;
pub mod const_eval;
pub mod csharp_cfg;
pub mod csharp_lowering;
pub mod csharp_summary;
pub mod csharp_taint_scan;
pub mod ir;
pub mod java_call_graph;
pub mod java_cfg;
pub mod java_lowering;
pub mod java_module_registry;
pub mod java_summary;
pub mod java_taint_scan;
pub mod js_call_graph;
pub mod js_cfg;
pub mod js_lowering;
pub mod js_module_registry;
pub mod js_summary;
pub mod js_taint_scan;
pub mod lattice;
pub mod lowering;
pub mod php_call_graph;
pub mod php_cfg;
pub mod php_lowering;
pub mod php_module_registry;
pub mod php_summary;
pub mod php_taint_scan;
pub mod rule_loader;
pub mod summary;
pub mod taint_scan;
pub mod transfer;
pub mod worklist;
