//! The scan itself: discovers the files, parses the `.sca` rules, runs
//! them, and performs the taint analysis. `orchestrator` drives the
//! whole pipeline described in `docs/ARCHITECTURE.md`.

pub mod counters;
pub mod dataflow;
pub mod discovery;
pub mod engine;
pub mod orchestrator;
pub mod parser;
