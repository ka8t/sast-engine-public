//! Library crate of `sast-engine`: everything except the command line,
//! which lives in `main.rs`. One module per stage of the product:
//!
//! - [`scan`]: finds the files, runs the rules and the taint analysis.
//! - [`rules`]: the embedded rule catalog, rule packs and custom rules.
//! - [`report`]: turns findings into HTML, SARIF, SBOM and JSON output.
//! - [`project`]: what belongs to the scanned project (configuration,
//!   suppressions, dependencies, database schema, its test suite).
//! - [`i18n`]: translations, shared by the CLI and the reports.

pub mod i18n;
pub mod project;
pub mod report;
pub mod rules;
pub mod scan;
