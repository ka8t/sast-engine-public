//! Library crate of `sast-engine`: everything except the command line,
//! which lives in `main.rs`. One module per stage of the product:
//!
//! - [`scan`]: finds the files, runs the rules and the taint analysis.
//! - [`rules`]: the catalog pack next to the binary, plain rule folders
//!   and custom rules.
//! - [`report`]: turns findings into HTML, SARIF, SBOM and JSON output.
//! - [`project`]: what belongs to the scanned project (configuration,
//!   suppressions, dependencies, database schema, its test suite).
//! - [`i18n`]: translations, shared by the CLI and the reports.

pub mod build_version;
pub mod i18n;
pub mod project;
pub mod report;
pub mod rules;
pub mod scan;

/// Version of this build, `0.1.0+415.588dc34` (ticket #149): the
/// `Cargo.toml` version, commit count and short hash, `-dirty` for a tree
/// with uncommitted changes, `+unknown` without git. Computed by
/// `build.rs` (`build_version::format_build_version`). Shown by
/// `--version`, first on every scan, and in every report and export.
pub const BUILD_VERSION: &str = env!("SAST_BUILD_VERSION");
