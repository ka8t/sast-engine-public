//! Everything specific to the scanned project rather than to the rules:
//! its configuration, its suppressions, its dependencies, its database
//! schema and its own test suite.

pub mod advisories;
pub mod advisory_file;
pub mod config_wizard;
pub mod database;
pub mod dependencies;
pub mod project_config;
pub mod suppress;
pub mod testing;
