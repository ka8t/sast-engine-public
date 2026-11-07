//! Everything specific to the scanned project rather than to the rules:
//! its configuration, its suppressions, its dependencies, its database
//! schema and its own test suite.

pub mod database;
pub mod dependencies;
pub mod project_config;
pub mod suppress;
pub mod testing;
