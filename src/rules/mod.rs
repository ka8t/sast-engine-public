//! Where rules come from: the plain `.sca` catalog read at run time, file
//! by file, for the target languages of the scan (ADR-0038), and the
//! custom-rule wizard. The rule sources themselves live in `rules/` at
//! the repository root.

pub mod catalog;
pub mod rule_wizard;
