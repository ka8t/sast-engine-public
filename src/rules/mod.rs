//! Where rules come from: encrypted rule packs loaded at run time
//! (ADR-0037), signed update packs, and the custom-rule wizard. The rule
//! sources themselves live in `rules/` at the repository root.

pub mod catalog;
pub mod client_key;
pub mod pack_format;
pub mod rule_packs;
pub mod rule_wizard;
pub mod rules_crypto;
