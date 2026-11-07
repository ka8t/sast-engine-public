//! Where rules come from: the encrypted catalog embedded in the binary,
//! signed update packs, and the custom-rule wizard. The rule files
//! themselves live in `rules/` at the repository root.

pub mod embedded_rules;
pub mod rule_packs;
pub mod rule_wizard;
pub mod rules_crypto;
