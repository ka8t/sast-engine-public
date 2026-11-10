//! Where rules come from: the rules folder read at run time, with its
//! plain `.sca` files and its encrypted rule packs (ADR-0039), signed
//! update packs, the client key and the custom-rule wizard. The rule
//! sources themselves live in `rules/` at the repository root.

pub mod catalog;
pub mod client_key;
pub mod pack_format;
pub mod rule_packs;
pub mod rule_wizard;
pub mod rules_crypto;
