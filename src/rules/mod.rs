//! Where rules come from (ADR-0040): the catalog pack `rules.scapack`
//! next to the binary (or `--rules <PATH>`, a pack or a folder of `.sca`
//! files), the custom rules folder, and the custom-rule wizard. The rule
//! sources themselves live in `rules/builtin` of the private repository.

pub mod catalog;
pub mod pack_format;
pub mod rule_wizard;
pub mod rules_crypto;
