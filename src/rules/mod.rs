//! Where rules come from (ADR-0040): the catalog pack `rules.scapack`
//! next to the binary (or `--rules <PATH>`). The rule sources themselves
//! live in `rules/builtin` of the private repository.

pub mod catalog;
pub mod pack_format;
pub mod rules_crypto;
