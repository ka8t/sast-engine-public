//! Rule pack file format (ADR-0037, simplified by ADR-0040): how the
//! `.sca` rule files of a catalog travel as one file, `rules.scapack`,
//! and are opened at run time.
//!
//! Layout of a `.scapack` file:
//!
//! ```text
//! b"SCAPACK1" | header length (u32, little endian) | header (JSON) | payload
//! ```
//!
//! - The header is clear JSON: format version, pack name, number of rule
//!   files and the fingerprint of the key that opens the pack.
//! - The payload is the JSON list of `[relative path, .sca source]`
//!   pairs, sorted by path, encrypted with ChaCha20-Poly1305 and the
//!   public demo key. The header bytes are authenticated as associated
//!   data: changing the name, the count or the fingerprint makes
//!   decryption fail.
//! - The nonce is derived from the header and the payload (ADR-0040), not
//!   drawn at random: the same rules always give the same file, so an
//!   unchanged catalog leaves the shared repository unchanged.
//!
//! The demo key is written in the source: the encryption only keeps the
//! rules from being copied as they are, it protects nothing (ADR-0040).
//!
//! Shared with `build.rs` (included there with `#[path]`), which writes
//! the pack of `rules/builtin` next to the compiled binary: this module
//! only uses `super::rules_crypto`, `serde_json`, `sha2` and `std`.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::rules_crypto;

/// File extension of a rule pack, without the dot.
pub const PACK_EXTENSION: &str = "scapack";

/// File name of the catalog pack, next to the binary (ADR-0040).
pub const PACK_FILE_NAME: &str = "rules.scapack";

/// File name of the demo pack a private-repository build writes next to
/// the binary, beside the full one (ticket #153). The export script
/// delivers the same content as the shared repository's
/// `rules/rules.scapack`; the binary itself never reads this file.
pub const DEMO_PACK_FILE_NAME: &str = "rules-demo.scapack";

/// Name stored in the header of the demo pack.
pub const DEMO_PACK_NAME: &str = "demo";

/// Magic bytes at the start of every pack, version included: a future
/// incompatible layout gets a new magic rather than a guess.
const MAGIC: &[u8; 8] = b"SCAPACK1";

/// Version written in the header's `format` field.
const FORMAT_VERSION: u64 = 1;

/// Upper bound on the clear header, so a corrupt length cannot make the
/// reader allocate or slice past a sane size.
const MAX_HEADER_LEN: usize = 64 * 1024;

/// One rule file of a pack: path relative to the catalog root (for
/// example `python/security/eval.sca`) and its `.sca` source.
pub type RuleSource = (String, String);

/// Clear header of a pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackHeader {
    /// Pack name, for messages (`builtin`, `demo`…).
    pub name: String,
    /// Fingerprint of the key that opens the pack ([`key_fingerprint`]).
    pub key_fingerprint: String,
    /// Number of rule files in the payload.
    pub rule_files: usize,
}

/// The public demo key (ADR-0037, ADR-0040): written in the source on
/// purpose, it opens every pack.
pub fn demo_key() -> [u8; 32] {
    rules_crypto::derive_key(
        rules_crypto::CATALOG_ROOT_SECRET,
        rules_crypto::SALT_DEMO_UNIVERSAL,
        rules_crypto::DEFAULT_INFO,
    )
}

/// Short public identifier of a key: the first 8 bytes of a domain
/// separated SHA-256, in hex (16 characters). It names the key in a pack
/// header without revealing it.
pub fn key_fingerprint(key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sast-engine-key-fingerprint-v1");
    hasher.update(key);
    hasher.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Builds a pack holding `files` (sorted here by relative path, so the
/// result does not depend on the caller's order) encrypted with the demo
/// key. Deterministic: the same name and files give the same bytes.
pub fn write_pack(name: &str, files: &[RuleSource]) -> Vec<u8> {
    write_pack_with_key(name, files, &demo_key())
}

/// [`write_pack`] with another key: only the tests use it, to check that
/// a pack for an unknown key is refused.
pub fn write_pack_with_key(name: &str, files: &[RuleSource], key: &[u8; 32]) -> Vec<u8> {
    let mut sorted: Vec<&RuleSource> = files.iter().collect();
    sorted.sort();
    // Written by hand, keys in alphabetical order: `serde_json::json!`
    // orders keys by insertion or alphabetically depending on the
    // `preserve_order` feature, which differs between `build.rs` and the
    // binary (ticket #153). The bytes must not depend on it: the build's
    // `rules-demo.scapack` and `rules pack --demo` must be identical, and
    // the alphabetical order is the one already published.
    let header_bytes = format!(
        "{{\"format\":{FORMAT_VERSION},\"key_fingerprint\":{},\"name\":{},\"rule_files\":{}}}",
        serde_json::Value::from(key_fingerprint(key)),
        serde_json::Value::from(name),
        sorted.len()
    )
    .into_bytes();
    let payload_plain = serde_json::to_vec(&sorted).expect("JSON payload");
    // Content-derived nonce: the nonce changes whenever the header or any
    // rule changes, so it never repeats for two different plaintexts.
    let mut hasher = Sha256::new();
    hasher.update(b"sast-engine-pack-nonce-v1");
    hasher.update((header_bytes.len() as u64).to_le_bytes());
    hasher.update(&header_bytes);
    hasher.update(&payload_plain);
    let nonce: [u8; 12] = hasher.finalize()[..12].try_into().expect("12 bytes");
    let payload =
        rules_crypto::encrypt_bytes_with_aad_and_nonce(&payload_plain, &header_bytes, key, &nonce);

    let mut out = Vec::with_capacity(MAGIC.len() + 4 + header_bytes.len() + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&payload);
    out
}

/// Splits a pack into its header, the raw header bytes (the associated
/// data of the payload) and the encrypted payload. `Err` with a short
/// reason if the file is not a pack or is truncated.
fn split_pack(bytes: &[u8]) -> Result<(PackHeader, &[u8], &[u8]), String> {
    let rest = bytes
        .strip_prefix(MAGIC.as_slice())
        .ok_or_else(|| "not a rule pack (unknown file signature)".to_string())?;
    if rest.len() < 4 {
        return Err("truncated rule pack (no header length)".to_string());
    }
    let (len_bytes, rest) = rest.split_at(4);
    let header_len = u32::from_le_bytes(len_bytes.try_into().expect("4 bytes")) as usize;
    if header_len > MAX_HEADER_LEN || header_len > rest.len() {
        return Err("truncated rule pack (header)".to_string());
    }
    let (header_bytes, payload) = rest.split_at(header_len);
    let header: serde_json::Value = serde_json::from_slice(header_bytes)
        .map_err(|e| format!("invalid rule pack header: {e}"))?;
    let format = header.get("format").and_then(|v| v.as_u64());
    if format != Some(FORMAT_VERSION) {
        return Err(format!(
            "unsupported rule pack format {format:?}, expected {FORMAT_VERSION}"
        ));
    }
    // Packs signed under ADR-0037 end with a signature this format no
    // longer reads: refuse them by name rather than as a corrupt file.
    if header.get("signed").and_then(|v| v.as_bool()) == Some(true) {
        return Err("signed rule pack: no longer supported (ADR-0040)".to_string());
    }
    let text = |key: &str| {
        header
            .get(key)
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| format!("invalid rule pack header: missing \"{key}\""))
    };
    let rule_files = header
        .get("rule_files")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "invalid rule pack header: missing \"rule_files\"".to_string())?
        as usize;
    let parsed = PackHeader {
        name: text("name")?,
        key_fingerprint: text("key_fingerprint")?,
        rule_files,
    };
    Ok((parsed, header_bytes, payload))
}

/// Reads only the clear header of a pack, without decrypting it.
pub fn read_header(bytes: &[u8]) -> Result<PackHeader, String> {
    split_pack(bytes).map(|(header, ..)| header)
}

/// Opens a pack with the demo key: its header and its rule files. `Err`
/// if the file is not a valid pack, if it needs another key (a client
/// pack of ADR-0037), or if any byte of the header or payload was altered.
pub fn open_pack(bytes: &[u8]) -> Result<(PackHeader, Vec<RuleSource>), String> {
    let key = demo_key();
    let (header, header_bytes, payload) = split_pack(bytes)?;
    if header.key_fingerprint != key_fingerprint(&key) {
        return Err(format!(
            "rule pack needs key {}, this engine only has the demo key {} (ADR-0040)",
            header.key_fingerprint,
            key_fingerprint(&key)
        ));
    }
    let plain = rules_crypto::decrypt_bytes_with_aad(payload, header_bytes, &key)
        .ok_or_else(|| "rule pack is corrupt or was altered".to_string())?;
    let files: Vec<RuleSource> =
        serde_json::from_slice(&plain).map_err(|e| format!("invalid rule pack content: {e}"))?;
    if files.len() != header.rule_files {
        return Err("rule pack content does not match its header".to_string());
    }
    Ok((header, files))
}

/// Every `.sca` file under `root`, as `(path relative to root with `/`
/// separators, source)` pairs sorted by path. Used by `build.rs` to pack
/// `rules/builtin` and by `sast-engine rules pack`. A missing `root` gives
/// an empty list; an unreadable file is an error naming it.
pub fn collect_sca_sources(root: &Path) -> Result<Vec<RuleSource>, String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<RuleSource>) -> Result<(), String> {
        let Ok(read_dir) = std::fs::read_dir(dir) else {
            return Ok(());
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            // Like the scan walk (ticket #147): a symbolic link to a
            // folder is not followed.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                walk(root, &path, out)?;
            } else if file_type.is_file()
                && path.extension().and_then(|e| e.to_str()) == Some("sca")
            {
                let rel = path
                    .strip_prefix(root)
                    .expect("the file comes from root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                out.push((rel, content));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

/// Whether a `.sca` source is a demo rule: one of its lines is
/// `demo_fallback true` (the `requires` block, `src/scan/parser`), the
/// value compared like the parser does (trimmed, case-insensitive).
///
/// A line check rather than the parser, because `build.rs` shares this
/// module and cannot pull the parser in. A test compares this check with
/// the parser on every file of `rules/builtin`, so the two cannot drift
/// apart unnoticed (ticket #153).
pub fn is_demo_rule(source: &str) -> bool {
    source.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.next() == Some("demo_fallback")
            && words
                .next()
                .is_some_and(|value| value.trim_matches('"').eq_ignore_ascii_case("true"))
    })
}

/// The demo rules of a catalog (ticket #153): the only selection of what
/// the shared repository receives, used by `build.rs` for
/// `rules-demo.scapack` and by `sast-engine rules pack --demo` for the
/// export, so both give the same pack byte for byte.
pub fn demo_sources(files: &[RuleSource]) -> Vec<RuleSource> {
    files
        .iter()
        .filter(|(_, content)| is_demo_rule(content))
        .cloned()
        .collect()
}

/// Hex SHA-256 of a rule file's source: what `rules diff` and
/// `rules list` compare and print (ADR-0040).
pub fn source_sha256(content: &str) -> String {
    Sha256::digest(content.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Differences between two sets of rule files, by relative path
/// (ADR-0040): what `rules diff` prints.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RuleDiff {
    /// In the second set only (for `rules diff <pack> <folder>`: in the
    /// folder, missing from the pack).
    pub added: Vec<String>,
    /// In the first set only (in the pack, gone from the folder).
    pub removed: Vec<String>,
    /// In both, with a different source.
    pub modified: Vec<String>,
    /// In both, identical.
    pub unchanged: usize,
}

impl RuleDiff {
    /// Whether both sets hold exactly the same rule files.
    pub fn is_identical(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

/// Compares `before` (a pack's files) with `after` (a folder's files),
/// each path listed once in sorted order. Sources are compared by their
/// SHA-256, the value `rules list` prints.
pub fn diff_rule_sources(before: &[RuleSource], after: &[RuleSource]) -> RuleDiff {
    use std::collections::BTreeMap;
    let index = |files: &[RuleSource]| -> BTreeMap<String, String> {
        files
            .iter()
            .map(|(rel, content)| (rel.clone(), source_sha256(content)))
            .collect()
    };
    let (old, new) = (index(before), index(after));
    let mut diff = RuleDiff::default();
    for (rel, hash) in &old {
        match new.get(rel) {
            None => diff.removed.push(rel.clone()),
            Some(other) if other != hash => diff.modified.push(rel.clone()),
            Some(_) => diff.unchanged += 1,
        }
    }
    diff.added = new
        .keys()
        .filter(|rel| !old.contains_key(*rel))
        .cloned()
        .collect();
    diff
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<RuleSource> {
        vec![
            ("python/b.sca".to_string(), "rule b\nend\n".to_string()),
            ("java/a.sca".to_string(), "rule a\nend\n".to_string()),
        ]
    }

    #[test]
    fn test_pack_round_trip_sorts_files_and_keeps_header() {
        let pack = write_pack("demo", &sample());
        let (header, files) = open_pack(&pack).expect("pack opens with the demo key");
        assert_eq!(header.name, "demo");
        assert_eq!(header.rule_files, 2);
        assert_eq!(header.key_fingerprint, key_fingerprint(&demo_key()));
        let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["java/a.sca", "python/b.sca"]);
        let header_only = read_header(&pack).expect("header readable without key");
        assert_eq!(header_only, header);
    }

    #[test]
    fn test_pack_payload_is_not_readable_in_clear() {
        let pack = write_pack("demo", &sample());
        let text = String::from_utf8_lossy(&pack);
        assert!(!text.contains("rule a"), "rule source must be encrypted");
    }

    /// ADR-0040: the same rules give the same bytes, whatever the order
    /// they are passed in; one changed character changes the pack.
    #[test]
    fn test_pack_is_deterministic_and_content_dependent() {
        let mut reversed = sample();
        reversed.reverse();
        assert_eq!(write_pack("demo", &sample()), write_pack("demo", &reversed));
        let mut changed = sample();
        changed[0].1.push(' ');
        assert_ne!(write_pack("demo", &sample()), write_pack("demo", &changed));
    }

    #[test]
    fn test_open_pack_rejects_other_key_corrupt_and_truncated() {
        let pack = write_pack("demo", &sample());

        let other = write_pack_with_key("client", &sample(), &[7u8; 32]);
        assert!(open_pack(&other).unwrap_err().contains("needs key"));

        let mut corrupt = pack.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        assert!(open_pack(&corrupt).unwrap_err().contains("corrupt"));

        assert!(open_pack(&pack[..10]).unwrap_err().contains("truncated"));
        let not_a_pack = open_pack(b"rule x\nend\n");
        assert!(not_a_pack.unwrap_err().contains("not a rule pack"));
    }

    /// The header is authenticated: raising the declared rule count (same
    /// length, so the layout stays valid) breaks decryption.
    #[test]
    fn test_open_pack_rejects_altered_header() {
        let mut bytes = write_pack("demo", &sample());
        let pos = bytes
            .windows(b"\"rule_files\":2".len())
            .position(|w| w == b"\"rule_files\":2")
            .expect("count in header");
        bytes[pos + b"\"rule_files\":".len()] = b'3';
        assert!(open_pack(&bytes).unwrap_err().contains("corrupt"));
    }

    /// A pack signed under ADR-0037 is refused by name.
    #[test]
    fn test_signed_pack_is_refused_with_a_clear_reason() {
        let header =
            br#"{"format":1,"name":"x","key_fingerprint":"0","rule_files":0,"signed":true}"#;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
        bytes.extend_from_slice(header);
        assert!(read_header(&bytes).unwrap_err().contains("signed"));
    }

    /// Ticket #153: the header bytes are fixed (alphabetical keys, no
    /// space), whatever the `serde_json` features of the build.
    #[test]
    fn test_pack_header_bytes_are_fixed() {
        let pack = write_pack("de\"mo", &sample());
        let len = u32::from_le_bytes(pack[8..12].try_into().unwrap()) as usize;
        let header = std::str::from_utf8(&pack[12..12 + len]).unwrap();
        let expected = format!(
            "{{\"format\":1,\"key_fingerprint\":\"{}\",\"name\":\"de\\\"mo\",\"rule_files\":2}}",
            key_fingerprint(&demo_key())
        );
        assert_eq!(header, expected);
        assert_eq!(read_header(&pack).unwrap().name, "de\"mo");
    }

    #[test]
    fn test_demo_sources_keep_demo_fallback_true_only() {
        let files = vec![
            (
                "a.sca".to_string(),
                "requires\n    demo_fallback  true\nend\n".to_string(),
            ),
            (
                "b.sca".to_string(),
                "requires\n    demo_fallback false\nend\n".to_string(),
            ),
            ("c.sca".to_string(), "rule c\nend\n".to_string()),
            ("d.sca".to_string(), "  demo_fallback TRUE\n".to_string()),
            ("e.sca".to_string(), "# demo_fallback true\n".to_string()),
        ];
        let paths: Vec<String> = demo_sources(&files).into_iter().map(|(p, _)| p).collect();
        assert_eq!(paths, ["a.sca", "d.sca"]);
    }

    #[test]
    fn test_key_fingerprint_is_stable_short_and_key_specific() {
        let a = key_fingerprint(&[1u8; 32]);
        let b = key_fingerprint(&[2u8; 32]);
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
        assert_eq!(a, key_fingerprint(&[1u8; 32]));
    }

    #[test]
    fn test_collect_sca_sources_sorted_relative_and_sca_only() {
        let root = std::env::temp_dir().join(format!("sast_pack_collect_{}", std::process::id()));
        std::fs::create_dir_all(root.join("python/security")).unwrap();
        std::fs::write(root.join("python/security/b.sca"), "b").unwrap();
        std::fs::write(root.join("a.sca"), "a").unwrap();
        std::fs::write(root.join("notes.md"), "x").unwrap();
        let files = collect_sca_sources(&root).unwrap();
        std::fs::remove_dir_all(&root).ok();
        let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["a.sca", "python/security/b.sca"]);
        let missing = collect_sca_sources(Path::new("/nonexistent/sast/rules")).unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn test_diff_rule_sources_added_removed_modified() {
        let before = vec![
            ("a.sca".to_string(), "A".to_string()),
            ("b.sca".to_string(), "B".to_string()),
            ("c.sca".to_string(), "C".to_string()),
        ];
        let after = vec![
            ("a.sca".to_string(), "A".to_string()),
            ("b.sca".to_string(), "B2".to_string()),
            ("d.sca".to_string(), "D".to_string()),
        ];
        let diff = diff_rule_sources(&before, &after);
        assert_eq!(diff.added, ["d.sca"]);
        assert_eq!(diff.removed, ["c.sca"]);
        assert_eq!(diff.modified, ["b.sca"]);
        assert_eq!(diff.unchanged, 1);
        assert!(!diff.is_identical());
        assert!(diff_rule_sources(&before, &before).is_identical());
    }

    #[test]
    fn test_source_sha256_is_hex_of_the_source() {
        assert_eq!(
            source_sha256(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
