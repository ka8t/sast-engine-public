//! Rule pack file format (ADR-0037, ticket #141): how a set of `.sca`
//! rule files travels encrypted and is opened at run time.
//!
//! Layout of a `.scapack` file:
//!
//! ```text
//! b"SCAPACK1" | header length (u32, little endian) | header (JSON) | payload [| signature]
//! ```
//!
//! - The header is clear JSON: format version, pack name, number of rule
//!   files and the fingerprint of the key that opens the pack. The engine
//!   reads it first, to pick the right key without trying them all.
//! - The payload is the JSON list of `[relative path, .sca source]`
//!   pairs, sorted by path, encrypted with ChaCha20-Poly1305. The header
//!   bytes are authenticated as associated data: changing the name, the
//!   count or the fingerprint makes decryption fail.
//! - A pack built by CodeFixture is signed (ADR-0037, ticket #144): its
//!   header says `"signed": true` and the file ends with a 64-byte
//!   Ed25519 signature of everything before it. This module only frames
//!   the signature (the signing function is passed in, verification lives
//!   in `rule_packs.rs`), so `build.rs` needs no signature library.
//!
//! Shared with `build.rs` (included there with `#[path]`), which writes
//! the pack of `rules/builtin` next to the compiled binary: this module
//! only uses `super::rules_crypto`, `serde_json`, `sha2` and `std`.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::rules_crypto;

/// File extension of a rule pack, without the dot.
pub const PACK_EXTENSION: &str = "scapack";

/// Magic bytes at the start of every pack, version included: a future
/// incompatible layout gets a new magic rather than a guess.
const MAGIC: &[u8; 8] = b"SCAPACK1";

/// Version written in the header's `format` field.
const FORMAT_VERSION: u64 = 1;

/// Length of an Ed25519 signature, appended to signed packs.
pub const SIGNATURE_LEN: usize = 64;

/// Upper bound on the clear header, so a corrupt length cannot make the
/// reader allocate or slice past a sane size.
const MAX_HEADER_LEN: usize = 64 * 1024;

/// One rule file of a pack: path relative to the catalog root (for
/// example `python/security/eval.sca`) and its `.sca` source.
pub type RuleSource = (String, String);

/// Clear header of a pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackHeader {
    /// Pack name, for messages (`builtin`, `demo`, a client name…).
    pub name: String,
    /// Fingerprint of the key that opens the pack ([`key_fingerprint`]).
    pub key_fingerprint: String,
    /// Number of rule files in the payload.
    pub rule_files: usize,
    /// The pack ends with an Ed25519 signature (official CodeFixture pack).
    pub signed: bool,
}

/// The public demo key (ADR-0037): written in the source on purpose, it
/// opens the demo pack and the development packs built by `build.rs`.
pub fn demo_key() -> [u8; 32] {
    rules_crypto::derive_key(
        rules_crypto::CATALOG_ROOT_SECRET,
        rules_crypto::SALT_DEMO_UNIVERSAL,
        rules_crypto::DEFAULT_INFO,
    )
}

/// Short public identifier of a key: the first 8 bytes of a domain
/// separated SHA-256, in hex (16 characters). It names a key in a pack
/// header, a message or a support exchange without revealing it.
pub fn key_fingerprint(key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sast-engine-key-fingerprint-v1");
    hasher.update(key);
    hasher.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Builds an unsigned pack holding `files` (sorted here by relative path,
/// so the result does not depend on the caller's order) encrypted with
/// `key`.
pub fn write_pack(name: &str, files: &[RuleSource], key: &[u8; 32]) -> Vec<u8> {
    write_pack_signed_by(name, files, key, None)
}

/// Function that signs the bytes of a pack (Ed25519, 64 bytes).
pub type PackSigner<'a> = &'a dyn Fn(&[u8]) -> [u8; SIGNATURE_LEN];

/// [`write_pack`], signed by `signer` when given: the header then says
/// `"signed": true` and the signature of all preceding bytes is appended.
pub fn write_pack_signed_by(
    name: &str,
    files: &[RuleSource],
    key: &[u8; 32],
    signer: Option<PackSigner>,
) -> Vec<u8> {
    let mut sorted: Vec<&RuleSource> = files.iter().collect();
    sorted.sort();
    let header = serde_json::json!({
        "format": FORMAT_VERSION,
        "name": name,
        "key_fingerprint": key_fingerprint(key),
        "rule_files": sorted.len(),
        "signed": signer.is_some(),
    });
    let header_bytes = serde_json::to_vec(&header).expect("JSON header");
    let payload_plain = serde_json::to_vec(&sorted).expect("JSON payload");
    let payload = rules_crypto::encrypt_bytes_with_aad(&payload_plain, &header_bytes, key);

    let mut out = Vec::with_capacity(MAGIC.len() + 4 + header_bytes.len() + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&payload);
    if let Some(sign) = signer {
        let signature = sign(&out);
        out.extend_from_slice(&signature);
    }
    out
}

/// Parts of a pack file.
struct PackParts<'a> {
    header: PackHeader,
    /// Raw header bytes: the associated data of the payload.
    header_bytes: &'a [u8],
    /// Encrypted payload.
    payload: &'a [u8],
    /// For a signed pack: the signed bytes (everything before the
    /// signature) and the signature.
    signature: Option<SignedContent<'a>>,
}

/// Splits a pack into its parts. `Err` with a short reason if the file is
/// not a pack or is truncated.
fn split_pack(bytes: &[u8]) -> Result<PackParts<'_>, String> {
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
    let (header_bytes, mut payload) = rest.split_at(header_len);
    let header: serde_json::Value = serde_json::from_slice(header_bytes)
        .map_err(|e| format!("invalid rule pack header: {e}"))?;
    let format = header.get("format").and_then(|v| v.as_u64());
    if format != Some(FORMAT_VERSION) {
        return Err(format!(
            "unsupported rule pack format {format:?}, expected {FORMAT_VERSION}"
        ));
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
    let signed = header.get("signed").and_then(|v| v.as_bool()) == Some(true);
    let parsed = PackHeader {
        name: text("name")?,
        key_fingerprint: text("key_fingerprint")?,
        rule_files,
        signed,
    };
    let mut signature = None;
    if signed {
        if payload.len() < SIGNATURE_LEN {
            return Err("truncated rule pack (signature)".to_string());
        }
        let (body, sig) = payload.split_at(payload.len() - SIGNATURE_LEN);
        payload = body;
        let signed_len = bytes.len() - SIGNATURE_LEN;
        signature = Some((
            &bytes[..signed_len],
            sig.try_into().expect("SIGNATURE_LEN bytes"),
        ));
    }
    Ok(PackParts {
        header: parsed,
        header_bytes,
        payload,
        signature,
    })
}

/// Reads only the clear header of a pack, without any key.
pub fn read_header(bytes: &[u8]) -> Result<PackHeader, String> {
    split_pack(bytes).map(|parts| parts.header)
}

/// Signed bytes of a pack and their signature.
pub type SignedContent<'a> = (&'a [u8], [u8; SIGNATURE_LEN]);

/// For a signed pack, the signed bytes and the signature to verify;
/// `None` for an unsigned pack.
pub fn signed_content(bytes: &[u8]) -> Result<Option<SignedContent<'_>>, String> {
    split_pack(bytes).map(|parts| parts.signature)
}

/// Opens a pack with `key`: its header and its rule files. `Err` if the
/// file is not a valid pack, if `key` is not the pack's key, or if any
/// byte of the header or payload was altered.
pub fn open_pack(bytes: &[u8], key: &[u8; 32]) -> Result<(PackHeader, Vec<RuleSource>), String> {
    let PackParts {
        header,
        header_bytes,
        payload,
        ..
    } = split_pack(bytes)?;
    if header.key_fingerprint != key_fingerprint(key) {
        return Err(format!(
            "rule pack needs key {}, not {}",
            header.key_fingerprint,
            key_fingerprint(key)
        ));
    }
    let plain = rules_crypto::decrypt_bytes_with_aad(payload, header_bytes, key)
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
/// `rules/builtin`, and by the tests that need the source catalog.
/// A missing `root` gives an empty list.
pub fn collect_sca_sources(root: &Path) -> Vec<RuleSource> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<RuleSource>) {
        let Ok(read_dir) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("sca") {
                let rel = path
                    .strip_prefix(root)
                    .expect("the file comes from root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let content = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
                out.push((rel, content));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
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
        let key = demo_key();
        let pack = write_pack("demo", &sample(), &key);
        let opened = open_pack(&pack, &key);
        let (header, files) = opened.expect("pack opens with its own key");
        assert_eq!(header.name, "demo");
        assert_eq!(header.rule_files, 2);
        assert_eq!(header.key_fingerprint, key_fingerprint(&key));
        let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["java/a.sca", "python/b.sca"]);
        let header_only = read_header(&pack).expect("header readable without key");
        assert_eq!(header_only, header);
    }

    #[test]
    fn test_pack_payload_is_not_readable_in_clear() {
        let pack = write_pack("demo", &sample(), &demo_key());
        let text = String::from_utf8_lossy(&pack);
        assert!(!text.contains("rule a"), "rule source must be encrypted");
    }

    #[test]
    fn test_open_pack_rejects_wrong_key_corrupt_and_truncated() {
        let key = demo_key();
        let other = [7u8; 32];
        let pack = write_pack("demo", &sample(), &key);

        let wrong_key = open_pack(&pack, &other);
        assert!(wrong_key.unwrap_err().contains("needs key"));

        let mut corrupt = pack.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        let corrupt_result = open_pack(&corrupt, &key);
        assert!(corrupt_result.unwrap_err().contains("corrupt"));

        let truncated = open_pack(&pack[..10], &key);
        assert!(truncated.unwrap_err().contains("truncated"));

        let not_a_pack = open_pack(b"rule x\nend\n", &key);
        assert!(not_a_pack.unwrap_err().contains("not a rule pack"));
    }

    /// The header is authenticated: raising the declared rule count (same
    /// length, so the layout stays valid) breaks decryption.
    #[test]
    fn test_open_pack_rejects_altered_header() {
        let key = demo_key();
        let mut bytes = write_pack("demo", &sample(), &key);
        let pos = bytes
            .windows(b"\"rule_files\":2".len())
            .position(|w| w == b"\"rule_files\":2")
            .expect("count in header");
        bytes[pos + b"\"rule_files\":".len()] = b'3';
        let result = open_pack(&bytes, &key);
        assert!(result.unwrap_err().contains("corrupt"));
    }

    /// Ticket #144: a signed pack carries the flag and a trailing
    /// signature of everything before it, and still opens with its key;
    /// an unsigned pack has no signature part.
    #[test]
    fn test_signed_pack_framing() {
        let key = demo_key();
        let signer = |bytes: &[u8]| {
            let mut sig = [0u8; SIGNATURE_LEN];
            sig[0] = bytes.len() as u8;
            sig
        };
        let signed = write_pack_signed_by("official", &sample(), &key, Some(&signer));
        let unsigned = write_pack("client", &sample(), &key);

        let header = read_header(&signed).expect("signed header");
        assert!(header.signed);
        let (message, sig) = signed_content(&signed).unwrap().expect("signature part");
        assert_eq!(message, &signed[..signed.len() - SIGNATURE_LEN]);
        assert_eq!(sig[0], message.len() as u8);
        let opened = open_pack(&signed, &key).map(|(_, files)| files.len());
        assert_eq!(opened, Ok(2));

        assert!(!read_header(&unsigned).unwrap().signed);
        assert_eq!(signed_content(&unsigned), Ok(None));
    }

    #[test]
    fn test_key_fingerprint_is_stable_short_and_key_specific() {
        let a = key_fingerprint(&[1u8; 32]);
        let b = key_fingerprint(&[2u8; 32]);
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
        let again = key_fingerprint(&[1u8; 32]);
        assert_eq!(a, again);
    }

    #[test]
    fn test_collect_sca_sources_sorted_relative_and_sca_only() {
        let root = std::env::temp_dir().join(format!("sast_pack_collect_{}", std::process::id()));
        std::fs::create_dir_all(root.join("python/security")).unwrap();
        std::fs::write(root.join("python/security/b.sca"), "b").unwrap();
        std::fs::write(root.join("a.sca"), "a").unwrap();
        std::fs::write(root.join("notes.md"), "x").unwrap();
        let files = collect_sca_sources(&root);
        std::fs::remove_dir_all(&root).ok();
        let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["a.sca", "python/security/b.sca"]);
        let missing = collect_sca_sources(Path::new("/nonexistent/sast/rules"));
        assert!(missing.is_empty());
    }
}
