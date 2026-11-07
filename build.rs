//! Embeds the builtin rule catalog (`rules/builtin/**/*.sca`) into the
//! binary at compile time, so `sast-engine scan` never needs an explicit
//! `--rules <DIR>` — mirror of `SCA_PACKAGE_DIR / "rules" / "builtin"` on
//! the Audit side, always resolved automatically, never a CLI argument.
//! Generates `$OUT_DIR/embedded_rules.rs`, included by
//! `src/rules/embedded_rules.rs`.
//!
//! **Encrypted, not plaintext** (ticket #65): the catalog is serialized
//! into a single JSON blob, then encrypted with the "universal" key from
//! `rules_crypto.rs` (`SALT_DEMO_UNIVERSAL` derived from
//! `CATALOG_ROOT_SECRET`), and embedded via `include_bytes!` rather than
//! one `include_str!` per file — running `strings` on the compiled binary
//! no longer exposes the rule contents. Decrypted once at runtime by
//! `embedded_rules::compile_embedded_rules`.
//!
//! Also generates `$OUT_DIR/editor_release_data.rs` (ticket #85/spec
//! #82): the publisher Ed25519 public key, used by `src/rules/rule_packs.rs`
//! to verify the signature of rule update pack manifests.
//! `SAST_EDITOR_PUBLIC_KEY_HEX`
//! carries the hex value directly (not a file path) — a lone public key
//! does not justify an intermediate file. Variable unset → `None` static, same philosophy as above (no
//! possible failure for this reason). Variable set but malformed (not 64
//! hex characters) → explicit panic at compile time.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

// `decrypt_blob` is not used by `build.rs` (decryption is a runtime
// concern) — `#[allow(dead_code)]` on the whole
// module rather than duplicating the attributes already set in the
// source file itself for its own (library) context.
#[path = "src/rules/rules_crypto.rs"]
#[allow(dead_code)]
mod rules_crypto;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR absent");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR absent");

    embed_builtin_rules(&manifest_dir, &out_dir);
    generate_editor_release_data(&out_dir);
}

fn embed_builtin_rules(manifest_dir: &str, out_dir: &str) {
    let rules_dir = Path::new(manifest_dir).join("rules").join("builtin");

    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    collect_sca_files(&rules_dir, &rules_dir, &mut entries);
    entries.sort();

    println!("cargo:rerun-if-changed={}", rules_dir.display());
    for (_, abs) in &entries {
        println!("cargo:rerun-if-changed={}", abs.display());
    }

    // A single JSON blob of (relative path, content) rather than one
    // `include_str!` per file — ticket #65: reading each file ourselves
    // (instead of letting `include_str!` do it) is what allows the
    // result to be encrypted before it is embedded.
    let pairs: Vec<(String, String)> = entries
        .iter()
        .map(|(rel, abs)| {
            let content = fs::read_to_string(abs)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", abs.display()));
            (rel.clone(), content)
        })
        .collect();
    let plaintext = serde_json::to_value(&pairs).expect("JSON serialization of the catalog");

    let key = rules_crypto::derive_key(
        rules_crypto::CATALOG_ROOT_SECRET,
        rules_crypto::SALT_DEMO_UNIVERSAL,
        rules_crypto::DEFAULT_INFO,
    );
    let ciphertext = rules_crypto::encrypt_blob(&plaintext, &key);

    let blob_path = Path::new(out_dir).join("embedded_rules.bin");
    fs::write(&blob_path, &ciphertext).expect("writing the encrypted rules blob");

    let code = "pub static ENCRYPTED_RULES_BLOB: &[u8] = \
                include_bytes!(\"embedded_rules.bin\");\n";
    let dest = Path::new(out_dir).join("embedded_rules.rs");
    fs::write(&dest, code).expect("writing the embedded rule catalog");
}

/// Generates `editor_release_data.rs` — see the file header docstring
/// for the unset/valid/malformed behavior. The environment variable
/// carries the hex value directly (not a file path): a 32-byte public key needs
/// neither an intermediate file nor a dedicated JSON format.
fn generate_editor_release_data(out_dir: &str) {
    println!("cargo:rerun-if-env-changed=SAST_EDITOR_PUBLIC_KEY_HEX");

    let code = match env::var("SAST_EDITOR_PUBLIC_KEY_HEX") {
        Err(_) => {
            "pub(crate) static INJECTED_EDITOR_PUBLIC_KEY_HEX: Option<&str> = None;\n".to_string()
        }
        Ok(hex) => {
            let trimmed = hex.trim();
            let looks_valid = trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit());
            if !looks_valid {
                panic!(
                    "SAST_EDITOR_PUBLIC_KEY_HEX is invalid (expected 64 Ed25519 hex \
                     characters, found {} character(s): {trimmed:?}) — \
                     unset the environment variable for a build without injection, \
                     or fix its value.",
                    trimmed.len()
                )
            }
            format!(
                "pub(crate) static INJECTED_EDITOR_PUBLIC_KEY_HEX: Option<&str> = Some({trimmed:?});\n"
            )
        }
    };

    let dest = Path::new(out_dir).join("editor_release_data.rs");
    fs::write(&dest, code).expect("writing the generated publisher public key");
}

fn collect_sca_files(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_sca_files(root, &path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("sca") {
            let rel = path
                .strip_prefix(root)
                .expect("the file comes from root")
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
}
