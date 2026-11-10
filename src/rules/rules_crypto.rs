//! Encryption of embedded rules (Step 4.1, decision of 2026-08-24).
//! Port of `Audit/sca/encryption.py`, with a deliberate architecture
//! change already decided in the plan: `chacha20poly1305`
//! (RustCrypto, pure Rust) replaces the hand-rolled HMAC-SHA256
//! counter-mode + Encrypt-then-MAC on the Python side — motivated
//! there solely by avoiding the `cryptography` dependency
//! (FFI/OpenSSL, -16 MB on the Nuitka binary), a constraint that
//! doesn't apply in Rust: less hand-written crypto code = less risk.
//!
//! **Accepted consequence**: blobs generated on the Rust side are NOT
//! bit-for-bit compatible with those from the current Python client
//! (different format: Poly1305 authenticates the whole AEAD in one
//! pass, no separate 32-byte HMAC tag) — a new, separate trust
//! lineage, not an in-place replacement of the existing Python fleet.
//!
//! `derive_key` (HKDF-SHA256, RFC 5869) stays **algorithm-identical**
//! to Python — verified empirically byte-for-byte against the
//! in-house Python implementation. Built directly on `sha2` (already
//! a dependency) without a dedicated `hkdf` crate: the available
//! `hkdf` crate depends on an older `digest`/`hmac` ecosystem,
//! incompatible with the `sha2 0.11` already pinned for
//! `ed25519-dalek` — HMAC-SHA256 and HKDF-extract/expand are only a
//! few lines each anyway (RFC 2104/5869, the same choice Python made
//! by reimplementing them from the stdlib rather than adding a
//! dependency), ported here identically to `derive_key` on the Python
//! side rather than forcing a fragile version resolution.
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};

const HMAC_BLOCK_SIZE: usize = 64;

/// HMAC-SHA256 (RFC 2104), direct implementation — same algorithm as
/// `hmac.new(key, msg, hashlib.sha256).digest()` on the Python side.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; HMAC_BLOCK_SIZE];
    if key.len() > HMAC_BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; HMAC_BLOCK_SIZE];
    let mut opad = [0x5cu8; HMAC_BLOCK_SIZE];
    for i in 0..HMAC_BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

/// HKDF salt of the embedded catalog — key derived from a shared root
/// secret, identical across every binary. Encryption only prevents
/// trivial extraction via `strings`.
pub const SALT_DEMO_UNIVERSAL: &[u8] = b"sast_engine_demo_universal_v1";

/// Root secret for the "universal" key of the embedded rule catalog
/// (ticket #65) — fixed, identical in every build of the binary.
///
/// Since ADR-0037 (ticket #141) this is the **public demo key** on
/// purpose: it opens the demo pack and the packs built from
/// `rules/builtin` for development. The source is public, so it protects
/// nothing; what is sold travels in packs encrypted with a per-client key.
///
/// **The threshold aimed for is precise, don't overestimate it**: this
/// secret (and `SALT_DEMO_UNIVERSAL`/`DEFAULT_INFO` below) must be
/// present in plaintext in the binary for runtime decryption to work
/// without a network call — a `strings` pass finds them just as
/// easily as it used to find the catalog before this ticket. What
/// changes: the catalog is no longer a list of `.sca` files copyable
/// as-is, one now has to write (or obtain) an HKDF+ChaCha20-Poly1305
/// decryption script to reconstitute it — a real obstacle against
/// *trivial* extraction (`strings | grep`), not against a motivated
/// attacker willing to spend a few dozen minutes. Never present this
/// mechanism as stronger protection than that in a
/// commercial/support context.
pub(crate) const CATALOG_ROOT_SECRET: &[u8] = b"sast-engine-embedded-rules-catalog-root-v1";

/// HKDF `info` parameter (RFC 5869) — inherited as-is from Python
/// (`derive_key` there literally references the AEAD algorithm used
/// on the Python side, AES-256-GCM; Rust uses ChaCha20-Poly1305, cf.
/// the file-level doc above, but the `info` value itself only needs
/// to be a stable identifier for derivation, not an accurate
/// description of the algorithm actually used on the Rust side).
/// `pub(crate)` (not private) since ticket #65: also called from
/// `embedded_rules.rs`, a different module, to derive the same key on
/// the runtime decryption side as the one used on the `build.rs` side
/// at encryption time.
pub(crate) const DEFAULT_INFO: &[u8] = b"aes-256-gcm";

/// Derives a 32-byte key via HKDF-SHA256 (RFC 5869) — a line-by-line
/// mirror of `derive_key` on the Python side (extract then expand,
/// hand-implemented on top of `hmac_sha256`). Length fixed at 32
/// bytes (like Python's default): a single expand iteration always
/// suffices (`n = ceil(32/32) = 1`), no need for the RFC's general
/// multi-block loop.
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(salt, ikm);
    let mut msg = Vec::with_capacity(info.len() + 1);
    msg.extend_from_slice(info);
    msg.push(1u8);
    hmac_sha256(&prk, &msg)
}

/// `derive_key` with Python's default parameters
/// (`salt=b"sca_builtin_rules_v1"`, `info=b"aes-256-gcm"`) — used only
/// for cross-checking HKDF compatibility in tests, not in production
/// on the Rust side (which uses
/// `SALT_DEMO_UNIVERSAL`/`SALT_DEMO_UNIVERSAL`, a new lineage).
#[cfg(test)]
fn derive_key_python_defaults(ikm: &[u8]) -> [u8; 32] {
    derive_key(ikm, b"sca_builtin_rules_v1", DEFAULT_INFO)
}

/// Encrypts `data` (canonical JSON) into a ChaCha20-Poly1305
/// authenticated blob. Format: nonce (12 bytes) + ciphertext (the
/// Poly1305 tag, 16 bytes, is already appended at the end by the
/// crate).
pub fn encrypt_blob(data: &serde_json::Value, key: &[u8; 32]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let plaintext = serde_json::to_vec(data).expect("valeur JSON sérialisable");
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("chiffrement ChaCha20-Poly1305 (n'échoue jamais en pratique)");
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypts a blob produced by `encrypt_blob`. `None` if the blob is
/// too short, the key is wrong, or the content is corrupted/non-JSON
/// (Poly1305 authentication rejects any tampering before
/// deserialization is even attempted).
pub fn decrypt_blob(blob: &[u8], key: &[u8; 32]) -> Option<serde_json::Value> {
    if blob.len() < 12 + 16 {
        return None;
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

/// Encrypts raw bytes with ChaCha20-Poly1305, authenticating `aad`
/// (associated data, not encrypted) along with them — used by rule packs
/// (ADR-0037) so that their clear header cannot be altered without the
/// decryption failing. Same layout as [`encrypt_blob`]: nonce (12 bytes)
/// then ciphertext with its 16-byte tag.
pub fn encrypt_bytes_with_aad(plaintext: &[u8], aad: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use chacha20poly1305::aead::Payload;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("chiffrement ChaCha20-Poly1305 (n'échoue jamais en pratique)");
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Reverse of [`encrypt_bytes_with_aad`]. `None` if the blob is too
/// short, the key is wrong, or the blob or `aad` was altered.
pub fn decrypt_bytes_with_aad(blob: &[u8], aad: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::Payload;
    if blob.len() < 12 + 16 {
        return None;
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_derive_key_deterministic() {
        let k1 = derive_key(b"secret", b"salt", b"info");
        let k2 = derive_key(b"secret", b"salt", b"info");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_key_differs_by_salt() {
        let k1 = derive_key(b"secret", SALT_DEMO_UNIVERSAL, DEFAULT_INFO);
        let k2 = derive_key(b"secret", b"another_salt", DEFAULT_INFO);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_key_hkdf_matches_python_reference_values() {
        // Reference values computed with the EXACT in-house HKDF-SHA256
        // implementation of sca/encryption.py::derive_key (pure stdlib
        // hmac/hashlib, no third-party lib):
        //   python3 -c "
        //   import hashlib, hmac
        //   def derive_key(ikm, salt=b'sca_builtin_rules_v1', info=b'aes-256-gcm', length=32):
        //       prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        //       n = (length + 31) // 32
        //       okm = b''; t = b''
        //       for i in range(1, n + 1):
        //           t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        //           okm += t
        //       return okm[:length]
        //   print(derive_key(b'my-secret-key-material').hex())
        //   "
        let key = derive_key_python_defaults(b"my-secret-key-material");
        let hex = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex,
            "0f1b9bb097089df79a783b8e8a9bc4e39d1c1506bca5267efc02ed0ba6ce60ab"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = derive_key(b"my-secret", SALT_DEMO_UNIVERSAL, DEFAULT_INFO);
        let data = json!({"rules": [{"id": "eval_usage"}], "count": 703});
        let blob = encrypt_blob(&data, &key);
        let decrypted =
            decrypt_blob(&blob, &key).expect("déchiffrement doit réussir avec la bonne clé");
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_decrypt_fails_with_wrong_key() {
        let key1 = derive_key(b"key-one", SALT_DEMO_UNIVERSAL, DEFAULT_INFO);
        let key2 = derive_key(b"key-two", SALT_DEMO_UNIVERSAL, DEFAULT_INFO);
        let data = json!({"x": 1});
        let blob = encrypt_blob(&data, &key1);
        assert!(
            decrypt_blob(&blob, &key2).is_none(),
            "mauvaise clé -> échec d'authentification Poly1305"
        );
    }

    #[test]
    fn test_decrypt_fails_on_corrupted_blob() {
        let key = derive_key(b"key", SALT_DEMO_UNIVERSAL, DEFAULT_INFO);
        let data = json!({"x": 1});
        let mut blob = encrypt_blob(&data, &key);
        let last = blob.len() - 1;
        blob[last] ^= 0xFF; // corrupts the last byte (Poly1305 tag)
        assert!(decrypt_blob(&blob, &key).is_none());
    }

    #[test]
    fn test_decrypt_fails_on_too_short_blob() {
        let key = derive_key(b"key", SALT_DEMO_UNIVERSAL, DEFAULT_INFO);
        assert!(decrypt_blob(&[0u8; 10], &key).is_none());
        assert!(decrypt_blob(&[], &key).is_none());
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext_each_time() {
        // Random nonce on each call -> same plaintext, different ciphertext.
        let key = derive_key(b"key", SALT_DEMO_UNIVERSAL, DEFAULT_INFO);
        let data = json!({"x": 1});
        let blob1 = encrypt_blob(&data, &key);
        let blob2 = encrypt_blob(&data, &key);
        assert_ne!(
            blob1, blob2,
            "nonce aléatoire -> blobs distincts pour le même plaintext"
        );
    }
}
