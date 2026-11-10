//! Client key file (ADR-0037, ticket #142): the per-client key that
//! opens the rule packs CodeFixture builds for that client, and later
//! encrypts the client's own rules (ticket #143).
//!
//! The file is `sast-engine.key`, small JSON written by `tools/sast-keys`:
//!
//! ```json
//! {"format": 1, "client": "Acme", "key": "<64 hexadecimal characters>"}
//! ```
//!
//! Where the engine takes the key from, first match wins:
//!
//! 1. `--key-file <path>`;
//! 2. the `SAST_ENGINE_KEY` environment variable, holding either the key
//!    file content or just the 64 hexadecimal characters — the form for
//!    CI secrets and for a `.env` loaded by the client's own tools;
//! 3. `sast-engine.key` next to the executable.
//!
//! The project being scanned is deliberately not searched: a key file
//! there could end up committed to the client's repository. The key
//! itself never appears in a message, a log or a report: errors name the
//! source and the problem only, `Debug` hides the value, and the key is
//! shown to people through its fingerprint (`pack_format::key_fingerprint`).

use std::fmt;
use std::path::{Path, PathBuf};

use super::pack_format;

/// File name of the client key, next to the executable.
pub const KEY_FILE_NAME: &str = "sast-engine.key";

/// Environment variable that can hold the client key.
pub const KEY_ENV_VAR: &str = "SAST_ENGINE_KEY";

/// Version of the key file layout.
const KEY_FILE_FORMAT: u64 = 1;

/// A client key read from a key file.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientKey {
    /// Client name, for messages (`Acme`). Empty when the key was given
    /// as bare hexadecimal in `SAST_ENGINE_KEY`.
    pub client: String,
    /// The 32-byte key. Never print it: use [`ClientKey::fingerprint`].
    pub key: [u8; 32],
}

impl fmt::Debug for ClientKey {
    /// Hides the key: a `{:?}` in a log or a test failure must not leak it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientKey")
            .field("client", &self.client)
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl ClientKey {
    /// Public fingerprint of the key (16 hex characters).
    pub fn fingerprint(&self) -> String {
        pack_format::key_fingerprint(&self.key)
    }

    /// Key file content for this key — what `tools/sast-keys` hands to the
    /// client, and what the tests write.
    pub fn to_key_file(&self) -> String {
        let hex: String = self.key.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "{}\n",
            serde_json::json!({"format": KEY_FILE_FORMAT, "client": self.client, "key": hex})
        )
    }
}

/// Parses key file content. Errors describe the problem without ever
/// quoting the content (it may hold the key).
pub fn parse_key_file(text: &str) -> Result<ClientKey, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "not a key file (invalid JSON)".to_string())?;
    if value.get("format").and_then(|v| v.as_u64()) != Some(KEY_FILE_FORMAT) {
        return Err(format!(
            "unsupported key file format, expected {KEY_FILE_FORMAT}"
        ));
    }
    let client = value
        .get("client")
        .and_then(|v| v.as_str())
        .filter(|c| !c.trim().is_empty())
        .ok_or_else(|| "missing \"client\"".to_string())?
        .to_string();
    let key = value
        .get("key")
        .and_then(|v| v.as_str())
        .and_then(decode_key_hex)
        .ok_or_else(|| "\"key\" must be 64 hexadecimal characters".to_string())?;
    Ok(ClientKey { client, key })
}

/// Reads and parses a key file. The error names the file, never its
/// content.
pub fn read_key_file(path: &Path) -> Result<ClientKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("unreadable ({e})"))?;
    parse_key_file(&text)
}

/// Parses the value of `SAST_ENGINE_KEY`: the key file content (JSON),
/// or only the 64 hexadecimal characters of the key (no client name).
pub fn parse_env_value(text: &str) -> Result<ClientKey, String> {
    let text = text.trim();
    if text.starts_with('{') {
        return parse_key_file(text);
    }
    decode_key_hex(text)
        .map(|key| ClientKey {
            client: String::new(),
            key,
        })
        .ok_or_else(|| {
            format!("{KEY_ENV_VAR} must hold 64 hexadecimal characters or a key file content")
        })
}

/// Where a client key was found, for messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// A key file (`--key-file` or `sast-engine.key` next to the executable).
    File(PathBuf),
    /// The `SAST_ENGINE_KEY` environment variable.
    EnvVar,
}

impl fmt::Display for KeySource {
    /// The file path, or the variable name: what a message can show.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySource::File(path) => write!(f, "{}", path.display()),
            KeySource::EnvVar => write!(f, "{KEY_ENV_VAR}"),
        }
    }
}

/// Finds and reads the client key: `explicit` (`--key-file`) even if the
/// file is missing (the read then reports it), else `env_value` (the
/// content of `SAST_ENGINE_KEY`, ignored when blank), else
/// `sast-engine.key` in `exe_dir` when it exists. `None` when there is no
/// client key: only the demo key is available. The `Err` names the
/// problem, never the key.
pub fn load_client_key(
    explicit: Option<PathBuf>,
    env_value: Option<&str>,
    exe_dir: Option<&Path>,
) -> Option<(KeySource, Result<ClientKey, String>)> {
    if let Some(path) = explicit {
        let key = read_key_file(&path);
        return Some((KeySource::File(path), key));
    }
    if let Some(value) = env_value.filter(|v| !v.trim().is_empty()) {
        return Some((KeySource::EnvVar, parse_env_value(value)));
    }
    let path = exe_dir?.join(KEY_FILE_NAME);
    if !path.is_file() {
        return None;
    }
    let key = read_key_file(&path);
    Some((KeySource::File(path), key))
}

/// Decodes exactly 64 hex characters into 32 bytes.
fn decode_key_hex(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    bytes?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_a() -> ClientKey {
        ClientKey {
            client: "Acme".to_string(),
            key: [0xA1; 32],
        }
    }

    #[test]
    fn test_key_file_round_trip() {
        let text = key_a().to_key_file();
        let parsed = parse_key_file(&text);
        assert_eq!(parsed, Ok(key_a()));
    }

    /// Ticket #142: the key value never appears in an error or in Debug.
    #[test]
    fn test_errors_and_debug_never_show_the_key() {
        let hex = "a1".repeat(32);
        let debug = format!("{:?}", key_a());
        assert!(!debug.contains(&hex), "{debug}");
        assert!(debug.contains(&key_a().fingerprint()));

        let bad_json = format!("{{\"format\": 1, \"client\": \"Acme\", \"key\": \"{hex}\"");
        let short = format!(
            "{{\"format\": 1, \"client\": \"Acme\", \"key\": \"{}\"}}",
            &hex[..60]
        );
        let no_client = format!("{{\"format\": 1, \"key\": \"{hex}\"}}");
        let wrong_format = format!("{{\"format\": 2, \"client\": \"A\", \"key\": \"{hex}\"}}");
        for text in [bad_json, short, no_client, wrong_format] {
            let err = parse_key_file(&text).unwrap_err();
            assert!(!err.contains(&hex[..16]), "{err}");
        }
    }

    #[test]
    fn test_parse_key_file_reports_each_problem() {
        let hex = "0f".repeat(32);
        let cases = [
            ("not json", "invalid JSON"),
            ("{\"format\": 2}", "unsupported key file format"),
            ("{\"format\": 1, \"key\": \"00\"}", "missing \"client\""),
            ("{\"format\": 1, \"client\": \" \"}", "missing \"client\""),
            (
                "{\"format\": 1, \"client\": \"A\", \"key\": \"zz\"}",
                "64 hexadecimal",
            ),
        ];
        for (text, expected) in cases {
            let err = parse_key_file(text).unwrap_err();
            assert!(err.contains(expected), "{text} -> {err}");
        }
        let upper = format!(
            "{{\"format\": 1, \"client\": \"A\", \"key\": \"{}\"}}",
            hex.to_uppercase()
        );
        let parsed = parse_key_file(&upper);
        assert_eq!(parsed.map(|k| k.key), Ok([0x0f; 32]));
    }

    /// Ticket #142: `--key-file` wins over `SAST_ENGINE_KEY`, which wins
    /// over `sast-engine.key` next to the executable; a blank variable
    /// counts as unset; nothing found means demo key only.
    #[test]
    fn test_load_client_key_precedence() {
        let base = std::env::temp_dir().join(format!("sast_key_load_{}", std::process::id()));
        let exe_dir = base.join("bin");
        std::fs::create_dir_all(&exe_dir).unwrap();
        let file_key = key_a();
        let env_hex = "b2".repeat(32);

        let none = load_client_key(None, Some("  "), Some(&exe_dir));
        std::fs::write(exe_dir.join(KEY_FILE_NAME), file_key.to_key_file()).unwrap();
        let next_to_exe = load_client_key(None, None, Some(&exe_dir));
        let from_env = load_client_key(None, Some(&env_hex), Some(&exe_dir));
        let explicit = load_client_key(
            Some(exe_dir.join(KEY_FILE_NAME)),
            Some(&env_hex),
            Some(&exe_dir),
        );
        let missing = load_client_key(Some(base.join("missing.key")), None, None);
        std::fs::remove_dir_all(&base).ok();

        assert_eq!(none, None);
        let exe_path = exe_dir.join(KEY_FILE_NAME);
        assert_eq!(
            next_to_exe,
            Some((KeySource::File(exe_path.clone()), Ok(file_key.clone())))
        );
        let env_key = ClientKey {
            client: String::new(),
            key: [0xB2; 32],
        };
        assert_eq!(from_env, Some((KeySource::EnvVar, Ok(env_key))));
        assert_eq!(explicit, Some((KeySource::File(exe_path), Ok(file_key))));
        let (source, result) = missing.expect("explicit path is always used");
        assert_eq!(source, KeySource::File(base.join("missing.key")));
        assert!(result.unwrap_err().contains("unreadable"));
    }

    /// The variable takes the bare key or the key file content; a bad
    /// value is reported without quoting it.
    #[test]
    fn test_parse_env_value_forms() {
        let json = parse_env_value(&key_a().to_key_file());
        assert_eq!(json, Ok(key_a()));
        let bare = parse_env_value(&format!(" {} \n", "a1".repeat(32)));
        assert_eq!(
            bare.map(|k| (k.client, k.key)),
            Ok((String::new(), [0xA1; 32]))
        );
        let bad = parse_env_value("a1a1-not-a-key");
        let err = bad.unwrap_err();
        assert!(err.contains(KEY_ENV_VAR) && !err.contains("a1a1"), "{err}");
        assert_eq!(KeySource::EnvVar.to_string(), KEY_ENV_VAR);
    }
}
