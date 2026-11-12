//! The advisory database file, `advisories.sadb` (ADR-0042, ticket #177).
//!
//! `tools/sast-advisories` writes it, the engine reads it during
//! `scan --with-deps` (`advisories.rs`). Both go through this module, so
//! the layout is written down once. The engine side only reads; the
//! writer lives here because it is the same layout, and it opens no
//! network connection.
//!
//! Layout, all integers little-endian:
//!
//! ```text
//! b"SADB"            magic bytes
//! u32                container format (FORMAT_VERSION)
//! u32                header length in bytes
//! header             JSON, UTF-8: Header below
//! body               per ecosystem, one gzip member, in header order
//! ```
//!
//! The header is clear JSON, readable without decompressing anything:
//! format, creation date, source, and per ecosystem its advisory count,
//! the newest OSV `modified` date and where its gzip member sits in the
//! body. Each member holds the JSON of one ecosystem as
//! `sast-advisories` writes it (`tools/sast-advisories/src/format.rs`);
//! this module does not look inside.
//!
//! **Deterministic**: the same ecosystems give the same bytes. The
//! creation date is the newest OSV `modified` date of the data, not the
//! time of writing, and every gzip member has a zero time and no file
//! name. Not encrypted: the data is public.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};

/// First bytes of every database file.
pub const MAGIC: &[u8; 4] = b"SADB";

/// Container layout version. A reader refuses any other value rather
/// than misreading the file.
pub const FORMAT_VERSION: u32 = 1;

/// File name next to the executables: `sast-advisories update` writes
/// it there, `scan --with-deps` reads it there.
pub const FILE_NAME: &str = "advisories.sadb";

/// Longest header accepted when reading, against a corrupted length.
const MAX_HEADER_BYTES: u32 = 1 << 20;

/// The clear JSON header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub format: u32,
    /// Newest OSV `modified` date across the ecosystems (RFC 3339): the
    /// date of the data, so that unchanged data keeps the same bytes.
    pub created: String,
    /// Where the advisories come from.
    pub source: String,
    /// In body order.
    pub ecosystems: Vec<EcosystemEntry>,
}

/// One ecosystem of the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemEntry {
    /// OSV ecosystem name (`PyPI`, `npm`, `Maven`, `NuGet`, `Packagist`).
    pub name: String,
    /// Number of advisories in its member.
    pub advisories: usize,
    /// Newest OSV `modified` date of this ecosystem.
    pub last_modified: String,
    /// Offset of its gzip member from the start of the body.
    pub offset: u64,
    /// Length of its gzip member.
    pub length: u64,
}

/// One ecosystem to write: its name, counts and JSON payload.
#[derive(Debug, Clone)]
pub struct EcosystemPayload {
    pub name: String,
    pub advisories: usize,
    pub last_modified: String,
    /// The JSON of the ecosystem, uncompressed.
    pub json: Vec<u8>,
}

/// A database read from disk: its header and its compressed members.
#[derive(Debug, Clone)]
pub struct DatabaseFile {
    pub path: PathBuf,
    pub header: Header,
    body: Vec<u8>,
}

impl DatabaseFile {
    /// The uncompressed JSON of `ecosystem`, `None` when the file does
    /// not hold it.
    pub fn ecosystem_json(&self, ecosystem: &str) -> Option<Result<Vec<u8>, String>> {
        let entry = self.header.ecosystems.iter().find(|e| e.name == ecosystem)?;
        let start = entry.offset as usize;
        let end = start.checked_add(entry.length as usize)?;
        let Some(member) = self.body.get(start..end) else {
            return Some(Err(format!(
                "{}: {ecosystem} lies outside the file",
                self.path.display()
            )));
        };
        let mut out = Vec::new();
        Some(
            GzDecoder::new(member)
                .read_to_end(&mut out)
                .map(|_| out)
                .map_err(|e| format!("{}: {ecosystem}: {e}", self.path.display())),
        )
    }
}

/// The bytes of a database holding `ecosystems`, sorted by name so that
/// the order they are given in does not change the file.
pub fn encode(source: &str, ecosystems: &[EcosystemPayload]) -> std::io::Result<Vec<u8>> {
    let mut sorted: Vec<&EcosystemPayload> = ecosystems.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut body = Vec::new();
    let mut entries = Vec::new();
    for eco in sorted {
        let mut encoder = flate2::GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), Compression::best());
        encoder.write_all(&eco.json)?;
        let member = encoder.finish()?;
        entries.push(EcosystemEntry {
            name: eco.name.clone(),
            advisories: eco.advisories,
            last_modified: eco.last_modified.clone(),
            offset: body.len() as u64,
            length: member.len() as u64,
        });
        body.extend_from_slice(&member);
    }
    let created = entries
        .iter()
        .map(|e| e.last_modified.as_str())
        .max()
        .unwrap_or("")
        .to_string();
    let header = Header {
        format: FORMAT_VERSION,
        created,
        source: source.to_string(),
        ecosystems: entries,
    };
    let header_json = serde_json::to_vec(&header).map_err(std::io::Error::other)?;
    let mut out = Vec::with_capacity(12 + header_json.len() + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Writes the database to `path` through a temporary file renamed over
/// it, so that a scan running at the same time reads either the old or
/// the new file, never half of one.
pub fn write(path: &Path, source: &str, ecosystems: &[EcosystemPayload]) -> std::io::Result<()> {
    let bytes = encode(source, ecosystems)?;
    let tmp = path.with_extension("sadb.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// Parses database bytes read from `path` (named in the errors).
pub fn decode(path: &Path, bytes: Vec<u8>) -> Result<DatabaseFile, String> {
    let fail = |what: &str| format!("{}: {what}", path.display());
    if bytes.len() < 12 || &bytes[..4] != MAGIC {
        return Err(fail("not an advisory database (sadb) file"));
    }
    let format = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if format != FORMAT_VERSION {
        return Err(fail(&format!(
            "format {format} not supported by this engine (expected {FORMAT_VERSION})"
        )));
    }
    let header_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if header_len > MAX_HEADER_BYTES || 12 + header_len as usize > bytes.len() {
        return Err(fail("truncated header"));
    }
    let header_end = 12 + header_len as usize;
    let header: Header = serde_json::from_slice(&bytes[12..header_end])
        .map_err(|e| fail(&format!("invalid header: {e}")))?;
    if header.format != FORMAT_VERSION {
        return Err(fail(&format!("header format {} not supported", header.format)));
    }
    Ok(DatabaseFile {
        path: path.to_path_buf(),
        header,
        body: bytes[header_end..].to_vec(),
    })
}

/// Reads the database at `path`. `Ok(None)` when there is no file.
pub fn read(path: &Path) -> Result<Option<DatabaseFile>, String> {
    match std::fs::read(path) {
        Ok(bytes) => decode(path, bytes).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The database next to the running executable.
pub fn default_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(FILE_NAME)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(name: &str, n: usize, date: &str) -> EcosystemPayload {
        EcosystemPayload {
            name: name.to_string(),
            advisories: n,
            last_modified: date.to_string(),
            json: format!("{{\"ecosystem\":\"{name}\",\"advisories\":[{n}]}}").into_bytes(),
        }
    }

    /// Ticket #177: what is written is read back, ecosystem by
    /// ecosystem; the header is readable without decompressing.
    #[test]
    fn test_write_then_read_gives_the_same_ecosystems() {
        let a = [payload("PyPI", 3, "2026-11-10T00:00:00Z"), payload("npm", 5, "2026-11-11T00:00:00Z")];
        let bytes = encode("OSV", &a).unwrap();
        let db = decode(Path::new("x.sadb"), bytes.clone()).unwrap();
        assert_eq!(db.header.created, "2026-11-11T00:00:00Z");
        assert_eq!(db.header.source, "OSV");
        assert_eq!(db.header.ecosystems.len(), 2);
        assert_eq!(db.header.ecosystems[0].name, "PyPI");
        assert_eq!(db.header.ecosystems[1].advisories, 5);
        assert_eq!(db.ecosystem_json("npm").unwrap().unwrap(), a[1].json);
        assert_eq!(db.ecosystem_json("PyPI").unwrap().unwrap(), a[0].json);
        assert!(db.ecosystem_json("Maven").is_none());
        // Clear header right after the 12 fixed bytes.
        let len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let header: serde_json::Value = serde_json::from_slice(&bytes[12..12 + len]).unwrap();
        assert_eq!(header["ecosystems"][0]["name"], "PyPI");
    }

    /// Same input, same bytes, whatever the order and the time.
    #[test]
    fn test_encode_is_deterministic() {
        let a = [payload("npm", 5, "2026-11-11T00:00:00Z"), payload("PyPI", 3, "2026-11-10T00:00:00Z")];
        let b = [a[1].clone(), a[0].clone()];
        let first = encode("OSV", &a).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_eq!(first, encode("OSV", &b).unwrap());
    }

    /// An unknown format, another file or a truncated one is refused
    /// with the path, never misread; a missing file is `None`.
    #[test]
    fn test_unknown_or_broken_files_are_refused() {
        let good = encode("OSV", &[payload("PyPI", 1, "2026-01-01T00:00:00Z")]).unwrap();
        let mut newer = good.clone();
        newer[4..8].copy_from_slice(&2u32.to_le_bytes());
        let err = decode(Path::new("db.sadb"), newer).unwrap_err();
        assert!(err.contains("db.sadb") && err.contains("format 2"), "{err}");
        assert!(decode(Path::new("x"), b"{\"format\":1}".to_vec()).is_err());
        assert!(decode(Path::new("x"), good[..14].to_vec()).is_err());
        let mut cut = good.clone();
        cut.truncate(good.len() - 5);
        let db = decode(Path::new("x"), cut).unwrap();
        assert!(db.ecosystem_json("PyPI").unwrap().is_err());
        let dir = std::env::temp_dir().join(format!("sadb-missing-{}", std::process::id()));
        assert!(read(&dir.join(FILE_NAME)).unwrap().is_none());
    }

    #[test]
    fn test_write_is_atomic_and_readable() {
        let dir = std::env::temp_dir().join(format!("sadb-write-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE_NAME);
        write(&path, "OSV", &[payload("NuGet", 2, "2026-01-01T00:00:00Z")]).unwrap();
        let db = read(&path).unwrap().unwrap();
        assert_eq!(db.header.ecosystems[0].name, "NuGet");
        assert!(!dir.join("advisories.sadb.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
