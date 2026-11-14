//! Cache of the data-flow (taint) pass between two scans of the same
//! folder (2026-11-14).
//!
//! Every scan used to redo the whole taint pass, the costliest phase (20 s
//! of 33 s on a 600-file Python project), even when nothing had changed.
//! The Python `Audit` had a cache per file (`sca/file_cache.py`), but a
//! per-file cache is wrong for this engine: the taint pass follows calls
//! from file to file, so editing `quotas.py` can change a finding of
//! `router.py`. The maintainer chose (2026-11-14) an invalidation that follows those
//! dependencies:
//!
//! - per file: the hash of its text and its `dependency_fingerprint` (its
//!   functions, the calls and imports it resolves); a file whose hash or
//!   fingerprint differs is *dirty*;
//! - per rule: every function summary and every file's findings of the
//!   previous run. `resolve_summaries_incremental` recomputes the summaries
//!   of dirty files and of the functions whose callees' summaries changed,
//!   and reuses the others; a file is analysed again when it is dirty or
//!   reads a summary that changed, and keeps its previous findings
//!   otherwise;
//! - the whole cache is dropped when the engine binary, the report
//!   language or the format change, and a rule's entry when its definition
//!   changes.
//!
//! Suppressions and `# sca-ignore` are applied after the cache, on every
//! scan, so changing them never needs a fresh analysis. A cache that cannot
//! be read is ignored: the scan is then a full one, never a wrong one.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scan::dataflow::call_graph::NodeKey;
use crate::scan::dataflow::transfer::{Finding, FunctionSummary};

/// Version of the cache file layout; a different one is ignored.
const FORMAT: u32 = 1;

/// Hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// What makes a whole cache valid: the engine build and the report
/// language (rule messages are written in it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheKey {
    /// `BUILD_VERSION` plus the size and modification time of the running
    /// binary: a rebuild with uncommitted changes keeps the same version
    /// string but must not reuse results of other code.
    pub engine: String,
    /// `--lang` of the scan.
    pub lang: String,
}

impl CacheKey {
    /// The key of the running engine for `lang`.
    pub fn current(lang: &str) -> Self {
        let stamp = std::env::current_exe()
            .and_then(std::fs::metadata)
            .map(|m| {
                let modified = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_nanos());
                format!("{}:{modified}", m.len())
            })
            .unwrap_or_default();
        CacheKey {
            engine: format!("{}+{stamp}", crate::BUILD_VERSION),
            lang: lang.to_string(),
        }
    }
}

/// One file as seen by the previous run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileState {
    /// SHA-256 of the file's bytes.
    pub hash: String,
    /// SHA-256 of its `dependency_fingerprint`.
    pub deps: String,
}

/// One taint rule as computed by the previous run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleState {
    /// SHA-256 of the rule's compiled JSON: a changed rule is computed
    /// from scratch.
    pub rule_hash: String,
    /// Every function summary, as `(file, function, summary)`.
    pub summaries: Vec<(String, String, FunctionSummary)>,
    /// Every file's findings, in the order the pass produced them.
    pub findings: BTreeMap<String, Vec<Finding>>,
}

impl RuleState {
    /// The summaries as `resolve_summaries_incremental` reads them.
    pub fn previous_summaries(&self) -> BTreeMap<NodeKey, Arc<FunctionSummary>> {
        self.summaries
            .iter()
            .map(|(f, n, s)| ((f.clone(), n.clone()), Arc::new(s.clone())))
            .collect()
    }
}

/// The cache of one language's taint pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintCache {
    pub format: u32,
    pub key: CacheKey,
    pub files: BTreeMap<String, FileState>,
    /// By rule id.
    pub rules: BTreeMap<String, RuleState>,
}

impl TaintCache {
    /// An empty cache for `key`.
    pub fn new(key: CacheKey) -> Self {
        TaintCache {
            format: FORMAT,
            key,
            files: BTreeMap::new(),
            rules: BTreeMap::new(),
        }
    }

    /// The cache file of `language` in `dir`.
    pub fn path(dir: &Path, language: &str) -> PathBuf {
        dir.join(format!("taint-{language}.json.gz"))
    }

    /// The previous cache, when it exists, reads, and was written by the
    /// same engine for the same language; `None` otherwise (full scan).
    pub fn load(path: &Path, key: &CacheKey) -> Option<Self> {
        let cache: TaintCache = read_gz_json(path)?;
        (cache.format == FORMAT && &cache.key == key).then_some(cache)
    }

    /// Writes the cache atomically (temporary file, then rename): an
    /// interrupted scan leaves the previous cache or none, never half of one.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        write_gz_json(path, self)
    }

    /// The files whose text or dependencies changed since this cache, among
    /// `current` (new files included).
    pub fn dirty_files(&self, current: &BTreeMap<String, FileState>) -> BTreeSet<String> {
        current
            .iter()
            .filter(|(path, state)| self.files.get(*path) != Some(state))
            .map(|(path, _)| path.clone())
            .collect()
    }
}

/// One file of the pattern pass (phase B) as computed by the previous run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatternFileState {
    /// SHA-256 of the file's bytes.
    pub hash: String,
    /// `file_contains::governance_fingerprint` of the file: which
    /// governance files (`not_path_has_file`) exist around it.
    pub governance: String,
    /// The rules' findings before suppressions, as `(index of the rule in
    /// the loaded rules, finding)`; valid because the whole cache is
    /// dropped when the loaded rules change.
    pub findings: Vec<(usize, crate::scan::engine::Finding)>,
}

/// The cache of the pattern pass. A pattern rule only reads its own file
/// and the existence of governance files, both in each file's key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternCache {
    pub format: u32,
    pub key: CacheKey,
    /// SHA-256 of every loaded rule, in order.
    pub rules_hash: String,
    pub files: BTreeMap<String, PatternFileState>,
}

impl PatternCache {
    /// An empty cache for `key` and `rules_hash`.
    pub fn new(key: CacheKey, rules_hash: String) -> Self {
        PatternCache {
            format: FORMAT,
            key,
            rules_hash,
            files: BTreeMap::new(),
        }
    }

    /// The cache file in `dir`.
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("patterns.json.gz")
    }

    /// The previous cache when it was written by the same engine, for the
    /// same language and the same rules; `None` otherwise.
    pub fn load(path: &Path, key: &CacheKey, rules_hash: &str) -> Option<Self> {
        let cache: PatternCache = read_gz_json(path)?;
        (cache.format == FORMAT && &cache.key == key && cache.rules_hash == rules_hash)
            .then_some(cache)
    }

    /// Writes the cache atomically.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        write_gz_json(path, self)
    }
}

fn read_gz_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    flate2::read::GzDecoder::new(file).read_to_string(&mut text).ok()?;
    serde_json::from_str(&text).ok()
}

/// Temporary file, then rename: an interrupted scan leaves the previous
/// cache or none, never half of one.
fn write_gz_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let file = std::fs::File::create(&tmp)?;
        let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        gz.write_all(&serde_json::to_vec(value).map_err(std::io::Error::other)?)?;
        gz.finish()?;
    }
    std::fs::rename(&tmp, path)
}

/// How much of one language's taint pass was redone, for the scan's
/// console line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheStat {
    /// `python`, … for a taint pass; `patterns` for the pattern pass.
    pub language: String,
    /// Files of the language.
    pub files: usize,
    /// Files whose text or dependencies changed.
    pub dirty: usize,
    /// (rule, file) analyses run, over the total.
    pub analysed: usize,
    pub total: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_round_trip_and_key_check() {
        let dir = std::env::temp_dir().join(format!("sca-cache-{}", std::process::id()));
        let key = CacheKey {
            engine: "e1".to_string(),
            lang: "fr".to_string(),
        };
        let mut cache = TaintCache::new(key.clone());
        cache.files.insert(
            "a.py".to_string(),
            FileState {
                hash: sha256_hex(b"x"),
                deps: sha256_hex(b""),
            },
        );
        cache.rules.insert("r".to_string(), RuleState::default());
        let path = TaintCache::path(&dir, "python");
        cache.save(&path).unwrap();
        let back = TaintCache::load(&path, &key).unwrap();
        assert_eq!(back.files, cache.files);
        let other = CacheKey {
            engine: "e2".to_string(),
            lang: "fr".to_string(),
        };
        assert!(TaintCache::load(&path, &other).is_none(), "another engine: full scan");
        std::fs::write(&path, b"garbage").unwrap();
        assert!(TaintCache::load(&path, &key).is_none(), "unreadable: full scan");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_dirty_files_lists_new_and_changed() {
        let state = |h: &str| FileState {
            hash: h.to_string(),
            deps: String::new(),
        };
        let mut cache = TaintCache::new(CacheKey::current("en"));
        cache.files.insert("same.py".to_string(), state("1"));
        cache.files.insert("edited.py".to_string(), state("1"));
        let current = BTreeMap::from([
            ("same.py".to_string(), state("1")),
            ("edited.py".to_string(), state("2")),
            ("new.py".to_string(), state("3")),
        ]);
        let dirty: Vec<String> = cache.dirty_files(&current).into_iter().collect();
        assert_eq!(dirty, vec!["edited.py".to_string(), "new.py".to_string()]);
    }
}
