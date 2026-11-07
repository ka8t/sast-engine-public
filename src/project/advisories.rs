//! Offline matching of the audited project's dependencies against the
//! advisory database written by `tools/sast-advisories` (ADR-0035).
//!
//! **No network here.** `tools/sast-advisories` downloads published
//! vulnerabilities (OSV) on its own schedule; this module only reads its
//! files (`<dir>/<Ecosystem>.json`, format in
//! `tools/sast-advisories/src/format.rs`). This keeps the 2026-08-25
//! decision that the engine never queries a public database while it
//! scans: what changed is that the database now comes to the engine.
//!
//! **Deliberate deviation from Python**: `Audit` delegated CVE
//! matching to `pip-audit`/`npm audit` (network, two ecosystems) and
//! this port had left it out (`dependencies.rs`). The five ecosystems
//! whose manifests the engine already parses are covered here.
//!
//! Only dependencies pinned to one exact version are matched. A range
//! such as `>=2.0` or `^1.2.0` names a lower bound, not the installed
//! version, and matching that bound would report a version the project
//! may not use.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;

use crate::project::dependencies::Dependency;

/// File layout version this engine understands — must match
/// `FORMAT_VERSION` in `tools/sast-advisories/src/format.rs`.
const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
struct EcosystemFile {
    format: u32,
    advisories: Vec<Advisory>,
}

/// One vulnerability as stored by `sast-advisories`.
#[derive(Debug, Clone, Deserialize)]
pub struct Advisory {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: String,
    #[serde(default)]
    pub cwe: Vec<String>,
    packages: Vec<AffectedPackage>,
}

#[derive(Debug, Clone, Deserialize)]
struct AffectedPackage {
    name: String,
    #[serde(default)]
    ranges: Vec<Vec<Event>>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Event {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<String>,
}

impl Advisory {
    /// The identifier to show first: the CVE when there is one (aliases
    /// list CVEs first), else the OSV id.
    pub fn display_id(&self) -> &str {
        self.aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .unwrap_or(&self.id)
    }

    /// Lowest `fixed` version above `version` among the ranges of
    /// `package_key`, i.e. the upgrade to propose.
    fn fixed_version_for(
        &self,
        ecosystem: &str,
        package_key: &str,
        version: &str,
    ) -> Option<String> {
        self.packages
            .iter()
            .filter(|p| normalize_name(ecosystem, &p.name) == package_key)
            .flat_map(|p| p.ranges.iter().flatten())
            .filter_map(|e| e.fixed.as_deref())
            .filter(|f| compare_versions(f, version) == Ordering::Greater)
            .min_by(|a, b| compare_versions(a, b))
            .map(str::to_string)
    }
}

/// Advisories indexed by `(ecosystem, normalized package name)`.
#[derive(Debug, Default)]
pub struct AdvisoryDb {
    by_package: BTreeMap<(String, String), Vec<Arc<Advisory>>>,
    /// Ecosystems actually loaded, for the scan summary.
    pub loaded_ecosystems: Vec<String>,
}

/// A dependency hit by at least one vulnerability. `advisories` holds
/// one entry per distinct vulnerability: records from several
/// databases sharing an alias are merged first.
#[derive(Debug, Clone)]
pub struct VulnerableDependency {
    pub dependency: Dependency,
    pub version: String,
    pub advisories: Vec<Arc<Advisory>>,
    /// Lowest version fixing every advisory that has a fix, if any.
    pub fixed_version: Option<String>,
}

/// Loads the files of `ecosystems` found in `dir`. A missing file is
/// skipped (that ecosystem was never updated); an unreadable file or an
/// unknown format is returned as an error message per file, and the
/// other files are still loaded.
pub fn load(dir: &Path, ecosystems: &BTreeSet<String>) -> (AdvisoryDb, Vec<String>) {
    let mut db = AdvisoryDb::default();
    let mut errors = Vec::new();
    for ecosystem in ecosystems {
        let path = dir.join(format!("{ecosystem}.json"));
        let content = match std::fs::read(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                errors.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        let file: EcosystemFile = match serde_json::from_slice(&content) {
            Ok(f) => f,
            Err(e) => {
                errors.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        if file.format != FORMAT_VERSION {
            errors.push(format!(
                "{}: format {} not supported by this engine (expected {FORMAT_VERSION})",
                path.display(),
                file.format
            ));
            continue;
        }
        for advisory in file.advisories {
            let advisory = Arc::new(advisory);
            let names: BTreeSet<String> = advisory
                .packages
                .iter()
                .map(|p| normalize_name(ecosystem, &p.name))
                .collect();
            for name in names {
                db.by_package
                    .entry((ecosystem.clone(), name))
                    .or_default()
                    .push(advisory.clone());
            }
        }
        db.loaded_ecosystems.push(ecosystem.clone());
    }
    (db, errors)
}

/// Returns the dependencies of `deps` whose exact version is affected,
/// in input order.
pub fn find_vulnerable(deps: &[Dependency], db: &AdvisoryDb) -> Vec<VulnerableDependency> {
    let mut found = Vec::new();
    for dep in deps {
        let Some(version) = exact_version(dep) else {
            continue;
        };
        let key = (
            dep.ecosystem.clone(),
            normalize_name(&dep.ecosystem, &dep.name),
        );
        let Some(candidates) = db.by_package.get(&key) else {
            continue;
        };
        let hits: Vec<Arc<Advisory>> = candidates
            .iter()
            .filter(|a| affects(a, &dep.ecosystem, &key.1, version))
            .cloned()
            .collect();
        let mut advisories = merge_aliases(hits);
        // Most severe first, so a report truncating the list keeps the
        // ones that matter (Log4Shell before a log formatting bug).
        advisories.sort_by(|a, b| {
            severity_rank(&b.severity)
                .cmp(&severity_rank(&a.severity))
                .then_with(|| a.display_id().cmp(b.display_id()))
        });
        if advisories.is_empty() {
            continue;
        }
        let fixes: Vec<Option<String>> = advisories
            .iter()
            .map(|a| a.fixed_version_for(&dep.ecosystem, &key.1, version))
            .collect();
        // One upgrade target only when every advisory has a fix:
        // otherwise any version would still leave one open.
        let fixed_version = if fixes.iter().all(Option::is_some) {
            fixes
                .into_iter()
                .flatten()
                .max_by(|a, b| compare_versions(a, b))
        } else {
            None
        };
        found.push(VulnerableDependency {
            dependency: dep.clone(),
            version: version.to_string(),
            advisories,
            fixed_version,
        });
    }
    found
}

/// The exact version a dependency is pinned to, or `None` for a range.
/// `dependencies.rs` keeps the lower bound of a range in `version`
/// (mirroring Python), so exactness is read back from the manifest line:
/// `==` for PyPI, a bare version for npm/Packagist. The Maven and NuGet
/// parsers only fill `version` for a pinned value already.
fn exact_version(dep: &Dependency) -> Option<&str> {
    let version = dep.version.as_deref()?;
    let exact = match dep.ecosystem.as_str() {
        "PyPI" => dep.raw_line.contains("==") && !version.contains('*'),
        "npm" | "Packagist" => {
            // `raw_line` is `"name": "spec"`: the spec is the last
            // quoted string.
            let spec = dep.raw_line.rsplit('"').nth(1).unwrap_or_default().trim();
            spec == version
        }
        "Maven" | "NuGet" => true,
        _ => false,
    };
    exact.then_some(version)
}

/// Package name normalization per ecosystem, applied to both sides:
/// PyPI per PEP 503 (case-insensitive, `-`/`_`/`.` equivalent), NuGet
/// and Packagist case-insensitive, npm and Maven exact.
fn normalize_name(ecosystem: &str, name: &str) -> String {
    match ecosystem {
        "PyPI" => {
            let mut out = String::with_capacity(name.len());
            let mut last_sep = false;
            for c in name.chars() {
                if matches!(c, '-' | '_' | '.') {
                    if !last_sep {
                        out.push('-');
                    }
                    last_sep = true;
                } else {
                    out.push(c.to_ascii_lowercase());
                    last_sep = false;
                }
            }
            out
        }
        "NuGet" | "Packagist" => name.to_lowercase(),
        _ => name.to_string(),
    }
}

/// Whether `version` of `package_key` is affected by `advisory`: listed
/// explicitly by OSV, or inside one of its ranges.
fn affects(advisory: &Advisory, ecosystem: &str, package_key: &str, version: &str) -> bool {
    advisory
        .packages
        .iter()
        .filter(|p| normalize_name(ecosystem, &p.name) == package_key)
        .any(|p| {
            if !p.versions.is_empty() {
                return p
                    .versions
                    .iter()
                    .any(|v| compare_versions(v, version) == Ordering::Equal);
            }
            p.ranges.iter().any(|events| in_range(events, version))
        })
}

/// OSV range evaluation (https://ossf.github.io/osv-schema/#evaluation):
/// events sorted by version, then walked in order — `introduced` opens
/// the range, `fixed`/`limit` close it at that version, `last_affected`
/// closes it after that version. `introduced: "0"` is below every
/// version.
fn in_range(events: &[Event], version: &str) -> bool {
    let mut sorted: Vec<(&str, &Event)> = events
        .iter()
        .filter_map(|e| {
            let v = e
                .introduced
                .as_deref()
                .or(e.fixed.as_deref())
                .or(e.last_affected.as_deref())
                .or(e.limit.as_deref())?;
            Some((v, e))
        })
        .collect();
    sorted.sort_by(|a, b| compare_versions(a.0, b.0));

    let mut affected = false;
    for (bound, event) in sorted {
        let cmp = compare_versions(version, bound);
        if event.introduced.is_some() {
            if bound == "0" || cmp != Ordering::Less {
                affected = true;
            }
        } else if event.fixed.is_some() || event.limit.is_some() {
            if cmp != Ordering::Less {
                affected = false;
            }
        } else if event.last_affected.is_some() && cmp == Ordering::Greater {
            affected = false;
        }
    }
    affected
}

/// Merges advisories that describe the same vulnerability (shared id or
/// alias, e.g. a `PYSEC-` record and its `GHSA-` twin), keeping the
/// most severe record of each group.
fn merge_aliases(hits: Vec<Arc<Advisory>>) -> Vec<Arc<Advisory>> {
    let mut groups: Vec<(BTreeSet<String>, Arc<Advisory>)> = Vec::new();
    for advisory in hits {
        let ids: BTreeSet<String> = std::iter::once(advisory.id.clone())
            .chain(advisory.aliases.iter().cloned())
            .collect();
        match groups.iter_mut().find(|(g, _)| !g.is_disjoint(&ids)) {
            Some((group_ids, kept)) => {
                group_ids.extend(ids);
                if severity_rank(&advisory.severity) > severity_rank(&kept.severity) {
                    *kept = advisory;
                }
            }
            None => groups.push((ids, advisory)),
        }
    }
    groups.into_iter().map(|(_, a)| a).collect()
}

/// Engine severity for an advisory. `UNKNOWN` (no qualitative rating in
/// the source record) is reported as `MEDIUM`.
pub fn engine_severity(advisory: &Advisory) -> &'static str {
    match advisory.severity.as_str() {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "LOW" => "LOW",
        _ => "MEDIUM",
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

/// Generic version comparison shared by the five ecosystems.
///
/// Versions split into numeric and alphabetic segments on `.`, `-`,
/// `_`, `+` and digit/letter boundaries (`1.0rc1` → `1`,`0`,`rc`,`1`).
/// Numbers compare numerically; a missing segment counts as `0` against
/// a number (`1.0` = `1.0.0`). Words rank as pre-releases below the
/// release (`dev` < `alpha`/`a` < `beta`/`b` < `milestone`/`m` <
/// `rc`/`c`/`cr` < other words < release), except `post`/`sp`/`patch`
/// which rank above it, and `final`/`ga`/`release` which equal it.
/// SemVer build metadata (`+…`) is ignored, and a leading `v` dropped.
///
/// This approximates PEP 440, SemVer, Maven and NuGet ordering for the
/// versions found in practice; it is not a full implementation of any
/// of them. OSV's explicit `versions` lists, used first by `affects`,
/// avoid the comparison altogether for most PyPI records.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let sa = segments(a);
    let sb = segments(b);
    for i in 0..sa.len().max(sb.len()) {
        let ord = match (sa.get(i), sb.get(i)) {
            (Some(x), Some(y)) => compare_segment(x, y),
            (Some(x), None) => compare_segment(x, &Segment::Release),
            (None, Some(y)) => compare_segment(&Segment::Release, y),
            (None, None) => Ordering::Equal,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

#[derive(Debug, Clone, PartialEq)]
enum Segment {
    Num(u64),
    Word(u8),
    /// Stands for a missing segment.
    Release,
}

const RELEASE_RANK: u8 = 6;

fn word_rank(word: &str) -> u8 {
    match word {
        "dev" | "snapshot" => 0,
        "alpha" | "a" => 1,
        "beta" | "b" => 2,
        "milestone" | "m" => 3,
        "rc" | "c" | "cr" | "pre" | "preview" => 4,
        "final" | "ga" | "release" | "r" => RELEASE_RANK,
        "post" | "sp" | "patch" | "pl" => 7,
        _ => 5,
    }
}

fn segments(version: &str) -> Vec<Segment> {
    let version = version.trim();
    let version = version.strip_prefix('v').unwrap_or(version);
    let version = version.split('+').next().unwrap_or(version);
    let mut out = Vec::new();
    let mut current = String::new();
    let flush = |current: &mut String, out: &mut Vec<Segment>| {
        if current.is_empty() {
            return;
        }
        if let Ok(n) = current.parse::<u64>() {
            out.push(Segment::Num(n));
        } else {
            let rank = word_rank(&current.to_lowercase());
            if rank != RELEASE_RANK {
                out.push(Segment::Word(rank));
            }
        }
        current.clear();
    };
    for c in version.chars() {
        if matches!(c, '.' | '-' | '_') {
            flush(&mut current, &mut out);
            continue;
        }
        let boundary = current
            .chars()
            .last()
            .is_some_and(|last| last.is_ascii_digit() != c.is_ascii_digit());
        if boundary {
            flush(&mut current, &mut out);
        }
        current.push(c);
    }
    flush(&mut current, &mut out);
    out
}

fn compare_segment(a: &Segment, b: &Segment) -> Ordering {
    use Segment::*;
    match (a, b) {
        (Num(x), Num(y)) => x.cmp(y),
        (Num(x), Release) => x.cmp(&0),
        (Release, Num(y)) => 0.cmp(y),
        // A number continues the release (`1.0.1` > `1.0rc1`), so it
        // ranks above every word.
        (Num(_), Word(_)) => Ordering::Greater,
        (Word(_), Num(_)) => Ordering::Less,
        (Word(x), Word(y)) => x.cmp(y),
        (Word(x), Release) => x.cmp(&RELEASE_RANK),
        (Release, Word(y)) => RELEASE_RANK.cmp(y),
        (Release, Release) => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dep(ecosystem: &str, name: &str, version: Option<&str>, raw_line: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(str::to_string),
            ecosystem: ecosystem.to_string(),
            file: PathBuf::from("manifest"),
            line: 1,
            raw_line: raw_line.to_string(),
        }
    }

    fn db_from(ecosystem: &str, json: &str) -> AdvisoryDb {
        let dir = std::env::temp_dir().join(format!(
            "auditrust-advisories-{}-{}",
            std::process::id(),
            ecosystem
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{ecosystem}.json")), json).unwrap();
        let (db, errors) = load(&dir, &BTreeSet::from([ecosystem.to_string()]));
        assert!(errors.is_empty(), "{errors:?}");
        db
    }

    #[test]
    fn test_compare_versions_orders_common_schemes() {
        let ascending = [
            "1.0.0.dev1",
            "1.0.0a1",
            "1.0.0b2",
            "1.0.0rc1",
            "1.0",
            "1.0.0.post1",
            "1.0.1",
            "1.2",
            "1.10",
        ];
        for pair in ascending.windows(2) {
            assert_eq!(
                compare_versions(pair[0], pair[1]),
                Ordering::Less,
                "{} < {}",
                pair[0],
                pair[1]
            );
        }
        assert_eq!(compare_versions("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("v2.3.4", "2.3.4"), Ordering::Equal);
        assert_eq!(compare_versions("2.0.0+build5", "2.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("5.3.0.RELEASE", "5.3.0"), Ordering::Equal);
        assert_eq!(compare_versions("2.0.0-beta.1", "2.0.0"), Ordering::Less);
        assert_eq!(compare_versions("2.12.6.1", "2.12.6"), Ordering::Greater);
    }

    #[test]
    fn test_in_range_follows_osv_events() {
        let range = |events: &[(&str, &str)]| -> Vec<Event> {
            events
                .iter()
                .map(|(kind, v)| {
                    let v = Some(v.to_string());
                    Event {
                        introduced: (*kind == "introduced").then(|| v.clone()).flatten(),
                        fixed: (*kind == "fixed").then(|| v.clone()).flatten(),
                        last_affected: (*kind == "last_affected").then(|| v.clone()).flatten(),
                        limit: None,
                    }
                })
                .collect()
        };
        let two_windows = range(&[
            ("introduced", "0"),
            ("fixed", "1.5"),
            ("introduced", "2.0"),
            ("fixed", "2.3"),
        ]);
        assert!(in_range(&two_windows, "1.4.9"));
        assert!(!in_range(&two_windows, "1.5"));
        assert!(!in_range(&two_windows, "1.9"));
        assert!(in_range(&two_windows, "2.2"));
        assert!(!in_range(&two_windows, "2.3.1"));
        let last = range(&[("introduced", "1.0"), ("last_affected", "1.2")]);
        assert!(in_range(&last, "1.2"));
        assert!(!in_range(&last, "1.2.1"));
        assert!(!in_range(&last, "0.9"));
        let open = range(&[("introduced", "0")]);
        assert!(in_range(&open, "99.0"));
    }

    #[test]
    fn test_exact_version_ignores_ranges() {
        assert_eq!(
            exact_version(&dep("PyPI", "lxml", Some("4.6.2"), "lxml==4.6.2")),
            Some("4.6.2")
        );
        assert_eq!(
            exact_version(&dep("PyPI", "lxml", Some("4.6.2"), "lxml>=4.6.2")),
            None
        );
        assert_eq!(
            exact_version(&dep(
                "npm",
                "lodash",
                Some("4.17.20"),
                "\"lodash\": \"4.17.20\""
            )),
            Some("4.17.20")
        );
        assert_eq!(
            exact_version(&dep(
                "npm",
                "lodash",
                Some("4.17.20"),
                "\"lodash\": \"^4.17.20\""
            )),
            None
        );
        assert_eq!(
            exact_version(&dep("Maven", "g:a", Some("1.0"), "g:a 1.0")),
            Some("1.0")
        );
        assert_eq!(exact_version(&dep("Maven", "g:a", None, "g:a ${v}")), None);
    }

    #[test]
    fn test_find_vulnerable_matches_merges_aliases_and_proposes_fix() {
        let db = db_from(
            "PyPI",
            r#"{"format":1,"ecosystem":"PyPI","last_modified":"x","updated_at":0,"advisories":[
              {"id":"GHSA-1","aliases":["CVE-2021-28957","PYSEC-2021-19"],"summary":"XSS","severity":"MEDIUM",
               "packages":[{"name":"LXML","ranges":[[{"introduced":"0"},{"fixed":"4.6.3"}]]}]},
              {"id":"PYSEC-2021-19","aliases":["CVE-2021-28957"],"summary":"XSS","severity":"UNKNOWN",
               "packages":[{"name":"lxml","versions":["4.6.2"]}]},
              {"id":"GHSA-2","aliases":["CVE-2021-43818"],"summary":"Other","severity":"HIGH",
               "packages":[{"name":"lxml","ranges":[[{"introduced":"0"},{"fixed":"4.6.5"}]]}]},
              {"id":"GHSA-3","summary":"Not this version","severity":"HIGH",
               "packages":[{"name":"lxml","ranges":[[{"introduced":"5.0"}]]}]}
            ]}"#,
        );
        let deps = [
            dep("PyPI", "lxml", Some("4.6.2"), "lxml==4.6.2"),
            dep("PyPI", "lxml", Some("4.6.2"), "lxml>=4.6.2"),
            dep("PyPI", "requests", Some("2.0"), "requests==2.0"),
        ];
        let found = find_vulnerable(&deps, &db);
        assert_eq!(
            found.len(),
            1,
            "range spec and unknown package are not reported"
        );
        let hit = &found[0];
        let ids: Vec<&str> = hit.advisories.iter().map(|a| a.display_id()).collect();
        assert_eq!(
            ids,
            vec!["CVE-2021-43818", "CVE-2021-28957"],
            "PYSEC twin merged, most severe first"
        );
        assert_eq!(hit.fixed_version.as_deref(), Some("4.6.5"), "fixes both");
    }

    #[test]
    fn test_find_vulnerable_without_fix_proposes_none() {
        let db = db_from(
            "npm",
            r#"{"format":1,"ecosystem":"npm","last_modified":"x","updated_at":0,"advisories":[
              {"id":"MAL-2026-1","summary":"Malicious code","severity":"CRITICAL",
               "packages":[{"name":"evil-pkg","ranges":[[{"introduced":"0"}]]}]}]}"#,
        );
        let found = find_vulnerable(
            &[dep(
                "npm",
                "evil-pkg",
                Some("1.0.0"),
                "\"evil-pkg\": \"1.0.0\"",
            )],
            &db,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].fixed_version, None);
        assert_eq!(engine_severity(&found[0].advisories[0]), "CRITICAL");
    }

    #[test]
    fn test_load_reports_unknown_format_and_skips_missing_files() {
        let dir = std::env::temp_dir().join(format!(
            "auditrust-advisories-format-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Maven.json"), r#"{"format":99,"advisories":[]}"#).unwrap();
        let wanted = BTreeSet::from(["Maven".to_string(), "NuGet".to_string()]);
        let (db, errors) = load(&dir, &wanted);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("format 99"));
        assert!(db.loaded_ecosystems.is_empty());
    }

    #[test]
    fn test_normalize_name_per_ecosystem() {
        assert_eq!(
            normalize_name("PyPI", "Zope.Interface__x"),
            "zope-interface-x"
        );
        assert_eq!(
            normalize_name("NuGet", "Newtonsoft.Json"),
            "newtonsoft.json"
        );
        assert_eq!(normalize_name("npm", "@Scope/Pkg"), "@Scope/Pkg");
    }
}
