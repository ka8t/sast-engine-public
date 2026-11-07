//! File discovery — faithful port of
//! `Audit/sca/runner.py::AuditRunner._find_files`/`_is_excluded` and
//! `sca/rule_engine.py::_matches_any_exclude`. Step 5.
//!
//! `_matches_any_exclude` (subdirectory pruning during the
//! walk, for perf) and `_is_excluded` (final check on a file
//! path) are **calibrated differently** on the Python side — not the
//! same way of wrapping the path as a substring (`/{path}/` vs
//! `/{path}`), not the same constraint on the "simple folder" pattern
//! (`"/" not in clean` only on the `_matches_any_exclude` side) —
//! reproduced as-is, not unified.
#![allow(dead_code)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use regex::Regex as StdRegex;

/// Translates a shell-glob pattern (Python `fnmatch`: `*`, `?`,
/// `[seq]`, `[!seq]`) into a full-text anchored regex. `fnmatch` does not
/// treat `/` specially (unlike the `glob` module): `*` matches
/// anything including path separators.
fn fnmatch_to_regex(pattern: &str) -> String {
    let mut out = String::from("^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                out.push_str(".*");
                i += 1;
            }
            '?' => {
                out.push('.');
                i += 1;
            }
            '[' => {
                let mut j = i + 1;
                let negate = j < chars.len() && (chars[j] == '!' || chars[j] == '^');
                if negate {
                    j += 1;
                }
                let class_start = j;
                if j < chars.len() && chars[j] == ']' {
                    j += 1; // a ']' right after [ or [! is literal, not the closing bracket
                }
                while j < chars.len() && chars[j] != ']' {
                    j += 1;
                }
                if j >= chars.len() {
                    // No closing ']' found: literal '['.
                    out.push_str("\\[");
                    i += 1;
                } else {
                    let body: String = chars[class_start..j].iter().collect();
                    out.push('[');
                    if negate {
                        out.push('^');
                    }
                    out.push_str(&body.replace('\\', "\\\\"));
                    out.push(']');
                    i = j + 1;
                }
            }
            c => {
                out.push_str(&regex::escape(&c.to_string()));
                i += 1;
            }
        }
    }
    out.push('$');
    out
}

fn fnmatch(name: &str, pattern: &str) -> bool {
    let Ok(re) = StdRegex::new(&fnmatch_to_regex(pattern)) else {
        return false;
    };
    re.is_match(name)
}

/// Mirror of `rule_engine.py::_matches_any_exclude` — used for
/// pruning subdirectories during the recursive walk (perf:
/// avoids descending into `node_modules/`, `.venv/`, `__pycache__/`…).
/// `rel_path`: path relative to the project, `/` or `\` separators.
pub fn matches_any_exclude(rel_path: &str, excludes: &[String]) -> bool {
    let norm = rel_path.replace('\\', "/");
    for pattern in excludes {
        if fnmatch(&norm, pattern) {
            return true;
        }
        if let Some(rest) = pattern.strip_prefix("**/")
            && let Some(middle) = rest.strip_suffix("/**")
            && !middle.is_empty()
        {
            let haystack = format!("/{norm}/");
            if haystack.contains(&format!("/{middle}/"))
                || norm == middle
                || norm.starts_with(&format!("{middle}/"))
            {
                return true;
            }
        }
        let clean = pattern.trim_end_matches('/');
        if !clean.is_empty() && !clean.contains('/') {
            let haystack = format!("/{norm}/");
            if haystack.contains(&format!("/{clean}/")) || norm.starts_with(&format!("{clean}/")) {
                return true;
            }
        }
    }
    false
}

/// Mirror of `runner.py::AuditRunner._is_excluded` — final check
/// on a file (full glob, "simple folder" pattern,
/// "extension" pattern on the basename).
pub fn is_excluded(rel_path: &str, basename: &str, exclude_patterns: &[String]) -> bool {
    let norm = rel_path.replace('\\', "/");
    for pattern in exclude_patterns {
        if fnmatch(&norm, pattern) {
            return true;
        }
        let clean = pattern.trim_end_matches('/');
        if !clean.is_empty() {
            let haystack = format!("/{norm}");
            if haystack.contains(&format!("/{clean}/")) || norm.starts_with(&format!("{clean}/")) {
                return true;
            }
        }
        if fnmatch(basename, pattern) {
            return true;
        }
    }
    false
}

/// File discovery configuration.
pub struct FileDiscoveryConfig {
    /// Extensions kept (`filename.ends_with(ext)`) — empty = everything.
    pub extensions: Vec<String>,
    /// EXACT filenames kept (case-insensitive comparison), in
    /// addition to extensions — for formats without a
    /// standard extension (`Dockerfile`, ticket #69/spec #68; mirror
    /// of `Audit/sca/rule_engine.py::_find_dockerfile_files`,
    /// `filename.lower() in (...)`). FULL name comparison, not
    /// `ends_with`: a file named `MyDockerfile` must not silently
    /// match — only the case is ignored, not the length
    /// of the name. A file passes the filter as soon as it satisfies
    /// `extensions` OR `filenames` (not both); empty by default —
    /// no behavior change for existing callers.
    pub filenames: Vec<String>,
    /// Exclusion patterns applied at the file level (`is_excluded`).
    pub exclude_patterns: Vec<String>,
    /// Subdirectory pruning patterns during the walk
    /// (`matches_any_exclude`) — often identical to
    /// `exclude_patterns` on the caller side, but kept separate (mirror
    /// of the two distinct config lists on the Python side).
    pub prune_excludes: Vec<String>,
}

/// Discovers files under `root` (project root, used to compute
/// relative paths) by recursively walking `paths` (paths
/// relative to `root`). Mirror of `_find_files`.
pub fn find_files(root: &Path, paths: &[&Path], config: &FileDiscoveryConfig) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for start in paths {
        let full_path = root.join(start);
        if !full_path.exists() {
            continue;
        }
        walk_dir(&full_path, root, config, &mut files, &mut seen);
    }
    files
}

fn walk_dir(
    dir: &Path,
    root: &Path,
    config: &FileDiscoveryConfig,
    files: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut subdirs = Vec::new();
    let mut filepaths = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else {
            filepaths.push(path);
        }
    }

    // Sort first (ticket #102, found via the first-ever Linux CI run):
    // `read_dir` order is filesystem-dependent (readdir() gives no
    // ordering guarantee), so results could differ between macOS and
    // Linux for the identical source tree. Alphabetical by filename
    // makes scan results reproducible across machines — matches the same
    // fix applied to `Audit/sca/runner.py::_find_files` (shared bug, not
    // a Rust-vs-Python difference).
    filepaths.sort_unstable();
    subdirs.sort_unstable();

    // Pruning of excluded subdirectories before descending into them (perf).
    if !config.prune_excludes.is_empty() {
        subdirs.retain(|d| {
            let rel = d
                .strip_prefix(root)
                .unwrap_or(d)
                .to_string_lossy()
                .replace('\\', "/");
            !matches_any_exclude(&rel, &config.prune_excludes)
        });
    }

    for filepath in &filepaths {
        let filename = filepath
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if !config.extensions.is_empty() || !config.filenames.is_empty() {
            let matches_extension = config
                .extensions
                .iter()
                .any(|ext| filename.ends_with(ext.as_str()));
            let matches_filename = config
                .filenames
                .iter()
                .any(|name| filename.eq_ignore_ascii_case(name));
            if !matches_extension && !matches_filename {
                continue;
            }
        }
        let rel_path = filepath
            .strip_prefix(root)
            .unwrap_or(filepath)
            .to_string_lossy()
            .replace('\\', "/");
        if is_excluded(&rel_path, &filename, &config.exclude_patterns) {
            continue;
        }
        if seen.insert(filepath.clone()) {
            files.push(filepath.clone());
        }
    }

    for d in &subdirs {
        walk_dir(d, root, config, files, seen);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Creates a unique temporary directory (cleaned up by the calling test).
    fn temp_project_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("sast_discovery_test_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn default_config() -> FileDiscoveryConfig {
        FileDiscoveryConfig {
            extensions: vec![".py".to_string()],
            filenames: vec![],
            exclude_patterns: vec![],
            prune_excludes: vec![],
        }
    }

    #[test]
    fn test_fnmatch_star_matches_any_substring() {
        assert!(fnmatch("foo.min.js", "*.min.js"));
        assert!(!fnmatch("foo.js", "*.min.js"));
    }

    #[test]
    fn test_fnmatch_question_mark_matches_single_char() {
        assert!(fnmatch("a.py", "?.py"));
        assert!(!fnmatch("ab.py", "?.py"));
    }

    #[test]
    fn test_fnmatch_bracket_class() {
        assert!(fnmatch("a.py", "[ab].py"));
        assert!(fnmatch("b.py", "[ab].py"));
        assert!(!fnmatch("c.py", "[ab].py"));
    }

    #[test]
    fn test_fnmatch_negated_bracket_class() {
        assert!(!fnmatch("a.py", "[!ab].py"));
        assert!(fnmatch("c.py", "[!ab].py"));
    }

    #[test]
    fn test_matches_any_exclude_glob_star_star() {
        let excludes = vec!["**/node_modules/**".to_string()];
        assert!(matches_any_exclude("src/node_modules/pkg", &excludes));
        assert!(matches_any_exclude("node_modules", &excludes));
        assert!(!matches_any_exclude("src/app.py", &excludes));
    }

    #[test]
    fn test_matches_any_exclude_simple_folder_no_slash_only() {
        // The "/" not in clean constraint is specific to
        // matches_any_exclude (not is_excluded): "sub/vendor/" does NOT
        // match through this path (only a direct fnmatch could).
        let excludes = vec!["vendor/".to_string()];
        assert!(matches_any_exclude("vendor", &excludes));
        assert!(matches_any_exclude("src/vendor", &excludes));
    }

    #[test]
    fn test_is_excluded_extension_pattern_on_basename() {
        let excludes = vec!["*.min.js".to_string()];
        assert!(is_excluded("src/app.min.js", "app.min.js", &excludes));
        assert!(!is_excluded("src/app.js", "app.js", &excludes));
    }

    #[test]
    fn test_is_excluded_simple_folder_pattern() {
        let excludes = vec!["vendor/".to_string()];
        assert!(is_excluded("vendor/lib.py", "lib.py", &excludes));
        assert!(is_excluded("src/vendor/lib.py", "lib.py", &excludes));
        assert!(!is_excluded("src/vendored/lib.py", "lib.py", &excludes));
    }

    #[test]
    fn test_find_files_extension_filter_and_recursion() {
        let root = temp_project_dir();
        write_file(&root, "a.py", "x = 1\n");
        write_file(&root, "sub/b.py", "y = 2\n");
        write_file(&root, "c.txt", "not python\n");
        let config = default_config();
        let files = find_files(&root, &[Path::new(".")], &config);
        assert_eq!(
            files.len(),
            2,
            "seuls les .py sont retenus, à toute profondeur"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_find_files_prunes_excluded_subdirs() {
        let root = temp_project_dir();
        write_file(&root, "a.py", "x = 1\n");
        write_file(&root, "node_modules/dep.py", "y = 2\n");
        let config = FileDiscoveryConfig {
            extensions: vec![".py".to_string()],
            filenames: vec![],
            exclude_patterns: vec!["node_modules/".to_string()],
            prune_excludes: vec!["node_modules/".to_string()],
        };
        let files = find_files(&root, &[Path::new(".")], &config);
        assert_eq!(files.len(), 1, "node_modules/ élagué, seul a.py reste");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_find_files_nonexistent_path_skipped_silently() {
        let root = temp_project_dir();
        let config = default_config();
        let files = find_files(&root, &[Path::new("does_not_exist")], &config);
        assert!(files.is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_find_files_no_extension_filter_matches_everything() {
        let root = temp_project_dir();
        write_file(&root, "a.py", "x\n");
        write_file(&root, "b.txt", "y\n");
        let config = FileDiscoveryConfig {
            extensions: vec![],
            filenames: vec![],
            exclude_patterns: vec![],
            prune_excludes: vec![],
        };
        let files = find_files(&root, &[Path::new(".")], &config);
        assert_eq!(files.len(), 2);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Ticket #69/spec #68: `filenames` recognizes a format with no
    /// standard extension by EXACT name — `MyDockerfile` must not
    /// match silently (full-name comparison, not
    /// `ends_with`).
    #[test]
    fn test_filenames_matches_exact_name_not_suffix() {
        let root = temp_project_dir();
        write_file(&root, "Dockerfile", "FROM scratch\n");
        write_file(&root, "MyDockerfile", "not a real dockerfile\n");
        write_file(&root, "app.py", "x = 1\n");
        let config = FileDiscoveryConfig {
            extensions: vec![],
            filenames: vec!["Dockerfile".to_string()],
            exclude_patterns: vec![],
            prune_excludes: vec![],
        };
        let files = find_files(&root, &[Path::new(".")], &config);
        assert_eq!(files.len(), 1, "seul Dockerfile doit matcher : {files:?}");
        assert_eq!(files[0].file_name().unwrap(), "Dockerfile");
        std::fs::remove_dir_all(&root).ok();
    }

    /// Fix from 2026-09-01 (flagged in review of ticket #69):
    /// the comparison is case-insensitive, mirroring
    /// `Audit/sca/rule_engine.py::_find_dockerfile_files`
    /// (`filename.lower() in (...)`) — an all-lowercase `dockerfile`
    /// must match `filenames: ["Dockerfile"]`.
    #[test]
    fn test_filenames_matches_case_insensitively() {
        let root = temp_project_dir();
        write_file(&root, "dockerfile", "FROM scratch\n");
        let config = FileDiscoveryConfig {
            extensions: vec![],
            filenames: vec!["Dockerfile".to_string()],
            exclude_patterns: vec![],
            prune_excludes: vec![],
        };
        let files = find_files(&root, &[Path::new(".")], &config);
        assert_eq!(
            files.len(),
            1,
            "dockerfile (minuscules) doit matcher : {files:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// A file passes the filter as soon as it satisfies `extensions` OR
    /// `filenames` — the two mechanisms combine, they are not exclusive.
    #[test]
    fn test_filenames_and_extensions_combine() {
        let root = temp_project_dir();
        write_file(&root, "Dockerfile", "FROM scratch\n");
        write_file(&root, "a.py", "x = 1\n");
        write_file(&root, "b.txt", "y\n");
        let config = FileDiscoveryConfig {
            extensions: vec![".py".to_string()],
            filenames: vec!["Dockerfile".to_string()],
            exclude_patterns: vec![],
            prune_excludes: vec![],
        };
        let files = find_files(&root, &[Path::new(".")], &config);
        assert_eq!(files.len(), 2, "Dockerfile + a.py, pas b.txt : {files:?}");
        std::fs::remove_dir_all(&root).ok();
    }
}
