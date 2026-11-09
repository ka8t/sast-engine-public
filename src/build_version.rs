//! Build version (ticket #149): the `Cargo.toml` version followed by the
//! commit count and short hash of the tree the binary was built from, e.g.
//! `0.1.0+415.588dc34`, plus `-dirty` when it held uncommitted changes.
//!
//! A tester could not tell whether his binary included the latest fixes:
//! `--version` always printed `0.1.0`, which is never bumped between
//! releases. The commit count grows with every commit without any manual
//! step; the hash names the exact code. `build.rs` computes the parts with
//! git and exports the result as `SAST_BUILD_VERSION`; this file is shared
//! with it through `#[path]`, so the formatting is tested here.

/// Formats the build version. `commits` and `hash` come from git; when
/// either is missing (no git, or not a repository, e.g. a downloaded
/// archive) the suffix is `+unknown` and the build still succeeds.
pub fn format_build_version(
    package_version: &str,
    commits: Option<&str>,
    hash: Option<&str>,
    dirty: bool,
) -> String {
    fn clean(s: Option<&str>) -> Option<&str> {
        s.map(str::trim).filter(|s| !s.is_empty())
    }
    match (clean(commits), clean(hash)) {
        (Some(commits), Some(hash)) => {
            let dirty = if dirty { "-dirty" } else { "" };
            format!("{package_version}+{commits}.{hash}{dirty}")
        }
        _ => format!("{package_version}+unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_build_version_cases() {
        assert_eq!(
            format_build_version("0.1.0", Some("415\n"), Some("588dc34\n"), false),
            "0.1.0+415.588dc34"
        );
        assert_eq!(
            format_build_version("0.1.0", Some("415"), Some("588dc34"), true),
            "0.1.0+415.588dc34-dirty"
        );
        assert_eq!(
            format_build_version("0.1.0", None, Some("588dc34"), true),
            "0.1.0+unknown"
        );
        assert_eq!(
            format_build_version("0.2.0", Some(""), None, false),
            "0.2.0+unknown"
        );
    }
}
