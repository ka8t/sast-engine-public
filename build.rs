//! Copies the rule catalog (`rules/builtin/**/*.sca`) into `rules/` next
//! to the compiled binary (ADR-0038): the engine reads its rules at run
//! time, file by file, from that folder, so `cargo build`/`cargo run`/the
//! CLI tests need it beside `target/<profile>/sast-engine`. No rule is
//! embedded in the binary, encrypted or signed.
//!
//! In this repository the folder holds the full catalog; in the shared
//! repository `rules/builtin` holds the demo rules only, so the same build
//! copies the demo rules.
//!
//! Also exports `SAST_BUILD_VERSION` (ticket #149).

use std::env;
use std::fs;
use std::path::Path;

#[path = "src/build_version.rs"]
mod build_version;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR absent");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR absent");

    copy_builtin_rules(&manifest_dir, &out_dir);
    export_build_version(&manifest_dir);
}

/// Exports `SAST_BUILD_VERSION` (ticket #149, `src/build_version.rs`):
/// the package version, commit count and short hash from git, `-dirty`
/// when tracked files differ from the commit. Any git failure (git not
/// installed, no repository) gives `+unknown`, never a build error.
///
/// Reruns when the commit changes (`HEAD`, branch refs, packed refs) or
/// files are staged (the index), so a new commit changes the version
/// without touching any file. An edit of a tracked file that is never
/// staged does not rerun the script: such a build may lack `-dirty`.
fn export_build_version(manifest_dir: &str) {
    let git = |args: &[&str]| -> Option<String> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(manifest_dir)
            .args(args)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
    };
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        let git_dir = Path::new(&git_dir);
        for watched in ["HEAD", "index", "packed-refs", "refs/heads"] {
            println!("cargo:rerun-if-changed={}", git_dir.join(watched).display());
        }
    }
    let commits = git(&["rev-list", "--count", "HEAD"]);
    let hash = git(&["rev-parse", "--short=7", "HEAD"]);
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .is_some_and(|changes| !changes.is_empty());
    let version = build_version::format_build_version(
        &env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION absent"),
        commits.as_deref(),
        hash.as_deref(),
        dirty,
    );
    println!("cargo:rustc-env=SAST_BUILD_VERSION={version}");
}

/// Replaces `rules/` in the directory of the compiled binary with a copy
/// of `rules/builtin`, same tree (`<language>/<category>/<rule>.sca`).
/// `OUT_DIR` is `<target>/<profile>/build/<crate>-<hash>/out`, so that
/// directory is three levels up; it follows `CARGO_TARGET_DIR` and
/// `--target` on its own. Writing outside `OUT_DIR` is unusual for a build
/// script, but the binary looks for its rules next to itself, exactly as
/// it does in an installed copy.
///
/// The folder is emptied first, so a rule deleted from `rules/builtin`
/// does not linger, and neither does the `builtin.scapack` of the former
/// encrypted packs (ADR-0037). It is a build output: rules added by hand
/// in `target/<profile>/rules/` disappear at the next build that copies.
fn copy_builtin_rules(manifest_dir: &str, out_dir: &str) {
    let source = Path::new(manifest_dir).join("rules").join("builtin");
    println!("cargo:rerun-if-changed={}", source.display());
    let profile_dir = Path::new(out_dir)
        .ancestors()
        .nth(3)
        .expect("OUT_DIR is <target>/<profile>/build/<crate>/out");
    let target = profile_dir.join("rules");
    if target.exists() {
        fs::remove_dir_all(&target).expect("emptying the rules/ folder next to the binary");
    }
    fs::create_dir_all(&target).expect("creating the rules/ folder next to the binary");
    copy_sca_tree(&source, &source, &target);
}

/// Copies every `.sca` file under `dir` to the same relative path under
/// `target`, recursively, and registers each one with `rerun-if-changed`.
/// Symbolic links are not followed, like the scan walk (ticket #147).
fn copy_sca_tree(root: &Path, dir: &Path, target: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            copy_sca_tree(root, &path, target);
        } else if file_type.is_file() && path.extension().is_some_and(|e| e == "sca") {
            println!("cargo:rerun-if-changed={}", path.display());
            let rel = path.strip_prefix(root).expect("path under the rules root");
            let dest = target.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).expect("creating a rule folder next to the binary");
            }
            fs::copy(&path, &dest).expect("copying a rule file next to the binary");
        }
    }
}
