//! Copies the plain rule catalog (`rules/builtin/**/*.sca`) into `rules/`
//! next to the compiled binary (ADR-0039): the engine reads its rules at
//! run time from that folder, so `cargo build`/`cargo run`/the CLI tests
//! need it beside `target/<profile>/sast-engine`. No rule is embedded in
//! the binary.
//!
//! In this repository the folder holds the full catalog; in the shared
//! repository `rules/builtin` holds the demo rules only, so the same build
//! copies the demo rules and the binary is usable as it is. The rules the
//! editor sells travel as encrypted packs (`*.scapack`, ADR-0037), which
//! the client drops into that same folder: this script never removes them.
//!
//! Also generates `$OUT_DIR/editor_release_data.rs` (ticket #85/spec
//! #82): the publisher Ed25519 public key, used by `src/rules/rule_packs.rs`
//! to verify signed packs. `SAST_EDITOR_PUBLIC_KEY_HEX` carries the hex
//! value directly (not a file path) — a lone public key does not justify
//! an intermediate file. Variable unset → `None` static (the key written
//! in `rule_packs.rs` applies). Variable set but malformed (not 64 hex
//! characters) → explicit panic at compile time.
//!
//! And exports `SAST_BUILD_VERSION` (ticket #149).

use std::env;
use std::fs;
use std::path::Path;

#[path = "src/build_version.rs"]
mod build_version;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR absent");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR absent");

    copy_builtin_rules(&manifest_dir, &out_dir);
    generate_editor_release_data(&out_dir);
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

/// Refreshes the plain catalog in `rules/` of the directory of the
/// compiled binary from `rules/builtin`, same tree
/// (`<language>/<category>/<rule>.sca`). `OUT_DIR` is
/// `<target>/<profile>/build/<crate>-<hash>/out`, so that directory is
/// three levels up; it follows `CARGO_TARGET_DIR` and `--target` on its
/// own. Writing outside `OUT_DIR` is unusual for a build script, but the
/// binary looks for its rules next to itself, exactly as it does in an
/// installed copy.
///
/// Only what this script copies is replaced first: the language folders
/// and the `.sca` files at the top of `rules/`, so a rule deleted from
/// `rules/builtin` does not linger. Everything else stays, above all the
/// rule packs (`*.scapack`) a client or a tester dropped there.
fn copy_builtin_rules(manifest_dir: &str, out_dir: &str) {
    let source = Path::new(manifest_dir).join("rules").join("builtin");
    println!("cargo:rerun-if-changed={}", source.display());
    let profile_dir = Path::new(out_dir)
        .ancestors()
        .nth(3)
        .expect("OUT_DIR is <target>/<profile>/build/<crate>/out");
    let target = profile_dir.join("rules");
    fs::create_dir_all(&target).expect("creating the rules/ folder next to the binary");
    remove_copied_rules(&target);
    copy_sca_tree(&source, &source, &target);
}

/// Removes from `target` what [`copy_builtin_rules`] copies there: the
/// folders named after a rule language (the list of
/// `src/rules/catalog.rs::RULE_LANGUAGES`) and the `.sca` files at its
/// top. Packs and any other entry are kept.
fn remove_copied_rules(target: &Path) {
    const RULE_LANGUAGES: [&str; 8] = [
        "csharp",
        "dockerfile",
        "html",
        "java",
        "javascript",
        "php",
        "python",
        "yaml",
    ];
    let Ok(entries) = fs::read_dir(target) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() && RULE_LANGUAGES.contains(&name.as_str()) {
            fs::remove_dir_all(&path).expect("emptying a language folder next to the binary");
        } else if file_type.is_file() && path.extension().is_some_and(|e| e == "sca") {
            fs::remove_file(&path).expect("removing a rule file next to the binary");
        }
    }
}

/// Generates `editor_release_data.rs` — see the file header docstring
/// for the unset/valid/malformed behavior.
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
