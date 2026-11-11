//! Puts the rule catalog pack `rules.scapack` next to the compiled
//! binary (ADR-0040): the engine reads its rules at run time from that
//! file, so `cargo build`/`cargo run`/the CLI tests need it beside
//! `target/<profile>/sast-engine`. No rule is embedded in the binary, and
//! the binary and its pack can be moved anywhere together.
//!
//! - In the private repository, `rules/builtin` holds the full catalog as
//!   plain `.sca` files: they are compiled into the pack, encrypted with
//!   the public demo key (`pack_format`).
//! - In the shared repository there is no `.sca` file: the demo pack
//!   `rules/rules.scapack`, written by `scripts/export_public_repo.sh`, is
//!   copied as it is.
//!
//! Also exports `SAST_BUILD_VERSION` (ticket #149).

use std::env;
use std::fs;
use std::path::Path;

// Only the encryption side is used here (decryption is a runtime
// concern): `#[allow(dead_code)]` on both modules rather than on each item.
#[path = "src/rules/rules_crypto.rs"]
#[allow(dead_code)]
mod rules_crypto;

// `pack_format.rs` reaches the crypto module as `super::rules_crypto`,
// which resolves to the module above here and to `crate::rules::
// rules_crypto` in the library.
#[path = "src/rules/pack_format.rs"]
#[allow(dead_code)]
mod pack_format;

#[path = "src/build_version.rs"]
mod build_version;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR absent");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR absent");

    write_catalog_pack(&manifest_dir, &out_dir);
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

/// Writes `rules.scapack` in the directory of the compiled binary.
/// `OUT_DIR` is `<target>/<profile>/build/<crate>-<hash>/out`, so that
/// directory is three levels up; it follows `CARGO_TARGET_DIR` and
/// `--target` on its own. Writing outside `OUT_DIR` is unusual for a build
/// script, but the binary looks for its pack next to itself, exactly as it
/// does once copied elsewhere.
///
/// Source: the `.sca` files of `rules/builtin` when there are any, else
/// the committed `rules/rules.scapack`. Neither is a build error: the
/// binary then stops at the first scan and names the missing pack. The
/// pack is deterministic (`pack_format::write_pack`), so a build with
/// unchanged rules rewrites the same bytes.
fn write_catalog_pack(manifest_dir: &str, out_dir: &str) {
    let rules = Path::new(manifest_dir).join("rules");
    let builtin = rules.join("builtin");
    let committed = rules.join(pack_format::PACK_FILE_NAME);
    // A directory is scanned recursively by Cargo: any added, removed or
    // edited rule file reruns this script.
    println!("cargo:rerun-if-changed={}", builtin.display());
    println!("cargo:rerun-if-changed={}", committed.display());

    let profile_dir = Path::new(out_dir)
        .ancestors()
        .nth(3)
        .expect("OUT_DIR is <target>/<profile>/build/<crate>/out");
    let dest = profile_dir.join(pack_format::PACK_FILE_NAME);

    let files = pack_format::collect_sca_sources(&builtin).unwrap_or_else(|e| panic!("{e}"));
    if !files.is_empty() {
        let pack = pack_format::write_pack("builtin", &files);
        fs::write(&dest, pack).expect("writing rules.scapack next to the binary");
    } else if committed.is_file() {
        fs::copy(&committed, &dest).expect("copying rules/rules.scapack next to the binary");
    } else {
        println!(
            "cargo:warning=no rule found: neither .sca files in {} nor {}",
            builtin.display(),
            committed.display()
        );
    }
}
