//! Packs the rule catalog (`rules/builtin/**/*.sca`) into
//! `rules/builtin.scapack` next to the compiled binary (ADR-0037,
//! ticket #141): the engine loads its rules at run time from encrypted
//! packs, so `cargo build`/`cargo run`/the CLI tests need that pack
//! beside `target/<profile>/sast-engine`. The pack is encrypted with the
//! public demo key (`pack_format::demo_key`); no rule source is embedded
//! in the binary any more (it was, encrypted, since ticket #65).
//!
//! In this repository the pack holds the full catalog, for development
//! only. What is sold travels in packs encrypted with a per-client key
//! (ADR-0037, `tools/sast-keys`). In the shared repository `rules/builtin`
//! holds the demo rules only, so the same build writes the demo pack.
//!
//! Also generates `$OUT_DIR/editor_release_data.rs` (ticket #85/spec
//! #82): the publisher Ed25519 public key, used by `src/rules/rule_packs.rs`
//! to verify the signature of rule update pack manifests.
//! `SAST_EDITOR_PUBLIC_KEY_HEX`
//! carries the hex value directly (not a file path) — a lone public key
//! does not justify an intermediate file. Variable unset → `None` static, same philosophy as above (no
//! possible failure for this reason). Variable set but malformed (not 64
//! hex characters) → explicit panic at compile time.

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

    write_builtin_pack(&manifest_dir, &out_dir);
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

/// Writes `rules/builtin.scapack` in the directory of the compiled
/// binary. `OUT_DIR` is `<target>/<profile>/build/<crate>-<hash>/out`, so
/// that directory is three levels up; it follows `CARGO_TARGET_DIR` and
/// `--target` on its own. Writing outside `OUT_DIR` is unusual for a build
/// script, but the binary looks for its packs next to itself, exactly as
/// it does in a client installation.
fn write_builtin_pack(manifest_dir: &str, out_dir: &str) {
    let rules_dir = Path::new(manifest_dir).join("rules").join("builtin");
    println!("cargo:rerun-if-changed={}", rules_dir.display());
    let files = pack_format::collect_sca_sources(&rules_dir);
    for (rel, _) in &files {
        println!("cargo:rerun-if-changed={}", rules_dir.join(rel).display());
    }

    let profile_dir = Path::new(out_dir)
        .ancestors()
        .nth(3)
        .expect("OUT_DIR is <target>/<profile>/build/<crate>/out");
    let packs_dir = profile_dir.join("rules");
    fs::create_dir_all(&packs_dir).expect("creating the rules/ folder next to the binary");
    let pack = pack_format::write_pack("builtin", &files, &pack_format::demo_key());
    fs::write(packs_dir.join("builtin.scapack"), pack).expect("writing rules/builtin.scapack");
}

/// Generates `editor_release_data.rs` — see the file header docstring
/// for the unset/valid/malformed behavior. The environment variable
/// carries the hex value directly (not a file path): a 32-byte public key needs
/// neither an intermediate file nor a dedicated JSON format.
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
