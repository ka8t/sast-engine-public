# Installation

Follow part A on a Mac, part B on Windows, then part C to update and part D for the results. Allow about 15 minutes if the tools are not installed yet.

Two tools are used:

| Tool | Job | When |
|---|---|---|
| `git` | downloads this repository into a local folder, then its updates | at installation, then for each update |
| `cargo` (Rust) | builds the engine from the downloaded code | after each download or update |

## Part A: macOS

Run every command in the **Terminal** app.

```bash
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

`xcode-select` installs `git` among other developer tools; `curl` installs Rust (`cargo`), press Enter when it asks. Close and reopen the Terminal, then download and build:

```bash
cd ~
git clone https://github.com/ka8t/sast-engine-public.git
cd sast-engine-public
cargo build --release
./target/release/sast-engine --version
./target/release/sast-engine scan /path/to/your/project --lang en
```

`git clone` copies the repository into a new local folder, `~/sast-engine-public`. `--version` prints the build, for example `sast-engine 0.1.0+42.c5be809`: the commit count and short commit hash tell exactly which code you built. Every scan prints it on its first line too.

## Part B: Windows

Run every command in **PowerShell**.

```powershell
winget install Git.Git
winget install Rustlang.Rustup
winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

Close and reopen PowerShell, then download and build:

```powershell
cd ~
git clone https://github.com/ka8t/sast-engine-public.git
cd sast-engine-public
cargo build --release
.\target\release\sast-engine.exe --version
.\target\release\sast-engine.exe scan C:\path\to\your\project --lang en
```

## Part C: updating

From your `sast-engine-public` folder:

```bash
git pull && cargo build --release
```

`git pull` downloads only the new commits into your local copy, like an incremental sync: no need to delete the folder and clone again. `cargo build --release` then rebuilds the binary. Windows PowerShell 5 does not accept `&&`: run `git pull`, then `cargo build --release`. Check with `--version`: the commit count must have grown.

If `git pull` refuses because of local changes, `git stash` sets them aside and `git pull` then works (`git stash pop` brings them back). To match GitHub exactly and drop your local edits for good: `git fetch origin` then `git reset --hard origin/main`.

## Part D: results

Every scan writes into the scanned folder, under `audit-reports/`. The terminal prints the report path on the `Report generated` line: open that file in a browser. Do not commit `audit-reports/`, because it contains the scan results. Scans never read this folder back as source code.

Versions before November 2026 wrote to `docs/audit-reports/`. The first scan after the upgrade still compares with the last export found there, then writes only to `audit-reports/`. You can delete the old folder afterwards.

## Choosing the languages checked

The demo rules are plain `.sca` files, one folder per language. `cargo build` copies them from `rules/builtin` to `target/release/rules/`, next to the engine, and every scan reads them there. A scan keeps only the rules of the project's languages, set by `languages` in the project's `audit.config.json`:

```json
{ "languages": ["python", "javascript"], "paths": { "include": ["src/"] } }
```

- Accepted values: `python`, `java`, `javascript`, `typescript` (same rules as `javascript`), `php`, `csharp`, `html`, `yaml`, `dockerfile`. The Dockerfile rules are always added.
- Without `languages`, the scan reads the rules of the languages of the files it finds.
- On the first run in a terminal, the engine offers to create `audit.config.json` with the languages it detects. If you later add code in another language, add it to `languages`: until then, its files are checked by no rule, and every scan says so in a warning.

Each scan then prints what it loaded (`--quiet` hides these lines, not the warnings):

```text
[sast-engine] Rules: 305/708 file(s) kept for the project's languages, in /path/to/target/release/rules
[sast-engine]   pack acme.scapack (official, signed by CodeFixture): 708 rule file(s)
[sast-engine] 303 rule(s) loaded for languages: java, javascript
```

## Installing the full rule catalog

You receive two files from CodeFixture: a rule pack, `<name>.scapack`, encrypted for you and signed, and your key file, `sast-engine.key`.

1. Copy the pack into `target/release/rules/`, next to the engine. Builds never remove it.
2. Copy `sast-engine.key` next to the engine, in `target/release/`. You can instead pass it with `--key-file /path/to/sast-engine.key`, or put its content in the `SAST_ENGINE_KEY` environment variable.
3. Run `sast-engine rules key`: it prints your client name and the key fingerprint, never the key.

The next scan shows the pack on its `pack` line. Without the right key, the scan says which pack needs another key and keeps the demo rules. For a rule update, replace the pack with the new one.

`cargo clean` deletes `target/` with everything in it, your pack and key included. Keep a copy elsewhere, or keep them out of `target/` and point the engine at them with `--rules` and `--key-file`.

## Writing your own rules

Put your own `.sca` files in `~/.sast-engine/custom-rules/` (`%USERPROFILE%\.sast-engine\custom-rules\` on Windows), one folder per language as in `rules/builtin`. Every scan loads them in addition to the catalog, and the report labels their findings as your own rules. No build, update or `cargo clean` touches that folder. `--custom-rules-dir` points to another one.
