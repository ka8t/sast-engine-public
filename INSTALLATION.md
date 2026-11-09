# Installation

Follow part A on a Mac, part B on Windows, then part C. Allow about 15 minutes if the tools are not installed yet.

## Part A: macOS

Run every command in the **Terminal** app.

```bash
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Close and reopen the Terminal. From the folder of this repository:

```bash
cargo build --release
./target/release/sast-engine scan /path/to/your/project --lang en
```

## Part B: Windows

Run every command in **PowerShell**.

```powershell
winget install Rustlang.Rustup
winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

Close and reopen PowerShell. From the folder of this repository:

```powershell
cargo build --release
.\target\release\sast-engine.exe scan C:\path\to\your\project --lang en
```

## Part C: results

Every scan writes into the scanned folder, under `audit-reports/`. The terminal prints the report path on the `Report generated` line: open that file in a browser. Do not commit `audit-reports/`, because it contains the scan results. Scans never read this folder back as source code.

Versions before November 2026 wrote to `docs/audit-reports/`. The first scan after the upgrade still compares with the last export found there, then writes only to `audit-reports/`. You can delete the old folder afterwards.

## Installing the full rule catalog

You receive `rules-full.tar.gz` from CodeFixture. From the folder of this repository:

```bash
rm -rf rules/builtin
tar -xzmf /path/to/rules-full.tar.gz
cargo build --release
```

On Windows, replace the first line with `Remove-Item -Recurse -Force rules\builtin`. Repeat these steps for each rule update.
