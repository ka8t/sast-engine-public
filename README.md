# sast-engine

Security scanner for source code by [CodeFixture](https://codefixture.com). It analyzes Python, Java, JavaScript/TypeScript, PHP, C#, HTML, YAML and Dockerfile sources, including data-flow (taint) analysis, and writes an HTML report.

This repository holds the complete engine and a sample of its detection rules. The analysis runs on your machine: your code never leaves it.

## Analyse a folder

Once the engine is built (see below), run from the `sast-engine-public` folder, replacing the path with the folder of your code:

macOS:

```bash
./target/release/sast-engine scan /path/to/your/project --lang en
```

Windows (PowerShell):

```powershell
.\target\release\sast-engine.exe scan C:\path\to\your\project --lang en
```

- `--lang` sets the report language: `en`, `fr`, `es` or `de`.
- If you received `advisories.sadb`, add `--with-deps` to also check your dependencies against published vulnerabilities (see [step 6](INSTALLATION.md#step-6-add-the-full-catalog-and-the-vulnerability-database-optional)).
- The first run on a project asks what to analyse and writes `audit.config.json`; run the same command again for the analysis.
- The report is written into your project, under `audit-reports/`: the terminal prints its path on the `Report generated` line. Open it in a browser.

## First installation

From nothing installed to the first analysis, in a terminal (macOS):

```bash
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# close and reopen the Terminal, then:
cd ~
git clone https://github.com/ka8t/sast-engine-public.git
cd sast-engine-public
cargo build --release
./target/release/sast-engine scan /path/to/your/project --lang en
```

Windows (PowerShell):

```powershell
winget install Git.Git
winget install Rustlang.Rustup
winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
# close and reopen PowerShell, then:
cd ~
git clone https://github.com/ka8t/sast-engine-public.git
cd sast-engine-public
cargo build --release
.\target\release\sast-engine.exe scan C:\path\to\your\project --lang en
```

[`INSTALLATION.md`](INSTALLATION.md) takes you step by step from download to a full analysis of your own code: installing the tools, building the engine, describing your project, running the analysis, reading the report (your code, the proposed fix, the data-flow path) and analysing again after a fix.

The sample rules come compiled into one file, `rules/rules.scapack`: the engine you build uses it at once, and the two can be moved anywhere together. Each scan keeps only the rules of the scanned project's languages: see [step 7](INSTALLATION.md#step-7-describe-your-project-first-run).

## Already installed?

From your `sast-engine-public` folder:

```bash
git pull
cargo build --release
```

With the full rule catalog, copy `rules.scapack` (and `advisories.sadb`) next to the engine again afterwards: see [step 11](INSTALLATION.md#step-11-update-the-engine).

## Full rule catalog

The sample covers a small part of what the engine detects. The full catalog has more than 700 rules and is available from [CodeFixture](https://codefixture.com), with its updates, as a rule pack that replaces the sample one: see [step 6](INSTALLATION.md#step-6-add-the-full-catalog-and-the-vulnerability-database-optional).

## License

Proprietary evaluation license — see [`LICENSE`](LICENSE). You may build and test the engine to evaluate it; any other use, including within a company, requires an agreement with [CodeFixture](https://codefixture.com).
