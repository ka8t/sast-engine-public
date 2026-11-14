# sast-engine

Security scanner for source code by [CodeFixture](https://codefixture.com). It analyzes Python, Java, JavaScript/TypeScript, PHP, C#, HTML, YAML and Dockerfile sources, including data-flow (taint) analysis, and writes an HTML report.

This repository holds the complete engine and a sample of its detection rules. The analysis runs on your machine: your code never leaves it.

[`INSTALLATION.md`](INSTALLATION.md) takes you step by step from download to a full analysis of your own code: installing the tools, building the engine, describing your project, running the analysis, reading the report (your code, the proposed fix, the data-flow path) and analysing again after a fix.

The sample rules come compiled into one file, `rules/rules.scapack`: the engine you build uses it at once, and the two can be moved anywhere together. Each scan keeps only the rules of the scanned project's languages: see [step 7](INSTALLATION.md#step-7-describe-your-project-first-run).

## Full rule catalog

The sample covers a small part of what the engine detects. The full catalog has more than 700 rules and is available from [CodeFixture](https://codefixture.com), with its updates, as a rule pack that replaces the sample one: see [step 6](INSTALLATION.md#step-6-add-the-full-catalog-and-the-vulnerability-database-optional).

## License

Proprietary evaluation license — see [`LICENSE`](LICENSE). You may build and test the engine to evaluate it; any other use, including within a company, requires an agreement with [CodeFixture](https://codefixture.com).
