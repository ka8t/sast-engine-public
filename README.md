# sast-engine

Security scanner for source code by [CodeFixture](https://codefixture.com). It analyzes Python, Java, JavaScript/TypeScript, PHP, C#, HTML, YAML and Dockerfile sources, including data-flow (taint) analysis, and writes an HTML report.

This repository holds the complete engine and a sample of its detection rules. To build and run it, follow [`INSTALLATION.md`](INSTALLATION.md).

The rules are plain `.sca` files read at each scan, only for the languages of the scanned project: see [Choosing the languages checked](INSTALLATION.md#choosing-the-languages-checked).

## Full rule catalog

The sample covers a small part of what the engine detects. The full catalog has more than 700 rules and is available from [CodeFixture](https://codefixture.com), with its updates.

## License

Proprietary evaluation license — see [`LICENSE`](LICENSE). You may build and test the engine to evaluate it; any other use, including within a company, requires an agreement with [CodeFixture](https://codefixture.com).
