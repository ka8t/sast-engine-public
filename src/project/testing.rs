//! Runs the audited project's unit tests — ported from the
//! *test execution* part of `Audit/sca/testing.py`
//! (`_auto_detect_test_command`/`_run_tests_sequential`/
//! `_parse_pytest_output`).
//!
//! **Deliberately not ported**: `_validate_fixtures` and its whole
//! apparatus (`_test_fixture_core`, mtime-based incremental cache,
//! `ProcessPoolExecutor` parallelization, retries) — this isn't a
//! client-facing feature, it's Audit's **internal** QA tooling
//! that runs Audit against its own fixture corpus to validate the
//! quality of its rules. On the AuditRust side,
//! this same discipline already exists natively via `cargo test` and
//! `tests/fixtures/sca/` (100% pass rate tracked as a gauge). Reimplementing
//! this machinery as a feature of the distributed binary
//! would duplicate this discipline with no clear benefit for an
//! end user of `sast-engine scan` — to revisit only if
//! an explicit `--self-test` mode is requested.
//!
//! Runs arbitrary code from the audited project (its own test
//! suite) — opt-in capability only, never run without explicit
//! request (mirrors `--with-tests` on the Python side).

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use fancy_regex::Regex;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TestResults {
    pub passed: usize,
    pub failed: usize,
    pub errors: usize,
    pub skipped: usize,
    pub total: usize,
    pub duration: f64,
    pub success_rate: f64,
    pub failed_tests: Vec<String>,
    pub error_tests: Vec<String>,
}

fn has_glob_match(root: &Path, pattern_suffix: &str) -> bool {
    // Minimal port of glob.glob(recursive=True) for the few patterns
    // actually used by _auto_detect_test_command (recursive file
    // extension) — not a general glob engine.
    fn walk(dir: &Path, suffix: &str, depth: u32) -> bool {
        if depth > 12 {
            return false;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path
                    .file_name()
                    .is_some_and(|n| n == "node_modules" || n == ".git")
                {
                    continue;
                }
                if walk(&path, suffix, depth + 1) {
                    return true;
                }
            } else if path.to_string_lossy().ends_with(suffix) {
                return true;
            }
        }
        false
    }
    walk(root, pattern_suffix, 0)
}

/// Auto-detects the audited project's test command — a port of
/// `_auto_detect_test_command`.
pub fn auto_detect_test_command(root: &Path, languages: &[String]) -> Option<String> {
    let which = |bin: &str| -> bool { which::which(bin).is_ok() };

    if languages.iter().any(|l| l == "python") {
        let tests_dir = ["tests", "test"]
            .into_iter()
            .find(|d| root.join(d).is_dir());
        let tests_dir = tests_dir.or_else(|| {
            std::fs::read_dir(root).ok().and_then(|mut entries| {
                entries
                    .any(|e| {
                        e.ok().is_some_and(|e| {
                            let n = e.file_name();
                            let n = n.to_string_lossy();
                            n.starts_with("test_") && n.ends_with(".py")
                        })
                    })
                    .then_some(".")
            })
        });
        if let Some(tests_dir) = tests_dir {
            if which("python3") {
                return Some(format!("python3 -m pytest {tests_dir} -v --tb=short"));
            }
            if which("python") {
                return Some(format!("python -m pytest {tests_dir} -v --tb=short"));
            }
        }
    }

    if languages.iter().any(|l| l == "javascript") {
        let has_tests = root.join("__tests__").is_dir()
            || has_glob_match(root, ".test.js")
            || has_glob_match(root, ".spec.js")
            || has_glob_match(root, ".test.ts")
            || has_glob_match(root, ".spec.ts");
        let pkg_json = root.join("package.json");
        if has_tests || pkg_json.exists() {
            if pkg_json.exists()
                && let Ok(content) = std::fs::read_to_string(&pkg_json)
                && let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&content)
            {
                let test_script = pkg
                    .get("scripts")
                    .and_then(|s| s.get("test"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !test_script.is_empty()
                    && !test_script.contains("no test specified")
                    && which("npm")
                {
                    return Some("npm test".to_string());
                }
            }
            if root.join("jest.config.js").exists()
                || root.join("jest.config.ts").exists()
                || root.join("jest.config.json").exists()
            {
                if which("npx") {
                    return Some("npx jest --passWithNoTests".to_string());
                }
            } else if (root.join("vitest.config.js").exists()
                || root.join("vitest.config.ts").exists())
                && which("npx")
            {
                return Some("npx vitest run".to_string());
            }
        }
    }

    if languages.iter().any(|l| l == "java") {
        let has_tests = root.join("src").join("test").is_dir() || has_glob_match(root, "Test.java");
        if has_tests {
            if root.join("pom.xml").exists() && which("mvn") {
                return Some("mvn test -B".to_string());
            }
            for gf in ["build.gradle", "build.gradle.kts"] {
                if root.join(gf).exists() && which("gradle") {
                    return Some("gradle test".to_string());
                }
            }
        }
    }

    if languages.iter().any(|l| l == "php") {
        let has_tests = root.join("tests").is_dir() || has_glob_match(root, "Test.php");
        if has_tests {
            let phpunit = root.join("vendor").join("bin").join("phpunit");
            if phpunit.exists() {
                return Some("vendor/bin/phpunit".to_string());
            }
        }
    }

    if languages.iter().any(|l| l == "csharp") {
        let has_tests = has_glob_match(root, ".Tests") || has_glob_match(root, "Test.cs");
        if has_tests && which("dotnet") {
            return Some("dotnet test".to_string());
        }
    }

    None
}

/// Runs the test command in `root` (5 min timeout, mirroring Python)
/// and parses its output — a port of `_run_tests_sequential` +
/// `_parse_pytest_output`. Doesn't shell out the command (`sh -c`): it
/// is split into argv like `shlex.split` on the Python side (no shell
/// injection via the configured/detected command).
pub fn run_tests(root: &Path, command: &str, timeout: Duration) -> Result<TestResults, String> {
    let args =
        shell_words::split(command).map_err(|e| format!("commande de test invalide: {e}"))?;
    let Some((program, args)) = args.split_first() else {
        return Err("commande de test vide".to_string());
    };

    let output = run_with_timeout(program, args, root, timeout)?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if !output.status.success() && !combined.contains("passed") && !combined.contains("failed") {
        let first_stderr_line = String::from_utf8_lossy(&output.stderr)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        let error_msg = if first_stderr_line.is_empty() {
            format!("exit code {}", output.status.code().unwrap_or(-1))
        } else {
            first_stderr_line
        };
        return Err(format!("la commande de test a échoué: {error_msg}"));
    }

    Ok(parse_pytest_output(&combined))
}

fn run_with_timeout(
    program: &str,
    args: &[String],
    cwd: &Path,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("impossible de lancer {program}: {e}"))?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().map_err(|e| e.to_string()),
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("délai dépassé ({}s)", timeout.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Parses pytest output (summary line `=== X passed, Y failed in
/// Zs ===`) — a port of `_parse_pytest_output`.
pub fn parse_pytest_output(output: &str) -> TestResults {
    let mut results = TestResults::default();

    let summary_re = Regex::new(r"(?m)={2,}\s*(.*?)\s*={2,}\s*$").expect("pattern résumé valide");
    let summary_line = summary_re
        .captures(output)
        .ok()
        .flatten()
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    if !summary_line.is_empty() {
        results.passed = capture_count(&summary_line, r"(\d+)\s+passed");
        results.failed = capture_count(&summary_line, r"(\d+)\s+failed");
        results.errors = capture_count(&summary_line, r"(\d+)\s+error");
        results.skipped = capture_count(&summary_line, r"(\d+)\s+skipped");
        results.duration = Regex::new(r"in\s+([\d.]+)s")
            .ok()
            .and_then(|re| re.captures(&summary_line).ok().flatten())
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0.0);
    }

    if results.passed == 0 && results.failed == 0 {
        results.passed = count_matches(output, r"\bPASSED\b");
        results.failed = count_matches(output, r"\bFAILED\b");
        results.errors = count_matches(output, r"\bERROR\b");
    }

    results.total = results.passed + results.failed + results.errors + results.skipped;
    if results.total > 0 {
        results.success_rate =
            (results.passed as f64 / results.total as f64 * 1000.0).round() / 10.0;
    }

    if results.failed > 0 {
        results.failed_tests = find_all(output, r"(tests/\S+::\S+)\s+FAILED")
            .into_iter()
            .take(10)
            .collect();
    }
    if results.errors > 0 {
        results.error_tests = find_all(output, r"(tests/\S+::\S+)\s+ERROR")
            .into_iter()
            .take(10)
            .collect();
    }

    results
}

fn capture_count(text: &str, pattern: &str) -> usize {
    Regex::new(pattern)
        .ok()
        .and_then(|re| re.captures(text).ok().flatten())
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok())
        .unwrap_or(0)
}

fn count_matches(text: &str, pattern: &str) -> usize {
    Regex::new(pattern)
        .map(|re| re.find_iter(text).filter_map(|m| m.ok()).count())
        .unwrap_or(0)
}

fn find_all(text: &str, pattern: &str) -> Vec<String> {
    let Ok(re) = Regex::new(pattern) else {
        return vec![];
    };
    re.captures_iter(text)
        .filter_map(|c| c.ok())
        .filter_map(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pytest_summary_line() {
        let output = "collected 5 items\n\n===== 3 passed, 2 failed in 1.23s =====";
        let r = parse_pytest_output(output);
        assert_eq!(r.passed, 3);
        assert_eq!(r.failed, 2);
        assert_eq!(r.duration, 1.23);
        assert_eq!(r.total, 5);
        assert_eq!(r.success_rate, 60.0);
    }

    #[test]
    fn test_parse_pytest_all_passed() {
        let output = "===== 10 passed in 0.5s =====";
        let r = parse_pytest_output(output);
        assert_eq!(r.passed, 10);
        assert_eq!(r.failed, 0);
        assert_eq!(r.success_rate, 100.0);
    }

    #[test]
    fn test_parse_pytest_fallback_without_summary_line() {
        let output = "tests/test_a.py::test_x PASSED\ntests/test_b.py::test_y FAILED\n";
        let r = parse_pytest_output(output);
        assert_eq!(r.passed, 1);
        assert_eq!(r.failed, 1);
    }

    #[test]
    fn test_parse_pytest_extracts_failed_test_names() {
        let output = "tests/test_a.py::test_x FAILED\n===== 0 passed, 1 failed in 0.1s =====";
        let r = parse_pytest_output(output);
        assert_eq!(r.failed_tests, vec!["tests/test_a.py::test_x".to_string()]);
    }

    #[test]
    fn test_auto_detect_python_pytest_dir() {
        let tmp = std::env::temp_dir().join(format!("auditrust-testdetect-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("tests")).unwrap();
        let cmd = auto_detect_test_command(&tmp, &["python".to_string()]);
        assert!(cmd.is_some());
        assert!(cmd.unwrap().contains("pytest"));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_auto_detect_no_match_returns_none() {
        let tmp =
            std::env::temp_dir().join(format!("auditrust-testdetect-empty-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let cmd = auto_detect_test_command(&tmp, &["python".to_string()]);
        assert!(cmd.is_none());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_run_tests_reports_timeout() {
        let tmp = std::env::temp_dir();
        let result = run_tests(&tmp, "sleep 5", Duration::from_millis(100));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("délai"));
    }

    #[test]
    fn test_run_tests_parses_real_command_output() {
        let tmp = std::env::temp_dir();
        let result = run_tests(
            &tmp,
            "echo '===== 2 passed in 0.1s ====='",
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(result.passed, 2);
    }
}
