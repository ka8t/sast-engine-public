//! Detection of unpinned dependencies (`unpinned_dependency`) and
//! license compliance — port of the **static** part of
//! `Audit/sca/dependencies.py` (manifest parsers + unpinned
//! detection + license checking).
//!
//! **Deliberately not ported** (decision of 2026-08-25, cf. memory
//! `project_no_dependency_scanning`): `_check_dependency_tools`/
//! `_scan_with_pip_audit`/`_scan_with_npm_audit` — CVE matching
//! via `pip-audit`/`npm audit` as a subprocess. These optional
//! third-party tools query public databases by default (PyPI JSON
//! API, OSV.dev, npm registry), i.e. outbound network access — the maintainer
//! chose to stay cautious for this specific piece of work and to
//! port only the static detection.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use regex::Regex;

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    /// `None` = unpinned dependency (`unpinned_dependency`).
    pub version: Option<String>,
    pub ecosystem: String,
    pub file: PathBuf,
    pub line: usize,
    pub raw_line: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepFileType {
    Requirements,
    PackageJson,
    PomXml,
    BuildGradle,
    Csproj,
    ComposerJson,
}

fn read_lines(path: &Path) -> Vec<(usize, String)> {
    std::fs::read_to_string(path)
        .map(|content| {
            content
                .lines()
                .enumerate()
                .map(|(i, l)| (i + 1, l.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

const ROOT_DEP_FILES: [(&str, DepFileType); 5] = [
    ("requirements.txt", DepFileType::Requirements),
    ("pyproject.toml", DepFileType::Requirements),
    ("pom.xml", DepFileType::PomXml),
    ("build.gradle", DepFileType::BuildGradle),
    ("composer.json", DepFileType::ComposerJson),
];

fn add_root_files(
    base: &Path,
    dep_files: &mut Vec<(PathBuf, DepFileType)>,
    seen: &mut std::collections::BTreeSet<PathBuf>,
) {
    for (filename, file_type) in ROOT_DEP_FILES {
        let filepath = normalize(&base.join(filename));
        if filepath.exists() && seen.insert(filepath.clone()) {
            dep_files.push((filepath, file_type));
        }
    }
    for entry in glob_csproj(base) {
        let entry = normalize(&entry);
        if seen.insert(entry.clone()) {
            dep_files.push((entry, DepFileType::Csproj));
        }
    }
    for entry in glob_requirements_dir(base) {
        let entry = normalize(&entry);
        if seen.insert(entry.clone()) {
            dep_files.push((entry, DepFileType::Requirements));
        }
    }
}

/// Finds the dependency manifest files of the audited project —
/// port of `_find_dependency_files`.
pub fn find_dependency_files(
    root_dir: &Path,
    include_paths: &[String],
) -> Vec<(PathBuf, DepFileType)> {
    let mut dep_files = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    add_root_files(root_dir, &mut dep_files, &mut seen);

    for base_path in include_paths {
        let full_path = root_dir.join(base_path);
        if !full_path.exists() {
            continue;
        }
        add_root_files(&full_path, &mut dep_files, &mut seen);

        let pkg_json = normalize(&full_path.join("package.json"));
        if pkg_json.exists() && seen.insert(pkg_json.clone()) {
            dep_files.push((pkg_json, DepFileType::PackageJson));
        }
    }

    dep_files
}

fn normalize(path: &Path) -> PathBuf {
    // `Path::components()` already eliminates "." segments (unlike a
    // plain string concatenation) — a sufficient equivalent
    // to `os.path.normpath` for the use `_find_dependency_files` makes
    // of it (deduplicating "root/./requirements.txt" and "root/requirements.txt").
    path.components().collect()
}

fn glob_csproj(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "csproj"))
                .collect()
        })
        .unwrap_or_default()
}

fn glob_requirements_dir(dir: &Path) -> Vec<PathBuf> {
    let req_dir = dir.join("requirements");
    std::fs::read_dir(&req_dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "txt"))
                .collect()
        })
        .unwrap_or_default()
}

/// Port of `_parse_requirements_txt` (delegates to
/// `parse_pyproject_toml` for that specific file, like Python).
pub fn parse_requirements_txt(path: &Path) -> Vec<Dependency> {
    if path.file_name().is_some_and(|n| n == "pyproject.toml") {
        return parse_pyproject_toml(path);
    }
    let name_ver_re = Regex::new(r"^([a-zA-Z0-9_.-]+)\s*==\s*([0-9][0-9a-zA-Z.*]*)").unwrap();
    let name_re = Regex::new(r"^([a-zA-Z0-9_.-]+)").unwrap();
    let ver_re = Regex::new(r"[>=~<]+\s*([0-9][0-9a-zA-Z.*]*)").unwrap();

    let mut deps = Vec::new();
    for (line_num, line) in read_lines(path) {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') || stripped.starts_with('-') {
            continue;
        }
        if let Some(caps) = name_ver_re.captures(stripped) {
            deps.push(Dependency {
                name: caps[1].to_lowercase(),
                version: Some(caps[2].to_string()),
                ecosystem: "PyPI".to_string(),
                file: path.to_path_buf(),
                line: line_num,
                raw_line: stripped.to_string(),
            });
        } else if let Some(name_caps) = name_re.captures(stripped) {
            let version = ver_re.captures(stripped).map(|c| c[1].to_string());
            deps.push(Dependency {
                name: name_caps[1].to_lowercase(),
                version,
                ecosystem: "PyPI".to_string(),
                file: path.to_path_buf(),
                line: line_num,
                raw_line: stripped.to_string(),
            });
        }
    }
    deps
}

/// Port of `_parse_pyproject_toml` (simplified extraction, not a
/// real TOML parser — same choice as Python).
pub fn parse_pyproject_toml(path: &Path) -> Vec<Dependency> {
    let deps_section_re = Regex::new(r"^dependencies\s*=\s*\[").unwrap();
    let with_version_re =
        Regex::new(r#"^\s*"([a-zA-Z0-9_.-]+)\s*(==|>=|~=|<=)\s*([0-9][0-9a-zA-Z.*]*)"#).unwrap();
    let name_only_re = Regex::new(r#"^\s*"([a-zA-Z0-9_.-]+)""#).unwrap();

    let mut deps = Vec::new();
    let mut in_deps_section = false;
    for (line_num, line) in read_lines(path) {
        let stripped = line.trim();
        if deps_section_re.is_match(stripped) {
            in_deps_section = true;
            continue;
        }
        if !in_deps_section {
            continue;
        }
        if stripped == "]" {
            in_deps_section = false;
            continue;
        }
        if let Some(caps) = with_version_re.captures(stripped) {
            deps.push(Dependency {
                name: caps[1].to_lowercase(),
                version: Some(caps[3].to_string()),
                ecosystem: "PyPI".to_string(),
                file: path.to_path_buf(),
                line: line_num,
                raw_line: stripped
                    .trim_matches(|c| c == '"' || c == ',')
                    .trim()
                    .to_string(),
            });
        } else if let Some(caps) = name_only_re.captures(stripped) {
            deps.push(Dependency {
                name: caps[1].to_lowercase(),
                version: None,
                ecosystem: "PyPI".to_string(),
                file: path.to_path_buf(),
                line: line_num,
                raw_line: stripped
                    .trim_matches(|c| c == '"' || c == ',')
                    .trim()
                    .to_string(),
            });
        }
    }
    deps
}

fn build_line_map(lines: &[(usize, String)]) -> BTreeMap<String, usize> {
    let re = Regex::new(r#""([^"]+)"\s*:\s*"([^"]*)""#).unwrap();
    let mut map = BTreeMap::new();
    for (line_num, line) in lines {
        if let Some(caps) = re.captures(line) {
            map.entry(caps[1].to_string()).or_insert(*line_num);
        }
    }
    map
}

/// Port of `_parse_package_json`.
pub fn parse_package_json(path: &Path) -> Vec<Dependency> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&content) else {
        return vec![];
    };

    let lines = read_lines(path);
    let line_map = build_line_map(&lines);
    let prefix_re = Regex::new(r"^[\^~>=<]*").unwrap();
    let mut deps = Vec::new();
    for section in ["dependencies", "devDependencies"] {
        let Some(serde_json::Value::Object(section_deps)) = pkg.get(section) else {
            continue;
        };
        for (name, version_spec) in section_deps {
            let version_spec_str = version_spec.as_str().unwrap_or_default();
            let clean_version = prefix_re.replace(version_spec_str, "").trim().to_string();
            // Unpinned if the result is not a numeric version
            // (not necessarily a full x.y.z semver — exact mirror of
            // `clean_version[0].isdigit()` on the Python side, not a
            // strict `is_pinned` check, which is computed but never
            // used in `_parse_package_json`).
            let version = if !clean_version.is_empty()
                && clean_version.chars().next().unwrap().is_ascii_digit()
            {
                Some(clean_version.clone())
            } else {
                None
            };
            deps.push(Dependency {
                name: name.clone(),
                version,
                ecosystem: "npm".to_string(),
                file: path.to_path_buf(),
                line: *line_map.get(name).unwrap_or(&0),
                raw_line: format!("\"{name}\": \"{version_spec_str}\""),
            });
        }
    }
    deps
}

/// Port of `_parse_pom_xml` (regex over raw text, not an
/// XML parser — same choice as Python).
pub fn parse_pom_xml(path: &Path) -> Vec<Dependency> {
    let lines = read_lines(path);
    let content = lines
        .iter()
        .map(|(_, l)| l.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    let dep_block_re = Regex::new(r"(?s)<dependency>(.*?)</dependency>").unwrap();
    let group_id_re = Regex::new(r"<groupId>(.*?)</groupId>").unwrap();
    let artifact_id_re = Regex::new(r"<artifactId>(.*?)</artifactId>").unwrap();
    let version_re = Regex::new(r"<version>(.*?)</version>").unwrap();
    let pinned_re = Regex::new(r"^[0-9][0-9a-zA-Z._-]*$").unwrap();

    let mut deps = Vec::new();
    for block_caps in dep_block_re.captures_iter(&content) {
        let block = &block_caps[1];
        let Some(artifact_id) = artifact_id_re.captures(block) else {
            continue;
        };
        let artifact_id = artifact_id[1].to_string();
        let group_id = group_id_re.captures(block).map(|c| c[1].to_string());
        let name = match &group_id {
            Some(g) => format!("{g}:{artifact_id}"),
            None => artifact_id.clone(),
        };
        let raw_version = version_re.captures(block).map(|c| c[1].trim().to_string());

        let line_num = lines
            .iter()
            .find(|(_, l)| l.contains(&artifact_id))
            .map(|(n, _)| *n)
            .unwrap_or(0);

        let is_pinned = raw_version
            .as_deref()
            .is_some_and(|v| pinned_re.is_match(v) && !v.contains("${"));
        let version = if is_pinned { raw_version.clone() } else { None };
        deps.push(Dependency {
            name,
            version,
            ecosystem: "Maven".to_string(),
            file: path.to_path_buf(),
            line: line_num,
            raw_line: format!(
                "{} {}",
                deps_name_placeholder(&group_id, &artifact_id),
                raw_version.as_deref().unwrap_or("(no version)")
            ),
        });
    }
    deps
}

fn deps_name_placeholder(group_id: &Option<String>, artifact_id: &str) -> String {
    match group_id {
        Some(g) => format!("{g}:{artifact_id}"),
        None => artifact_id.to_string(),
    }
}

/// Port of `_parse_build_gradle`.
pub fn parse_build_gradle(path: &Path) -> Vec<Dependency> {
    let quoted_re = Regex::new(
        r#"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+['"]([^'"]+:[^'"]+):([^'"]+)['"]"#,
    )
    .unwrap();
    let paren_re = Regex::new(
        r#"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(\s*"([^"]+:[^"]+):([^"]+)""#,
    )
    .unwrap();
    let pinned_re = Regex::new(r"^[0-9][0-9a-zA-Z._-]*$").unwrap();

    let mut deps = Vec::new();
    for (line_num, line) in read_lines(path) {
        let stripped = line.trim();
        let caps = quoted_re
            .captures(stripped)
            .or_else(|| paren_re.captures(stripped));
        if let Some(caps) = caps {
            let name = caps[1].to_string();
            let version = caps[2].trim().to_string();
            let is_pinned = pinned_re.is_match(&version);
            deps.push(Dependency {
                name,
                version: if is_pinned { Some(version) } else { None },
                ecosystem: "Maven".to_string(),
                file: path.to_path_buf(),
                line: line_num,
                raw_line: stripped.to_string(),
            });
        }
    }
    deps
}

/// Port of `_parse_csproj`.
pub fn parse_csproj(path: &Path) -> Vec<Dependency> {
    let re =
        Regex::new(r#"<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]*)")?"#).unwrap();
    let pinned_re = Regex::new(r"^[0-9]+\.[0-9]+[0-9a-zA-Z._-]*$").unwrap();

    let mut deps = Vec::new();
    for (line_num, line) in read_lines(path) {
        if let Some(caps) = re.captures(&line) {
            let name = caps[1].to_string();
            let version = caps
                .get(2)
                .map(|m| m.as_str().trim().to_string())
                .filter(|v| !v.is_empty());
            let is_pinned = version
                .as_deref()
                .is_some_and(|v| pinned_re.is_match(v) && !v.contains('*') && !v.contains('['));
            deps.push(Dependency {
                name,
                version: if is_pinned { version } else { None },
                ecosystem: "NuGet".to_string(),
                file: path.to_path_buf(),
                line: line_num,
                raw_line: line.trim().to_string(),
            });
        }
    }
    deps
}

/// Port of `_parse_composer_json`.
pub fn parse_composer_json(path: &Path) -> Vec<Dependency> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) else {
        return vec![];
    };

    let lines = read_lines(path);
    let line_map = build_line_map(&lines);
    let prefix_re = Regex::new(r"^[\^~>=<|]*").unwrap();
    let pinned_re = Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+$").unwrap();

    let mut deps = Vec::new();
    for section in ["require", "require-dev"] {
        let Some(serde_json::Value::Object(section_deps)) = data.get(section) else {
            continue;
        };
        for (name, version_spec) in section_deps {
            if name == "php" || name.starts_with("ext-") {
                continue;
            }
            let version_spec_str = version_spec.as_str().unwrap_or_default();
            let clean_version = prefix_re.replace(version_spec_str, "").trim().to_string();
            let is_pinned = pinned_re.is_match(&clean_version);
            deps.push(Dependency {
                name: name.clone(),
                version: if is_pinned { Some(clean_version) } else { None },
                ecosystem: "Packagist".to_string(),
                file: path.to_path_buf(),
                line: *line_map.get(name).unwrap_or(&0),
                raw_line: format!("\"{name}\": \"{version_spec_str}\""),
            });
        }
    }
    deps
}

/// Parses a manifest file according to its type — single entry point
/// combining the 6 parsers (port of the `parsers` dict from
/// `_audit_dependencies`).
pub fn parse_dependency_file(path: &Path, file_type: DepFileType) -> Vec<Dependency> {
    match file_type {
        DepFileType::Requirements => parse_requirements_txt(path),
        DepFileType::PackageJson => parse_package_json(path),
        DepFileType::PomXml => parse_pom_xml(path),
        DepFileType::BuildGradle => parse_build_gradle(path),
        DepFileType::Csproj => parse_csproj(path),
        DepFileType::ComposerJson => parse_composer_json(path),
    }
}

/// Discovers and parses every dependency manifest of the audited
/// project: the root, plus each `paths.include` entry — mirrors
/// `_find_dependency_files` + the per-file parsers, as used both by
/// `_audit_dependencies` (`--with-deps`) and `_export_sbom` (`--sbom`)
/// on the Python side. Shared by both Rust consumers so they can never
/// disagree on which manifests make up the project.
///
/// `include_paths` is `ScanConfig::include_paths` (`["."]` by default).
/// Fix from 2026-11-04: the dependencies phase used to pass `&[]` here
/// (a leftover from before `ScanConfig::include_paths` existed), so a
/// `package.json` under an included subfolder (e.g. `frontend/`) was
/// never seen, unlike Python which walks `paths.include`.
pub fn collect_dependencies(root_dir: &Path, include_paths: &[String]) -> Vec<Dependency> {
    find_dependency_files(root_dir, include_paths)
        .iter()
        .flat_map(|(path, file_type)| parse_dependency_file(path, *file_type))
        .collect()
}

#[derive(Debug, Clone)]
pub struct LicenseIssue {
    pub file: PathBuf,
    pub license: String,
}

/// Checks the compliance of licenses declared in `package.json`/
/// `composer.json` against an allowed SPDX list — port of
/// `_check_licenses`.
pub fn check_licenses(
    dep_files: &[(PathBuf, DepFileType)],
    allowed: &[String],
) -> Vec<LicenseIssue> {
    if allowed.is_empty() {
        return vec![];
    }
    let allowed_upper: Vec<String> = allowed.iter().map(|l| l.to_uppercase()).collect();
    let mut issues = Vec::new();
    for (path, file_type) in dep_files {
        if !matches!(
            file_type,
            DepFileType::PackageJson | DepFileType::ComposerJson
        ) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };
        let Some(license) = data
            .get("license")
            .and_then(|v| v.as_str())
            .filter(|l| !l.is_empty())
        else {
            continue;
        };
        if !allowed_upper.contains(&license.to_uppercase()) {
            issues.push(LicenseIssue {
                file: path.clone(),
                license: license.to_string(),
            });
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(name: &str, content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("auditrust-deps-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_parse_requirements_txt_pinned_and_unpinned() {
        let path = write_tmp(
            "requirements.txt",
            "# comment\nDjango==4.2.1\nrequests>=2.0\nflask\n",
        );
        let deps = parse_requirements_txt(&path);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "django");
        assert_eq!(deps[0].version, Some("4.2.1".to_string()));
        assert_eq!(deps[1].name, "requests");
        assert_eq!(deps[1].version, Some("2.0".to_string()));
        assert_eq!(deps[2].name, "flask");
        assert_eq!(deps[2].version, None);
    }

    #[test]
    fn test_parse_pyproject_toml_dependencies_section() {
        let path = write_tmp(
            "pyproject.toml",
            "[project]\ndependencies = [\n  \"django==4.2.1\",\n  \"requests\",\n]\n",
        );
        let deps = parse_pyproject_toml(&path);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].version, Some("4.2.1".to_string()));
        assert_eq!(deps[1].version, None);
    }

    #[test]
    fn test_parse_package_json_strips_caret_prefix() {
        let path = write_tmp(
            "package.json",
            r#"{"dependencies": {"react": "^18.2.0"}, "devDependencies": {"jest": "*"}}"#,
        );
        let deps = parse_package_json(&path);
        let react = deps.iter().find(|d| d.name == "react").unwrap();
        assert_eq!(react.version, Some("18.2.0".to_string()));
        let jest = deps.iter().find(|d| d.name == "jest").unwrap();
        assert_eq!(jest.version, None);
    }

    #[test]
    fn test_parse_pom_xml_extracts_group_and_artifact() {
        let path = write_tmp(
            "pom.xml",
            "<dependency>\n<groupId>org.springframework</groupId>\n<artifactId>spring-core</artifactId>\n<version>5.3.20</version>\n</dependency>",
        );
        let deps = parse_pom_xml(&path);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "org.springframework:spring-core");
        assert_eq!(deps[0].version, Some("5.3.20".to_string()));
    }

    #[test]
    fn test_parse_pom_xml_placeholder_version_is_unpinned() {
        let path = write_tmp(
            "pom2.xml",
            "<dependency>\n<artifactId>lib</artifactId>\n<version>${lib.version}</version>\n</dependency>",
        );
        let deps = parse_pom_xml(&path);
        assert_eq!(deps[0].version, None);
    }

    #[test]
    fn test_parse_build_gradle_quoted_form() {
        let path = write_tmp(
            "build.gradle",
            "implementation 'com.google.guava:guava:31.1-jre'\napi \"org.slf4j:slf4j-api:+\"\n",
        );
        let deps = parse_build_gradle(&path);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].version, Some("31.1-jre".to_string()));
        assert_eq!(deps[1].version, None); // "+" is not a valid pin
    }

    #[test]
    fn test_parse_csproj_package_reference() {
        let path = write_tmp(
            "test.csproj",
            r#"<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />"#,
        );
        let deps = parse_csproj(&path);
        assert_eq!(deps[0].version, Some("13.0.1".to_string()));
    }

    #[test]
    fn test_parse_composer_json_ignores_php_and_ext() {
        let path = write_tmp(
            "composer.json",
            r#"{"require": {"php": ">=8.0", "ext-json": "*", "monolog/monolog": "2.5.0"}}"#,
        );
        let deps = parse_composer_json(&path);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "monolog/monolog");
    }

    #[test]
    fn test_find_dependency_files_root_requirements() {
        let dir = std::env::temp_dir().join(format!("auditrust-deps-find-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("requirements.txt"), "django==4.0\n").unwrap();
        let files = find_dependency_files(&dir, &[]);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].1, DepFileType::Requirements);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_check_licenses_flags_disallowed() {
        let path = write_tmp("pkg_with_license.json", r#"{"license": "GPL-3.0"}"#);
        let issues = check_licenses(&[(path, DepFileType::PackageJson)], &["MIT".to_string()]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].license, "GPL-3.0");
    }

    #[test]
    fn test_check_licenses_empty_allowlist_skips_check() {
        let path = write_tmp("pkg_with_license2.json", r#"{"license": "GPL-3.0"}"#);
        let issues = check_licenses(&[(path, DepFileType::PackageJson)], &[]);
        assert!(issues.is_empty());
    }
}
