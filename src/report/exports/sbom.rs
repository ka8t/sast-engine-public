//! CycloneDX SBOM export.
//!
//! Version **1.6** (latest CycloneDX spec to date). Reproduces exactly
//! the structure and scope of the current client-facing SBOM on the
//! Python side (`Audit/sca/comparison.py`, CycloneDX 1.5) — only the
//! `specVersion` value changes. Fields deliberately absent here
//! because they are absent on the Python side today: component hash,
//! license. Adding them would be a new SAST feature, out of scope for
//! this port (cf. "Initial out-of-scope", plan §0).
//!
//! Wired to the CLI by `scan --sbom` (2026-11-04). Unlike Python
//! (`runner.py:722-728`), no license gates it (ADR-0034).

use serde::Serialize;

use crate::project::dependencies::Dependency;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SbomReport {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,

    #[serde(rename = "specVersion")]
    pub spec_version: String,

    pub version: u32,

    pub metadata: Metadata,

    pub components: Vec<Component>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Metadata {
    /// ISO 8601 (RFC 3339) timestamp of SBOM generation.
    pub timestamp: String,
    pub tools: Vec<Tool>,
    pub component: RootComponent,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Tool {
    pub name: String,
    pub version: String,
}

/// The root component — the scanned project itself, not a dependency.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RootComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
}

/// A detected dependency of the scanned project.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Component {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    pub purl: String,
}

impl SbomReport {
    /// Builds an empty SBOM report (0 components) for `project_name`/
    /// `project_version`, timestamped at `timestamp` (ISO 8601 — the
    /// caller supplies the time, this function never reads the system
    /// clock: testable determinism, cf. Step 6/9 golden tests).
    pub fn new(
        project_name: impl Into<String>,
        project_version: impl Into<String>,
        tool_name: impl Into<String>,
        tool_version: impl Into<String>,
        timestamp: impl Into<String>,
    ) -> Self {
        SbomReport {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            version: 1,
            metadata: Metadata {
                timestamp: timestamp.into(),
                tools: vec![Tool {
                    name: tool_name.into(),
                    version: tool_version.into(),
                }],
                component: RootComponent {
                    component_type: "application".to_string(),
                    name: project_name.into(),
                    version: project_version.into(),
                },
            },
            components: Vec::new(),
        }
    }

    pub fn push_component(&mut self, component: Component) {
        self.components.push(component);
    }

    pub fn to_json_string(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

/// Builds the PURL (Package URL) of a dependency, same convention as
/// `Audit/sca/comparison.py::_export_sbom`: `pkg:<type>/<name>@<version>`,
/// except Maven (`group:artifact`) which becomes `pkg:maven/<group>/<artifact>@<version>`.
pub fn build_purl(purl_type: &str, name: &str, version: &str) -> String {
    if purl_type == "maven"
        && let Some((group, artifact)) = name.split_once(':')
    {
        return format!("pkg:{purl_type}/{group}/{artifact}@{version}");
    }
    format!("pkg:{purl_type}/{name}@{version}")
}

/// PURL type of a dependency ecosystem — same table as `ecosystem_to_purl`
/// in `Audit/sca/comparison.py::_export_sbom`; unknown ecosystem →
/// `generic`.
pub fn purl_type_for_ecosystem(ecosystem: &str) -> &'static str {
    match ecosystem {
        "PyPI" => "pypi",
        "npm" => "npm",
        "Maven" => "maven",
        "NuGet" => "nuget",
        "Packagist" => "composer",
        _ => "generic",
    }
}

/// Builds the project SBOM from the statically parsed dependencies —
/// port of `_export_sbom`: one `library` component per dependency, in
/// discovery order, version `unknown` when unpinned. No deduplication,
/// like Python (a dependency declared in two manifests appears twice).
pub fn build_dependency_sbom(
    deps: &[Dependency],
    project_name: &str,
    project_version: &str,
    tool_name: &str,
    tool_version: &str,
    timestamp: &str,
) -> SbomReport {
    let mut report = SbomReport::new(
        project_name,
        project_version,
        tool_name,
        tool_version,
        timestamp,
    );
    for dep in deps {
        let version = dep.version.clone().unwrap_or_else(|| "unknown".to_string());
        let purl = build_purl(purl_type_for_ecosystem(&dep.ecosystem), &dep.name, &version);
        report.push_component(Component {
            component_type: "library".to_string(),
            name: dep.name.clone(),
            version,
            purl,
        });
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, version: Option<&str>, ecosystem: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            ecosystem: ecosystem.to_string(),
            file: std::path::PathBuf::from("x"),
            line: 1,
            raw_line: String::new(),
        }
    }

    #[test]
    fn test_build_dependency_sbom_maps_ecosystems_and_unpinned() {
        let deps = vec![
            dep("requests", Some("2.31.0"), "PyPI"),
            dep("org.springframework:spring-core", Some("6.1.0"), "Maven"),
            dep("monolog/monolog", None, "Packagist"),
            dep("weird", Some("1"), "Cargo"),
        ];
        let sbom = build_dependency_sbom(&deps, "p", "", "sast-engine", "0.1.0", "t");
        let purls: Vec<&str> = sbom.components.iter().map(|c| c.purl.as_str()).collect();
        assert_eq!(
            purls,
            vec![
                "pkg:pypi/requests@2.31.0",
                "pkg:maven/org.springframework/spring-core@6.1.0",
                "pkg:composer/monolog/monolog@unknown",
                "pkg:generic/weird@1",
            ]
        );
        assert!(
            sbom.components
                .iter()
                .all(|c| c.component_type == "library")
        );
    }

    fn sample_report() -> SbomReport {
        let mut report = SbomReport::new(
            "mon-projet",
            "1.0",
            "sast-engine",
            "0.1.0",
            "2026-08-24T12:00:00Z",
        );
        report.push_component(Component {
            component_type: "library".to_string(),
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            purl: build_purl("pypi", "requests", "2.31.0"),
        });
        report
    }

    #[test]
    fn test_spec_version_is_1_6() {
        assert_eq!(sample_report().spec_version, "1.6");
    }

    #[test]
    fn test_bom_format_is_cyclonedx() {
        assert_eq!(sample_report().bom_format, "CycloneDX");
    }

    #[test]
    fn test_empty_report_has_zero_components() {
        let report = SbomReport::new("p", "1.0", "sast-engine", "0.1.0", "2026-08-24T12:00:00Z");
        assert!(report.components.is_empty());
    }

    #[test]
    fn test_json_is_valid_and_round_trips_key_fields() {
        let report = sample_report();
        let json = report.to_json_string().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["bomFormat"], "CycloneDX");
        assert_eq!(value["specVersion"], "1.6");
        assert_eq!(value["components"][0]["name"], "requests");
    }

    #[test]
    fn test_purl_pypi() {
        assert_eq!(
            build_purl("pypi", "requests", "2.31.0"),
            "pkg:pypi/requests@2.31.0"
        );
    }

    #[test]
    fn test_purl_maven_splits_group_artifact() {
        assert_eq!(
            build_purl("maven", "org.springframework:spring-core", "6.1.0"),
            "pkg:maven/org.springframework/spring-core@6.1.0"
        );
    }

    #[test]
    fn test_purl_maven_without_colon_falls_back_to_name() {
        // No ':' in name: fallback behavior, same limitation as Python
        // (sca/comparison.py only handles the group:artifact case).
        assert_eq!(
            build_purl("maven", "spring-core", "6.1.0"),
            "pkg:maven/spring-core@6.1.0"
        );
    }

    #[test]
    fn test_no_components_have_hash_or_license_fields() {
        // Verifies the deliberately limited scope (Decision #9): the
        // serialization must not contain any hash/licenses field, not
        // present in the current Python client.
        let json = sample_report().to_json_string().unwrap();
        assert!(!json.contains("\"hashes\""));
        assert!(!json.contains("\"licenses\""));
    }
}
