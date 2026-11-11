//! SARIF 2.1.0 export.
//!
//! Faithful port of `Audit/sca/comparison.py::_export_sarif`. Version
//! **2.1.0** unambiguously (stable/final version of the OASIS
//! standard, already the one produced by Python — `$schema`
//! explicitly references `sarif-schema-2.1.0.json`).
//!
//! **Input**: `ReportFinding`, a flat denormalized model (each finding
//! carries its `risk`/`cwe`/`owasp` directly, no separate lookup in a
//! rule catalog like `self._rule(rk)` on the Python side) — this
//! module remains a pure data→JSON transformer, independent of the
//! orchestrator (Step 5, not yet built) which will have to build these
//! `ReportFinding` from the outputs of the various executors
//! (`engine::Finding` for regex/file_contains/ast,
//! `dataflow::transfer::Finding` for taint).
//!
//! Accepted simplification: the `rk = f.rule_key or f.rule` (fallback)
//! on the Python side exists for legacy findings outside the DSL
//! engine (dependency scanning) — out of scope, a product decision
//! already made (`project_no_dependency_scanning`): every finding from
//! this engine always has a `rule_key`, no fallback needed.
//!
//! Temporary `#![allow(dead_code)]`: not yet wired to the CLI (Step 5,
//! sequenced afterward) — to be removed at that point.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Flat model of a finding, as consumed by the SARIF export (and,
/// eventually, the other report formats). Denormalized: rule data
/// (risk/cwe/owasp) is carried directly by the finding, not resolved
/// via a separate catalog.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportFinding {
    pub rule_key: String,
    pub rule_name: String,
    pub category: String,
    /// CRITICAL | HIGH | MEDIUM | LOW | INFO.
    pub severity: String,
    pub risk: String,
    pub file: String,
    pub line: usize,
    pub solution: Option<String>,
    pub cwe: Vec<String>,
    pub owasp: Option<String>,
    /// First taint flow attached to this finding — compatibility alias
    /// pointing to `taint_flows[0]`, mirroring `Finding.taint_flow`
    /// (singular) on the Audit side. `None` for a regex/file_contains/
    /// ast finding that no taint flow has ever joined.
    pub taint_flow: Option<TaintFlow>,
    /// All taint flows attached to this finding — mirrors
    /// `Finding.taint_flows` (`rule_engine.py::_integrate_taint_flow`):
    /// when a flow reaches a sink already flagged by an existing
    /// finding on the same line, it is added here instead of
    /// duplicating a report line (cf. `orchestrator::
    /// integrate_taint_finding`). `#[serde(default)]` to stay
    /// compatible with a baseline JSON written before this field.
    #[serde(default)]
    pub taint_flows: Vec<TaintFlow>,
    /// Detected code line — needed by the HTML report
    /// (`finding-item.html`), absent from SARIF/SBOM exports.
    pub code: String,
    /// Context displayed around the detected line (2 lines before/after
    /// by default, joined with `\n`) — port of `sca/utils.py::get_context`.
    pub context_before: String,
    pub context_after: String,
    /// Confidence score 0-100 — fixed at 90 for taint findings
    /// (mirrors `sca/rule_engine.py:1131`), as declared by the rule
    /// for regex/file_contains/ast findings.
    pub confidence: i64,
    pub benefit: String,
    /// Author of the last commit that touched the line — `None` as
    /// long as git blame isn't wired up (separate effort, not yet
    /// implemented on the AuditRust side).
    pub committer: Option<String>,
    /// Where the rule comes from: "json_builtin" (the catalog,
    /// `rules.scapack` next to the executable or `--rules <PATH>`), "json_custom"
    /// (the client's own rules, custom rules folder), "advisory_db"
    /// (vulnerable dependency).
    pub rule_source: String,
}

/// Source → sink flow of a taint finding, for `codeFlows` (standard
/// SARIF 2.1.0).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaintFlow {
    /// DSL rule that originated this flow — mirrors `TaintFlow.rule_key`
    /// on the Audit side (`sca/models.py`). Used to deduplicate attaching
    /// the same flow twice to a finding (`orchestrator::
    /// integrate_taint_finding`) and, eventually, to display which rules
    /// contributed to a merged finding.
    #[serde(default)]
    pub rule_key: String,
    pub source_file: String,
    pub source_line: usize,
    pub source_expr: String,
    /// (line, variable name, code) — intermediate propagation steps.
    pub chain: Vec<(usize, String, String)>,
    pub sink_file: String,
    pub sink_line: usize,
    pub sink_expr: String,
    /// http | cli | env | stdin | file | network — mirrors
    /// `TaintFlow.source_kind` on the Audit side (`sca/models.py`), as
    /// declared by the `SourceSpec` of the DSL rule that matched.
    /// `#[serde(default)]` to stay compatible with a baseline JSON
    /// written before this field.
    #[serde(default)]
    pub source_kind: String,
}

fn severity_to_sarif_level(severity: &str) -> String {
    match severity {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        "LOW" | "INFO" => "note",
        _ => "warning",
    }
    .to_string()
}

/// Normalizes a file path into a SARIF URI (`/` separators,
/// OS-independent).
fn normalize_uri(path: &str) -> String {
    path.replace('\\', "/")
}

// ============================================================================
// SARIF types (exact JSON structure)
// ============================================================================

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifText,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifText,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifRuleConfig,
    pub properties: SarifRuleProperties,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifText {
    pub text: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifRuleConfig {
    pub level: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifRuleProperties {
    pub category: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex")]
    pub rule_index: usize,
    pub level: String,
    pub message: SarifText,
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixes: Option<Vec<SarifFix>>,
    #[serde(rename = "codeFlows", skip_serializing_if = "Option::is_none")]
    pub code_flows: Option<Vec<SarifCodeFlow>>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifFix {
    pub description: SarifText,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifCodeFlow {
    #[serde(rename = "threadFlows")]
    pub thread_flows: Vec<SarifThreadFlow>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifThreadFlow {
    pub locations: Vec<SarifThreadFlowLocation>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifThreadFlowLocation {
    pub location: SarifThreadFlowLocationInner,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifThreadFlowLocationInner {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
    pub message: SarifText,
}

// ============================================================================
// Building
// ============================================================================

fn physical_location(file: &str, line: usize) -> SarifPhysicalLocation {
    SarifPhysicalLocation {
        artifact_location: SarifArtifactLocation {
            uri: normalize_uri(file),
        },
        region: SarifRegion {
            start_line: line.max(1),
        },
    }
}

fn build_code_flows(tf: &TaintFlow) -> Vec<SarifCodeFlow> {
    let mut locations = Vec::with_capacity(tf.chain.len() + 2);
    locations.push(SarifThreadFlowLocation {
        location: SarifThreadFlowLocationInner {
            physical_location: physical_location(&tf.source_file, tf.source_line),
            message: SarifText {
                text: format!("Source: {}", tf.source_expr),
            },
        },
    });
    for (line, var, code) in &tf.chain {
        let code_snippet: String = code.chars().take(80).collect();
        locations.push(SarifThreadFlowLocation {
            location: SarifThreadFlowLocationInner {
                physical_location: physical_location(&tf.source_file, *line),
                message: SarifText {
                    text: format!("{var}: {code_snippet}"),
                },
            },
        });
    }
    locations.push(SarifThreadFlowLocation {
        location: SarifThreadFlowLocationInner {
            physical_location: physical_location(&tf.sink_file, tf.sink_line),
            message: SarifText {
                text: format!("Impact: {}", tf.sink_expr),
            },
        },
    });
    vec![SarifCodeFlow {
        thread_flows: vec![SarifThreadFlow { locations }],
    }]
}

/// Builds a complete SARIF 2.1.0 report from a list of denormalized
/// findings.
pub fn build_sarif_report(
    findings: &[ReportFinding],
    tool_name: &str,
    tool_version: &str,
    information_uri: &str,
) -> SarifReport {
    let mut rules_index: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut rules_list: Vec<SarifRule> = Vec::new();

    for f in findings {
        if rules_index.contains_key(&f.rule_key) {
            continue;
        }
        rules_index.insert(f.rule_key.clone(), rules_list.len());
        let mut tags = vec![f.category.to_lowercase()];
        tags.extend(f.cwe.iter().cloned());
        if let Some(owasp) = &f.owasp {
            tags.push(owasp.clone());
        }
        rules_list.push(SarifRule {
            id: f.rule_key.clone(),
            name: f.rule_name.clone(),
            short_description: SarifText {
                text: f.rule_name.clone(),
            },
            full_description: SarifText {
                text: f.risk.clone(),
            },
            default_configuration: SarifRuleConfig {
                level: severity_to_sarif_level(&f.severity),
            },
            properties: SarifRuleProperties {
                category: f.category.clone(),
                tags,
            },
        });
    }

    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            let rule_index = *rules_index.get(&f.rule_key).unwrap_or(&0);
            let message_text = if f.risk.is_empty() {
                f.rule_name.clone()
            } else {
                f.risk.clone()
            };
            SarifResult {
                rule_id: f.rule_key.clone(),
                rule_index,
                level: severity_to_sarif_level(&f.severity),
                message: SarifText { text: message_text },
                locations: vec![SarifLocation {
                    physical_location: physical_location(&f.file, f.line),
                }],
                fixes: f.solution.as_ref().map(|s| {
                    vec![SarifFix {
                        description: SarifText { text: s.clone() },
                    }]
                }),
                code_flows: f.taint_flow.as_ref().map(build_code_flows),
            }
        })
        .collect();

    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: tool_name.to_string(),
                    version: tool_version.to_string(),
                    information_uri: information_uri.to_string(),
                    rules: rules_list,
                },
            },
            results,
        }],
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule_key: &str, file: &str, line: usize) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_name: "Test Rule".to_string(),
            category: "Injection".to_string(),
            severity: "HIGH".to_string(),
            risk: "Risque de test".to_string(),
            file: file.to_string(),
            line,
            solution: None,
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: String::new(),
            context_before: String::new(),
            context_after: String::new(),
            confidence: 90,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
        }
    }

    #[test]
    fn test_schema_and_version() {
        let report = build_sarif_report(&[], "sast-engine", "1.0", "https://codefixture.com");
        assert_eq!(
            report.schema,
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        );
        assert_eq!(report.version, "2.1.0");
    }

    #[test]
    fn test_empty_findings_produces_empty_results_and_rules() {
        let report = build_sarif_report(&[], "sast-engine", "1.0", "https://codefixture.com");
        assert!(report.runs[0].results.is_empty());
        assert!(report.runs[0].tool.driver.rules.is_empty());
    }

    #[test]
    fn test_single_finding_produces_one_rule_and_one_result() {
        let f = finding("sql_injection", "app.py", 12);
        let report = build_sarif_report(&[f], "sast-engine", "1.0", "https://codefixture.com");
        assert_eq!(report.runs[0].tool.driver.rules.len(), 1);
        assert_eq!(report.runs[0].results.len(), 1);
        assert_eq!(report.runs[0].results[0].rule_id, "sql_injection");
        assert_eq!(report.runs[0].results[0].rule_index, 0);
    }

    #[test]
    fn test_dedup_rules_by_rule_key() {
        let findings = vec![
            finding("sql_injection", "a.py", 1),
            finding("sql_injection", "b.py", 2),
        ];
        let report = build_sarif_report(&findings, "sast-engine", "1.0", "https://codefixture.com");
        assert_eq!(
            report.runs[0].tool.driver.rules.len(),
            1,
            "un seul rule_key -> une seule entrée rules"
        );
        assert_eq!(
            report.runs[0].results.len(),
            2,
            "mais deux results distincts"
        );
        assert_eq!(report.runs[0].results[0].rule_index, 0);
        assert_eq!(report.runs[0].results[1].rule_index, 0);
    }

    #[test]
    fn test_severity_to_sarif_level_mapping() {
        assert_eq!(severity_to_sarif_level("CRITICAL"), "error");
        assert_eq!(severity_to_sarif_level("HIGH"), "error");
        assert_eq!(severity_to_sarif_level("MEDIUM"), "warning");
        assert_eq!(severity_to_sarif_level("LOW"), "note");
        assert_eq!(severity_to_sarif_level("INFO"), "note");
        assert_eq!(severity_to_sarif_level("UNKNOWN"), "warning");
    }

    #[test]
    fn test_tags_include_category_cwe_owasp() {
        let mut f = finding("xss", "app.py", 1);
        f.cwe = vec!["CWE-79".to_string()];
        f.owasp = Some("A03:2021".to_string());
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        let tags = &report.runs[0].tool.driver.rules[0].properties.tags;
        assert!(
            tags.contains(&"injection".to_string()),
            "catégorie en minuscules"
        );
        assert!(tags.contains(&"CWE-79".to_string()));
        assert!(tags.contains(&"A03:2021".to_string()));
    }

    #[test]
    fn test_fixes_present_when_solution_given() {
        let mut f = finding("xss", "app.py", 1);
        f.solution = Some("Échapper la sortie HTML".to_string());
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        let fixes = report.runs[0].results[0].fixes.as_ref().unwrap();
        assert_eq!(fixes[0].description.text, "Échapper la sortie HTML");
    }

    #[test]
    fn test_fixes_absent_when_no_solution() {
        let f = finding("xss", "app.py", 1);
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert!(report.runs[0].results[0].fixes.is_none());
    }

    #[test]
    fn test_code_flows_present_for_taint_flow() {
        let mut f = finding("sql_injection", "app.py", 10);
        f.taint_flow = Some(TaintFlow {
            rule_key: "taint_sqli".to_string(),
            source_file: "app.py".to_string(),
            source_line: 1,
            source_expr: "request.GET['q']".to_string(),
            chain: vec![(5, "q".to_string(), "q = request.GET['q']".to_string())],
            sink_file: "app.py".to_string(),
            sink_line: 10,
            sink_expr: "cursor.execute(q)".to_string(),
            source_kind: "http".to_string(),
        });
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        let flows = report.runs[0].results[0].code_flows.as_ref().unwrap();
        let locations = &flows[0].thread_flows[0].locations;
        assert_eq!(locations.len(), 3, "source + 1 étape de chaîne + sink");
        assert!(locations[0].location.message.text.starts_with("Source:"));
        assert!(locations[2].location.message.text.starts_with("Impact:"));
    }

    #[test]
    fn test_code_flows_absent_without_taint_flow() {
        let f = finding("xss", "app.py", 1);
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert!(report.runs[0].results[0].code_flows.is_none());
    }

    #[test]
    fn test_windows_path_normalized_to_forward_slash() {
        let f = finding("xss", "src\\app.py", 1);
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert_eq!(
            report.runs[0].results[0].locations[0]
                .physical_location
                .artifact_location
                .uri,
            "src/app.py"
        );
    }

    #[test]
    fn test_line_zero_clamped_to_one() {
        let f = finding("xss", "app.py", 0);
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert_eq!(
            report.runs[0].results[0].locations[0]
                .physical_location
                .region
                .start_line,
            1
        );
    }

    #[test]
    fn test_unicode_path_preserved() {
        let f = finding("xss", "src/éàü_fichier.py", 3);
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert_eq!(
            report.runs[0].results[0].locations[0]
                .physical_location
                .artifact_location
                .uri,
            "src/éàü_fichier.py"
        );
    }

    #[test]
    fn test_json_serializable() {
        let f = finding("xss", "app.py", 1);
        let report = build_sarif_report(&[f], "sast-engine", "1.0", "https://codefixture.com");
        let json = serde_json::to_string(&report)
            .expect("le rapport SARIF doit être sérialisable en JSON");
        assert!(json.contains("\"ruleId\":\"xss\""));
        assert!(json.contains("\"$schema\""));
    }

    #[test]
    fn test_message_falls_back_to_rule_name_when_risk_empty() {
        let mut f = finding("xss", "app.py", 1);
        f.risk = String::new();
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert_eq!(report.runs[0].results[0].message.text, "Test Rule");
    }
}
