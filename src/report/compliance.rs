//! Computation of the ISO/IEC 27001:2022 Annex A, OWASP ASVS v5.0.0 and
//! NIST CSF 2.0 compliance matrices from a scan's findings — port of
//! `Audit/sca/compliance.py` (computation part only; HTML generation is
//! a separate piece of work, see `report.rs`).
//!
//! The 3 mapping files (`asvs_mapping.json`, `iso27001_mapping.json`,
//! `nist_csf_mapping.json`) are static, not editable by the client, and
//! embedded at compile time via `include_str!` — the equivalent of the
//! Python side's Nuitka compiled mode, which embeds these files in the
//! binary from `SCA_PACKAGE_DIR` (`sca/`, see `sca/__init__.py`).

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::report::exports::sarif::ReportFinding;

const ASVS_MAPPING_JSON: &str = include_str!("../../resources/mappings/asvs_mapping.json");
const ISO27001_MAPPING_JSON: &str = include_str!("../../resources/mappings/iso27001_mapping.json");
const NIST_CSF_MAPPING_JSON: &str = include_str!("../../resources/mappings/nist_csf_mapping.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStatus {
    Findings,
    Covered,
    NotCovered,
}

#[derive(Debug, Clone, Default)]
pub struct SharedVsSpecific {
    pub shared_total: usize,
    pub shared_clean: usize,
    pub shared_clean_pct: i64,
    pub specific_total: usize,
    pub specific_clean: usize,
    pub specific_clean_pct: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleScope {
    Shared,
    Specific,
}

/// Classifies each mapped rule_key as "shared" (mapped in ≥2 of the 3
/// frameworks) or "specific" (mapped in only one) — Franck's feedback
/// R06: a shared rule earns compliance points in several frameworks at
/// once, so a framework's true differentiating value is measured on its
/// specific rules.
fn rule_referential_scope(
    iso: &Iso27001Mapping,
    asvs: &AsvsMapping,
    nist: &NistCsfMapping,
) -> BTreeMap<String, RuleScope> {
    let iso_rules: std::collections::BTreeSet<&String> = iso.mapping.keys().collect();
    let asvs_rules: std::collections::BTreeSet<&String> = asvs.mapping.keys().collect();
    let nist_rules: std::collections::BTreeSet<&String> = nist.mapping.keys().collect();

    let mut scope = BTreeMap::new();
    for rk in iso_rules
        .iter()
        .chain(asvs_rules.iter())
        .chain(nist_rules.iter())
    {
        let n = iso_rules.contains(*rk) as u8
            + asvs_rules.contains(*rk) as u8
            + nist_rules.contains(*rk) as u8;
        scope.entry((*rk).clone()).or_insert(if n >= 2 {
            RuleScope::Shared
        } else {
            RuleScope::Specific
        });
    }
    scope
}

fn split_shared_vs_specific(
    testable_item_to_rules: &BTreeMap<String, Vec<String>>,
    findings_by_rule: &BTreeMap<String, Vec<&ReportFinding>>,
    rule_scope: &BTreeMap<String, RuleScope>,
) -> SharedVsSpecific {
    let mut out = SharedVsSpecific::default();
    for rule_keys in testable_item_to_rules.values() {
        let is_shared = rule_keys
            .iter()
            .any(|rk| rule_scope.get(rk) == Some(&RuleScope::Shared));
        let has_finding = rule_keys.iter().any(|rk| findings_by_rule.contains_key(rk));
        if is_shared {
            out.shared_total += 1;
            if !has_finding {
                out.shared_clean += 1;
            }
        } else {
            out.specific_total += 1;
            if !has_finding {
                out.specific_clean += 1;
            }
        }
    }
    out.shared_clean_pct = pct(out.shared_clean, out.shared_total);
    out.specific_clean_pct = pct(out.specific_clean, out.specific_total);
    out
}

fn pct(numerator: usize, denominator: usize) -> i64 {
    if denominator == 0 {
        0
    } else {
        (numerator as f64 / denominator as f64 * 100.0).round() as i64
    }
}

fn findings_by_rule(findings: &[ReportFinding]) -> BTreeMap<String, Vec<&ReportFinding>> {
    let mut m: BTreeMap<String, Vec<&ReportFinding>> = BTreeMap::new();
    for f in findings {
        m.entry(f.rule_key.clone()).or_default().push(f);
    }
    m
}

/// Inverts a rule_key -> [item_id, ...] mapping into item_id -> [rule_key, ...].
fn invert_mapping(mapping: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (rule_key, item_ids) in mapping {
        for item_id in item_ids {
            out.entry(item_id.clone())
                .or_default()
                .push(rule_key.clone());
        }
    }
    out
}

// =============================================================================
// ISO/IEC 27001:2022 Annex A
// =============================================================================

#[derive(Debug, Deserialize)]
struct Iso27001Control {
    theme: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct Iso27001Mapping {
    controls: BTreeMap<String, Iso27001Control>,
    mapping: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct Iso27001ControlDetail {
    pub id: String,
    pub name: String,
    pub theme: String,
    pub status: ComplianceStatus,
    pub rules_count: usize,
    pub finding_count: usize,
    pub severities: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Iso27001ThemeSummary {
    pub total: usize,
    pub covered: usize,
    pub with_findings: usize,
    pub finding_count: usize,
}

#[derive(Debug, Clone)]
pub struct Iso27001Compliance {
    pub total_controls: usize,
    pub covered_controls: usize,
    pub coverage_pct: i64,
    pub clean_controls: usize,
    pub clean_pct: i64,
    pub with_findings: usize,
    pub themes: BTreeMap<String, Iso27001ThemeSummary>,
    pub controls: BTreeMap<String, Iso27001ControlDetail>,
    pub shared_vs_specific: SharedVsSpecific,
}

const ISO27001_THEMES: [&str; 4] = ["organizational", "people", "physical", "technological"];
const SEVERITIES: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

fn load_iso27001_mapping() -> Iso27001Mapping {
    serde_json::from_str(ISO27001_MAPPING_JSON).expect("iso27001_mapping.json embarqué invalide")
}

/// Ids referenced by a compliance mapping (keys of its `mapping`
/// section) but absent from the actually compiled rule catalog —
/// "drift" in the sense of ticket #37/spec #26 (anti-drift guardrail).
/// Pure comparison, reused by the three guardrails (ISO27001, ASVS,
/// NIST CSF) rather than duplicated in each. `#[cfg(test)]`: only makes
/// sense for these guardrails, no caller in production.
#[cfg(test)]
fn drifted_mapping_ids<'a>(
    mapping_keys: impl Iterator<Item = &'a String>,
    compiled_ids: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    mapping_keys
        .filter(|k| !compiled_ids.contains(*k))
        .cloned()
        .collect()
}

pub fn compute_iso27001_compliance(
    findings: &[ReportFinding],
    rule_scope: &BTreeMap<String, RuleScope>,
) -> Iso27001Compliance {
    let m = load_iso27001_mapping();
    let by_rule = findings_by_rule(findings);
    let control_to_rules = invert_mapping(&m.mapping);

    let mut control_details = BTreeMap::new();
    let mut covered_set = std::collections::BTreeSet::new();
    let mut with_findings_set = std::collections::BTreeSet::new();

    for (ctrl_id, ctrl_info) in &m.controls {
        let rules_for_ctrl = control_to_rules.get(ctrl_id).cloned().unwrap_or_default();
        let is_covered = !rules_for_ctrl.is_empty();
        let mut finding_count = 0usize;
        let mut severities: BTreeMap<String, usize> =
            SEVERITIES.iter().map(|s| (s.to_string(), 0)).collect();
        for rk in &rules_for_ctrl {
            if let Some(fs) = by_rule.get(rk) {
                for f in fs {
                    finding_count += 1;
                    if let Some(c) = severities.get_mut(&f.severity) {
                        *c += 1;
                    }
                }
            }
        }
        if is_covered {
            covered_set.insert(ctrl_id.clone());
        }
        if finding_count > 0 {
            with_findings_set.insert(ctrl_id.clone());
        }
        let status = if finding_count > 0 {
            ComplianceStatus::Findings
        } else if is_covered {
            ComplianceStatus::Covered
        } else {
            ComplianceStatus::NotCovered
        };
        control_details.insert(
            ctrl_id.clone(),
            Iso27001ControlDetail {
                id: ctrl_id.clone(),
                name: ctrl_info.name.clone(),
                theme: ctrl_info.theme.clone(),
                status,
                rules_count: rules_for_ctrl.len(),
                finding_count,
                severities,
            },
        );
    }

    let mut themes = BTreeMap::new();
    for theme in ISO27001_THEMES {
        let theme_controls: Vec<&Iso27001ControlDetail> = control_details
            .values()
            .filter(|c| c.theme == theme)
            .collect();
        themes.insert(
            theme.to_string(),
            Iso27001ThemeSummary {
                total: theme_controls.len(),
                covered: theme_controls
                    .iter()
                    .filter(|c| c.status != ComplianceStatus::NotCovered)
                    .count(),
                with_findings: theme_controls
                    .iter()
                    .filter(|c| c.status == ComplianceStatus::Findings)
                    .count(),
                finding_count: theme_controls.iter().map(|c| c.finding_count).sum(),
            },
        );
    }

    let total = m.controls.len();
    let covered = covered_set.len();
    let clean_count = covered - with_findings_set.len();
    let shared_vs_specific = split_shared_vs_specific(&control_to_rules, &by_rule, rule_scope);

    Iso27001Compliance {
        total_controls: total,
        covered_controls: covered,
        coverage_pct: pct(covered, total),
        clean_controls: clean_count,
        clean_pct: pct(clean_count, covered),
        with_findings: with_findings_set.len(),
        themes,
        controls: control_details,
        shared_vs_specific,
    }
}

// =============================================================================
// OWASP ASVS v5.0.0
// =============================================================================

#[derive(Debug, Deserialize)]
struct AsvsChapter {
    name: String,
    count: usize,
}

#[derive(Debug, Deserialize)]
struct AsvsRequirement {
    chapter: String,
    #[serde(default = "default_level")]
    level: String,
    name: String,
}

fn default_level() -> String {
    "L1".to_string()
}

#[derive(Debug, Deserialize)]
struct AsvsMapping {
    total_requirements: usize,
    chapters: BTreeMap<String, AsvsChapter>,
    requirements: BTreeMap<String, AsvsRequirement>,
    mapping: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct AsvsRequirementDetail {
    pub id: String,
    pub name: String,
    pub chapter: String,
    pub level: String,
    pub status: ComplianceStatus,
    pub rules_count: usize,
    pub finding_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct AsvsChapterSummary {
    pub name: String,
    pub total: usize,
    pub covered: usize,
    pub with_findings: usize,
    pub finding_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct AsvsLevelSummary {
    pub total: usize,
    pub covered: usize,
    pub coverage_pct: i64,
}

#[derive(Debug, Clone)]
pub struct AsvsCompliance {
    pub total_requirements: usize,
    pub covered_requirements: usize,
    pub coverage_pct: i64,
    pub clean_requirements: usize,
    pub clean_pct: i64,
    pub with_findings: usize,
    pub chapters: BTreeMap<String, AsvsChapterSummary>,
    pub levels: BTreeMap<String, AsvsLevelSummary>,
    pub requirements: BTreeMap<String, AsvsRequirementDetail>,
    pub shared_vs_specific: SharedVsSpecific,
}

fn load_asvs_mapping() -> AsvsMapping {
    serde_json::from_str(ASVS_MAPPING_JSON).expect("asvs_mapping.json embarqué invalide")
}

pub fn compute_asvs_compliance(
    findings: &[ReportFinding],
    rule_scope: &BTreeMap<String, RuleScope>,
) -> AsvsCompliance {
    let m = load_asvs_mapping();
    let by_rule = findings_by_rule(findings);
    let req_to_rules = invert_mapping(&m.mapping);

    let mut req_details = BTreeMap::new();
    let mut covered_set = std::collections::BTreeSet::new();
    let mut with_findings_set = std::collections::BTreeSet::new();

    for (req_id, req_info) in &m.requirements {
        let rules_for_req = req_to_rules.get(req_id).cloned().unwrap_or_default();
        let is_covered = !rules_for_req.is_empty();
        let finding_count: usize = rules_for_req
            .iter()
            .map(|rk| by_rule.get(rk).map_or(0, |v| v.len()))
            .sum();
        if is_covered {
            covered_set.insert(req_id.clone());
        }
        if finding_count > 0 {
            with_findings_set.insert(req_id.clone());
        }
        let status = if finding_count > 0 {
            ComplianceStatus::Findings
        } else if is_covered {
            ComplianceStatus::Covered
        } else {
            ComplianceStatus::NotCovered
        };
        req_details.insert(
            req_id.clone(),
            AsvsRequirementDetail {
                id: req_id.clone(),
                name: req_info.name.clone(),
                chapter: req_info.chapter.clone(),
                level: req_info.level.clone(),
                status,
                rules_count: rules_for_req.len(),
                finding_count,
            },
        );
    }

    let mut chapters = BTreeMap::new();
    for (ch_key, ch_info) in &m.chapters {
        let ch_reqs: Vec<&AsvsRequirementDetail> = req_details
            .values()
            .filter(|r| &r.chapter == ch_key)
            .collect();
        chapters.insert(
            ch_key.clone(),
            AsvsChapterSummary {
                name: ch_info.name.clone(),
                total: ch_info.count,
                covered: ch_reqs
                    .iter()
                    .filter(|r| r.status != ComplianceStatus::NotCovered)
                    .count(),
                with_findings: ch_reqs
                    .iter()
                    .filter(|r| r.status == ComplianceStatus::Findings)
                    .count(),
                finding_count: ch_reqs.iter().map(|r| r.finding_count).sum(),
            },
        );
    }

    let mut levels = BTreeMap::new();
    for level in ["L1", "L2", "L3"] {
        let level_reqs: Vec<&AsvsRequirementDetail> =
            req_details.values().filter(|r| r.level == level).collect();
        let total_level = level_reqs.len();
        let covered_level = level_reqs
            .iter()
            .filter(|r| r.status != ComplianceStatus::NotCovered)
            .count();
        levels.insert(
            level.to_string(),
            AsvsLevelSummary {
                total: total_level,
                covered: covered_level,
                coverage_pct: pct(covered_level, total_level),
            },
        );
    }

    let total = m.total_requirements;
    let covered = covered_set.len();
    let clean_count = covered - with_findings_set.len();
    let shared_vs_specific = split_shared_vs_specific(&req_to_rules, &by_rule, rule_scope);

    AsvsCompliance {
        total_requirements: total,
        covered_requirements: covered,
        coverage_pct: pct(covered, total),
        clean_requirements: clean_count,
        clean_pct: pct(clean_count, covered),
        with_findings: with_findings_set.len(),
        chapters,
        levels,
        requirements: req_details,
        shared_vs_specific,
    }
}

// =============================================================================
// NIST CSF 2.0
// =============================================================================

#[derive(Debug, Deserialize)]
struct NistFunction {
    name: String,
}

#[derive(Debug, Deserialize)]
struct NistSubcategory {
    function: String,
    category: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct NistCsfMapping {
    functions: BTreeMap<String, NistFunction>,
    subcategories: BTreeMap<String, NistSubcategory>,
    mapping: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct NistSubcategoryDetail {
    pub id: String,
    pub function: String,
    pub category: String,
    pub name: String,
    pub status: ComplianceStatus,
    pub rules_count: usize,
    pub finding_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct NistFunctionSummary {
    pub name: String,
    pub total: usize,
    pub covered: usize,
    pub with_findings: usize,
    pub finding_count: usize,
    pub subcategories: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NistCsfCompliance {
    pub total_subcategories: usize,
    pub covered_subcategories: usize,
    pub with_findings: usize,
    pub coverage_pct: i64,
    pub clean_subcategories: usize,
    pub clean_pct: i64,
    pub by_function: BTreeMap<String, NistFunctionSummary>,
    pub subcategories: BTreeMap<String, NistSubcategoryDetail>,
    pub shared_vs_specific: SharedVsSpecific,
}

fn load_nist_csf_mapping() -> NistCsfMapping {
    serde_json::from_str(NIST_CSF_MAPPING_JSON).expect("nist_csf_mapping.json embarqué invalide")
}

pub fn compute_nist_csf_compliance(
    findings: &[ReportFinding],
    rule_scope: &BTreeMap<String, RuleScope>,
) -> NistCsfCompliance {
    let m = load_nist_csf_mapping();
    let by_rule = findings_by_rule(findings);
    let subcat_to_rules = invert_mapping(&m.mapping);

    let mut subcategories = BTreeMap::new();
    let mut covered_set = std::collections::BTreeSet::new();
    let mut with_findings_set = std::collections::BTreeSet::new();

    for (subcat_id, meta) in &m.subcategories {
        let rules_for_subcat = subcat_to_rules.get(subcat_id).cloned().unwrap_or_default();
        let is_covered = !rules_for_subcat.is_empty();
        let finding_count: usize = rules_for_subcat
            .iter()
            .map(|rk| by_rule.get(rk).map_or(0, |v| v.len()))
            .sum();
        if is_covered {
            covered_set.insert(subcat_id.clone());
        }
        let status = if finding_count > 0 {
            with_findings_set.insert(subcat_id.clone());
            ComplianceStatus::Findings
        } else if is_covered {
            ComplianceStatus::Covered
        } else {
            ComplianceStatus::NotCovered
        };
        subcategories.insert(
            subcat_id.clone(),
            NistSubcategoryDetail {
                id: subcat_id.clone(),
                function: meta.function.clone(),
                category: meta.category.clone(),
                name: meta.name.clone(),
                status,
                rules_count: rules_for_subcat.len(),
                finding_count,
            },
        );
    }

    let mut by_function = BTreeMap::new();
    for (func_code, func_info) in &m.functions {
        let func_subcats: Vec<&String> = m
            .subcategories
            .keys()
            .filter(|s| s.starts_with(&format!("{func_code}.")))
            .collect();
        let covered = func_subcats
            .iter()
            .filter(|s| covered_set.contains(**s))
            .count();
        let with_findings = func_subcats
            .iter()
            .filter(|s| with_findings_set.contains(**s))
            .count();
        let finding_count: usize = func_subcats
            .iter()
            .map(|s| subcategories.get(*s).map_or(0, |d| d.finding_count))
            .sum();
        let mut sorted_subcats: Vec<String> = func_subcats.iter().map(|s| (*s).clone()).collect();
        sorted_subcats.sort();
        by_function.insert(
            func_code.clone(),
            NistFunctionSummary {
                name: func_info.name.clone(),
                total: func_subcats.len(),
                covered,
                with_findings,
                finding_count,
                subcategories: sorted_subcats,
            },
        );
    }

    let total = m.subcategories.len();
    let covered = covered_set.len();
    let clean_count = covered - with_findings_set.len();
    let shared_vs_specific = split_shared_vs_specific(&subcat_to_rules, &by_rule, rule_scope);

    NistCsfCompliance {
        total_subcategories: total,
        covered_subcategories: covered,
        with_findings: with_findings_set.len(),
        coverage_pct: pct(covered, total),
        clean_subcategories: clean_count,
        clean_pct: pct(clean_count, covered),
        by_function,
        subcategories,
        shared_vs_specific,
    }
}

/// Loads the 3 mappings and computes the rule sharing reference — the
/// single public entry point, to be called once per report generation
/// and the result then passed to the 3 `compute_*` functions.
pub fn load_rule_referential_scope() -> BTreeMap<String, RuleScope> {
    rule_referential_scope(
        &load_iso27001_mapping(),
        &load_asvs_mapping(),
        &load_nist_csf_mapping(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule_key: &str, severity: &str) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_name: rule_key.to_string(),
            category: "SECURITY".to_string(),
            severity: severity.to_string(),
            risk: String::new(),
            file: "src/test.py".to_string(),
            line: 10,
            solution: None,
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: "cursor.execute(f'SELECT * FROM {table}')".to_string(),
            context_before: String::new(),
            context_after: String::new(),
            confidence: 90,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
        }
    }

    // === drifted_mapping_ids (ticket #37): the reusable utility itself,
    // independent of any real mapping file — proves that detection
    // works (both positive AND negative), not just that the current
    // ISO27001 mapping passes. ===

    #[test]
    fn test_drifted_mapping_ids_detects_id_absent_from_compiled_catalog() {
        let mapping_keys = ["real_rule".to_string(), "ghost_rule".to_string()];
        let compiled: std::collections::BTreeSet<String> =
            ["real_rule".to_string()].into_iter().collect();
        let drifted = drifted_mapping_ids(mapping_keys.iter(), &compiled);
        assert_eq!(drifted, vec!["ghost_rule".to_string()]);
    }

    #[test]
    fn test_drifted_mapping_ids_empty_when_all_ids_present() {
        let mapping_keys = ["real_rule".to_string()];
        let compiled: std::collections::BTreeSet<String> =
            ["real_rule".to_string(), "other_rule".to_string()]
                .into_iter()
                .collect();
        let drifted = drifted_mapping_ids(mapping_keys.iter(), &compiled);
        assert!(drifted.is_empty());
    }

    // === Mapping integrity (port of TestMappingIntegrity/TestAsvsMappingIntegrity) ===

    #[test]
    fn test_iso27001_has_93_controls() {
        let m = load_iso27001_mapping();
        assert_eq!(m.controls.len(), 93);
    }

    #[test]
    fn test_iso27001_theme_distribution() {
        let m = load_iso27001_mapping();
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for c in m.controls.values() {
            *counts.entry(c.theme.as_str()).or_insert(0) += 1;
        }
        assert_eq!(counts["organizational"], 37);
        assert_eq!(counts["people"], 8);
        assert_eq!(counts["physical"], 14);
        assert_eq!(counts["technological"], 34);
    }

    // === Anti-drift guardrail against the compiled catalog (ticket #37,
    // priority 1 of spec #26 — ISO27001 has the widest measured drift)
    // — distinct from `test_iso27001_mapping_references_valid_
    // controls` below, which checks the mapping file's INTERNAL
    // self-consistency (the ctrl_ids it references exist in its own
    // `controls` section), not its consistency with the actually
    // compiled rule catalog. ===

    /// Known drift for `iso27001_mapping.json`, recomputed on
    /// 2026-09-02 (ticket #75) after completing the C# catalog outside
    /// taint/HTML/YAML CI-CD/Dockerfile (tickets #70-#74) — 29 phantom
    /// ids, down from 55 before this completion (measured on
    /// 2026-09-01, ticket #37): almost all ids that overlapped with
    /// the newly ported languages (C# outside taint, HTML, YAML CI/CD,
    /// Dockerfile) are now present in the compiled catalog and
    /// therefore drop out of this baseline. Two remaining causes, not
    /// separated here (the distinction has no impact on the guardrail,
    /// only on a possible future regeneration of the mapping, out of
    /// this ticket's scope): (1) native C# taint engine not yet built
    /// — `_csharp` ids that overlap with a `taint_*.sca` entry
    /// excluded by ticket #70 (see ADR-0003, tickets #77-81); (2)
    /// drift already present on the Python side itself (e.g.
    /// `test_error`/`unvalidated_input`/`vulnerable_dependency`,
    /// names that are clearly dead in the Python source).
    ///
    /// Frozen baseline: the test that uses it fails on any NEW drift
    /// beyond this list, never on this one. Do not add an id here to
    /// silence a failure without understanding why it disappeared from
    /// the compiled catalog.
    const ISO27001_KNOWN_PHANTOM_IDS: &[&str] = &[
        "dangerous_eval",
        "db_config_missing",
        "db_connection_error",
        "db_psql_error",
        "db_tool_missing",
        "insecure_random",
        "ldap_injection_java",
        "ldap_injection_python",
        "non_compliant_license",
        "open_redirect_csharp",
        "open_redirect_java",
        "open_redirect_php",
        "path_traversal_csharp",
        "path_traversal_java",
        "path_traversal_javascript",
        "path_traversal_python",
        "ssrf_csharp",
        "ssrf_java",
        "ssrf_javascript",
        "ssrf_php",
        "test_error",
        "test_failed",
        "unpinned_dependency",
        "unsafe_deserialization",
        "unvalidated_input",
        "vulnerable_dependency",
        "xss_echo_php",
        "xss_innerhtml",
        "xss_raw_html",
    ];

    #[test]
    fn test_iso27001_mapping_no_new_drift_against_compiled_catalog() {
        let m = load_iso27001_mapping();
        let compiled_ids = crate::rules::embedded_rules::compiled_rule_ids();
        let drifted = drifted_mapping_ids(m.mapping.keys(), &compiled_ids);
        let known: std::collections::BTreeSet<&str> =
            ISO27001_KNOWN_PHANTOM_IDS.iter().copied().collect();
        let new_drift: Vec<&String> = drifted
            .iter()
            .filter(|id| !known.contains(id.as_str()))
            .collect();
        assert!(
            new_drift.is_empty(),
            "nouvelle dérive détectée dans iso27001_mapping.json (id absent du catalogue compilé, \
             hors baseline déjà documentée dans ISO27001_KNOWN_PHANTOM_IDS) : {new_drift:?}"
        );
    }

    // === ASVS anti-drift guardrail (ticket #38, priority 2 of spec #26)
    // — same mechanism as the ISO27001 guardrail above, `drifted_
    // mapping_ids` utility reused as-is (no second implementation). ===

    /// Known drift for `asvs_mapping.json`, recomputed on 2026-09-02
    /// (ticket #75), with the same method as `ISO27001_KNOWN_PHANTOM_
    /// IDS` above (extracting `rule <id>` ids from the compiled `.sca`
    /// catalog, diffed against the mapping's keys) — 23 phantom ids,
    /// down from 37 before completing the C# catalog outside
    /// taint/HTML/YAML CI-CD/Dockerfile (measured on 2026-09-01, ticket
    /// #38): the figure below is the exact measurement and is
    /// authoritative. Almost all remaining ids overlap with
    /// `ISO27001_KNOWN_PHANTOM_IDS` (same two causes: C# taint engine
    /// not yet built — see ADR-0003, tickets #77-81 — and names
    /// already dead on the Python source side);
    /// `missing_frame_protection`/`missing_referrer_policy`/
    /// `missing_x_content_type_options`/`ssti_python` remain specific
    /// to ASVS (HTTP header protections and Python SSTI not yet ported
    /// under these exact names, or renamed during the port).
    ///
    /// Frozen baseline: the test that uses it fails on any NEW drift
    /// beyond this list, never on this one. Do not add an id here to
    /// silence a failure without understanding why it disappeared from
    /// the compiled catalog.
    const ASVS_KNOWN_PHANTOM_IDS: &[&str] = &[
        "dangerous_eval",
        "insecure_random",
        "ldap_injection_java",
        "ldap_injection_python",
        "missing_frame_protection",
        "missing_referrer_policy",
        "missing_x_content_type_options",
        "open_redirect_csharp",
        "open_redirect_java",
        "open_redirect_php",
        "path_traversal_csharp",
        "path_traversal_java",
        "path_traversal_javascript",
        "path_traversal_python",
        "ssrf_csharp",
        "ssrf_java",
        "ssrf_javascript",
        "ssrf_php",
        "ssti_python",
        "unsafe_deserialization",
        "xss_echo_php",
        "xss_innerhtml",
        "xss_raw_html",
    ];

    #[test]
    fn test_asvs_mapping_no_new_drift_against_compiled_catalog() {
        let m = load_asvs_mapping();
        let compiled_ids = crate::rules::embedded_rules::compiled_rule_ids();
        let drifted = drifted_mapping_ids(m.mapping.keys(), &compiled_ids);
        let known: std::collections::BTreeSet<&str> =
            ASVS_KNOWN_PHANTOM_IDS.iter().copied().collect();
        let new_drift: Vec<&String> = drifted
            .iter()
            .filter(|id| !known.contains(id.as_str()))
            .collect();
        assert!(
            new_drift.is_empty(),
            "nouvelle dérive détectée dans asvs_mapping.json (id absent du catalogue compilé, \
             hors baseline déjà documentée dans ASVS_KNOWN_PHANTOM_IDS) : {new_drift:?}"
        );
    }

    // === NIST CSF anti-drift guardrail (ticket #39, priority 3 of spec
    // #26) — same mechanism as the ISO27001/ASVS guardrails above,
    // `drifted_mapping_ids` utility reused as-is (no third
    // implementation). ===

    /// Known drift for `nist_csf_mapping.json`, recomputed on
    /// 2026-09-02 (ticket #75), same method as `ISO27001_KNOWN_PHANTOM_
    /// IDS`/`ASVS_KNOWN_PHANTOM_IDS` above — 24 phantom ids, down from
    /// 34 before completing the C# catalog outside taint/HTML/YAML
    /// CI-CD/Dockerfile (measured on 2026-09-01, ticket #39): the
    /// figure below is the exact measurement and is authoritative.
    /// Here again almost all of them overlap with the ISO27001/ASVS
    /// baselines (same two causes: C# taint engine not yet built —
    /// see ADR-0003, tickets #77-81 — and names already dead on the
    /// Python source side, e.g. `unvalidated_input`/
    /// `vulnerable_dependency`); a few ids are specific to NIST CSF
    /// (`open_redirect` without a language suffix,
    /// `insecure_deserialize_call`, `xxe_injection_python`);
    /// `non_compliant_license` actually overlaps with
    /// `ISO27001_KNOWN_PHANTOM_IDS`, not a NIST CSF exclusive.
    ///
    /// Frozen baseline: the test that uses it fails on any NEW drift
    /// beyond this list, never on this one. Do not add an id here to
    /// silence a failure without understanding why it disappeared from
    /// the compiled catalog.
    const NIST_CSF_KNOWN_PHANTOM_IDS: &[&str] = &[
        "dangerous_eval",
        "insecure_deserialize_call",
        "ldap_injection_java",
        "ldap_injection_python",
        "non_compliant_license",
        "open_redirect",
        "open_redirect_csharp",
        "open_redirect_java",
        "open_redirect_php",
        "path_traversal_csharp",
        "path_traversal_java",
        "path_traversal_javascript",
        "path_traversal_python",
        "ssrf_csharp",
        "ssrf_java",
        "ssrf_javascript",
        "ssrf_php",
        "unpinned_dependency",
        "unsafe_deserialization",
        "unvalidated_input",
        "vulnerable_dependency",
        "xss_innerhtml",
        "xss_raw_html",
        "xxe_injection_python",
    ];

    #[test]
    fn test_nist_csf_mapping_no_new_drift_against_compiled_catalog() {
        let m = load_nist_csf_mapping();
        let compiled_ids = crate::rules::embedded_rules::compiled_rule_ids();
        let drifted = drifted_mapping_ids(m.mapping.keys(), &compiled_ids);
        let known: std::collections::BTreeSet<&str> =
            NIST_CSF_KNOWN_PHANTOM_IDS.iter().copied().collect();
        let new_drift: Vec<&String> = drifted
            .iter()
            .filter(|id| !known.contains(id.as_str()))
            .collect();
        assert!(
            new_drift.is_empty(),
            "nouvelle dérive détectée dans nist_csf_mapping.json (id absent du catalogue compilé, \
             hors baseline déjà documentée dans NIST_CSF_KNOWN_PHANTOM_IDS) : {new_drift:?}"
        );
    }

    #[test]
    fn test_iso27001_mapping_references_valid_controls() {
        let m = load_iso27001_mapping();
        let valid_ids: std::collections::BTreeSet<&String> = m.controls.keys().collect();
        for ctrl_ids in m.mapping.values() {
            for ctrl_id in ctrl_ids {
                assert!(
                    valid_ids.contains(ctrl_id),
                    "contrôle inexistant: {ctrl_id}"
                );
            }
        }
    }

    #[test]
    fn test_asvs_has_348_total_and_17_chapters() {
        let m = load_asvs_mapping();
        assert_eq!(m.total_requirements, 348);
        assert_eq!(m.chapters.len(), 17);
        let sum: usize = m.chapters.values().map(|c| c.count).sum();
        assert_eq!(sum, 348);
    }

    #[test]
    fn test_asvs_mapping_references_valid_requirements() {
        let m = load_asvs_mapping();
        let valid_ids: std::collections::BTreeSet<&String> = m.requirements.keys().collect();
        for req_ids in m.mapping.values() {
            for req_id in req_ids {
                assert!(
                    valid_ids.contains(req_id),
                    "requirement inexistant: {req_id}"
                );
            }
        }
    }

    #[test]
    fn test_nist_mapping_references_valid_subcategories() {
        let m = load_nist_csf_mapping();
        let valid_ids: std::collections::BTreeSet<&String> = m.subcategories.keys().collect();
        for subcat_ids in m.mapping.values() {
            for subcat_id in subcat_ids {
                assert!(
                    valid_ids.contains(subcat_id),
                    "sous-catégorie inexistante: {subcat_id}"
                );
            }
        }
    }

    // === ISO 27001 coverage computation (port of TestComplianceComputation) ===

    #[test]
    fn test_iso27001_compute_empty_findings() {
        let scope = load_rule_referential_scope();
        let result = compute_iso27001_compliance(&[], &scope);
        assert_eq!(result.total_controls, 93);
        assert!(result.covered_controls > 0);
        assert_eq!(result.with_findings, 0);
        for c in result.controls.values() {
            assert!(c.status != ComplianceStatus::Findings);
            assert_eq!(c.finding_count, 0);
        }
    }

    #[test]
    fn test_iso27001_compute_with_findings() {
        let scope = load_rule_referential_scope();
        let findings = vec![finding("sql_injection_fstring", "HIGH")];
        let result = compute_iso27001_compliance(&findings, &scope);
        assert!(result.with_findings > 0);
        let ctrl = &result.controls["A.8.28"];
        assert_eq!(ctrl.status, ComplianceStatus::Findings);
        assert!(ctrl.finding_count >= 1);
    }

    #[test]
    fn test_iso27001_coverage_percentage() {
        let scope = load_rule_referential_scope();
        let result = compute_iso27001_compliance(&[], &scope);
        let expected_pct = (result.covered_controls as f64 / 93.0 * 100.0).round() as i64;
        assert_eq!(result.coverage_pct, expected_pct);
    }

    #[test]
    fn test_iso27001_themes_aggregation() {
        let scope = load_rule_referential_scope();
        let result = compute_iso27001_compliance(&[], &scope);
        assert_eq!(result.themes.len(), 4);
        let total: usize = result.themes.values().map(|t| t.total).sum();
        assert_eq!(total, 93);
    }

    #[test]
    fn test_iso27001_shared_vs_specific_split() {
        let scope = load_rule_referential_scope();
        let result = compute_iso27001_compliance(&[], &scope);
        let sv = &result.shared_vs_specific;
        assert_eq!(sv.shared_total + sv.specific_total, result.covered_controls);
        assert!(sv.shared_clean_pct <= 100);
        assert!(sv.specific_clean_pct <= 100);
        assert!(sv.shared_total > 0);
    }

    #[test]
    fn test_rule_referential_scope_known_shared_rule() {
        let iso = load_iso27001_mapping();
        let asvs = load_asvs_mapping();
        let scope = load_rule_referential_scope();
        assert!(!scope.is_empty());
        let overlap = iso.mapping.keys().find(|rk| asvs.mapping.contains_key(*rk));
        let sample_rule = overlap.expect("ISO27001 et ASVS doivent avoir un recouvrement réel");
        assert_eq!(scope[sample_rule], RuleScope::Shared);
    }

    // === ASVS coverage computation (port of TestAsvsComputation) ===

    #[test]
    fn test_asvs_compute_empty_findings() {
        let scope = load_rule_referential_scope();
        let result = compute_asvs_compliance(&[], &scope);
        assert_eq!(result.total_requirements, 348);
        assert!(result.covered_requirements > 0);
        assert_eq!(result.with_findings, 0);
        for r in result.requirements.values() {
            assert!(r.status != ComplianceStatus::Findings);
            assert_eq!(r.finding_count, 0);
        }
    }

    #[test]
    fn test_asvs_compute_with_findings() {
        let scope = load_rule_referential_scope();
        let findings = vec![finding("sql_injection_fstring", "HIGH")];
        let result = compute_asvs_compliance(&findings, &scope);
        assert!(result.with_findings > 0);
        let req = &result.requirements["1.2.4"];
        assert_eq!(req.status, ComplianceStatus::Findings);
        assert!(req.finding_count >= 1);
    }

    #[test]
    fn test_asvs_chapters_and_levels_aggregation() {
        let scope = load_rule_referential_scope();
        let result = compute_asvs_compliance(&[], &scope);
        assert_eq!(result.chapters.len(), 17);
        assert_eq!(result.levels.len(), 3);
        for level in ["L1", "L2", "L3"] {
            assert!(result.levels.contains_key(level));
        }
    }

    #[test]
    fn test_asvs_shared_vs_specific_split() {
        let scope = load_rule_referential_scope();
        let result = compute_asvs_compliance(&[], &scope);
        let sv = &result.shared_vs_specific;
        assert_eq!(
            sv.shared_total + sv.specific_total,
            result.covered_requirements
        );
    }

    // === NIST CSF coverage computation (port of TestNistCsfComputation) ===

    #[test]
    fn test_nist_compute_empty_findings() {
        let scope = load_rule_referential_scope();
        let m = load_nist_csf_mapping();
        let result = compute_nist_csf_compliance(&[], &scope);
        assert_eq!(result.total_subcategories, m.subcategories.len());
        assert!(result.covered_subcategories > 0);
        assert_eq!(result.with_findings, 0);
        for s in result.subcategories.values() {
            assert!(s.status != ComplianceStatus::Findings);
            assert_eq!(s.finding_count, 0);
        }
    }

    #[test]
    fn test_nist_compute_with_findings() {
        let scope = load_rule_referential_scope();
        let findings = vec![finding("sql_injection_fstring", "HIGH")];
        let result = compute_nist_csf_compliance(&findings, &scope);
        assert!(result.with_findings > 0);
        let subcat = &result.subcategories["PR.DS-10"];
        assert_eq!(subcat.status, ComplianceStatus::Findings);
        assert!(subcat.finding_count >= 1);
    }

    #[test]
    fn test_nist_covered_independent_of_findings() {
        // Franck's feedback R31: applicability must not depend on findings.
        let scope = load_rule_referential_scope();
        let clean = compute_nist_csf_compliance(&[], &scope);
        let dirty =
            compute_nist_csf_compliance(&[finding("sql_injection_fstring", "HIGH")], &scope);
        assert_eq!(clean.covered_subcategories, dirty.covered_subcategories);
        assert_eq!(clean.total_subcategories, dirty.total_subcategories);
    }

    #[test]
    fn test_nist_by_function_aggregation() {
        let scope = load_rule_referential_scope();
        let result = compute_nist_csf_compliance(&[], &scope);
        let total: usize = result.by_function.values().map(|f| f.total).sum();
        assert_eq!(total, result.total_subcategories);
    }

    #[test]
    fn test_nist_shared_vs_specific_split() {
        let scope = load_rule_referential_scope();
        let result = compute_nist_csf_compliance(&[], &scope);
        let sv = &result.shared_vs_specific;
        assert_eq!(
            sv.shared_total + sv.specific_total,
            result.covered_subcategories
        );
    }

    #[test]
    fn test_multiple_findings_same_rule_count_individually() {
        // hardcoded_secret maps to several ISO controls — checks that
        // 2 distinct findings on the same rule count twice, not once.
        let scope = load_rule_referential_scope();
        let findings = vec![
            finding("hardcoded_secret", "HIGH"),
            finding("hardcoded_secret", "HIGH"),
        ];
        let result = compute_iso27001_compliance(&findings, &scope);
        let ctrl = &result.controls["A.8.28"];
        assert_eq!(ctrl.finding_count, 2);
        assert_eq!(ctrl.severities["HIGH"], 2);
    }

    #[test]
    fn test_pct_zero_denominator_is_zero_not_nan() {
        assert_eq!(pct(0, 0), 0);
    }
}
