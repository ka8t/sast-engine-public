//! Searches for usages, in the audited project's code, of dropped/
//! modified schema elements — port of `_analyze_code_usage`
//! (`Audit/sca/database.py`). Escalates the severity of a change
//! when references are found (a dropped column that is
//! never referenced in the code is less risky than a dropped column
//! that is actively used).

use regex::Regex;

use crate::project::database::schema::{ChangeType, CodeReference, SchemaChange};

/// Change types considered "critical" — only these
/// trigger a usage search (mirrors `critical_changes`).
fn is_critical(change_type: &ChangeType) -> bool {
    matches!(
        change_type,
        ChangeType::ColumnDropped | ChangeType::TableDropped | ChangeType::TypeChanged
    )
}

fn element_patterns(element: &str) -> Vec<Regex> {
    let escaped = regex::escape(element);
    [
        format!(r"\.{escaped}\b"),
        format!(r#"\[['"]{escaped}['"]\]"#),
        format!(r"\b{escaped}\b"),
    ]
    .iter()
    .filter_map(|p| Regex::new(p).ok())
    .collect()
}

/// Enriches each critical change with its code references —
/// port of `_analyze_code_usage`. `all_code`: (file, line,
/// content) for the full set of source files in the audited project
/// (typically Python + JavaScript, as on the Python side).
pub fn analyze_code_usage(
    changes: &mut [SchemaChange],
    all_code: &[(String, usize, String)],
    escalate: bool,
) {
    for change in changes.iter_mut() {
        if !is_critical(&change.change_type) {
            continue;
        }
        let Some(element) = change.column.clone().or_else(|| Some(change.table.clone())) else {
            continue;
        };
        if element.is_empty() {
            continue;
        }
        let patterns = element_patterns(&element);

        let mut references = Vec::new();
        for (file, line, code) in all_code {
            if patterns.iter().any(|p| p.is_match(code)) {
                references.push(CodeReference {
                    file: file.clone(),
                    line: *line,
                    code: code.chars().take(100).collect(),
                });
            }
        }

        if references.is_empty() {
            continue;
        }

        change
            .description
            .push_str(&format!(" (utilisé dans {} fichier(s))", references.len()));

        if escalate {
            match change.severity.as_str() {
                "HIGH" => {
                    change.severity = "CRITICAL".to_string();
                    change.rule.push_str("_WITH_USAGE");
                }
                "MEDIUM" => {
                    change.severity = "HIGH".to_string();
                    change.rule.push_str("_WITH_USAGE");
                }
                _ => {}
            }
        }

        let mut seen_files: Vec<&str> = Vec::new();
        for r in &references {
            if !seen_files.contains(&r.file.as_str()) {
                seen_files.push(&r.file);
            }
            if seen_files.len() >= 3 {
                break;
            }
        }
        change
            .risk
            .push_str(&format!(" Trouvé dans: {}", seen_files.join(", ")));
        if references.len() > 3 {
            change
                .risk
                .push_str(&format!(" et {} autre(s)...", references.len() - 3));
        }

        change.code_references = references;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(
        change_type: ChangeType,
        table: &str,
        column: Option<&str>,
        severity: &str,
    ) -> SchemaChange {
        SchemaChange {
            change_type,
            table: table.to_string(),
            column: column.map(|s| s.to_string()),
            rule: "COLUMN_DROPPED".to_string(),
            description: "Colonne supprimée: users.email".to_string(),
            severity: severity.to_string(),
            risk: "Risque de base.".to_string(),
            solution: String::new(),
            code_references: vec![],
        }
    }

    #[test]
    fn test_no_references_leaves_change_unmodified() {
        let mut changes = vec![change(
            ChangeType::ColumnDropped,
            "users",
            Some("email"),
            "HIGH",
        )];
        let all_code = vec![("app.py".to_string(), 1, "print('hello')".to_string())];
        analyze_code_usage(&mut changes, &all_code, true);
        assert_eq!(changes[0].severity, "HIGH");
        assert!(changes[0].code_references.is_empty());
    }

    #[test]
    fn test_dotted_reference_found_and_escalates_high_to_critical() {
        let mut changes = vec![change(
            ChangeType::ColumnDropped,
            "users",
            Some("email"),
            "HIGH",
        )];
        let all_code = vec![("app.py".to_string(), 10, "user.email = 'x'".to_string())];
        analyze_code_usage(&mut changes, &all_code, true);
        assert_eq!(changes[0].severity, "CRITICAL");
        assert!(changes[0].rule.ends_with("_WITH_USAGE"));
        assert_eq!(changes[0].code_references.len(), 1);
        assert!(changes[0].description.contains("utilisé dans 1 fichier"));
    }

    #[test]
    fn test_medium_escalates_to_high() {
        let mut changes = vec![change(
            ChangeType::ColumnDropped,
            "users",
            Some("email"),
            "MEDIUM",
        )];
        let all_code = vec![("app.py".to_string(), 10, "x = email".to_string())];
        analyze_code_usage(&mut changes, &all_code, true);
        assert_eq!(changes[0].severity, "HIGH");
    }

    #[test]
    fn test_escalate_false_keeps_original_severity() {
        let mut changes = vec![change(
            ChangeType::ColumnDropped,
            "users",
            Some("email"),
            "HIGH",
        )];
        let all_code = vec![("app.py".to_string(), 10, "user.email = 'x'".to_string())];
        analyze_code_usage(&mut changes, &all_code, false);
        assert_eq!(changes[0].severity, "HIGH");
        // References are still attached even without escalation.
        assert_eq!(changes[0].code_references.len(), 1);
    }

    #[test]
    fn test_non_critical_change_type_ignored() {
        let mut changes = vec![change(
            ChangeType::ColumnAdded,
            "users",
            Some("email"),
            "LOW",
        )];
        let all_code = vec![("app.py".to_string(), 10, "user.email = 'x'".to_string())];
        analyze_code_usage(&mut changes, &all_code, true);
        assert!(changes[0].code_references.is_empty());
        assert_eq!(changes[0].severity, "LOW");
    }

    #[test]
    fn test_bracket_notation_reference_found() {
        let mut changes = vec![change(
            ChangeType::ColumnDropped,
            "users",
            Some("email"),
            "HIGH",
        )];
        let all_code = vec![("app.js".to_string(), 3, "row['email']".to_string())];
        analyze_code_usage(&mut changes, &all_code, true);
        assert_eq!(changes[0].code_references.len(), 1);
    }

    #[test]
    fn test_word_boundary_avoids_partial_match() {
        // "email" must not match "emails_sent" (different word).
        let mut changes = vec![change(
            ChangeType::ColumnDropped,
            "users",
            Some("email"),
            "HIGH",
        )];
        let all_code = vec![("app.py".to_string(), 1, "emails_sent = 0".to_string())];
        analyze_code_usage(&mut changes, &all_code, true);
        assert!(changes[0].code_references.is_empty());
    }

    #[test]
    fn test_table_dropped_uses_table_name_when_no_column() {
        let mut changes = vec![change(ChangeType::TableDropped, "sessions", None, "HIGH")];
        let all_code = vec![("app.py".to_string(), 1, "db.sessions.delete()".to_string())];
        analyze_code_usage(&mut changes, &all_code, true);
        assert_eq!(changes[0].code_references.len(), 1);
    }

    #[test]
    fn test_risk_lists_up_to_3_files() {
        let mut changes = vec![change(
            ChangeType::ColumnDropped,
            "users",
            Some("email"),
            "HIGH",
        )];
        let all_code = vec![
            ("a.py".to_string(), 1, "user.email".to_string()),
            ("b.py".to_string(), 1, "user.email".to_string()),
            ("c.py".to_string(), 1, "user.email".to_string()),
            ("d.py".to_string(), 1, "user.email".to_string()),
        ];
        analyze_code_usage(&mut changes, &all_code, true);
        assert!(changes[0].risk.contains("et 1 autre(s)"));
    }
}
