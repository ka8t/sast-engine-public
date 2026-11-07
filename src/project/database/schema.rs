//! PostgreSQL schema model and diff between 2 schemas — port of the
//! computation part of `Audit/sca/database.py` (`_compare_schemas`/
//! `_calculate_schema_stats`), independent of the actual connection.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ColumnSchema {
    pub data_type: String,
    pub nullable: bool,
    pub default: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ConstraintSchema {
    pub constraint_type: String,
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct TableSchema {
    pub columns: BTreeMap<String, ColumnSchema>,
    pub constraints: BTreeMap<String, ConstraintSchema>,
    pub indexes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DatabaseSchema {
    pub timestamp: String,
    pub database: String,
    pub tables: BTreeMap<String, TableSchema>,
    pub enums: BTreeMap<String, Vec<String>>,
}

/// Severities configurable per change type — mirrors
/// `db_config["severity"]` (`sca/database.py`), identical defaults.
#[derive(Debug, Clone)]
pub struct SeverityConfig {
    pub table_added: String,
    pub table_dropped: String,
    pub column_added: String,
    pub column_dropped: String,
    pub type_changed: String,
    pub index_added: String,
}

impl Default for SeverityConfig {
    fn default() -> Self {
        Self {
            table_added: "INFO".to_string(),
            table_dropped: "HIGH".to_string(),
            column_added: "LOW".to_string(),
            column_dropped: "HIGH".to_string(),
            type_changed: "MEDIUM".to_string(),
            index_added: "INFO".to_string(),
        }
    }
}

/// Which change types are tracked — mirrors
/// `db_config["track"]`, all defaults `true`.
#[derive(Debug, Clone)]
pub struct TrackConfig {
    pub tables: bool,
    pub columns: bool,
    pub indexes: bool,
}

impl Default for TrackConfig {
    fn default() -> Self {
        Self {
            tables: true,
            columns: true,
            indexes: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeType {
    TableAdded,
    TableDropped,
    ColumnAdded,
    ColumnDropped,
    TypeChanged,
    NullableChanged,
    IndexAdded,
    IndexDropped,
}

#[derive(Debug, Clone)]
pub struct SchemaChange {
    pub change_type: ChangeType,
    pub table: String,
    pub column: Option<String>,
    pub rule: String,
    pub description: String,
    pub severity: String,
    pub risk: String,
    pub solution: String,
    /// Code references found by `_analyze_code_usage` — empty
    /// until enriched (separate computation, `code_usage.rs`).
    pub code_references: Vec<CodeReference>,
}

#[derive(Debug, Clone)]
pub struct CodeReference {
    pub file: String,
    pub line: usize,
    pub code: String,
}

/// Compares 2 schemas and returns the list of changes — port of
/// `_compare_schemas`.
pub fn compare_schemas(
    baseline: &DatabaseSchema,
    current: &DatabaseSchema,
    severity: &SeverityConfig,
    track: &TrackConfig,
) -> Vec<SchemaChange> {
    let mut changes = Vec::new();

    let baseline_tables: BTreeSet<&String> = baseline.tables.keys().collect();
    let current_tables: BTreeSet<&String> = current.tables.keys().collect();

    if track.tables {
        for table in current_tables.difference(&baseline_tables) {
            changes.push(SchemaChange {
                change_type: ChangeType::TableAdded,
                table: (*table).clone(),
                column: None,
                rule: "TABLE_ADDED".to_string(),
                description: format!("Nouvelle table: {table}"),
                severity: severity.table_added.clone(),
                risk: "Nouvelle table ajoutée au schéma.".to_string(),
                solution: "Aucune action requise si intentionnel.".to_string(),
                code_references: vec![],
            });
        }
        for table in baseline_tables.difference(&current_tables) {
            changes.push(SchemaChange {
                change_type: ChangeType::TableDropped,
                table: (*table).clone(),
                column: None,
                rule: "TABLE_DROPPED".to_string(),
                description: format!("Table supprimée: {table}"),
                severity: severity.table_dropped.clone(),
                risk: "La suppression d'une table peut causer des erreurs si le code y fait référence."
                    .to_string(),
                solution: "Vérifier que le code ne référence plus cette table.".to_string(),
                code_references: vec![],
            });
        }
    }

    if track.columns {
        for table in baseline_tables.intersection(&current_tables) {
            let baseline_table = &baseline.tables[*table];
            let current_table = &current.tables[*table];
            let baseline_cols: BTreeSet<&String> = baseline_table.columns.keys().collect();
            let current_cols: BTreeSet<&String> = current_table.columns.keys().collect();

            for col in current_cols.difference(&baseline_cols) {
                changes.push(SchemaChange {
                    change_type: ChangeType::ColumnAdded,
                    table: (*table).clone(),
                    column: Some((*col).clone()),
                    rule: "COLUMN_ADDED".to_string(),
                    description: format!("Nouvelle colonne: {table}.{col}"),
                    severity: severity.column_added.clone(),
                    risk: "Nouvelle colonne ajoutée.".to_string(),
                    solution: "Aucune action requise si intentionnel.".to_string(),
                    code_references: vec![],
                });
            }
            for col in baseline_cols.difference(&current_cols) {
                changes.push(SchemaChange {
                    change_type: ChangeType::ColumnDropped,
                    table: (*table).clone(),
                    column: Some((*col).clone()),
                    rule: "COLUMN_DROPPED".to_string(),
                    description: format!("Colonne supprimée: {table}.{col}"),
                    severity: severity.column_dropped.clone(),
                    risk: "La suppression d'une colonne peut causer des erreurs si le code y fait référence."
                        .to_string(),
                    solution: "Vérifier que le code ne référence plus cette colonne.".to_string(),
                    code_references: vec![],
                });
            }
            for col in baseline_cols.intersection(&current_cols) {
                let old = &baseline_table.columns[*col];
                let new = &current_table.columns[*col];
                if old.data_type != new.data_type {
                    changes.push(SchemaChange {
                        change_type: ChangeType::TypeChanged,
                        table: (*table).clone(),
                        column: Some((*col).clone()),
                        rule: "TYPE_CHANGED".to_string(),
                        description: format!(
                            "Type modifié: {table}.{col} ({} → {})",
                            old.data_type, new.data_type
                        ),
                        severity: severity.type_changed.clone(),
                        risk: "Le changement de type peut causer des erreurs de conversion."
                            .to_string(),
                        solution: "Vérifier la compatibilité avec le code existant.".to_string(),
                        code_references: vec![],
                    });
                }
                if old.nullable != new.nullable {
                    changes.push(SchemaChange {
                        change_type: ChangeType::NullableChanged,
                        table: (*table).clone(),
                        column: Some((*col).clone()),
                        rule: "NULLABLE_CHANGED".to_string(),
                        description: format!(
                            "Nullable modifié: {table}.{col} ({} → {})",
                            old.nullable, new.nullable
                        ),
                        severity: if !new.nullable { "MEDIUM" } else { "LOW" }.to_string(),
                        risk:
                            "Passer nullable=false peut causer des contraintes NOT NULL violations."
                                .to_string(),
                        solution: "S'assurer que le code gère correctement les valeurs NULL."
                            .to_string(),
                        code_references: vec![],
                    });
                }
            }
        }
    }

    if track.indexes {
        for table in baseline_tables.intersection(&current_tables) {
            let baseline_idx: BTreeSet<&String> = baseline.tables[*table].indexes.iter().collect();
            let current_idx: BTreeSet<&String> = current.tables[*table].indexes.iter().collect();
            for idx in current_idx.difference(&baseline_idx) {
                changes.push(SchemaChange {
                    change_type: ChangeType::IndexAdded,
                    table: (*table).clone(),
                    column: None,
                    rule: "INDEX_ADDED".to_string(),
                    description: format!("Index ajouté: {idx} sur {table}"),
                    severity: severity.index_added.clone(),
                    risk: "Nouvel index créé.".to_string(),
                    solution: "Aucune action requise.".to_string(),
                    code_references: vec![],
                });
            }
            for idx in baseline_idx.difference(&current_idx) {
                changes.push(SchemaChange {
                    change_type: ChangeType::IndexDropped,
                    table: (*table).clone(),
                    column: None,
                    rule: "INDEX_DROPPED".to_string(),
                    description: format!("Index supprimé: {idx} sur {table}"),
                    severity: "MEDIUM".to_string(),
                    risk: "La suppression d'un index peut impacter les performances.".to_string(),
                    solution: "Vérifier que l'index n'était pas nécessaire pour les performances."
                        .to_string(),
                    code_references: vec![],
                });
            }
        }
    }

    changes
}

#[derive(Debug, Clone, Default)]
pub struct SchemaChangeCounts {
    pub added_tables: usize,
    pub dropped_tables: usize,
    pub added_columns: usize,
    pub dropped_columns: usize,
    pub added_indexes: usize,
    pub dropped_indexes: usize,
    pub modified_columns: usize,
}

#[derive(Debug, Clone, Default)]
pub struct SchemaStats {
    pub tables_count: usize,
    pub columns_count: usize,
    pub indexes_count: usize,
    pub constraints_count: usize,
    pub enums_count: usize,
    pub changes: SchemaChangeCounts,
}

/// Computes statistics for the current schema — port of
/// `_calculate_schema_stats`.
pub fn calculate_schema_stats(current: &DatabaseSchema, changes: &[SchemaChange]) -> SchemaStats {
    let mut stats = SchemaStats {
        tables_count: current.tables.len(),
        columns_count: current.tables.values().map(|t| t.columns.len()).sum(),
        indexes_count: current.tables.values().map(|t| t.indexes.len()).sum(),
        constraints_count: current.tables.values().map(|t| t.constraints.len()).sum(),
        enums_count: current.enums.len(),
        changes: SchemaChangeCounts::default(),
    };
    for change in changes {
        match change.change_type {
            ChangeType::TableAdded => stats.changes.added_tables += 1,
            ChangeType::TableDropped => stats.changes.dropped_tables += 1,
            ChangeType::ColumnAdded => stats.changes.added_columns += 1,
            ChangeType::ColumnDropped => stats.changes.dropped_columns += 1,
            ChangeType::IndexAdded => stats.changes.added_indexes += 1,
            ChangeType::IndexDropped => stats.changes.dropped_indexes += 1,
            ChangeType::TypeChanged | ChangeType::NullableChanged => {
                stats.changes.modified_columns += 1
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_schema() -> DatabaseSchema {
        DatabaseSchema {
            timestamp: "t".to_string(),
            database: "db".to_string(),
            ..Default::default()
        }
    }

    fn table_with_column(col_type: &str, nullable: bool) -> TableSchema {
        let mut columns = BTreeMap::new();
        columns.insert(
            "id".to_string(),
            ColumnSchema {
                data_type: col_type.to_string(),
                nullable,
                default: None,
            },
        );
        TableSchema {
            columns,
            ..Default::default()
        }
    }

    #[test]
    fn test_no_changes_between_identical_schemas() {
        let mut schema = empty_schema();
        schema
            .tables
            .insert("users".to_string(), table_with_column("integer", false));
        let changes = compare_schemas(
            &schema,
            &schema,
            &SeverityConfig::default(),
            &TrackConfig::default(),
        );
        assert!(changes.is_empty());
    }

    #[test]
    fn test_table_added_and_dropped() {
        let mut baseline = empty_schema();
        baseline
            .tables
            .insert("old_table".to_string(), TableSchema::default());
        let mut current = empty_schema();
        current
            .tables
            .insert("new_table".to_string(), TableSchema::default());

        let changes = compare_schemas(
            &baseline,
            &current,
            &SeverityConfig::default(),
            &TrackConfig::default(),
        );
        assert_eq!(changes.len(), 2);
        assert!(
            changes
                .iter()
                .any(|c| c.change_type == ChangeType::TableAdded && c.table == "new_table")
        );
        assert!(
            changes
                .iter()
                .any(|c| c.change_type == ChangeType::TableDropped && c.table == "old_table")
        );
        // Default HIGH severity for a dropped table -- worth noting.
        let dropped = changes
            .iter()
            .find(|c| c.change_type == ChangeType::TableDropped)
            .unwrap();
        assert_eq!(dropped.severity, "HIGH");
    }

    #[test]
    fn test_column_type_change_detected() {
        let mut baseline = empty_schema();
        baseline
            .tables
            .insert("users".to_string(), table_with_column("integer", false));
        let mut current = empty_schema();
        current
            .tables
            .insert("users".to_string(), table_with_column("bigint", false));

        let changes = compare_schemas(
            &baseline,
            &current,
            &SeverityConfig::default(),
            &TrackConfig::default(),
        );
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::TypeChanged);
        assert!(changes[0].description.contains("integer → bigint"));
    }

    #[test]
    fn test_nullable_change_severity_depends_on_direction() {
        let mut baseline = empty_schema();
        baseline
            .tables
            .insert("users".to_string(), table_with_column("integer", true));
        let mut current = empty_schema();
        current
            .tables
            .insert("users".to_string(), table_with_column("integer", false));

        let changes = compare_schemas(
            &baseline,
            &current,
            &SeverityConfig::default(),
            &TrackConfig::default(),
        );
        assert_eq!(changes[0].change_type, ChangeType::NullableChanged);
        // true -> false (becomes NOT NULL) = MEDIUM, riskier than the reverse (LOW).
        assert_eq!(changes[0].severity, "MEDIUM");
    }

    #[test]
    fn test_track_config_disables_column_tracking() {
        let mut baseline = empty_schema();
        baseline
            .tables
            .insert("users".to_string(), table_with_column("integer", false));
        let mut current = empty_schema();
        current
            .tables
            .insert("users".to_string(), table_with_column("bigint", false));

        let track = TrackConfig {
            columns: false,
            ..Default::default()
        };
        let changes = compare_schemas(&baseline, &current, &SeverityConfig::default(), &track);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_calculate_schema_stats_counts_changes_by_type() {
        let mut current = empty_schema();
        current
            .tables
            .insert("users".to_string(), table_with_column("integer", false));
        let changes = vec![
            SchemaChange {
                change_type: ChangeType::TableAdded,
                table: "a".to_string(),
                column: None,
                rule: "TABLE_ADDED".to_string(),
                description: String::new(),
                severity: "INFO".to_string(),
                risk: String::new(),
                solution: String::new(),
                code_references: vec![],
            },
            SchemaChange {
                change_type: ChangeType::ColumnDropped,
                table: "a".to_string(),
                column: Some("b".to_string()),
                rule: "COLUMN_DROPPED".to_string(),
                description: String::new(),
                severity: "HIGH".to_string(),
                risk: String::new(),
                solution: String::new(),
                code_references: vec![],
            },
        ];
        let stats = calculate_schema_stats(&current, &changes);
        assert_eq!(stats.tables_count, 1);
        assert_eq!(stats.columns_count, 1);
        assert_eq!(stats.changes.added_tables, 1);
        assert_eq!(stats.changes.dropped_columns, 1);
    }
}
