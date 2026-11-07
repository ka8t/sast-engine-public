//! Live PostgreSQL connection and credential loading — port
//! of `_load_db_credentials`/`_extract_schema_psycopg2`
//! (`Audit/sca/database.py`).
//!
//! **New capability for AuditRust**: this is the first module in the
//! port that opens a network connection — to the **audited
//! project's** database (credentials supplied by the operator via `.env`),
//! not to a third-party service. A distinct category from the "no
//! network calls in the engine" rule, which targets calls to external
//! services like CVE feeds, not the
//! database that the audited project itself declares).
//!
//! **Not ported**: interactive mode (`_interactive_db_setup`,
//! `input()`/`getpass()` prompts + writing to `.env`/
//! `audit.config.json`) — doesn't match the usual invocation mode
//! of a SAST scan (CI/script). Without complete credentials, loading
//! simply fails (like the non-interactive branch on the Python side). The
//! subprocess `psql` fallback (`_extract_schema_psql`,
//! used on the Python side only when `psycopg2` isn't installed)
//! has no reason to exist here: the `postgres` crate is a direct
//! dependency, always available.

use std::collections::BTreeMap;
use std::path::Path;

use postgres::NoTls;

use crate::project::database::schema::{
    ColumnSchema, ConstraintSchema, DatabaseSchema, TableSchema,
};

#[derive(Debug, Clone)]
pub struct DbCredentials {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone, Default)]
pub struct DbConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub database: Option<String>,
    pub user: Option<String>,
    pub password_env_file: Option<String>,
    pub password_env_var: Option<String>,
}

/// Loads credentials from the JSON config + the password
/// from a `.env` file — port of `_load_db_credentials` (without
/// the interactive fallback, cf. module doc). `root_dir`: root of
/// the audited project, to resolve a relative `password_env_file`.
pub fn load_db_credentials(config: &DbConfig, root_dir: &Path) -> Result<DbCredentials, String> {
    let host = config
        .host
        .clone()
        .unwrap_or_else(|| "localhost".to_string());
    let port = config.port.unwrap_or(5432);
    let database = config.database.clone().unwrap_or_default();
    let user = config.user.clone().unwrap_or_default();

    if database.is_empty() || user.is_empty() {
        return Err("identifiants incomplets (database/user manquant dans la config)".to_string());
    }

    let env_file_name = config
        .password_env_file
        .clone()
        .unwrap_or_else(|| ".env".to_string());
    let env_path = Path::new(&env_file_name);
    let env_path = if env_path.is_absolute() {
        env_path.to_path_buf()
    } else {
        root_dir.join(env_path)
    };
    let env_var = config
        .password_env_var
        .clone()
        .unwrap_or_else(|| "DB_PASSWORD".to_string());

    let env_content = std::fs::read_to_string(&env_path)
        .map_err(|e| format!("fichier .env introuvable ({}): {e}", env_path.display()))?;

    let password = parse_env_var(&env_content, &env_var)
        .ok_or_else(|| format!("variable {env_var} absente de {}", env_path.display()))?;

    Ok(DbCredentials {
        host,
        port,
        database,
        user,
        password,
    })
}

/// Extracts a variable's value from the content of a `.env`
/// file — port of the parsing loop in `_load_db_credentials`.
fn parse_env_var(env_content: &str, var_name: &str) -> Option<String> {
    for line in env_content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() == var_name {
            let value = value.trim().trim_matches('"').trim_matches('\'');
            return Some(value.to_string());
        }
    }
    None
}

/// Extracts the current PostgreSQL schema via a live connection —
/// port of `_extract_schema_psycopg2`.
pub fn extract_pg_schema(credentials: &DbCredentials) -> Result<DatabaseSchema, String> {
    let mut config = postgres::Config::new();
    config
        .host(&credentials.host)
        .port(credentials.port)
        .dbname(&credentials.database)
        .user(&credentials.user)
        .password(&credentials.password);
    let mut client = config.connect(NoTls).map_err(|e| e.to_string())?;

    let mut schema = DatabaseSchema {
        timestamp: chrono::Local::now().to_rfc3339(),
        database: credentials.database.clone(),
        tables: BTreeMap::new(),
        enums: BTreeMap::new(),
    };

    let table_rows = client
        .query(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_type = 'BASE TABLE' \
             ORDER BY table_name",
            &[],
        )
        .map_err(|e| e.to_string())?;
    let table_names: Vec<String> = table_rows.iter().map(|r| r.get::<_, String>(0)).collect();

    for table_name in &table_names {
        let mut table = TableSchema::default();

        let col_rows = client
            .query(
                "SELECT column_name, data_type, is_nullable, column_default, \
                        character_maximum_length, numeric_precision \
                 FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = $1 \
                 ORDER BY ordinal_position",
                &[table_name],
            )
            .map_err(|e| e.to_string())?;
        for row in &col_rows {
            let col_name: String = row.get(0);
            let base_type: String = row.get(1);
            let is_nullable: String = row.get(2);
            let default: Option<String> = row.get(3);
            let max_length: Option<i32> = row.get(4);
            let numeric_precision: Option<i32> = row.get(5);
            let data_type = if let Some(len) = max_length {
                format!("{base_type}({len})")
            } else if let Some(prec) = numeric_precision {
                format!("{base_type}({prec})")
            } else {
                base_type
            };
            table.columns.insert(
                col_name,
                ColumnSchema {
                    data_type,
                    nullable: is_nullable == "YES",
                    default,
                },
            );
        }

        let constraint_rows = client
            .query(
                "SELECT tc.constraint_name, tc.constraint_type, \
                        string_agg(kcu.column_name, ', ' ORDER BY kcu.ordinal_position) \
                 FROM information_schema.table_constraints tc \
                 JOIN information_schema.key_column_usage kcu \
                     ON tc.constraint_name = kcu.constraint_name \
                     AND tc.table_schema = kcu.table_schema \
                 WHERE tc.table_schema = 'public' AND tc.table_name = $1 \
                 GROUP BY tc.constraint_name, tc.constraint_type",
                &[table_name],
            )
            .map_err(|e| e.to_string())?;
        for row in &constraint_rows {
            let name: String = row.get(0);
            let constraint_type: String = row.get(1);
            let columns: Option<String> = row.get(2);
            let columns = columns
                .map(|c| c.split(", ").map(|s| s.to_string()).collect())
                .unwrap_or_default();
            table.constraints.insert(
                name,
                ConstraintSchema {
                    constraint_type,
                    columns,
                },
            );
        }

        let index_rows = client
            .query(
                "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND tablename = $1",
                &[table_name],
            )
            .map_err(|e| e.to_string())?;
        table.indexes = index_rows.iter().map(|r| r.get::<_, String>(0)).collect();

        schema.tables.insert(table_name.clone(), table);
    }

    let enum_rows = client
        .query(
            "SELECT t.typname, array_agg(e.enumlabel ORDER BY e.enumsortorder) \
             FROM pg_type t \
             JOIN pg_enum e ON t.oid = e.enumtypid \
             JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace \
             WHERE n.nspname = 'public' \
             GROUP BY t.typname",
            &[],
        )
        .map_err(|e| e.to_string())?;
    for row in &enum_rows {
        let name: String = row.get(0);
        let labels: Vec<String> = row.get(1);
        schema.enums.insert(name, labels);
    }

    Ok(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_var_finds_value() {
        let content = "OTHER=1\nDB_PASSWORD=secret123\n";
        assert_eq!(
            parse_env_var(content, "DB_PASSWORD"),
            Some("secret123".to_string())
        );
    }

    #[test]
    fn test_parse_env_var_ignores_comments_and_blank_lines() {
        let content = "# comment\n\nDB_PASSWORD=secret\n";
        assert_eq!(
            parse_env_var(content, "DB_PASSWORD"),
            Some("secret".to_string())
        );
    }

    #[test]
    fn test_parse_env_var_strips_quotes() {
        let content = "DB_PASSWORD=\"quoted value\"\n";
        assert_eq!(
            parse_env_var(content, "DB_PASSWORD"),
            Some("quoted value".to_string())
        );
    }

    #[test]
    fn test_parse_env_var_missing_returns_none() {
        let content = "OTHER=1\n";
        assert_eq!(parse_env_var(content, "DB_PASSWORD"), None);
    }

    #[test]
    fn test_load_db_credentials_missing_database_fails() {
        let config = DbConfig {
            user: Some("u".to_string()),
            ..Default::default()
        };
        let result = load_db_credentials(&config, Path::new("/tmp"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_db_credentials_missing_env_file_fails() {
        let config = DbConfig {
            database: Some("mydb".to_string()),
            user: Some("myuser".to_string()),
            ..Default::default()
        };
        let result = load_db_credentials(&config, Path::new("/nonexistent-dir-xyz"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_db_credentials_full_success() {
        let tmp = std::env::temp_dir().join(format!("auditrust-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join(".env"), "DB_PASSWORD=hunter2\n").unwrap();
        let config = DbConfig {
            database: Some("mydb".to_string()),
            user: Some("myuser".to_string()),
            ..Default::default()
        };
        let creds = load_db_credentials(&config, &tmp).unwrap();
        assert_eq!(creds.password, "hunter2");
        assert_eq!(creds.host, "localhost");
        assert_eq!(creds.port, 5432);
        std::fs::remove_dir_all(&tmp).ok();
    }
}
