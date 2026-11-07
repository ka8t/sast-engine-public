//! AST for the `.sca` DSL — faithful port of `Audit/sca/dsl/nodes.py`.
//!
//! Intermediate structure between parsing a `.sca` file and its
//! compilation to the JSON format consumed by `rule_loader.py`.

use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MatchRegexBlock {
    pub pattern: String,
    pub is_text: bool,
    pub scope: String,
    pub with_pattern: String,
    pub with_is_text: bool,
    pub pattern_not: String,
    pub pattern_not_is_text: bool,
    pub pattern_inside: String,
    pub pattern_not_inside: String,
    pub line_number: usize,
}

impl MatchRegexBlock {
    pub fn new(line_number: usize) -> Self {
        MatchRegexBlock {
            scope: "line".to_string(),
            line_number,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MatchAstBlock {
    pub pattern: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MatchFileContainsBlock {
    pub has_patterns: Vec<String>,
    pub not_has_patterns: Vec<String>,
    pub scope: String,
    pub line_number: usize,
}

impl MatchFileContainsBlock {
    pub fn new(line_number: usize) -> Self {
        MatchFileContainsBlock {
            scope: "file".to_string(),
            line_number,
            ..Default::default()
        }
    }
}

/// A `match` block — regex, AST (tree-sitter) or file_contains.
#[derive(Debug, Clone, PartialEq)]
pub enum MatchBlock {
    Regex(MatchRegexBlock),
    Ast(MatchAstBlock),
    FileContains(MatchFileContainsBlock),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceSpec {
    pub pattern: String,
    pub kind: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SinkSpec {
    pub pattern: String,
    pub arg_index: i64,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SanitizerSpec {
    pub pattern: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PassthroughSpec {
    pub pattern: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct I18nBlock {
    pub texts: BTreeMap<String, String>,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MetadataBlock {
    pub cwe: Vec<String>,
    pub cve: Vec<String>,
    pub owasp: String,
    pub iso27001: Vec<String>,
    pub wcag: Vec<String>,
    pub asvs: Vec<String>,
    // AuditAi provenance (CONSTRAINTS.md C9) — empty for any
    // builtin or manually written custom rule.
    pub generated_by: String,
    pub generated_at: String,
    pub auditai_version: String,
    pub manifest_hash: String,
    pub org_id: String,
    pub signature: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LicenseBlock {
    pub min_tier: String,
    pub features: Vec<String>,
    pub demo_fallback: bool,
    pub line_number: usize,
}

impl Default for LicenseBlock {
    fn default() -> Self {
        LicenseBlock {
            min_tier: "demo".to_string(),
            features: Vec::new(),
            demo_fallback: false,
            line_number: 0,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FileConditionBlock {
    pub has_patterns: Vec<String>,
    pub not_has_patterns: Vec<String>,
    pub path_contains: Vec<String>,
    pub not_path_has_file: Vec<String>,
    pub min_lines: i64,
    pub scope: String,
    pub line_number: usize,
}

impl FileConditionBlock {
    pub fn new(line_number: usize) -> Self {
        FileConditionBlock {
            scope: "file".to_string(),
            line_number,
            ..Default::default()
        }
    }
}

/// Root node — a complete `.sca` rule (`rule ... end`).
#[derive(Debug, Clone, PartialEq)]
pub struct RuleNode {
    pub id: String,
    pub language: String,
    pub category: String,
    pub severity: String,
    pub confidence: i64,
    /// Optional — inferred by the compiler if absent.
    pub mode: String,
    pub match_blocks: Vec<MatchBlock>,
    pub file_conditions: Vec<FileConditionBlock>,
    pub sources: Vec<SourceSpec>,
    pub sinks: Vec<SinkSpec>,
    pub sanitizers: Vec<SanitizerSpec>,
    pub passthroughs: Vec<PassthroughSpec>,
    pub message: I18nBlock,
    pub risk: I18nBlock,
    pub solution: I18nBlock,
    pub benefit: I18nBlock,
    pub metadata: MetadataBlock,
    pub license: LicenseBlock,
    pub fix_before: String,
    pub fix_after: String,
    pub hook: String,
    pub line_number: usize,
}

impl RuleNode {
    pub fn new(id: impl Into<String>, line_number: usize) -> Self {
        RuleNode {
            id: id.into(),
            language: String::new(),
            category: String::new(),
            severity: String::new(),
            confidence: 80,
            mode: String::new(),
            match_blocks: Vec::new(),
            file_conditions: Vec::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: Vec::new(),
            passthroughs: Vec::new(),
            message: I18nBlock::default(),
            risk: I18nBlock::default(),
            solution: I18nBlock::default(),
            benefit: I18nBlock::default(),
            metadata: MetadataBlock::default(),
            license: LicenseBlock::default(),
            fix_before: String::new(),
            fix_after: String::new(),
            hook: String::new(),
            line_number,
        }
    }
}
