//! `.sca` DSL compiler → JSON — faithful port of
//! `Audit/sca/dsl/compiler.py`.
//!
//! Transforms a `RuleNode` (intermediate AST) into a JSON value
//! identical to the format produced by the existing `.json` files in
//! `sca/rules/builtin/`.

use super::model::{MatchBlock, RuleNode};
use serde_json::{Map, Value, json};

pub fn compile_to_json(node: &RuleNode) -> Value {
    let mode = if node.mode.is_empty() {
        infer_mode(node)
    } else {
        node.mode.clone()
    };

    let mut result = Map::new();
    result.insert("id".to_string(), json!(node.id));
    result.insert("language".to_string(), json!(node.language));
    result.insert(
        "category".to_string(),
        json!(if node.category.is_empty() {
            "security".to_string()
        } else {
            node.category.clone()
        }),
    );
    result.insert("severity".to_string(), json!(node.severity));
    result.insert("confidence".to_string(), json!(node.confidence));
    result.insert("mode".to_string(), json!(mode));
    result.insert("message".to_string(), texts_to_value(&node.message.texts));

    if !node.risk.texts.is_empty() {
        result.insert("risk".to_string(), texts_to_value(&node.risk.texts));
    }
    if !node.solution.texts.is_empty() {
        result.insert("solution".to_string(), texts_to_value(&node.solution.texts));
    }
    if !node.benefit.texts.is_empty() {
        result.insert("benefit".to_string(), texts_to_value(&node.benefit.texts));
    }
    if !node.fix_before.is_empty() {
        result.insert("fix_before".to_string(), json!(node.fix_before));
    }
    if !node.fix_after.is_empty() {
        result.insert("fix_after".to_string(), json!(node.fix_after));
    }

    result.insert(
        "requires".to_string(),
        json!({
            "min_tier": node.license.min_tier,
            "features": node.license.features,
            "demo_fallback": node.license.demo_fallback,
        }),
    );

    let mut meta = Map::new();
    if !node.metadata.cwe.is_empty() {
        meta.insert("cwe".to_string(), json!(node.metadata.cwe));
    }
    if !node.metadata.cve.is_empty() {
        meta.insert("cve".to_string(), json!(node.metadata.cve));
    }
    if !node.metadata.owasp.is_empty() {
        meta.insert("owasp".to_string(), json!(node.metadata.owasp));
    }
    if !node.metadata.iso27001.is_empty() {
        meta.insert("iso27001".to_string(), json!(node.metadata.iso27001));
    }
    if !node.metadata.asvs.is_empty() {
        meta.insert("asvs".to_string(), json!(node.metadata.asvs));
    }
    if !node.metadata.wcag.is_empty() {
        meta.insert("wcag".to_string(), json!(node.metadata.wcag));
    }
    if !node.metadata.generated_by.is_empty() {
        meta.insert(
            "generated_by".to_string(),
            json!(node.metadata.generated_by),
        );
    }
    if !node.metadata.generated_at.is_empty() {
        meta.insert(
            "generated_at".to_string(),
            json!(node.metadata.generated_at),
        );
    }
    if !node.metadata.auditai_version.is_empty() {
        meta.insert(
            "auditai_version".to_string(),
            json!(node.metadata.auditai_version),
        );
    }
    if !node.metadata.manifest_hash.is_empty() {
        meta.insert(
            "manifest_hash".to_string(),
            json!(node.metadata.manifest_hash),
        );
    }
    if !node.metadata.org_id.is_empty() {
        meta.insert("org_id".to_string(), json!(node.metadata.org_id));
    }
    if !node.metadata.signature.is_empty() {
        meta.insert("signature".to_string(), json!(node.metadata.signature));
    }
    if !meta.is_empty() {
        result.insert("metadata".to_string(), Value::Object(meta));
    }

    // --- Mode-specific content ---

    if mode == "regex" || mode == "regex+taint" {
        result.insert(
            "patterns".to_string(),
            compile_regex_blocks(&node.match_blocks),
        );
    }

    if mode == "taint" || mode == "regex+taint" {
        let sources: Vec<Value> = node
            .sources
            .iter()
            .map(|s| json!({"pattern": s.pattern, "kind": s.kind}))
            .collect();
        let sinks: Vec<Value> = node
            .sinks
            .iter()
            .map(|s| json!({"pattern": s.pattern, "arg_index": s.arg_index}))
            .collect();
        result.insert("sources".to_string(), json!(sources));
        result.insert("sinks".to_string(), json!(sinks));
        if !node.sanitizers.is_empty() {
            let sanitizers: Vec<Value> = node
                .sanitizers
                .iter()
                .map(|s| json!({"pattern": s.pattern}))
                .collect();
            result.insert("sanitizers".to_string(), json!(sanitizers));
        }
        if !node.passthroughs.is_empty() {
            let passthroughs: Vec<Value> = node
                .passthroughs
                .iter()
                .map(|p| json!({"pattern": p.pattern}))
                .collect();
            result.insert("passthroughs".to_string(), json!(passthroughs));
        }
    }

    if mode == "ast" {
        result.insert(
            "ast_patterns".to_string(),
            compile_ast_blocks(&node.match_blocks),
        );
    }

    if mode == "file_contains" || !node.file_conditions.is_empty() {
        let fc = compile_file_conditions(node);
        let has_empty = fc["has"].as_array().is_some_and(|a| a.is_empty());
        let not_has_empty = fc["not_has"].as_array().is_some_and(|a| a.is_empty());
        let has_extra = fc.get("min_lines").is_some()
            || fc.get("path_contains").is_some()
            || fc.get("not_path_has_file").is_some();
        if !has_empty || !not_has_empty || has_extra {
            result.insert("file_contains".to_string(), fc);
        }
    }

    if mode == "python_hook" {
        result.insert("hook".to_string(), json!(node.hook));
    }

    Value::Object(result)
}

pub fn infer_mode(node: &RuleNode) -> String {
    if !node.hook.is_empty() {
        return "python_hook".to_string();
    }

    let has_taint = !node.sources.is_empty() || !node.sinks.is_empty();
    let has_regex = node
        .match_blocks
        .iter()
        .any(|b| matches!(b, MatchBlock::Regex(_)));
    let has_ast = node
        .match_blocks
        .iter()
        .any(|b| matches!(b, MatchBlock::Ast(_)));
    let has_fc_blocks = node
        .match_blocks
        .iter()
        .any(|b| matches!(b, MatchBlock::FileContains(_)));
    let has_fc_conditions = !node.file_conditions.is_empty();

    if has_taint && has_regex {
        return "regex+taint".to_string();
    }
    if has_taint {
        return "taint".to_string();
    }
    if has_ast {
        return "ast".to_string();
    }
    if has_regex {
        return "regex".to_string();
    }
    if has_fc_blocks || has_fc_conditions {
        return "file_contains".to_string();
    }

    "regex".to_string()
}

/// Converts raw text to a regex: escapes everything except `*` -> `.*`.
pub fn text_to_regex(text: &str) -> String {
    const PLACEHOLDER: &str = "\u{0}STAR\u{0}";
    let with_placeholder = text.replace('*', PLACEHOLDER);
    let escaped = regex::escape(&with_placeholder);
    escaped.replace(&regex::escape(PLACEHOLDER), ".*")
}

fn compile_regex_blocks(blocks: &[MatchBlock]) -> Value {
    let mut patterns = Vec::new();
    for block in blocks {
        let MatchBlock::Regex(b) = block else {
            continue;
        };

        let pattern = if b.is_text {
            text_to_regex(&b.pattern)
        } else {
            b.pattern.clone()
        };
        let mut p = Map::new();
        p.insert("pattern".to_string(), json!(pattern));
        p.insert("match".to_string(), json!(b.scope));
        if !b.with_pattern.is_empty() {
            let wp = if b.with_is_text {
                text_to_regex(&b.with_pattern)
            } else {
                b.with_pattern.clone()
            };
            p.insert("with".to_string(), json!(wp));
        }
        if !b.pattern_not.is_empty() {
            let np = if b.pattern_not_is_text {
                text_to_regex(&b.pattern_not)
            } else {
                b.pattern_not.clone()
            };
            p.insert("pattern-not".to_string(), json!(np));
        }
        if !b.pattern_inside.is_empty() {
            p.insert("pattern-inside".to_string(), json!(b.pattern_inside));
        }
        if !b.pattern_not_inside.is_empty() {
            p.insert(
                "pattern-not-inside".to_string(),
                json!(b.pattern_not_inside),
            );
        }
        patterns.push(Value::Object(p));
    }
    json!(patterns)
}

fn compile_ast_blocks(blocks: &[MatchBlock]) -> Value {
    let patterns: Vec<Value> = blocks
        .iter()
        .filter_map(|b| match b {
            MatchBlock::Ast(a) => Some(json!({"pattern": a.pattern})),
            _ => None,
        })
        .collect();
    json!(patterns)
}

fn compile_file_conditions(node: &RuleNode) -> Value {
    let mut has: Vec<String> = Vec::new();
    let mut not_has: Vec<String> = Vec::new();
    let mut scope = "file".to_string();
    let mut path_contains: Option<Vec<String>> = None;
    let mut not_path_has_file: Option<Vec<String>> = None;
    let mut min_lines: Option<i64> = None;

    for block in &node.match_blocks {
        if let MatchBlock::FileContains(b) = block {
            has.extend(b.has_patterns.clone());
            not_has.extend(b.not_has_patterns.clone());
            scope = b.scope.clone();
        }
    }

    for fc in &node.file_conditions {
        has.extend(fc.has_patterns.clone());
        not_has.extend(fc.not_has_patterns.clone());
        if !fc.path_contains.is_empty() {
            path_contains = Some(fc.path_contains.clone());
        }
        if !fc.not_path_has_file.is_empty() {
            not_path_has_file = Some(fc.not_path_has_file.clone());
        }
        if fc.min_lines > 0 {
            min_lines = Some(fc.min_lines);
        }
        if fc.scope != "file" {
            scope = fc.scope.clone();
        }
    }

    let mut result = Map::new();
    result.insert("has".to_string(), json!(has));
    result.insert("not_has".to_string(), json!(not_has));
    result.insert("scope".to_string(), json!(scope));
    if let Some(pc) = path_contains {
        result.insert("path_contains".to_string(), json!(pc));
    }
    if let Some(npf) = not_path_has_file {
        result.insert("not_path_has_file".to_string(), json!(npf));
    }
    if let Some(ml) = min_lines {
        result.insert("min_lines".to_string(), json!(ml));
    }
    Value::Object(result)
}

fn texts_to_value(texts: &std::collections::BTreeMap<String, String>) -> Value {
    let map: Map<String, Value> = texts.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
    Value::Object(map)
}
