use crate::models::{EventCategory, RuleMatch, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("Failed to parse rules YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Invalid regex in rule {rule_id}: {source}")]
    Regex {
        rule_id: String,
        source: regex::Error,
    },
    #[error("I/O error reading rules: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTarget {
    Command,
    FileContent,
    FilePath,
    Process,
    Persistence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRuleDef {
    pub id: String,
    pub name: String,
    pub target: RuleTarget,
    pub category: EventCategory,
    pub severity: Severity,
    pub score: u32,
    pub pattern: String,
    #[serde(default)]
    pub case_insensitive: bool,
    pub explanation: String,
    pub remediation: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFile {
    pub version: String,
    pub rules: Vec<DetectionRuleDef>,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub def: DetectionRuleDef,
    pub regex: Regex,
}

use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct RuleEngine {
    rules: Arc<RwLock<Vec<CompiledRule>>>,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl RuleEngine {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, RuleError> {
        let parsed: RuleFile = serde_yaml::from_str(yaml)?;
        Self::compile(parsed.rules)
    }

    pub fn compile(defs: Vec<DetectionRuleDef>) -> Result<Self, RuleError> {
        let mut compiled = Vec::with_capacity(defs.len());
        for def in defs {
            let pattern = if def.case_insensitive {
                format!("(?i){}", def.pattern)
            } else {
                def.pattern.clone()
            };
            let regex = Regex::new(&pattern).map_err(|source| RuleError::Regex {
                rule_id: def.id.clone(),
                source,
            })?;
            compiled.push(CompiledRule { def, regex });
        }
        Ok(Self {
            rules: Arc::new(RwLock::new(compiled)),
        })
    }

    pub fn replace_rules(&self, new_defs: Vec<DetectionRuleDef>) -> Result<(), RuleError> {
        let mut compiled = Vec::with_capacity(new_defs.len());
        for def in new_defs {
            let pattern = if def.case_insensitive {
                format!("(?i){}", def.pattern)
            } else {
                def.pattern.clone()
            };
            let regex = Regex::new(&pattern).map_err(|source| RuleError::Regex {
                rule_id: def.id.clone(),
                source,
            })?;
            compiled.push(CompiledRule { def, regex });
        }

        let mut guard = self.rules.write().map_err(|_| RuleError::Regex {
            rule_id: "lock".to_string(),
            source: regex::Error::Syntax("Lock poisoned".to_string()),
        })?;
        *guard = compiled;
        Ok(())
    }

    pub fn builtin() -> Self {
        let yaml = include_str!("../../../rules/builtin_rules.yaml");
        Self::from_yaml_str(yaml).expect("Built-in rules YAML must be valid")
    }

    pub fn rule_count(&self) -> usize {
        self.rules.read().map(|g| g.len()).unwrap_or(0)
    }

    pub fn rules(&self) -> Vec<DetectionRuleDef> {
        self.rules
            .read()
            .map(|g| g.iter().map(|r| r.def.clone()).collect())
            .unwrap_or_default()
    }

    pub fn evaluate(&self, target: RuleTarget, input: &str) -> Vec<RuleMatch> {
        if input.is_empty() {
            return Vec::new();
        }
        let guard = match self.rules.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut matches = Vec::new();
        for rule in guard.iter() {
            if rule.def.target != target {
                continue;
            }
            if let Some(m) = rule.regex.find(input) {
                let snippet = truncate_evidence(m.as_str(), 140);
                matches.push(RuleMatch {
                    rule_id: rule.def.id.clone(),
                    rule_name: rule.def.name.clone(),
                    severity: rule.def.severity,
                    score: rule.def.score,
                    category: rule.def.category,
                    explanation: rule.def.explanation.clone(),
                    evidence: snippet,
                    remediation: rule.def.remediation.clone(),
                });
            }
        }
        matches
    }
}

fn truncate_evidence(s: &str, max_len: usize) -> String {
    let sanitized = s.replace(['\r', '\n'], " ");
    if sanitized.chars().count() <= max_len {
        sanitized
    } else {
        let truncated: String = sanitized.chars().take(max_len).collect();
        format!("{}...", truncated)
    }
}
