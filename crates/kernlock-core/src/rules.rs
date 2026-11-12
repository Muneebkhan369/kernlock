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

#[derive(Debug, Clone, Default)]
pub struct DynamicSignatures {
    pub hash_signatures: Vec<crate::intelligence::BundleHashSignature>,
    pub byte_signatures: Vec<(crate::intelligence::BundleByteSignature, Vec<u8>)>,
}

use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct RuleEngine {
    rules: Arc<RwLock<Vec<CompiledRule>>>,
    signatures: Arc<RwLock<DynamicSignatures>>,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            signatures: Arc::new(RwLock::new(DynamicSignatures::default())),
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
            signatures: Arc::new(RwLock::new(DynamicSignatures::default())),
        })
    }

    pub fn replace_rules(&self, new_defs: Vec<DetectionRuleDef>) -> Result<(), RuleError> {
        self.replace_definitions(new_defs, Vec::new(), Vec::new())
    }

    pub fn replace_definitions(
        &self,
        new_defs: Vec<DetectionRuleDef>,
        hash_sigs: Vec<crate::intelligence::BundleHashSignature>,
        byte_sigs: Vec<crate::intelligence::BundleByteSignature>,
    ) -> Result<(), RuleError> {
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

        let mut decoded_bytes = Vec::with_capacity(byte_sigs.len());
        for b in byte_sigs {
            let bytes = hex::decode(&b.pattern_hex).map_err(|_| RuleError::Regex {
                rule_id: b.id.clone(),
                source: regex::Error::Syntax(format!(
                    "Invalid hex pattern in byte signature {}",
                    b.id
                )),
            })?;
            decoded_bytes.push((b, bytes));
        }

        let mut rules_guard = self.rules.write().map_err(|_| RuleError::Regex {
            rule_id: "lock".to_string(),
            source: regex::Error::Syntax("Lock poisoned".to_string()),
        })?;
        let mut sigs_guard = self.signatures.write().map_err(|_| RuleError::Regex {
            rule_id: "lock".to_string(),
            source: regex::Error::Syntax("Lock poisoned".to_string()),
        })?;

        *rules_guard = compiled;
        sigs_guard.hash_signatures = hash_sigs;
        sigs_guard.byte_signatures = decoded_bytes;
        Ok(())
    }

    pub fn check_signatures(&self, bytes: &[u8], sha256: &str) -> Vec<RuleMatch> {
        let mut matches = crate::signatures::check_signatures(bytes, sha256);

        if let Ok(guard) = self.signatures.read() {
            for h in &guard.hash_signatures {
                if h.sha256.eq_ignore_ascii_case(sha256) {
                    matches.push(RuleMatch {
                        rule_id: format!(
                            "KL-BUNDLE-HASH-{}",
                            h.sha256.chars().take(8).collect::<String>()
                        ),
                        rule_name: h.threat_name.clone(),
                        severity: h.severity,
                        score: h.risk_score,
                        category: EventCategory::File,
                        explanation: format!(
                            "Matches SHA-256 hash in threat intelligence bundle: {}",
                            h.sha256
                        ),
                        evidence: format!("sha256={}", sha256),
                        remediation:
                            "Quarantine file immediately and inspect endpoint for compromise."
                                .to_string(),
                    });
                }
            }

            for (b_sig, pattern) in &guard.byte_signatures {
                if !pattern.is_empty()
                    && bytes
                        .windows(pattern.len())
                        .any(|w| w == pattern.as_slice())
                {
                    matches.push(RuleMatch {
                        rule_id: b_sig.id.clone(),
                        rule_name: b_sig.threat_name.clone(),
                        severity: b_sig.severity,
                        score: b_sig.risk_score,
                        category: EventCategory::File,
                        explanation: format!(
                            "Matches byte signature pattern in threat intelligence bundle: {}",
                            b_sig.id
                        ),
                        evidence: format!("pattern_hex={}", b_sig.pattern_hex),
                        remediation:
                            "Quarantine file immediately and inspect execution provenance."
                                .to_string(),
                    });
                }
            }
        }

        matches
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
