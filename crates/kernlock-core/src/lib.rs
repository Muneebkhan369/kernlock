pub mod analyzer;
pub mod models;
pub mod rules;

pub use analyzer::{
    analyze_command, analyze_file_bytes, detect_file_type, sha256_hex, shannon_entropy,
};
pub use models::*;
pub use rules::{DetectionRuleDef, RuleEngine, RuleError, RuleTarget};
