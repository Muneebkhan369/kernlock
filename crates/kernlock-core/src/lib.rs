pub mod analyzer;
pub mod formats;
pub mod models;
pub mod paths;
pub mod rules;
pub mod signatures;

pub use analyzer::{
    analyze_command, analyze_file_bytes, detect_file_type, is_path_excluded, scan_file_streaming,
    sha256_hex, shannon_entropy,
};
pub use models::*;
pub use rules::{DetectionRuleDef, RuleEngine, RuleError, RuleTarget};
pub use signatures::{check_signatures, HashSignature, ThreatSignature};
