pub mod analyzer;
pub mod formats;
pub mod intelligence;
pub mod models;
pub mod paths;
pub mod rules;
pub mod signatures;

pub use analyzer::{
    analyze_command, analyze_file_bytes, detect_file_type, is_path_excluded, scan_file_from_fd,
    scan_file_streaming, scan_stream_reader, sha256_hex, shannon_entropy,
};
pub use intelligence::{
    parse_version_tuple, validate_version_advance, BundleByteSignature, BundleHashSignature,
    DefinitionStatus, IntelligenceError, SignedThreatBundle, ThreatBundleManifest,
    OFFICIAL_PUBLIC_KEY_HEX,
};
pub use models::*;
pub use rules::{CompiledRule, DetectionRuleDef, RuleEngine, RuleError, RuleTarget};
pub use signatures::{check_signatures, HashSignature, ThreatSignature};
