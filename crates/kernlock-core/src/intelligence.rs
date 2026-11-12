use crate::models::Severity;
use crate::rules::DetectionRuleDef;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntelligenceError {
    #[error("Invalid public key: {0}")]
    InvalidKey(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Bundle validation error: {0}")]
    Validation(String),
    #[error("Version rollback rejected: candidate version {candidate} is not newer than current version {current}")]
    RollbackRejected { candidate: String, current: String },
    #[error("Timestamp rollback rejected: candidate timestamp {candidate} is not newer than current timestamp {current}")]
    TimestampRollbackRejected {
        candidate: DateTime<Utc>,
        current: DateTime<Utc>,
    },
}

/// Official KernLock Threat Intelligence pinned public key (32 bytes hex)
pub const OFFICIAL_PUBLIC_KEY_HEX: &str =
    "69d50c0ac704c7d545b942deb8427f610a0611e1a5194cc09d0f5ffd9a71d181";

/// Built-in baseline definition version string
pub const BUILTIN_BASELINE_VERSION: &str = "2026.11.1";

/// Fixed deterministic timestamp (2026-11-01T00:00:00Z) for the built-in baseline definitions.
/// Eliminates non-deterministic `Utc::now()` baseline initialization across daemon restarts.
pub const BUILTIN_BASELINE_TIMESTAMP_UNIX: i64 = 1762041600;

pub fn builtin_baseline_timestamp() -> DateTime<Utc> {
    DateTime::from_timestamp(BUILTIN_BASELINE_TIMESTAMP_UNIX, 0)
        .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionStatus {
    pub version: String,
    pub last_updated: DateTime<Utc>,
    pub rule_count: usize,
    pub hash_signature_count: usize,
    pub byte_signature_count: usize,
    pub official_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleHashSignature {
    pub sha256: String,
    pub threat_name: String,
    pub severity: Severity,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleByteSignature {
    pub id: String,
    pub threat_name: String,
    pub severity: Severity,
    pub risk_score: u32,
    pub pattern_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatBundleManifest {
    pub version: String,
    pub timestamp: DateTime<Utc>,
    pub rules: Vec<DetectionRuleDef>,
    pub hash_signatures: Vec<BundleHashSignature>,
    pub byte_signatures: Vec<BundleByteSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedThreatBundle {
    pub manifest: ThreatBundleManifest,
    pub signature_hex: String,
    pub public_key_hex: Option<String>,
}

impl SignedThreatBundle {
    pub fn new(
        manifest: ThreatBundleManifest,
        signing_key: &SigningKey,
    ) -> Result<Self, IntelligenceError> {
        let payload = serde_json::to_vec(&manifest)
            .map_err(|e| IntelligenceError::Serialization(e.to_string()))?;
        let signature = signing_key.sign(&payload);
        let signature_hex = hex::encode(signature.to_bytes());
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

        Ok(Self {
            manifest,
            signature_hex,
            public_key_hex: Some(public_key_hex),
        })
    }

    pub fn verify(&self, trusted_public_key: &VerifyingKey) -> Result<(), IntelligenceError> {
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|e| IntelligenceError::InvalidSignature(e.to_string()))?;
        if sig_bytes.len() != 64 {
            return Err(IntelligenceError::InvalidSignature(
                "Signature must be exactly 64 bytes".to_string(),
            ));
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        let payload = serde_json::to_vec(&self.manifest)
            .map_err(|e| IntelligenceError::Serialization(e.to_string()))?;

        trusted_public_key
            .verify_strict(&payload, &signature)
            .map_err(|e| IntelligenceError::VerificationFailed(e.to_string()))?;

        Ok(())
    }

    pub fn verify_with_hex_key(&self, key_hex: &str) -> Result<(), IntelligenceError> {
        let key_bytes =
            hex::decode(key_hex).map_err(|e| IntelligenceError::InvalidKey(e.to_string()))?;
        if key_bytes.len() != 32 {
            return Err(IntelligenceError::InvalidKey(
                "Public key must be exactly 32 bytes".to_string(),
            ));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        let key = VerifyingKey::from_bytes(&key_arr)
            .map_err(|e| IntelligenceError::InvalidKey(e.to_string()))?;
        self.verify(&key)
    }

    pub fn verify_official(&self) -> Result<(), IntelligenceError> {
        self.verify_with_hex_key(OFFICIAL_PUBLIC_KEY_HEX)
    }
}

pub fn parse_version_tuple(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u64>().unwrap_or(0))
        .collect()
}

pub fn validate_version_advance(
    current_ver: &str,
    current_ts: Option<DateTime<Utc>>,
    candidate_ver: &str,
    candidate_ts: DateTime<Utc>,
) -> Result<(), IntelligenceError> {
    let curr_parts = parse_version_tuple(current_ver);
    let cand_parts = parse_version_tuple(candidate_ver);

    if cand_parts <= curr_parts {
        return Err(IntelligenceError::RollbackRejected {
            candidate: candidate_ver.to_string(),
            current: current_ver.to_string(),
        });
    }

    if let Some(ts) = current_ts {
        if candidate_ts <= ts {
            return Err(IntelligenceError::TimestampRollbackRejected {
                candidate: candidate_ts,
                current: ts,
            });
        }
    }

    Ok(())
}
