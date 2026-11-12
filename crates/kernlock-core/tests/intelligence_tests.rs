use chrono::Utc;
use ed25519_dalek::SigningKey;
use kernlock_core::{
    BundleByteSignature, BundleHashSignature, DetectionRuleDef, EventCategory, IntelligenceError,
    RuleEngine, Severity, SignedThreatBundle, ThreatBundleManifest,
};

#[test]
fn test_signed_threat_bundle_verification_and_tampering_rejection() {
    // 1. Generate keypair for testing
    let seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let manifest = ThreatBundleManifest {
        version: "2026.11.12.2".to_string(),
        timestamp: Utc::now(),
        rules: vec![DetectionRuleDef {
            id: "KL-CUSTOM-001".to_string(),
            name: "Custom Miner Pattern".to_string(),
            target: kernlock_core::RuleTarget::FileContent,
            category: EventCategory::File,
            severity: Severity::High,
            score: 85,
            case_insensitive: true,
            pattern: "xmr-pool\\.example\\.invalid".to_string(),
            explanation: "Detects custom miner pool address".to_string(),
            remediation: "Isolate host".to_string(),
            tags: vec!["miner".to_string()],
        }],
        hash_signatures: vec![BundleHashSignature {
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            threat_name: "Test.Empty.Hash".to_string(),
            severity: Severity::Low,
            risk_score: 50,
        }],
        byte_signatures: vec![BundleByteSignature {
            id: "SIG-CANARY-01".to_string(),
            pattern_hex: hex::encode(b"EVIL_CANARY_STRING"),
            threat_name: "Test.Canary".to_string(),
            severity: Severity::Critical,
            risk_score: 95,
        }],
    };

    // 2. Sign bundle
    let bundle = SignedThreatBundle::new(manifest.clone(), &signing_key)
        .expect("signing bundle should succeed");

    // 3. Valid verification succeeds
    assert!(bundle.verify(&verifying_key).is_ok());

    // 4. Tampered manifest fails verification
    let mut tampered_bundle = bundle.clone();
    tampered_bundle.manifest.version = "2026.11.12.3-HACKED".to_string();
    let err = tampered_bundle
        .verify(&verifying_key)
        .expect_err("tampered manifest must fail verification");
    assert!(matches!(err, IntelligenceError::VerificationFailed(_)));

    // 5. Verification with wrong public key fails
    let wrong_seed = [99u8; 32];
    let wrong_signing_key = SigningKey::from_bytes(&wrong_seed);
    let wrong_verifying_key = wrong_signing_key.verifying_key();
    assert!(bundle.verify(&wrong_verifying_key).is_err());
}

#[test]
fn test_atomic_rule_engine_replacement_and_rollback_on_error() {
    let engine = RuleEngine::builtin();
    let initial_count = engine.rule_count();
    assert!(initial_count > 0);

    // 1. Valid replacement updates rule count atomically
    let valid_new_defs = vec![
        DetectionRuleDef {
            id: "KL-NEW-001".to_string(),
            name: "New Rule One".to_string(),
            target: kernlock_core::RuleTarget::Command,
            category: EventCategory::Command,
            severity: Severity::High,
            score: 80,
            case_insensitive: false,
            pattern: "bad_command_pattern".to_string(),
            explanation: "desc".to_string(),
            remediation: "fix".to_string(),
            tags: vec![],
        },
        DetectionRuleDef {
            id: "KL-NEW-002".to_string(),
            name: "New Rule Two".to_string(),
            target: kernlock_core::RuleTarget::FilePath,
            category: EventCategory::File,
            severity: Severity::Critical,
            score: 95,
            case_insensitive: false,
            pattern: "\\.suspicious_ext$".to_string(),
            explanation: "desc".to_string(),
            remediation: "fix".to_string(),
            tags: vec![],
        },
    ];

    engine
        .replace_rules(valid_new_defs.clone())
        .expect("replace rules should succeed");
    assert_eq!(engine.rule_count(), 2);
    assert_eq!(engine.rules()[0].id, "KL-NEW-001");

    // 2. Invalid regex pattern in batch triggers failure without altering existing rules
    let invalid_defs = vec![DetectionRuleDef {
        id: "KL-BAD-REGEX".to_string(),
        name: "Broken Regex".to_string(),
        target: kernlock_core::RuleTarget::Command,
        category: EventCategory::Command,
        severity: Severity::Low,
        score: 10,
        case_insensitive: false,
        pattern: "[unclosed-bracket".to_string(),
        explanation: "broken".to_string(),
        remediation: "fix".to_string(),
        tags: vec![],
    }];

    let err = engine.replace_rules(invalid_defs);
    assert!(err.is_err(), "broken regex must return error");

    // Existing rule set is preserved intact (atomic rollback)
    assert_eq!(engine.rule_count(), 2);
    assert_eq!(engine.rules()[0].id, "KL-NEW-001");
}

#[test]
fn test_anti_rollback_version_validation() {
    let base_ts = Utc::now();

    // 1. Monotonically increasing versions succeed
    assert!(kernlock_core::validate_version_advance(
        "2026.11.12.1",
        Some(base_ts),
        "2026.11.12.2",
        base_ts + chrono::Duration::seconds(10),
    )
    .is_ok());

    // 2. Equal version rejected
    assert!(kernlock_core::validate_version_advance(
        "2026.11.12.2",
        Some(base_ts),
        "2026.11.12.2",
        base_ts + chrono::Duration::seconds(10),
    )
    .is_err());

    // 3. Lower version rejected (rollback)
    let err = kernlock_core::validate_version_advance(
        "2026.11.12.2",
        Some(base_ts),
        "2026.11.12.1",
        base_ts + chrono::Duration::seconds(10),
    )
    .unwrap_err();
    assert!(matches!(err, IntelligenceError::RollbackRejected { .. }));

    // 4. Stale timestamp rejected
    let err_ts = kernlock_core::validate_version_advance(
        "2026.11.12.1",
        Some(base_ts),
        "2026.11.12.2",
        base_ts - chrono::Duration::seconds(10),
    )
    .unwrap_err();
    assert!(matches!(
        err_ts,
        IntelligenceError::TimestampRollbackRejected { .. }
    ));
}

#[test]
fn test_manifest_signature_tampering_rejects_modified_hashes_and_bytes() {
    let signing_key = SigningKey::from_bytes(&[77u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let manifest = ThreatBundleManifest {
        version: "2026.11.12.10".to_string(),
        timestamp: Utc::now(),
        rules: vec![],
        hash_signatures: vec![BundleHashSignature {
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            threat_name: "Trojan.A".to_string(),
            severity: Severity::High,
            risk_score: 90,
        }],
        byte_signatures: vec![BundleByteSignature {
            id: "SIG-01".to_string(),
            pattern_hex: "deadbeef".to_string(),
            threat_name: "Trojan.B".to_string(),
            severity: Severity::Critical,
            risk_score: 99,
        }],
    };

    let bundle = SignedThreatBundle::new(manifest, &signing_key).unwrap();
    assert!(bundle.verify(&verifying_key).is_ok());

    // Modify hash signatures in manifest -> signature verification MUST fail
    let mut tampered_hashes = bundle.clone();
    tampered_hashes.manifest.hash_signatures[0].sha256 =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    assert!(tampered_hashes.verify(&verifying_key).is_err());

    // Modify byte signatures in manifest -> signature verification MUST fail
    let mut tampered_bytes = bundle.clone();
    tampered_bytes.manifest.byte_signatures[0].pattern_hex = "cafebabe".to_string();
    assert!(tampered_bytes.verify(&verifying_key).is_err());
}
