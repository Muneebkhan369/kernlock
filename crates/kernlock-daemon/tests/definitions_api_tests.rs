use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use kernlock_core::{
    BundleByteSignature, BundleHashSignature, DefinitionStatus, DetectionRuleDef, EventCategory,
    RuleTarget, Severity, SignedThreatBundle, ThreatBundleManifest,
};
use kernlock_daemon::{api, auth, engine::KernLockEngine};
use std::fs;
use tempfile::TempDir;
use tower::ServiceExt;

#[tokio::test]
async fn test_definitions_api_lifecycle_and_tampering_rejection() {
    let tmp = TempDir::new().unwrap();
    let engine = KernLockEngine::init(tmp.path()).unwrap();
    let token = auth::load_or_create_token(tmp.path()).unwrap();

    // Generate test signing keypair and explicitly register its public key
    let trusted_seed = [55u8; 32];
    let trusted_signing_key = SigningKey::from_bytes(&trusted_seed);
    let trusted_pub_hex = hex::encode(trusted_signing_key.verifying_key().to_bytes());
    engine.add_trusted_key_hex(&trusted_pub_hex);

    // Generate an attacker keypair that is NOT registered
    let attacker_seed = [66u8; 32];
    let attacker_signing_key = SigningKey::from_bytes(&attacker_seed);

    let app = api::build_router(engine.clone(), token.clone(), None);

    // 1. Unauthenticated requests must be rejected
    let unauth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/definitions/status")
                .header(header::HOST, "127.0.0.1:17420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Initial definitions status
    let status_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/definitions/status")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_resp.status(), StatusCode::OK);
    let bytes = status_resp.into_body().collect().await.unwrap().to_bytes();
    let initial_status: DefinitionStatus = serde_json::from_slice(&bytes).unwrap();
    assert!(initial_status.rule_count > 0);
    assert_eq!(
        initial_status.version,
        kernlock_core::BUILTIN_BASELINE_VERSION
    );

    // 3. Attacker bundle signed with untrusted key must be REJECTED even if bundle includes its public key
    let attacker_manifest = ThreatBundleManifest {
        version: "2026.11.12.90".to_string(),
        timestamp: Utc::now() + Duration::hours(1),
        rules: vec![],
        hash_signatures: vec![],
        byte_signatures: vec![],
    };
    let attacker_bundle =
        SignedThreatBundle::new(attacker_manifest, &attacker_signing_key).unwrap();

    let attacker_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/definitions/update")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&attacker_bundle).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(attacker_resp.status(), StatusCode::BAD_REQUEST);

    // 4. Create legitimate threat bundle signed with trusted key
    let test_canary_hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
    let canary_payload = b"LIVE_MALWARE_PAYLOAD_CANARY";

    let legitimate_manifest = ThreatBundleManifest {
        version: "2026.11.12.95".to_string(),
        timestamp: Utc::now() + Duration::hours(2),
        rules: vec![DetectionRuleDef {
            id: "KL-LIVE-001".to_string(),
            name: "Live Dynamic Detection".to_string(),
            target: RuleTarget::Command,
            category: EventCategory::Command,
            severity: Severity::Critical,
            score: 99,
            case_insensitive: true,
            pattern: "malicious_live_command".to_string(),
            explanation: "Live threat update rule".to_string(),
            remediation: "Terminate host process".to_string(),
            tags: vec!["live_update".to_string()],
        }],
        hash_signatures: vec![BundleHashSignature {
            sha256: test_canary_hash.clone(),
            threat_name: "Trojan.LiveHashSample".to_string(),
            severity: Severity::High,
            risk_score: 90,
        }],
        byte_signatures: vec![BundleByteSignature {
            id: "KL-BUNDLE-BYTE-01".to_string(),
            pattern_hex: hex::encode(canary_payload),
            threat_name: "Trojan.LiveBytePayload".to_string(),
            severity: Severity::Critical,
            risk_score: 98,
        }],
    };

    let legitimate_bundle =
        SignedThreatBundle::new(legitimate_manifest, &trusted_signing_key).unwrap();

    let update_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/definitions/update")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&legitimate_bundle).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_resp.status(), StatusCode::OK);
    let bytes = update_resp.into_body().collect().await.unwrap().to_bytes();
    let updated_status: DefinitionStatus = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(updated_status.version, "2026.11.12.95");
    assert_eq!(updated_status.rule_count, 1);
    assert_eq!(updated_status.hash_signature_count, 1);
    assert_eq!(updated_status.byte_signature_count, 1);

    // 5. Verify dynamic byte signatures ACTUALLY participate in file scanning
    let scan_fixture = tmp.path().join("dropped_sample.bin");
    fs::write(&scan_fixture, canary_payload).unwrap();
    let scan_results = engine.scan_path(&scan_fixture).unwrap();
    assert_eq!(scan_results.len(), 1);
    assert!(scan_results[0].is_suspicious);
    assert_eq!(
        scan_results[0].threat_name.as_deref(),
        Some("Trojan.LiveBytePayload")
    );

    // 6. Anti-rollback check: Submitting an older or equal version must be REJECTED
    let rollback_manifest = ThreatBundleManifest {
        version: "2026.11.12.50".to_string(), // older than 2026.11.12.95
        timestamp: Utc::now() + Duration::hours(3),
        rules: vec![],
        hash_signatures: vec![],
        byte_signatures: vec![],
    };
    let rollback_bundle = SignedThreatBundle::new(rollback_manifest, &trusted_signing_key).unwrap();

    let rollback_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/definitions/update")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&rollback_bundle).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rollback_resp.status(), StatusCode::BAD_REQUEST);

    // 7. Tampered bundle: modifying manifest without updating signature must be REJECTED
    let mut tampered_bundle = legitimate_bundle.clone();
    tampered_bundle.manifest.version = "2026.11.12.999".to_string();

    let tampered_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/definitions/update")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&tampered_bundle).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tampered_resp.status(), StatusCode::BAD_REQUEST);

    // 8. Verify state was preserved intact after rejected updates
    let verify_status_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/definitions/status")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify_status_resp.status(), StatusCode::OK);
    let bytes = verify_status_resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let verified_status: DefinitionStatus = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(verified_status.version, "2026.11.12.95");
    assert_eq!(verified_status.rule_count, 1);

    // 9. Restart persistence: simulate daemon restart from the same data_dir
    drop(app);
    drop(engine);

    let engine_restarted = KernLockEngine::init(tmp.path()).unwrap();
    let restarted_status = engine_restarted.definition_status();
    assert_eq!(restarted_status.version, "2026.11.12.95");
    assert_eq!(restarted_status.rule_count, 1);
    assert_eq!(restarted_status.hash_signature_count, 1);
    assert_eq!(restarted_status.byte_signature_count, 1);

    // Dynamic signatures must still participate in scanning after restart
    let restart_scan = engine_restarted.scan_path(&scan_fixture).unwrap();
    assert_eq!(restart_scan.len(), 1);
    assert!(restart_scan[0].is_suspicious);
    assert_eq!(
        restart_scan[0].threat_name.as_deref(),
        Some("Trojan.LiveBytePayload")
    );

    // Anti-rollback must persist across daemon restarts
    engine_restarted.add_trusted_key_hex(&trusted_pub_hex);
    let rollback_after_restart_res = engine_restarted.update_definitions(rollback_bundle);
    assert!(rollback_after_restart_res.is_err());
}

#[tokio::test]
async fn test_concurrent_update_races_and_failed_recovery() {
    use std::sync::Arc;

    let tmp = TempDir::new().unwrap();
    let engine = Arc::new(KernLockEngine::init(tmp.path()).unwrap());

    let trusted_seed = [88u8; 32];
    let trusted_signing_key = SigningKey::from_bytes(&trusted_seed);
    let trusted_pub_hex = hex::encode(trusted_signing_key.verifying_key().to_bytes());
    engine.add_trusted_key_hex(&trusted_pub_hex);

    // Spawn 10 concurrent update attempts with candidate versions
    let mut handles = Vec::new();
    for i in 1..=10 {
        let eng = engine.clone();
        let key = trusted_signing_key.clone();
        let handle = tokio::spawn(async move {
            let manifest = ThreatBundleManifest {
                version: format!("2026.11.12.{}", 100 + i),
                timestamp: Utc::now() + Duration::seconds(i as i64 * 10),
                rules: vec![],
                hash_signatures: vec![],
                byte_signatures: vec![],
            };
            let bundle = SignedThreatBundle::new(manifest, &key).unwrap();
            eng.update_definitions(bundle)
        });
        handles.push(handle);
    }

    let mut success_count = 0;
    for h in handles {
        if let Ok(Ok(_)) = h.await {
            success_count += 1;
        }
    }

    // At least one must succeed and engine state must remain consistent
    assert!(success_count >= 1);
    let final_status = engine.definition_status();
    assert!(final_status.version.starts_with("2026.11.12."));

    // Verify recovery: even after failed update attempts, the engine remains fully operational
    let failed_manifest = ThreatBundleManifest {
        version: "2026.11.1".to_string(), // old version
        timestamp: Utc::now() - Duration::days(1),
        rules: vec![],
        hash_signatures: vec![],
        byte_signatures: vec![],
    };
    let failed_bundle = SignedThreatBundle::new(failed_manifest, &trusted_signing_key).unwrap();
    assert!(engine.update_definitions(failed_bundle).is_err());

    // Current version must be preserved intact
    assert_eq!(engine.definition_status().version, final_status.version);
}

#[tokio::test]
async fn test_update_definitions_transactional_validation_rejection() {
    let tmp = TempDir::new().unwrap();
    let engine = KernLockEngine::init(tmp.path()).unwrap();
    let token = auth::load_or_create_token(tmp.path()).unwrap();

    let trusted_seed = [11u8; 32];
    let trusted_signing_key = SigningKey::from_bytes(&trusted_seed);
    let trusted_pub_hex = hex::encode(trusted_signing_key.verifying_key().to_bytes());
    engine.add_trusted_key_hex(&trusted_pub_hex);

    let app = api::build_router(engine.clone(), token.clone(), None);

    // 1. Invalid regex pattern in rule definition
    let invalid_regex_manifest = ThreatBundleManifest {
        version: "2026.11.12.110".to_string(),
        timestamp: Utc::now() + Duration::hours(1),
        rules: vec![DetectionRuleDef {
            id: "KL-INVALID-REGEX".to_string(),
            name: "Invalid Regex Rule".to_string(),
            target: RuleTarget::Command,
            category: EventCategory::Command,
            severity: Severity::Critical,
            score: 99,
            case_insensitive: false,
            pattern: "(?P<unclosed_regex".to_string(),
            explanation: "Invalid regex syntax".to_string(),
            remediation: "None".to_string(),
            tags: vec![],
        }],
        hash_signatures: vec![],
        byte_signatures: vec![],
    };
    let bundle = SignedThreatBundle::new(invalid_regex_manifest, &trusted_signing_key).unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/definitions/update")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&bundle).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // Baseline version must be unchanged
    assert_eq!(
        engine.definition_status().version,
        kernlock_core::BUILTIN_BASELINE_VERSION
    );

    // Storage must NOT contain the invalid bundle
    let storage = kernlock_storage::Storage::open(tmp.path().join("kernlock.db")).unwrap();
    assert!(storage.load_threat_bundle().unwrap().is_none());

    // 2. Invalid byte signature hex
    let invalid_byte_manifest = ThreatBundleManifest {
        version: "2026.11.12.120".to_string(),
        timestamp: Utc::now() + Duration::hours(2),
        rules: vec![],
        hash_signatures: vec![],
        byte_signatures: vec![BundleByteSignature {
            id: "KL-BAD-HEX".to_string(),
            pattern_hex: "NOT_VALID_HEX!".to_string(),
            threat_name: "BadHex".to_string(),
            severity: Severity::High,
            risk_score: 80,
        }],
    };
    let bundle2 = SignedThreatBundle::new(invalid_byte_manifest, &trusted_signing_key).unwrap();

    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/definitions/update")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&bundle2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        engine.definition_status().version,
        kernlock_core::BUILTIN_BASELINE_VERSION
    );
    assert!(storage.load_threat_bundle().unwrap().is_none());
}

#[tokio::test]
async fn test_startup_recovery_with_corrupt_database_bundle_falls_back_to_baseline() {
    let tmp = TempDir::new().unwrap();

    // 1. Manually insert corrupt JSON into SQLite
    {
        let _storage = kernlock_storage::Storage::open(tmp.path().join("kernlock.db")).unwrap();
        // Insert corrupt JSON directly into threat_definitions table
        let conn = rusqlite::Connection::open(tmp.path().join("kernlock.db")).unwrap();
        conn.execute(
            "INSERT INTO threat_definitions (id, version, updated_at, bundle_json)
             VALUES (1, '9999.99.99', '2099-01-01T00:00:00Z', '{ \"corrupted\": json_broken')",
            [],
        )
        .unwrap();
    }

    // 2. Start engine - it must handle corrupt database gracefully and fallback to baseline
    let engine = KernLockEngine::init(tmp.path()).unwrap();
    let status = engine.definition_status();
    assert_eq!(status.version, kernlock_core::BUILTIN_BASELINE_VERSION);
    assert!(status.rule_count > 0);
}
