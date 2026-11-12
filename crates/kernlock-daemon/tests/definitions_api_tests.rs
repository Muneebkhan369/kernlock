use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use kernlock_core::{
    BundleByteSignature, BundleHashSignature, DefinitionStatus, DetectionRuleDef, EventCategory,
    RuleTarget, Severity, SignedThreatBundle, ThreatBundleManifest,
};
use kernlock_daemon::{api, auth, engine::KernLockEngine};
use tempfile::TempDir;
use tower::ServiceExt;

#[tokio::test]
async fn test_definitions_api_lifecycle_and_tampering_rejection() {
    let tmp = TempDir::new().unwrap();
    let engine = KernLockEngine::init(tmp.path()).unwrap();
    let token = auth::load_or_create_token(tmp.path()).unwrap();

    let app = api::build_router(engine, token.clone(), None);

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
    assert_eq!(initial_status.version, "2026.11.1-builtin");

    // 3. Create a new signed threat bundle
    let signing_key = SigningKey::from_bytes(&[55u8; 32]);
    let new_rules = vec![DetectionRuleDef {
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
    }];

    let manifest = ThreatBundleManifest {
        version: "2026.11.12.99".to_string(),
        timestamp: Utc::now(),
        rules: new_rules,
        hash_signatures: vec![BundleHashSignature {
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            threat_name: "Trojan.LiveSample".to_string(),
            severity: Severity::High,
            risk_score: 90,
        }],
        byte_signatures: vec![BundleByteSignature {
            id: "SIG-LIVE-01".to_string(),
            pattern_hex: hex::encode(b"LIVE_MALWARE_PAYLOAD"),
            threat_name: "Trojan.LivePayload".to_string(),
            severity: Severity::Critical,
            risk_score: 98,
        }],
    };

    let signed_bundle = SignedThreatBundle::new(manifest, &signing_key).unwrap();

    // 4. Update definitions with valid signed bundle
    let update_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/definitions/update")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&signed_bundle).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_resp.status(), StatusCode::OK);
    let bytes = update_resp.into_body().collect().await.unwrap().to_bytes();
    let updated_status: DefinitionStatus = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(updated_status.version, "2026.11.12.99");
    assert_eq!(updated_status.rule_count, 1);
    assert_eq!(updated_status.hash_signature_count, 1);
    assert_eq!(updated_status.byte_signature_count, 1);

    // 5. Verify /api/rules reflects the new rules
    let rules_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/rules")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rules_resp.status(), StatusCode::OK);
    let bytes = rules_resp.into_body().collect().await.unwrap().to_bytes();
    let rules: Vec<DetectionRuleDef> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "KL-LIVE-001");

    // 6. Tampered bundle must be rejected
    let mut tampered_bundle = signed_bundle.clone();
    tampered_bundle.manifest.version = "2026.11.12.666-EXPLOIT".to_string();

    let reject_resp = app
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
    assert_eq!(reject_resp.status(), StatusCode::BAD_REQUEST);

    // 7. Verify definitions remained at valid state after rejected update
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
    assert_eq!(verified_status.version, "2026.11.12.99");
    assert_eq!(verified_status.rule_count, 1);
}
