use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use kernlock_core::{ScanJobSummary, ScanProgress, ThreatRecord};
use kernlock_daemon::{api, auth, engine::KernLockEngine};
use std::fs;
use std::time::Duration;
use tempfile::TempDir;
use tower::ServiceExt;

#[tokio::test]
async fn test_scan_api_start_progress_history_and_threats() {
    let tmp = TempDir::new().unwrap();
    let scan_dir = tmp.path().join("scan_target");
    fs::create_dir_all(&scan_dir).unwrap();

    // Create a benign file
    fs::write(scan_dir.join("hello.txt"), b"Hello, world!").unwrap();

    // Create an EICAR test file
    fs::write(
        scan_dir.join("eicar.com"),
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();

    let engine = KernLockEngine::init(tmp.path().join("data")).unwrap();
    let token = auth::load_or_create_token(tmp.path().join("data")).unwrap();
    let app = api::build_router(engine, token.clone(), None);

    // 1. Start custom scan on scan_dir
    let start_req_body = serde_json::json!({
        "mode": "custom",
        "paths": [scan_dir.to_str().unwrap()]
    });

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/scan/start")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&start_req_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let start_res: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let scan_id_str = start_res["scan_id"].as_str().unwrap();
    assert!(!scan_id_str.is_empty());

    // 2. Poll progress until scan completes
    let mut completed = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/scan/current")
                    .header(header::HOST, "127.0.0.1:17420")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        if let Ok(prog) = serde_json::from_slice::<ScanProgress>(&bytes) {
            if prog.is_complete {
                completed = true;
                assert_eq!(prog.files_scanned, 2);
                assert_eq!(prog.threats_found, 1);
                break;
            }
        }
    }
    assert!(completed, "Scan did not complete in time");

    // 3. Check scan history
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/scan/history")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let history: Vec<ScanJobSummary> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].files_scanned, 2);
    assert_eq!(history[0].threats_found, 1);
    assert_eq!(history[0].threats.len(), 1);
    assert_eq!(
        history[0].threats[0].threat_name.as_deref(),
        Some("EICAR Standard Antivirus Test File")
    );

    // 4. Check threat history
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/threats/history")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let threats: Vec<ThreatRecord> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(threats.len(), 1);
    assert_eq!(threats[0].threat_name, "EICAR Standard Antivirus Test File");
    assert_eq!(threats[0].risk_score, 100);

    // 5. Test scan cancellation
    let start_req_body = serde_json::json!({
        "mode": "custom",
        "paths": [scan_dir.to_str().unwrap()]
    });

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/scan/start")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&start_req_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let cancel_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/scan/cancel")
                .header(header::HOST, "127.0.0.1:17420")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cancel_resp.status(), StatusCode::OK);
}
