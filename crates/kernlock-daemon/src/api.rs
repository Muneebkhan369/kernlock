use crate::auth::{constant_time_eq, is_allowed_origin, is_valid_loopback_host};
use crate::engine::KernLockEngine;
use axum::{
    extract::{Path as AxumPath, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use kernlock_core::{AlertStatus, PolicyConfig, ScanMode, ScanStatus, SignedThreatBundle};
use kernlock_platform::PlatformError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::ServeDir;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub engine: KernLockEngine,
    pub api_token: String,
}

#[derive(Serialize)]
struct StatusResponse {
    capabilities: kernlock_core::PlatformCapabilities,
    policy: PolicyConfig,
    watcher_active: bool,
    fanotify_active: bool,
    rules_loaded: usize,
}

#[derive(Deserialize)]
struct ScanPathRequest {
    path: String,
}

#[derive(Deserialize)]
struct StartScanRequest {
    mode: ScanMode,
    paths: Option<Vec<String>>,
}

#[derive(Serialize)]
struct StartScanResponse {
    scan_id: Uuid,
    status: ScanStatus,
}

#[derive(Serialize)]
struct CancelScanResponse {
    cancelled: bool,
}

#[derive(Deserialize)]
struct AnalyzeCommandRequest {
    command: String,
}

#[derive(Deserialize)]
struct QuarantineRequest {
    path: String,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct AlertStatusRequest {
    status: AlertStatus,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn err_resp(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse { error: msg.into() }))
}

fn map_platform_error(err: anyhow::Error) -> (StatusCode, Json<ErrorResponse>) {
    if let Some(PlatformError::Unsupported(msg)) = err.downcast_ref::<PlatformError>() {
        return err_resp(StatusCode::NOT_IMPLEMENTED, msg.clone());
    }
    err_resp(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

async fn security_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // 1. Validate Host header against DNS rebinding
    if let Some(host_val) = req.headers().get(header::HOST) {
        let host_str = host_val
            .to_str()
            .map_err(|_| err_resp(StatusCode::FORBIDDEN, "Invalid Host header"))?;
        if !is_valid_loopback_host(host_str) {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                "Forbidden: non-loopback Host header rejected",
            ));
        }
    }

    // 2. Validate Origin header when present
    if let Some(origin_val) = req.headers().get(header::ORIGIN) {
        let origin_str = origin_val
            .to_str()
            .map_err(|_| err_resp(StatusCode::FORBIDDEN, "Invalid Origin header"))?;
        if !is_allowed_origin(origin_str) {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                "Forbidden: unauthorized Origin rejected",
            ));
        }
    }

    // 3. Allow CORS preflight OPTIONS after Origin/Host checks
    if req.method() == Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    // 4. Require Bearer token authentication
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err_resp(StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

    let provided = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| err_resp(StatusCode::UNAUTHORIZED, "Invalid Authorization scheme"))?;

    if !constant_time_eq(provided.as_bytes(), state.api_token.as_bytes()) {
        return Err(err_resp(StatusCode::UNAUTHORIZED, "Invalid API token"));
    }

    Ok(next.run(req).await)
}

pub fn build_router(
    engine: KernLockEngine,
    api_token: String,
    static_dir: Option<PathBuf>,
) -> Router {
    let state = AppState { engine, api_token };

    let protected_api = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/processes", get(get_processes))
        .route("/api/persistence", get(get_persistence))
        .route("/api/scan/path", post(scan_path))
        .route("/api/scan/start", post(start_scan))
        .route("/api/scan/cancel", post(cancel_scan))
        .route("/api/scan/current", get(get_current_scan))
        .route("/api/scan/history", get(list_scan_history))
        .route("/api/threats/history", get(list_threats_history))
        .route("/api/analyze/command", post(analyze_command))
        .route("/api/events", get(list_events))
        .route("/api/alerts", get(list_alerts))
        .route("/api/alerts/:id/status", post(update_alert_status))
        .route(
            "/api/quarantine",
            get(list_quarantine).post(quarantine_file),
        )
        .route("/api/quarantine/:id/restore", post(restore_quarantine))
        .route("/api/quarantine/:id", delete(delete_quarantine))
        .route("/api/policy", get(get_policy).put(update_policy))
        .route("/api/rules", get(list_rules))
        .route("/api/definitions/status", get(get_definitions_status))
        .route("/api/definitions/update", post(update_definitions_endpoint))
        .route("/api/report", get(get_report))
        .route("/api/report/markdown", get(get_report_markdown))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ))
        .with_state(state.clone());

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
            origin.to_str().map(is_allowed_origin).unwrap_or(false)
        }))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    let router = Router::new()
        .route("/api/health", get(health))
        .merge(protected_api)
        .layer(cors);

    if let Some(dir) = static_dir {
        if dir.exists() {
            return router.fallback_service(ServeDir::new(dir));
        }
    }
    router
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "service": "kernlockd" }))
}

async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    let policy = state.engine.get_policy().unwrap_or_default();
    let capabilities = state.engine.capabilities();
    Json(StatusResponse {
        capabilities,
        policy,
        watcher_active: state.engine.is_watcher_active(),
        fanotify_active: state.engine.is_fanotify_active(),
        rules_loaded: state.engine.rules.rule_count(),
    })
}

async fn get_processes(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .list_processes()
        .map(Json)
        .map_err(map_platform_error)
}

async fn get_persistence(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .scan_persistence()
        .map(Json)
        .map_err(map_platform_error)
}

async fn scan_path(
    State(state): State<AppState>,
    Json(req): Json<ScanPathRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let p = PathBuf::from(&req.path);
    if !p.exists() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("Path does not exist: {}", req.path),
        ));
    }
    state
        .engine
        .scan_path(&p)
        .map(Json)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn start_scan(
    State(state): State<AppState>,
    Json(req): Json<StartScanRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    match state.engine.scanner.start_scan(req.mode, req.paths).await {
        Ok(scan_id) => Ok(Json(StartScanResponse {
            scan_id,
            status: ScanStatus::Running,
        })),
        Err(e) => Err(err_resp(StatusCode::CONFLICT, e.to_string())),
    }
}

async fn cancel_scan(State(state): State<AppState>) -> impl IntoResponse {
    let cancelled = state.engine.scanner.cancel_current_scan();
    Json(CancelScanResponse { cancelled })
}

async fn get_current_scan(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.engine.scanner.current_progress())
}

async fn list_scan_history(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .storage
        .list_scan_jobs(50)
        .map(Json)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn list_threats_history(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .storage
        .list_threat_records(100)
        .map(Json)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn analyze_command(
    State(state): State<AppState>,
    Json(req): Json<AnalyzeCommandRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .analyze_command_text(&req.command)
        .map(Json)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn list_events(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .storage
        .list_events(200)
        .map(Json)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn list_alerts(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .storage
        .list_alerts(200)
        .map(Json)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn update_alert_status(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    Json(req): Json<AlertStatusRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .storage
        .update_alert_status(id, req.status)
        .map(|_| Json(serde_json::json!({ "updated": true })))
        .map_err(|e| err_resp(StatusCode::NOT_FOUND, e.to_string()))
}

async fn list_quarantine(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .quarantine
        .list()
        .map(Json)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn quarantine_file(
    State(state): State<AppState>,
    Json(req): Json<QuarantineRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let reason = req
        .reason
        .unwrap_or_else(|| "Manually quarantined by user".to_string());
    state
        .engine
        .quarantine_file(&PathBuf::from(&req.path), &reason)
        .map(Json)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))
}

async fn restore_quarantine(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .restore_quarantine(id)
        .map(Json)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))
}

async fn delete_quarantine(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .delete_quarantine(id)
        .map(|_| Json(serde_json::json!({ "deleted": true })))
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))
}

async fn get_policy(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .get_policy()
        .map(Json)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn update_policy(
    State(state): State<AppState>,
    Json(policy): Json<PolicyConfig>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .update_policy(policy)
        .map(Json)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn list_rules(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.engine.rules.rules())
}

async fn get_report(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .generate_report()
        .map(Json)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn get_report_markdown(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    match state.engine.generate_report() {
        Ok(report) => Ok(state.engine.format_report_markdown(&report)),
        Err(e) => Err(err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

async fn get_definitions_status(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.engine.definition_status())
}

async fn update_definitions_endpoint(
    State(state): State<AppState>,
    Json(bundle): Json<SignedThreatBundle>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .update_definitions(bundle)
        .map(Json)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e.to_string()))
}
