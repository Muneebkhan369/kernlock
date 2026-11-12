use crate::engine::KernLockEngine;
use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use kernlock_core::{AlertStatus, PolicyConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub engine: KernLockEngine,
}

#[derive(Serialize)]
struct StatusResponse {
    capabilities: kernlock_core::PlatformCapabilities,
    policy: PolicyConfig,
    watcher_active: bool,
    rules_loaded: usize,
}

#[derive(Deserialize)]
struct ScanPathRequest {
    path: String,
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

pub fn build_router(engine: KernLockEngine, static_dir: Option<PathBuf>) -> Router {
    let state = AppState { engine };

    let api = Router::new()
        .route("/api/health", get(health))
        .route("/api/status", get(get_status))
        .route("/api/processes", get(get_processes))
        .route("/api/persistence", get(get_persistence))
        .route("/api/scan/path", post(scan_path))
        .route("/api/analyze/command", post(analyze_command))
        .route("/api/events", get(list_events))
        .route("/api/alerts", get(list_alerts))
        .route("/api/alerts/:id/status", post(update_alert_status))
        .route("/api/quarantine", get(list_quarantine).post(quarantine_file))
        .route("/api/quarantine/:id/restore", post(restore_quarantine))
        .route("/api/quarantine/:id", delete(delete_quarantine))
        .route("/api/policy", get(get_policy).put(update_policy))
        .route("/api/rules", get(list_rules))
        .route("/api/report", get(get_report))
        .route("/api/report/markdown", get(get_report_markdown))
        .with_state(state);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let router = api.layer(cors);

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
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn get_persistence(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .engine
        .scan_persistence()
        .map(Json)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
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
