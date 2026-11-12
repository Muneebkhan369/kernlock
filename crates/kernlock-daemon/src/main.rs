use anyhow::Result;
use clap::{Parser, Subcommand};
use kernlock_daemon::{api, auth, engine::KernLockEngine};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "kernlock",
    version,
    about = "KernLock Security — Detect. Block. Explain."
)]
struct Cli {
    #[arg(
        global = true,
        long,
        help = "Directory for SQLite database and quarantine vault"
    )]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the KernLock security daemon and local HTTP API
    Serve {
        #[arg(long, default_value_t = 17420)]
        port: u16,
        #[arg(long, help = "Optional path to built React UI dist directory")]
        ui_dir: Option<PathBuf>,
    },
    /// Show OS capabilities, privilege level, and active security mode
    Status,
    /// Statically scan a file or directory for threats
    Scan { path: PathBuf },
    /// Statically analyze a shell command or script string without executing it
    AnalyzeCmd { command: String },
    /// Inspect running processes and flag anomalies
    Processes,
    /// Inspect startup and persistence mechanisms
    Persistence,
    /// Manage quarantined files
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
    /// Generate a comprehensive security report
    Report {
        #[arg(long, default_value = "markdown")]
        format: String,
    },
}

#[derive(Subcommand)]
enum QuarantineAction {
    List,
    Restore { id: Uuid },
    Delete { id: Uuid },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kernlock=info,tower_http=warn".into()),
        )
        .init();

    let cli = Cli::parse();
    let data_dir = cli
        .data_dir
        .unwrap_or_else(kernlock_core::paths::default_data_dir);
    let engine = KernLockEngine::init(&data_dir)?;

    match cli.command {
        Commands::Serve { port, ui_dir } => {
            let api_token = auth::load_or_create_token(&data_dir)?;
            engine.start_fanotify_monitor();
            engine.start_realtime_watcher();
            let app = api::build_router(engine, api_token, ui_dir);
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            info!(
                "KernLock daemon listening on http://{} (Bearer token stored in {}/auth.token)",
                addr,
                data_dir.display()
            );
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
        Commands::Status => {
            let caps = engine.capabilities();
            println!("{}", serde_json::to_string_pretty(&caps)?);
        }
        Commands::Scan { path } => {
            let results = engine.scan_path(&path)?;
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        Commands::AnalyzeCmd { command } => {
            let result = engine.analyze_command_text(&command)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Processes => {
            let procs = engine.list_processes()?;
            println!("{}", serde_json::to_string_pretty(&procs)?);
        }
        Commands::Persistence => {
            let items = engine.scan_persistence()?;
            println!("{}", serde_json::to_string_pretty(&items)?);
        }
        Commands::Quarantine { action } => match action {
            QuarantineAction::List => {
                let items = engine.quarantine.list()?;
                println!("{}", serde_json::to_string_pretty(&items)?);
            }
            QuarantineAction::Restore { id } => {
                let rec = engine.restore_quarantine(id)?;
                println!("{}", serde_json::to_string_pretty(&rec)?);
            }
            QuarantineAction::Delete { id } => {
                engine.delete_quarantine(id)?;
                println!("Deleted quarantine record {}", id);
            }
        },
        Commands::Report { format } => {
            let report = engine.generate_report()?;
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", engine.format_report_markdown(&report));
            }
        }
    }

    Ok(())
}
