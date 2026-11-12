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
    /// Generate a fresh Ed25519 offline signing keypair
    GenerateSigningKey {
        #[arg(long, help = "Path to write the 32-byte hex private key")]
        out_priv_key: PathBuf,
        #[arg(long, help = "Path to write the 32-byte hex public key")]
        out_pub_key: PathBuf,
    },
    /// Cryptographically sign a threat bundle manifest using an offline private key
    SignBundle {
        #[arg(long, help = "Path to raw ThreatBundleManifest JSON file")]
        manifest: PathBuf,
        #[arg(long, help = "Path to private key hex file")]
        key_file: PathBuf,
        #[arg(long, help = "Path to write the output SignedThreatBundle JSON")]
        output: PathBuf,
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
            #[cfg(unix)]
            engine.start_unix_socket_server(&data_dir);
            #[cfg(target_os = "windows")]
            engine.start_windows_minifilter();
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
        Commands::GenerateSigningKey {
            out_priv_key,
            out_pub_key,
        } => {
            use ed25519_dalek::SigningKey;
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("CSPRNG error: {}", e))?;
            let signing_key = SigningKey::from_bytes(&seed);
            let priv_hex = hex::encode(signing_key.to_bytes());
            let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&out_priv_key)?;
                use std::io::Write;
                f.write_all(priv_hex.as_bytes())?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&out_priv_key, &priv_hex)?;
            }

            std::fs::write(&out_pub_key, &pub_hex)?;
            println!("Successfully generated Ed25519 offline signing keypair.");
            println!("Private Key (chmod 0600): {}", out_priv_key.display());
            println!("Public Key: {}", out_pub_key.display());
            println!("Public Key Hex: {}", pub_hex);
        }
        Commands::SignBundle {
            manifest,
            key_file,
            output,
        } => {
            use ed25519_dalek::SigningKey;
            use kernlock_core::intelligence::{SignedThreatBundle, ThreatBundleManifest};

            let manifest_str = std::fs::read_to_string(&manifest)?;
            let manifest_obj: ThreatBundleManifest = serde_json::from_str(&manifest_str)?;

            let key_hex = std::fs::read_to_string(&key_file)?;
            let key_bytes = hex::decode(key_hex.trim())?;
            if key_bytes.len() != 32 {
                anyhow::bail!("Private key must be exactly 32 bytes (64 hex characters)");
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key_bytes);
            let signing_key = SigningKey::from_bytes(&key_arr);

            let bundle = SignedThreatBundle::new(manifest_obj, &signing_key)
                .map_err(|e| anyhow::anyhow!("Signing failed: {}", e))?;

            let bundle_json = serde_json::to_string_pretty(&bundle)?;
            std::fs::write(&output, bundle_json)?;
            println!(
                "Successfully signed threat bundle v{} -> {}",
                bundle.manifest.version,
                output.display()
            );
        }
    }

    Ok(())
}
