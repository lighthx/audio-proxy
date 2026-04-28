use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{ArgAction, Parser};
use proxy::{ProxyConfig, ProxyServer};
use tracing_subscriber::{EnvFilter, fmt};

mod proxy;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Allowlisted HTTP/HTTPS proxy for audio services"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    #[arg(long = "allow-domain", action = ArgAction::Append)]
    allow_domains: Vec<String>,

    #[arg(long)]
    tls_cert: Option<PathBuf>,

    #[arg(long)]
    tls_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tracing();

    let args = Args::parse();
    let allowed_domains = if args.allow_domains.is_empty() {
        ProxyConfig::default_allowed_domains()
    } else {
        args.allow_domains
    };

    let config = ProxyConfig::new(allowed_domains);
    let server = ProxyServer::new(config);

    match (args.tls_cert, args.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            server.run_tls(args.listen, cert_path, key_path).await?
        }
        (None, None) => server.run(args.listen).await?,
        _ => {
            return Err("--tls-cert and --tls-key must be provided together".into());
        }
    }

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt().with_env_filter(filter).init();
}
