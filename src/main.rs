use std::net::SocketAddr;

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

    server.run(args.listen).await?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt().with_env_filter(filter).init();
}
