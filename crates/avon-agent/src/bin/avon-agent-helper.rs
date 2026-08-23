use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    data_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let server = avon_agent::helper::HelperServer::bind(
        &avon_agent::helper::HelperServer::socket_path(&cli.data_dir),
    )
    .await?;
    server.run().await
}
