use std::sync::Arc;

use avon_ca::config::{Cli, Cmd};
use avon_ca::keys::{load_or_init, SealedFileProvider};
use avon_ca::service::CaService;
use avon_config::Validate;
use avon_observability::{grpc_health, init_tracing, install_metrics, serve_health, Readiness};
use avon_protocol::v2::ca_service_server::CaServiceServer;
use clap::Parser;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    avon_tls::install_default_provider();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::GenerateMasterKey(c) => {
            SealedFileProvider::generate_master_key(&c.master_key_file)?;
            println!("master key written to {}", c.master_key_file.display());
        }
        Cmd::Init(c) => {
            c.db.validate()?;
            let pool = avon_db::connect(&c.db).await?;
            let provider = SealedFileProvider::from_file(&c.master_key_file)?;
            let keys = load_or_init(&pool, &provider, true).await?;
            println!(
                "issuing key id: {}",
                hex::encode(keys.issuing.verifying_key().key_id())
            );
        }
        Cmd::Serve(args) => {
            args.validate()?;
            init_tracing(&args.obs)?;
            install_metrics(args.obs.metrics_addr)?;
            let readiness = Readiness::new();
            let db_ready = readiness.register("database");
            let keys_ready = readiness.register("ca-keys");
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let health_rx = shutdown_rx.clone();
            tokio::spawn(serve_health(
                args.obs.health_addr,
                readiness.clone(),
                async move {
                    let mut rx = health_rx;
                    let _ = rx.wait_for(|v| *v).await;
                },
            ));

            let pool = avon_db::connect(&args.common.db).await?;
            db_ready.set(true);
            let provider = SealedFileProvider::from_file(&args.common.master_key_file)?;
            let keys = Arc::new(load_or_init(&pool, &provider, false).await?);
            keys_ready.set(true);

            let health = grpc_health();
            health
                .reporter
                .set_serving::<CaServiceServer<CaService>>()
                .await;
            let svc = CaService {
                pool,
                keys,
                device_lifetime_secs: args.device_lifetime_secs,
            };
            tracing::info!(addr = %args.listen_addr, "avon-ca serving");
            Server::builder()
                .tls_config(avon_tls::server_tls_config(&args.tls)?)?
                .add_service(health.service)
                .add_service(CaServiceServer::new(svc))
                .serve_with_shutdown(args.listen_addr, async {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = shutdown_tx.send(true);
                })
                .await?;
        }
    }
    Ok(())
}
