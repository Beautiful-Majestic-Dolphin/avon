//! In-process launchers for AVON services, wired to the test PKI.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use avon_protocol::v2::ca_service_client::CaServiceClient;
use tonic::transport::{Channel, Endpoint};

use crate::db::TestDb;
use crate::net::free_tcp_addr;
use crate::pki::TestPki;

pub struct SpawnedService {
    pub addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl SpawnedService {
    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

pub async fn spawn_ca(db: &TestDb, pki: &TestPki, dir: &Path) -> SpawnedService {
    use avon_ca::keys::{load_or_init, SealedFileProvider};
    use avon_ca::service::CaService;
    use avon_protocol::v2::ca_service_server::CaServiceServer;

    let master = dir.join("ca-master.key");
    if !master.exists() {
        SealedFileProvider::generate_master_key(&master).expect("master key");
    }
    let provider = SealedFileProvider::from_file(&master).expect("provider");
    let keys = Arc::new(
        load_or_init(db.pool(), &provider, true)
            .await
            .expect("ca keys"),
    );
    let tls = pki.write_to(dir, "ca", "spiffe://avon/service/ca", &["localhost"]);
    let addr = free_tcp_addr();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let svc = CaService {
        pool: db.pool().clone(),
        keys,
        device_lifetime_secs: 86_400,
    };
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(avon_tls::server_tls_config(&tls).expect("tls"))
            .expect("tls cfg")
            .add_service(CaServiceServer::new(svc))
            .serve_with_shutdown(addr, async {
                let _ = rx.await;
            })
            .await
            .expect("ca server");
    });
    wait_for_port(addr).await;
    SpawnedService {
        addr,
        shutdown: Some(tx),
    }
}

pub async fn ca_client(
    pki: &TestPki,
    dir: &Path,
    addr: SocketAddr,
    as_spiffe: &str,
) -> CaServiceClient<Channel> {
    let name = as_spiffe.replace(['/', ':'], "_");
    let tls = pki.write_to(dir, &name, as_spiffe, &[]);
    let channel = Endpoint::from_shared(format!("https://localhost:{}", addr.port()))
        .expect("endpoint")
        .tls_config(avon_tls::client_tls_config(&tls, "localhost").expect("client tls"))
        .expect("tls")
        .connect()
        .await
        .expect("connect");
    CaServiceClient::new(channel)
}

pub async fn wait_for_port(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("service at {addr} did not start");
}
