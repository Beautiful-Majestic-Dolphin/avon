#![allow(clippy::unwrap_used, clippy::expect_used)]
use avon_testkit::pki::TestPki;
use avon_tls::{rustls_client_config, rustls_server_config};
use rustls::NamedGroup;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn tls_negotiates_x25519mlkem768_with_mutual_auth() {
    let pki = TestPki::new();
    let server_id = pki.issue_tls("spiffe://avon/service/control", &["localhost"]);
    let client_id = pki.issue_tls(
        "spiffe://avon/service/gateway/00000000-0000-0000-0000-000000000009",
        &[],
    );

    let server_cfg = rustls_server_config(
        server_id.cert_pem.as_bytes(),
        server_id.key_pem.as_bytes(),
        pki.tls_ca_pem.as_bytes(),
        true,
    )
    .unwrap();
    let client_cfg = rustls_client_config(
        Some((client_id.cert_pem.as_bytes(), client_id.key_pem.as_bytes())),
        pki.tls_ca_pem.as_bytes(),
    )
    .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let (_, conn) = tls.get_ref();
        let group = conn.negotiated_key_exchange_group().unwrap().name();
        let peer = conn.peer_certificates().unwrap().len();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        (group, peer, buf)
    });

    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, tcp).await.unwrap();
    tls.write_all(b"ping").await.unwrap();
    tls.flush().await.unwrap();
    let (group, peer_certs, buf) = server.await.unwrap();
    assert_eq!(
        group,
        NamedGroup::X25519MLKEM768,
        "hybrid PQ group must be preferred"
    );
    assert_eq!(peer_certs, 1, "client certificate must be presented");
    assert_eq!(&buf, b"ping");
}
