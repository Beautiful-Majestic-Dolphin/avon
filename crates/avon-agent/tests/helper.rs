#![allow(clippy::unwrap_used)]
use avon_agent::helper::{HelperRequest, HelperResponse};
use std::path::PathBuf;

#[tokio::test]
async fn helper_protocol_roundtrips_and_validates_routes() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("helper.sock");
    let server = avon_agent::helper::HelperServer::bind(&sock).await.unwrap();
    let sock_clone = sock.clone();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut client = avon_agent::helper::HelperClient::connect(&sock_clone)
        .await
        .unwrap();
    let resp = client
        .request(HelperRequest::CreateTun {
            name: "tun0".into(),
            mtu: 1280,
        })
        .await
        .unwrap();
    match resp {
        HelperResponse::TunReady { name, mtu } => {
            assert_eq!(name, "tun0");
            assert_eq!(mtu, 1280);
        }
        _ => panic!("expected TunReady"),
    }

    let resp = client
        .request(HelperRequest::Configure {
            v4: "10.0.0.1/24".into(),
            v6: None,
            mtu: 1280,
            allowed_routes: vec!["10.0.0.0/8".into()],
        })
        .await
        .unwrap();
    assert!(matches!(resp, HelperResponse::Ok));

    // Too many routes should be rejected.
    let many: Vec<String> = (0..2000)
        .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
        .collect();
    let resp = client
        .request(HelperRequest::SetRoutes {
            add: many,
            remove: vec![],
        })
        .await
        .unwrap();
    assert!(matches!(resp, HelperResponse::Error { .. }));
}

#[test]
fn firewall_trait_is_object_safe() {
    let fw: Box<dyn avon_agent::platform::firewall::Firewall> =
        Box::new(avon_agent::platform::firewall::NoopFirewall);
    let _ = fw;
}
