#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use avon_protocol::v2::{pulse_up, DevicePosture, PulseHeartbeat, PulseUp};
use avon_testkit::{
    db::TestDb,
    device::TestDevice,
    pki::TestPki,
    services::{spawn_ca, spawn_control, ControlFixture},
};
use tokio_stream::StreamExt;

async fn fixture() -> ControlFixture {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    spawn_control(db, pki, dir, ca).await
}

#[tokio::test(flavor = "multi_thread")]
async fn heartbeat_persists_posture_and_acks_with_interval() {
    let f = fixture().await;
    let dev = TestDevice::enroll(&f, "tok").await;
    let mut client = dev.authenticate(&f).await.unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut down = client
        .pulse(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(PulseUp {
        msg: Some(pulse_up::Msg::Heartbeat(PulseHeartbeat {
            posture: Some(DevicePosture {
                os_name: "linux".into(),
                firewall_enabled: Some(true),
                disk_encrypted: Some(false),
                collected_at_unix: 1,
                ..Default::default()
            }),
            sessions: vec![],
        })),
    })
    .await
    .unwrap();
    let ack = down.next().await.unwrap().unwrap();
    match ack.msg.unwrap() {
        avon_protocol::v2::pulse_down::Msg::Ack(a) => assert_eq!(a.next_interval_secs, 30),
        other => panic!("unexpected {other:?}"),
    }
    let (posture, liveness): (serde_json::Value, String) =
        sqlx::query_as("SELECT posture, liveness::text FROM devices WHERE id = $1")
            .bind(dev.device_id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(posture["firewall_enabled"], true);
    assert_eq!(liveness, "online");
}

#[tokio::test(flavor = "multi_thread")]
async fn pulse_without_session_token_is_rejected() {
    let f = fixture().await;
    let dev = TestDevice::enroll(&f, "tok").await;
    let mut client = dev.client_without_token(&f).await;
    let (_tx, rx) = tokio::sync::mpsc::channel::<PulseUp>(1);
    let err = client
        .pulse(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread")]
async fn sweeper_marks_devices_stale_then_offline() {
    let f = fixture().await;
    let dev = TestDevice::enroll(&f, "tok").await;
    sqlx::query(
        "UPDATE devices SET liveness = 'online', last_seen_at = now() - interval '10 minutes' \
         WHERE id = $1",
    )
    .bind(dev.device_id)
    .execute(f.db.pool())
    .await
    .unwrap();
    avon_control::liveness::sweep_once(
        f.db.pool(),
        std::time::Duration::from_secs(90),
        std::time::Duration::from_secs(300),
    )
    .await
    .unwrap();
    let (l,): (String,) = sqlx::query_as("SELECT liveness::text FROM devices WHERE id = $1")
        .bind(dev.device_id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(l, "offline");
}
