#![allow(clippy::unwrap_used, clippy::expect_used)]
use avon_crypto::cert::{Certificate, ChainVerifier, SubjectKind};
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use avon_protocol::v2::{EnrollRequest, Fingerprint};
use avon_testkit::{
    db::TestDb,
    pki::{make_csr, TestPki},
    services::{agent_client_anonymous, spawn_ca, spawn_control, ControlFixture},
};
use rcgen::{KeyPair, PKCS_ED25519};
use uuid::Uuid;

async fn fixture() -> ControlFixture {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    spawn_control(db, pki, dir, ca).await
}

async fn insert_token(
    f: &ControlFixture,
    token: &str,
    max_uses: i32,
    pod: Option<Uuid>,
    approval: bool,
) {
    let hash = avon_control::store::hash_token(token);
    let pods: Vec<Uuid> = pod.into_iter().collect();
    sqlx::query(
        "INSERT INTO enrollment_tokens (tenant_id, token_hash, device_name, pod_ids, max_uses, \
         require_approval, expires_at) \
         VALUES ($1, $2, 'laptop', $3, $4, $5, now() + interval '1 hour')",
    )
    .bind(avon_db::DEFAULT_TENANT_ID)
    .bind(&hash[..])
    .bind(&pods)
    .bind(max_uses)
    .bind(approval)
    .execute(f.db.pool())
    .await
    .unwrap();
}

fn request(token: &str) -> EnrollRequest {
    let signing = HybridSigningKeyPair::generate().unwrap();
    let kem = HybridKemKeyPair::generate().unwrap();
    let tls_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    EnrollRequest {
        token: token.into(),
        csr: Some(make_csr(
            &signing,
            &kem.public_key(),
            &tls_key,
            SubjectKind::Device,
            "",
            [0; 16],
        )),
        fingerprint: Some(Fingerprint {
            version: 2,
            hash: vec![1; 32],
            identifier_kinds: vec!["machine-id".into()],
        }),
        attestation: None,
        requested_name: "my-laptop".into(),
        agent_version: "0.2.0".into(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn enroll_issues_credential_and_creates_device_with_pods() {
    let f = fixture().await;
    let pod: (Uuid,) =
        sqlx::query_as("INSERT INTO pods (tenant_id, name) VALUES ($1, 'eng') RETURNING id")
            .bind(avon_db::DEFAULT_TENANT_ID)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    insert_token(&f, "tok-1", 1, Some(pod.0), false).await;

    let mut client = agent_client_anonymous(&f).await;
    let resp = client.enroll(request("tok-1")).await.unwrap().into_inner();
    assert_eq!(resp.status, "active");
    let device_id = avon_protocol::bytes_to_uuid(&resp.device_id.unwrap().value).unwrap();
    let cred = resp.credential.unwrap();
    let chain = cred.chain.unwrap();
    let root = Certificate::decode(&chain.root.unwrap().encoded).unwrap();
    let issuing = Certificate::decode(&chain.issuing.unwrap().encoded).unwrap();
    let leaf = Certificate::decode(&cred.certificate.unwrap().encoded).unwrap();
    ChainVerifier::new(vec![root])
        .unwrap()
        .verify(
            &leaf,
            std::slice::from_ref(&issuing),
            chrono::Utc::now().timestamp(),
        )
        .unwrap();
    assert_eq!(leaf.tbs.subject_id, *device_id.as_bytes());

    let (status, name): (String, String) =
        sqlx::query_as("SELECT status::text, name FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!((status.as_str(), name.as_str()), ("active", "laptop"));
    let (pods,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM device_pods WHERE device_id = $1 AND pod_id = $2")
            .bind(device_id)
            .bind(pod.0)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(pods, 1);
    let (uses,): (i32,) = sqlx::query_as("SELECT use_count FROM enrollment_tokens")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(uses, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn token_is_single_use_and_errors_are_uniform() {
    let f = fixture().await;
    insert_token(&f, "tok-2", 1, None, false).await;
    let mut client = agent_client_anonymous(&f).await;
    client.enroll(request("tok-2")).await.unwrap();
    let second = client.enroll(request("tok-2")).await.unwrap_err();
    let unknown = client.enroll(request("nope")).await.unwrap_err();
    assert_eq!(second.code(), tonic::Code::PermissionDenied);
    assert_eq!(second.message(), unknown.message());
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_enrollments_cannot_exceed_max_uses() {
    let f = fixture().await;
    insert_token(&f, "tok-3", 2, None, false).await;
    let mut handles = Vec::new();
    for _ in 0..6 {
        let mut c = agent_client_anonymous(&f).await;
        handles.push(tokio::spawn(async move {
            c.enroll(request("tok-3")).await.is_ok()
        }));
    }
    let ok = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter(|r| *r.as_ref().unwrap())
        .count();
    assert_eq!(ok, 2);
    let (devices,): (i64,) = sqlx::query_as("SELECT count(*) FROM devices")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(devices, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_required_creates_pending_device() {
    let f = fixture().await;
    insert_token(&f, "tok-4", 1, None, true).await;
    let mut client = agent_client_anonymous(&f).await;
    let resp = client.enroll(request("tok-4")).await.unwrap().into_inner();
    assert_eq!(resp.status, "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_token_never_appears_in_logs() {
    let f = fixture().await;
    insert_token(&f, "super-secret-token", 1, None, false).await;
    let logs = f.capture_logs();
    let mut client = agent_client_anonymous(&f).await;
    client.enroll(request("super-secret-token")).await.unwrap();
    assert!(!logs.contents().contains("super-secret-token"));
}
