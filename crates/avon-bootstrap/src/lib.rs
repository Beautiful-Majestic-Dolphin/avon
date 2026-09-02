//! avon-bootstrap's testable core: issuing service credentials (and the
//! `devices` row a gateway needs to register), resolving tenants, and
//! creating the first owner. `main.rs` is a thin CLI wrapper around these.
//!
//! Split out into a library purely so `tests/` can exercise
//! [`issue_service_certs`] against a real Postgres without going through the
//! CLI — mirrors `avon-ca`, whose `main.rs` is likewise a wrapper around a
//! `lib.rs` for the same reason.

use std::path::Path;

use avon_ca::keys::CaKeys;
use avon_ca::pki::{store_issued, verify_csr, Issuer, SERVICE_LIFETIME_SECS};
use avon_crypto::cert::SubjectKind;
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use sqlx::PgPool;

/// Issue one TLS + AVON credential per service. A service whose identity is
/// already on disk is left untouched: `init` is idempotent, and re-running it
/// (a compose `up` that re-runs the one-shot bootstrap on a layer change, say)
/// must not rotate a service's keys. Rotating them mid-deployment invalidates
/// every session and enrollment already established against that identity --
/// the gateway would come back under a new id, and every connected agent would
/// be cut off. The CA is stable across re-runs (`load_or_init`), so an existing
/// service cert is still valid; there is nothing to reissue.
pub async fn issue_service_certs(
    pool: &PgPool,
    keys: &CaKeys,
    out: &Path,
    services: &[String],
    dns: &[String],
    tenant_id: uuid::Uuid,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(out)?;
    // Not `ca.crt`: that is the file name of the CA service's own leaf.
    std::fs::write(out.join("trust-ca.crt"), &keys.tls_ca_cert_pem)?;
    let dns_map: std::collections::HashMap<String, Vec<String>> = dns
        .iter()
        .filter_map(|d| d.split_once('='))
        .map(|(k, v)| (k.to_string(), v.split('+').map(String::from).collect()))
        .collect();
    for service in services {
        // Already initialised: keep the existing identity rather than rotate it.
        if out.join(format!("{service}.avon.crt")).exists() {
            println!("{service} already initialised; keeping its identity");
            continue;
        }
        let signing = HybridSigningKeyPair::generate()?;
        let kem = HybridKemKeyPair::generate()?;
        let tls_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let service_id = uuid::Uuid::new_v4();
        let csr = service_csr(&signing, &kem, &tls_key, service_id)?;
        let data = verify_csr(&csr)?;
        let mut sans = vec![if service == "gateway" {
            format!("spiffe://avon/service/gateway/{service_id}")
        } else {
            format!("spiffe://avon/service/{service}")
        }];
        sans.extend(
            dns_map
                .get(service)
                .cloned()
                .unwrap_or_else(|| vec![service.clone()]),
        );
        let issued = Issuer { keys }.issue(
            data,
            SubjectKind::Service,
            None,
            service_id,
            sans,
            SERVICE_LIFETIME_SECS,
        )?;
        store_issued(
            pool,
            &issued,
            None,
            service_id,
            "service",
            &keys.issuing.verifying_key().key_id(),
        )
        .await?;
        if service == "gateway" {
            // `gateways.id` (avon-control/src/service/gateway.rs) references
            // `devices(id)`, and the gateway derives its own identity from
            // this exact `service_id` (it becomes the cert's `subject_id`,
            // which avon-gateway/src/state.rs turns straight into its
            // GatewayId). A device row under any other id would satisfy the
            // foreign key and still never match the gateway that registers,
            // so it has to be keyed on `service_id`, not a fresh uuid.
            //
            // Only the gateway needs this: nothing else references a
            // service's identity through `devices`, so inventing rows for
            // `control`/`ca`/`admin` would just be unused rows.
            upsert_gateway_device(pool, service_id, tenant_id, service).await?;
        }
        write_0600(
            &out.join(format!("{service}.crt")),
            issued.tls_cert_pem.as_bytes(),
        )?;
        write_0600(
            &out.join(format!("{service}.key")),
            tls_key.serialize_pem().as_bytes(),
        )?;
        write_0600(
            &out.join(format!("{service}.avon.crt")),
            &issued.certificate.encode(),
        )?;
        write_0600(
            &out.join(format!("{service}.avon.key")),
            &signing.to_secret_bytes(),
        )?;
        write_0600(
            &out.join(format!("{service}.kem.key")),
            &kem.to_secret_bytes(),
        )?;
        println!("issued {service} ({service_id})");
    }
    Ok(())
}

/// Idempotently ensures the gateway's `devices` row exists under `id`.
/// Pulled out of [`issue_service_certs`] so its ON CONFLICT behavior — a
/// rerun against an existing database must not fail or produce a second row
/// for the same id — is directly testable, independent of that function's
/// internally-generated (and therefore uncontrollable-from-a-test) ids.
pub async fn upsert_gateway_device(
    pool: &PgPool,
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    name: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO devices (id, tenant_id, name, kind, status) \
         VALUES ($1, $2, $3, 'gateway', 'active') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(name)
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up a tenant's id by name. Bootstrap never creates tenant rows itself
/// (migration 0001 seeds `default` = [`avon_db::DEFAULT_TENANT_ID`]); this
/// only resolves the name a caller passed against what's already there.
pub async fn resolve_tenant(pool: &PgPool, tenant: &str) -> anyhow::Result<uuid::Uuid> {
    let (tenant_id,): (uuid::Uuid,) = sqlx::query_as("SELECT id FROM tenants WHERE name = $1")
        .bind(tenant)
        .fetch_one(pool)
        .await?;
    Ok(tenant_id)
}

pub async fn create_owner(
    pool: &PgPool,
    email: &str,
    password: &str,
    tenant_id: uuid::Uuid,
) -> anyhow::Result<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;
    use sha2::Digest;
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e))?
        .to_string();
    sqlx::query(
        "INSERT INTO users (tenant_id, email, password_hash, role, mfa_required) \
         VALUES ($1, $2, $3, 'owner', true) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await?;
    let token: [u8; 24] = avon_crypto::random::random_bytes_fixed()?;
    let token = hex::encode(token);
    let token_hash = sha2::Sha256::digest(token.as_bytes());
    sqlx::query(
        "INSERT INTO enrollment_tokens (tenant_id, token_hash, device_name, max_uses, expires_at) \
         VALUES ($1, $2, NULL, 100, now() + interval '7 days')",
    )
    .bind(tenant_id)
    .bind(&token_hash[..])
    .execute(pool)
    .await?;
    println!("owner {email} created; enrollment token (7 days, 100 uses): {token}");
    Ok(token)
}

fn service_csr(
    signing: &HybridSigningKeyPair,
    kem: &HybridKemKeyPair,
    tls_key: &rcgen::KeyPair,
    service_id: uuid::Uuid,
) -> anyhow::Result<avon_protocol::v2::Csr> {
    use avon_crypto::cert::TbsCertificate;
    use avon_crypto::hybrid::signature::Domain;
    let template = TbsCertificate {
        version: 2,
        serial: [0; 16],
        tenant_id: String::new(),
        subject_id: *service_id.as_bytes(),
        kind: SubjectKind::Service,
        signing_key: signing.verifying_key(),
        kem_key: Some(kem.public_key()),
        not_before: 0,
        not_after: 0,
        issuer_key_id: [0; 32],
        sans: vec![],
        tls_cert_sha256: None,
        hardware_binding: None,
    }
    .encode();
    let proof = signing.sign(Domain::Csr, &template)?.to_bytes();
    let params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    let tls_csr_pem = params.serialize_request(tls_key)?.pem()?;
    Ok(avon_protocol::v2::Csr {
        tbs_template: template,
        proof,
        tls_csr_pem,
        hardware_binding: Vec::new(),
    })
}

#[cfg(unix)]
fn write_0600(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_0600(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}
