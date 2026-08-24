//! One-shot initialisation for an AVON deployment.
//!
//! Runs with database access and the CA master key, so it loads `CaKeys`
//! directly rather than calling the CA over the network — the CA is not up yet
//! when its own TLS certificate has to be issued.

use std::path::{Path, PathBuf};

use avon_ca::keys::{load_or_init, CaKeys, SealedFileProvider};
use avon_ca::pki::{store_issued, verify_csr, Issuer, SERVICE_LIFETIME_SECS};
use avon_config::{DatabaseArgs, Validate};
use avon_crypto::cert::SubjectKind;
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use clap::{Parser, Subcommand};
use sha2::Digest;
use sqlx::PgPool;

#[derive(Parser)]
#[command(name = "avon-bootstrap", version)]
struct Cli {
    #[command(flatten)]
    db: DatabaseArgs,
    #[arg(long, env = "AVON_CA_MASTER_KEY_FILE")]
    master_key_file: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Everything a fresh deployment needs, in order and idempotently:
    /// migrations, master key, CA chain, service credentials, first owner.
    /// One command because the runtime image ships no shell.
    Init {
        #[arg(long, default_value = "/certs")]
        out: PathBuf,
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "ca,control,gateway,admin"
        )]
        services: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        dns: Vec<String>,
        #[arg(long, env = "ADMIN_EMAIL", default_value = "owner@example.com")]
        email: String,
        #[arg(long, env = "AVON_BOOTSTRAP_ADMIN_PASSWORD", hide_env_values = true)]
        password: String,
        #[arg(long, default_value = "default")]
        tenant: String,
    },
    /// Apply the embedded schema migrations.
    MigrateUp,
    /// Write a new 0600 sealed-file master key (fails if one already exists).
    GenerateMasterKey,
    /// Issue TLS credentials for infrastructure services into --out.
    Certs {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_delimiter = ',')]
        services: Vec<String>,
        /// DNS names per service, e.g. control=control+control.avon.svc
        #[arg(long, value_delimiter = ',')]
        dns: Vec<String>,
    },
    /// Create the first owner user and print a one-time enrollment token.
    Admin {
        #[arg(long)]
        email: String,
        #[arg(long, env = "AVON_BOOTSTRAP_ADMIN_PASSWORD", hide_env_values = true)]
        password: String,
        #[arg(long, default_value = "default")]
        tenant: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    avon_tls::install_default_provider();
    let cli = Cli::parse();
    cli.db.validate()?;

    match cli.cmd {
        Cmd::MigrateUp => {
            let pool = avon_db::connect(&cli.db).await?;
            avon_db::migrate(&pool).await?;
            println!("migrations applied");
        }
        Cmd::GenerateMasterKey => {
            SealedFileProvider::generate_master_key(&cli.master_key_file)?;
            println!("master key written to {}", cli.master_key_file.display());
        }
        Cmd::Init {
            out,
            services,
            dns,
            email,
            password,
            tenant,
        } => {
            let pool = avon_db::connect(&cli.db).await?;
            avon_db::migrate(&pool).await?;
            println!("migrations applied");
            if !cli.master_key_file.exists() {
                SealedFileProvider::generate_master_key(&cli.master_key_file)?;
                println!("master key written to {}", cli.master_key_file.display());
            }
            let provider = SealedFileProvider::from_file(&cli.master_key_file)?;
            let keys = load_or_init(&pool, &provider, true).await?;
            // Resolved once and shared: the gateway's device row and the
            // owner's user row must land in the same tenant, not just
            // "whichever id each function happened to look up".
            let tenant_id = resolve_tenant(&pool, &tenant).await?;
            issue_service_certs(&pool, &keys, &out, &services, &dns, tenant_id).await?;
            let token = create_owner(&pool, &email, &password, tenant_id).await?;
            // Write enroll token for compose e2e agents.
            let token_path = out.join("enroll.token");
            let _ = std::fs::write(&token_path, &token);
            // Also ensure /certs/enroll.token if out is different but /certs exists (e2e volume).
            if token_path != std::path::Path::new("/certs/enroll.token")
                && std::path::Path::new("/certs").exists()
            {
                let _ = std::fs::write("/certs/enroll.token", &token);
            }
        }
        Cmd::Certs { out, services, dns } => {
            let pool = avon_db::connect(&cli.db).await?;
            let provider = SealedFileProvider::from_file(&cli.master_key_file)?;
            let keys = load_or_init(&pool, &provider, true).await?;
            // `certs` has no --tenant of its own (it only reissues
            // infrastructure credentials, never touches users/tenants), so
            // fall back to the tenant migrations always seed.
            issue_service_certs(
                &pool,
                &keys,
                &out,
                &services,
                &dns,
                avon_db::DEFAULT_TENANT_ID,
            )
            .await?;
        }
        Cmd::Admin {
            email,
            password,
            tenant,
        } => {
            let pool = avon_db::connect(&cli.db).await?;
            let tenant_id = resolve_tenant(&pool, &tenant).await?;
            create_owner(&pool, &email, &password, tenant_id).await?;
        }
    }
    Ok(())
}

/// Issue one TLS + AVON credential per service. Certificates that already exist
/// on disk are reissued: this is cheap and keeps `init` idempotent.
async fn issue_service_certs(
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
            //
            // `service_id` is freshly generated on every call, so this can
            // never collide with a still-relevant previous row — but a
            // rerun against an existing database should still never fail to
            // insert, so guard it anyway.
            sqlx::query(
                "INSERT INTO devices (id, tenant_id, name, kind, status) \
                 VALUES ($1, $2, $3, 'gateway', 'active') \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(service_id)
            .bind(tenant_id)
            .bind(service)
            .execute(pool)
            .await?;
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

/// Look up a tenant's id by name. Bootstrap never creates tenant rows itself
/// (migration 0001 seeds `default` = [`avon_db::DEFAULT_TENANT_ID`]); this
/// only resolves the name a caller passed against what's already there.
async fn resolve_tenant(pool: &PgPool, tenant: &str) -> anyhow::Result<uuid::Uuid> {
    let (tenant_id,): (uuid::Uuid,) = sqlx::query_as("SELECT id FROM tenants WHERE name = $1")
        .bind(tenant)
        .fetch_one(pool)
        .await?;
    Ok(tenant_id)
}

async fn create_owner(
    pool: &PgPool,
    email: &str,
    password: &str,
    tenant_id: uuid::Uuid,
) -> anyhow::Result<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;
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
