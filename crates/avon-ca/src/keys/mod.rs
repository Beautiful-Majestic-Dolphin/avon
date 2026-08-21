mod provider;
mod sealed_file;

pub use provider::{KeyError, SealProvider};
pub use sealed_file::SealedFileProvider;

use avon_crypto::cert::{Certificate, SubjectKind, TbsCertificate};
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
};
use sha2::Digest;
use sqlx::PgPool;
use zeroize::Zeroizing;

const ROOT_LIFETIME_SECS: i64 = 10 * 365 * 86_400;
const ISSUING_LIFETIME_SECS: i64 = 2 * 365 * 86_400;

pub struct CaKeys {
    pub root: Option<HybridSigningKeyPair>,
    pub issuing: HybridSigningKeyPair,
    pub tls_ca: KeyPair,
    pub root_cert: Certificate,
    pub issuing_cert: Certificate,
    pub tls_ca_cert_pem: String,
    pub tls_ca_cert_der: Vec<u8>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_serial() -> Result<[u8; 16], KeyError> {
    avon_crypto::random::random_bytes_fixed::<16>().map_err(|_| KeyError::Random)
}

fn ca_tbs(
    kind: SubjectKind,
    kp: &HybridSigningKeyPair,
    issuer: &HybridSigningKeyPair,
    lifetime: i64,
) -> Result<TbsCertificate, KeyError> {
    Ok(TbsCertificate {
        version: 2,
        serial: random_serial()?,
        tenant_id: String::new(),
        subject_id: [0; 16],
        kind,
        signing_key: kp.verifying_key(),
        kem_key: None,
        not_before: now() - 300,
        not_after: now() + lifetime,
        issuer_key_id: issuer.verifying_key().key_id(),
        sans: vec![],
        tls_cert_sha256: None,
    })
}

#[derive(sqlx::FromRow)]
struct KeyRow {
    kind: String,
    key_id: Vec<u8>,
    certificate: Vec<u8>,
    sealed_private_key: Vec<u8>,
}

async fn insert(
    tx: &mut sqlx::PgConnection,
    provider: &dyn SealProvider,
    kind: &str,
    key_id: &[u8; 32],
    cert: &[u8],
    secret: &[u8],
) -> Result<(), KeyError> {
    let sealed = provider.seal(key_id, secret).await?;
    sqlx::query(
        "INSERT INTO ca_keys (kind, key_id, certificate, sealed_private_key, provider) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(kind)
    .bind(key_id.as_slice())
    .bind(cert)
    .bind(sealed)
    .bind(provider.name())
    .execute(&mut *tx)
    .await
    .map_err(KeyError::Db)?;
    Ok(())
}

async fn initialize(pool: &PgPool, provider: &dyn SealProvider) -> Result<(), KeyError> {
    let root_kp = HybridSigningKeyPair::generate().map_err(|_| KeyError::Random)?;
    let root_cert = Certificate::sign(
        ca_tbs(SubjectKind::RootCa, &root_kp, &root_kp, ROOT_LIFETIME_SECS)?,
        &root_kp,
    )
    .map_err(|_| KeyError::Random)?;
    let issuing_kp = HybridSigningKeyPair::generate().map_err(|_| KeyError::Random)?;
    let issuing_cert = Certificate::sign(
        ca_tbs(
            SubjectKind::IssuingCa,
            &issuing_kp,
            &root_kp,
            ISSUING_LIFETIME_SECS,
        )?,
        &root_kp,
    )
    .map_err(|_| KeyError::Random)?;

    let tls_key =
        KeyPair::generate_for(&PKCS_ED25519).map_err(|e| KeyError::X509(e.to_string()))?;
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|e| KeyError::X509(e.to_string()))?;
    params
        .distinguished_name
        .push(DnType::CommonName, "AVON TLS CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let tls_cert = params
        .self_signed(&tls_key)
        .map_err(|e| KeyError::X509(e.to_string()))?;

    // One transaction: either the whole chain lands or none of it does. A
    // concurrent initializer loses on `ca_keys_one_active_per_kind`.
    let mut tx = pool.begin().await.map_err(KeyError::Db)?;
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM ca_keys")
        .fetch_one(&mut *tx)
        .await
        .map_err(KeyError::Db)?;
    if count > 0 {
        return Ok(());
    }

    insert(
        &mut tx,
        provider,
        "root",
        &root_kp.verifying_key().key_id(),
        &root_cert.encode(),
        &root_kp.to_secret_bytes(),
    )
    .await?;
    insert(
        &mut tx,
        provider,
        "issuing",
        &issuing_kp.verifying_key().key_id(),
        &issuing_cert.encode(),
        &issuing_kp.to_secret_bytes(),
    )
    .await?;
    let tls_key_id: [u8; 32] = sha2::Sha256::digest(tls_cert.der().as_ref()).into();
    insert(
        &mut tx,
        provider,
        "tls",
        &tls_key_id,
        tls_cert.der().as_ref(),
        tls_key.serialize_der().as_slice(),
    )
    .await?;
    tx.commit().await.map_err(KeyError::Db)?;
    Ok(())
}

/// Load the active keys; with `init = true` create them when none exist.
pub async fn load_or_init(
    pool: &PgPool,
    provider: &dyn SealProvider,
    init: bool,
) -> Result<CaKeys, KeyError> {
    let rows: Vec<KeyRow> = sqlx::query_as(
        "SELECT kind, key_id, certificate, sealed_private_key FROM ca_keys WHERE active",
    )
    .fetch_all(pool)
    .await
    .map_err(KeyError::Db)?;
    if rows.is_empty() {
        if !init {
            return Err(KeyError::NotInitialized);
        }
        initialize(pool, provider).await?;
        return Box::pin(load_or_init(pool, provider, false)).await;
    }
    let find = |kind: &str| {
        rows.iter()
            .find(|r| r.kind == kind)
            .ok_or_else(|| KeyError::Missing(kind.to_string()))
    };
    let root_row = find("root")?;
    let issuing_row = find("issuing")?;
    let tls_row = find("tls")?;

    let key_id = |r: &KeyRow| -> Result<[u8; 32], KeyError> {
        r.key_id
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::Missing("key_id".into()))
    };

    let issuing_secret: Zeroizing<Vec<u8>> = provider
        .unseal(&key_id(issuing_row)?, &issuing_row.sealed_private_key)
        .await?;
    let issuing =
        HybridSigningKeyPair::from_secret_bytes(&issuing_secret).map_err(|_| KeyError::Unseal)?;
    let root = if std::env::var("AVON_CA_LOAD_ROOT")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        let s = provider
            .unseal(&key_id(root_row)?, &root_row.sealed_private_key)
            .await?;
        Some(HybridSigningKeyPair::from_secret_bytes(&s).map_err(|_| KeyError::Unseal)?)
    } else {
        None
    };
    let tls_secret = provider
        .unseal(&key_id(tls_row)?, &tls_row.sealed_private_key)
        .await?;
    let tls_ca =
        KeyPair::try_from(tls_secret.as_slice()).map_err(|e| KeyError::X509(e.to_string()))?;
    let tls_ca_cert_der = tls_row.certificate.clone();
    let tls_ca_cert_pem = pem_encode("CERTIFICATE", &tls_ca_cert_der);

    Ok(CaKeys {
        root,
        issuing,
        tls_ca,
        root_cert: Certificate::decode(&root_row.certificate)
            .map_err(|e| KeyError::X509(e.to_string()))?,
        issuing_cert: Certificate::decode(&issuing_row.certificate)
            .map_err(|e| KeyError::X509(e.to_string()))?,
        tls_ca_cert_pem,
        tls_ca_cert_der,
    })
}

pub(crate) fn pem_encode(tag: &str, der: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    let b64 = Base64::encode_string(der);
    let mut out = format!("-----BEGIN {tag}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {tag}-----\n"));
    out
}
