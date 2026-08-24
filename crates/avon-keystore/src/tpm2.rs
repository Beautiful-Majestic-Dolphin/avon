//! TPM 2.0 provider (Linux).
//!
//! No shipping TPM holds ML-KEM or ML-DSA keys, so this provider does not
//! pretend the PQ keys live in hardware. It puts three real TPM objects under a
//! primary key in the owner hierarchy and hangs everything else off them:
//!
//!   * a **binding key** — an unrestricted ECC P-256 signing key, `fixedTPM`
//!     and `fixedParent`, so it cannot be duplicated off this TPM. It signs the
//!     binding statement over both PQ public keys, which is what lets the
//!     control plane tell a hardware-backed device from a software one.
//!   * an **attestation key** — a *restricted* ECC P-256 signing key, also
//!     non-duplicable. Restricted is the point: a restricted key will only sign
//!     structures the TPM itself produced, which is why a `TPM2_Quote` it signs
//!     means something and a signature from the binding key would not.
//!   * a **sealed object** holding a 32-byte wrapping key. `TPM2_Create` seals
//!     at most 128 bytes, and the PQ secrets are thousands, so the secrets are
//!     encrypted with AES-256-GCM under that wrapping key and only the wrapping
//!     key is sealed. The blob on disk is therefore useless on another machine:
//!     recovering it needs `TPM2_Unseal` against *this* TPM's seed.
//!
//! Optionally the seal is bound to PCRs (`AVON_TPM_SEAL_PCRS=0,7`), which makes
//! the identity unusable after a firmware or secure-boot change. That is a
//! deliberate opt-in rather than the default: it is a real defence against
//! offline tampering and an equally real way to lose every device's identity on
//! a BIOS update.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use avon_crypto::hybrid::kem::{
    HybridKemCiphertext, HybridKemKeyPair, HybridKemPublicKey, HybridSharedSecret,
};
use avon_crypto::hybrid::signature::{
    Domain, HybridSignature, HybridSigningKeyPair, HybridVerifyingKey,
};
use p256::pkcs8::EncodePublicKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tss_esapi::abstraction::{ek, pcr as pcr_abstraction, AsymmetricAlgorithmSelection};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Data, Digest as TpmDigest, EccPoint, EccScheme, HashScheme, HashcheckTicket,
    KeyDerivationFunctionScheme, KeyedHashScheme, PcrSelectionList, PcrSelectionListBuilder,
    PcrSlot, Private, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters,
    SensitiveData, Signature as TpmSignature, SignatureScheme, SymmetricDefinition,
    SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{Context, TctiNameConf};
use zeroize::Zeroizing;

use crate::binding::binding_message;
use crate::provider::{
    write_private, write_provider_record, HardwareBinding, KeyError, KeyProvider, ProviderKind,
};

const SEALED_FILE: &str = "tpm-sealed.bin";
const PRIMARY_FILE: &str = "tpm-primary.ctx";
const PUBLIC_FILE: &str = "tpm-public.json";
const TLS_FILE: &str = "tls.key";

/// AES-256-GCM key size. Comfortably inside the 128-byte ceiling `TPM2_Create`
/// puts on sealed data — which the PQ secrets themselves are far too large for.
const WRAP_KEY_BYTES: usize = 32;
/// Associated data on the wrapped PQ material, so a blob cannot be replayed
/// into some other AES-GCM context that happens to share the wrapping key.
const WRAP_AAD: &[u8] = b"avon-tpm-sealed-material-v2";

/// PCRs a quote covers: 0 is the firmware code, 7 the secure-boot state. These
/// are the two `avon_attest::QuotePolicy` requires by default.
const QUOTE_PCRS: [PcrSlot; 2] = [PcrSlot::Slot0, PcrSlot::Slot7];

fn hw(message: impl std::fmt::Display) -> KeyError {
    KeyError::Provider {
        provider: ProviderKind::Tpm2,
        message: message.to_string(),
    }
}

fn unavailable(reason: impl std::fmt::Display) -> KeyError {
    KeyError::Unavailable {
        provider: ProviderKind::Tpm2,
        reason: reason.to_string(),
    }
}

#[derive(Serialize, Deserialize)]
struct PublicMaterial {
    signing_pk: Vec<u8>,
    kem_pk: Vec<u8>,
    /// SPKI DER of the binding key.
    hw_spki: Vec<u8>,
    /// SPKI DER of the attestation key. The control plane pins this on first
    /// use, so it belongs with the other public material.
    ak_spki: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct SealedBlob {
    /// Marshalled `TPM2B_PUBLIC`/`TPM2B_PRIVATE` of the sealed object holding
    /// the wrapping key.
    seal_public: Vec<u8>,
    seal_private: Vec<u8>,
    /// PCRs the seal is bound to. Empty means the object is authorised by
    /// `userWithAuth` alone.
    seal_pcrs: Vec<u32>,
    /// AES-256-GCM of the PQ secrets under the sealed wrapping key.
    nonce: Vec<u8>,
    ct: Vec<u8>,
    /// The non-duplicable binding key.
    binding_public: Vec<u8>,
    binding_private: Vec<u8>,
    /// The restricted attestation key that signs quotes.
    ak_public: Vec<u8>,
    ak_private: Vec<u8>,
}

pub struct Tpm2KeyProvider {
    dir: PathBuf,
    signing: HybridSigningKeyPair,
    kem: HybridKemKeyPair,
    tls_key_pem: String,
    hw_spki: Vec<u8>,
    ak_spki: Vec<u8>,
    sealed: SealedBlob,
}

// ---------------------------------------------------------------------------
// Context and templates
// ---------------------------------------------------------------------------

fn tcti() -> Result<TctiNameConf, KeyError> {
    if let Ok(s) = std::env::var("AVON_TPM_TCTI") {
        return TctiNameConf::from_str(&s).map_err(|e| unavailable(format!("AVON_TPM_TCTI: {e}")));
    }
    if let Ok(conf) = TctiNameConf::from_environment_variable() {
        return Ok(conf);
    }
    if Path::new("/dev/tpmrm0").exists() {
        return TctiNameConf::from_str("device:/dev/tpmrm0")
            .map_err(|e| unavailable(format!("/dev/tpmrm0: {e}")));
    }
    Err(unavailable(
        "no TPM: set AVON_TPM_TCTI or TPM2TOOLS_TCTI, or make /dev/tpmrm0 available",
    ))
}

fn context() -> Result<Context, KeyError> {
    Context::new(tcti()?).map_err(unavailable)
}

/// The primary is regenerated from this template on every open. A TPM derives a
/// primary deterministically from its seed and the template, so the same
/// template always yields the same key on the same TPM — and a different key on
/// any other, which is what makes a copied data directory worthless.
fn primary_template() -> Result<Public, KeyError> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(hw)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()
            .map_err(hw)?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(hw)
}

/// An ECC P-256 signing key under the primary. `restricted` decides what it is
/// allowed to sign: a restricted key signs only TPM-produced structures (so it
/// can quote), an unrestricted one signs caller-supplied digests (so it can
/// sign a binding statement). One key cannot do both.
fn signing_template(restricted: bool) -> Result<Public, KeyError> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(restricted)
        .build()
        .map_err(hw)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_curve(EccCurve::NistP256)
                .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_is_signing_key(true)
                .with_is_decryption_key(false)
                .with_restricted(restricted)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .build()
                .map_err(hw)?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(hw)
}

/// The keyed-hash object the wrapping key is sealed into. With `policy` set the
/// object is authorised only by that policy digest — `userWithAuth` is dropped,
/// otherwise a password session would bypass the PCR check entirely.
fn seal_template(policy: Option<TpmDigest>) -> Result<Public, KeyError> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(policy.is_none())
        .build()
        .map_err(hw)?;
    let mut builder = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(TpmDigest::default());
    if let Some(digest) = policy {
        builder = builder.with_auth_policy(digest);
    }
    builder.build().map_err(hw)
}

// ---------------------------------------------------------------------------
// PCR helpers
// ---------------------------------------------------------------------------

fn slot(index: u32) -> Result<PcrSlot, KeyError> {
    let bit = 1u32
        .checked_shl(index)
        .ok_or_else(|| hw(format!("PCR {index} is out of range")))?;
    PcrSlot::try_from(bit).map_err(|_| hw(format!("PCR {index} is not a valid slot")))
}

fn slot_index(s: PcrSlot) -> u32 {
    (s as u32).trailing_zeros()
}

fn selection(slots: &[PcrSlot]) -> Result<PcrSelectionList, KeyError> {
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, slots)
        .build()
        .map_err(hw)
}

/// PCRs the seal is bound to, from `AVON_TPM_SEAL_PCRS` (`"0,7"`). Unset or
/// empty means no PCR policy.
fn configured_seal_pcrs() -> Result<Vec<u32>, KeyError> {
    let Ok(raw) = std::env::var("AVON_TPM_SEAL_PCRS") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let index: u32 = part
            .parse()
            .map_err(|_| hw(format!("AVON_TPM_SEAL_PCRS: {part} is not a PCR index")))?;
        slot(index)?;
        out.push(index);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// The policy digest a `TPM2_PolicyPCR` over `slots` produces, computed in a
/// trial session so it can be baked into the sealed object's `authPolicy`.
fn pcr_policy_digest(ctx: &mut Context, slots: &[PcrSlot]) -> Result<TpmDigest, KeyError> {
    let sel = selection(slots)?;
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(hw)?
        .ok_or_else(|| hw("the TPM returned no trial session"))?;
    let policy = PolicySession::try_from(session).map_err(hw)?;
    let result = (|| -> Result<TpmDigest, KeyError> {
        ctx.policy_pcr(policy, TpmDigest::default(), sel)
            .map_err(hw)?;
        ctx.policy_get_digest(policy).map_err(hw)
    })();
    let _ = ctx.flush_context(SessionHandle::from(session).into());
    result
}

// ---------------------------------------------------------------------------
// Key material encoding
// ---------------------------------------------------------------------------

/// SPKI DER for a TPM ECC public key, by way of the uncompressed SEC1 point.
fn spki_of(public: &Public) -> Result<Vec<u8>, KeyError> {
    let Public::Ecc { unique, .. } = public else {
        return Err(hw("expected an ECC key"));
    };
    let (x, y) = (unique.x().value(), unique.y().value());
    if x.len() > 32 || y.len() > 32 {
        return Err(hw("ECC point coordinates are wider than P-256"));
    }
    let mut sec1 = vec![0u8; 65];
    sec1[0] = 0x04;
    sec1[1 + (32 - x.len())..33].copy_from_slice(x);
    sec1[33 + (32 - y.len())..65].copy_from_slice(y);
    let key = p256::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|e| hw(format!("TPM ECC point is not a P-256 point: {e}")))?;
    Ok(key
        .to_public_key_der()
        .map_err(|e| hw(e.to_string()))?
        .as_bytes()
        .to_vec())
}

/// DER-encode a TPM ECDSA signature so the rest of the system can treat it like
/// any other P-256 signature.
fn signature_der(sig: &TpmSignature) -> Result<Vec<u8>, KeyError> {
    let TpmSignature::EcDsa(ecc) = sig else {
        return Err(hw("expected an ECDSA signature"));
    };
    let pad = |v: &[u8]| -> Result<[u8; 32], KeyError> {
        if v.len() > 32 {
            return Err(hw("ECDSA scalar is wider than P-256"));
        }
        let mut out = [0u8; 32];
        out[32 - v.len()..].copy_from_slice(v);
        Ok(out)
    };
    let r = pad(ecc.signature_r().value())?;
    let s = pad(ecc.signature_s().value())?;
    let sig = p256::ecdsa::Signature::from_scalars(r, s)
        .map_err(|e| hw(format!("TPM returned a non-canonical signature: {e}")))?;
    Ok(sig.to_der().as_bytes().to_vec())
}

/// `TPM2_Sign` wants a ticket proving the digest came from the TPM. An
/// unrestricted key does not require one, and this is the null ticket that says
/// so — the caller-supplied digest is exactly what we mean to sign.
fn null_hashcheck() -> Result<HashcheckTicket, KeyError> {
    HashcheckTicket::try_from(tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
        tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
        hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
        digest: Default::default(),
    })
    .map_err(hw)
}

fn encode_material(signing: &HybridSigningKeyPair, kem: &HybridKemKeyPair) -> Zeroizing<Vec<u8>> {
    let mut material = Zeroizing::new(Vec::new());
    let s = signing.to_secret_bytes();
    let k = kem.to_secret_bytes();
    material.extend_from_slice(&(s.len() as u32).to_be_bytes());
    material.extend_from_slice(&s);
    material.extend_from_slice(&(k.len() as u32).to_be_bytes());
    material.extend_from_slice(&k);
    material
}

fn decode_material(material: &[u8]) -> Result<(HybridSigningKeyPair, HybridKemKeyPair), KeyError> {
    let mut pos = 0usize;
    let take = |n_at: &mut usize| -> Result<Vec<u8>, KeyError> {
        if *n_at + 4 > material.len() {
            return Err(KeyError::Corrupt("sealed material"));
        }
        let n = u32::from_be_bytes(
            material[*n_at..*n_at + 4]
                .try_into()
                .map_err(|_| KeyError::Corrupt("sealed material"))?,
        ) as usize;
        *n_at += 4;
        if *n_at + n > material.len() {
            return Err(KeyError::Corrupt("sealed material"));
        }
        let out = material[*n_at..*n_at + n].to_vec();
        *n_at += n;
        Ok(out)
    };
    let signing = HybridSigningKeyPair::from_secret_bytes(&take(&mut pos)?)?;
    let kem = HybridKemKeyPair::from_secret_bytes(&take(&mut pos)?)?;
    Ok((signing, kem))
}

fn aead(key: &[u8]) -> Result<avon_crypto::aead::AeadKey, KeyError> {
    Ok(avon_crypto::aead::AeadKey::new(
        avon_crypto::aead::Suite::Aes256Gcm,
        key.try_into()
            .map_err(|_| KeyError::Corrupt("wrapping key"))?,
    ))
}

// ---------------------------------------------------------------------------
// TPM session plumbing
// ---------------------------------------------------------------------------

/// Open a context, regenerate the primary, run `f`, then flush the primary.
/// Transient object slots are scarce on real TPMs, so nothing is left loaded.
fn with_primary<T>(
    f: impl FnOnce(&mut Context, KeyHandle) -> Result<T, KeyError>,
) -> Result<T, KeyError> {
    let template = primary_template()?;
    let mut ctx = context()?;
    let primary = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map_err(hw)?
        .key_handle;
    let out = f(&mut ctx, primary);
    let _ = ctx.flush_context(primary.into());
    out
}

/// Load children under a freshly regenerated primary, flush the primary, and
/// only then hand the handles to `f`.
///
/// A TPM guarantees just three transient object slots and sessions compete for
/// the same memory, so holding the parent while working with two children is
/// enough to exhaust a real one — `TPM2_Certify` needs both the certified key
/// and the signing key loaded at once. A loaded child does not need its parent,
/// so the parent goes first.
fn with_children<T>(
    objects: &[(&[u8], &[u8])],
    f: impl FnOnce(&mut Context, &[KeyHandle]) -> Result<T, KeyError>,
) -> Result<T, KeyError> {
    let template = primary_template()?;
    let mut ctx = context()?;
    let primary = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map_err(hw)?
        .key_handle;

    let mut handles: Vec<KeyHandle> = Vec::with_capacity(objects.len());
    let mut loaded = Ok(());
    for (public, private) in objects {
        match load_child(&mut ctx, primary, public, private) {
            Ok(h) => handles.push(h),
            Err(e) => {
                loaded = Err(e);
                break;
            }
        }
    }
    let _ = ctx.flush_context(primary.into());

    let out = match loaded {
        Ok(()) => f(&mut ctx, &handles),
        Err(e) => Err(e),
    };
    for h in handles {
        let _ = ctx.flush_context(h.into());
    }
    out
}

/// `TPM2_Create` a child of the primary. The template and any sensitive data
/// are built by the caller: an `execute_with_*_session` closure has to fail with
/// `tss_esapi::Error`, so nothing fallible of ours belongs inside it.
fn create_child(
    ctx: &mut Context,
    parent: KeyHandle,
    public: Public,
    sensitive: Option<SensitiveData>,
) -> Result<tss_esapi::structures::CreateKeyResult, KeyError> {
    ctx.execute_with_nullauth_session(|ctx| ctx.create(parent, public, None, sensitive, None, None))
        .map_err(hw)
}

fn load_child(
    ctx: &mut Context,
    parent: KeyHandle,
    public: &[u8],
    private: &[u8],
) -> Result<KeyHandle, KeyError> {
    let public = Public::unmarshall(public).map_err(|_| KeyError::Corrupt("tpm object public"))?;
    let private =
        Private::try_from(private.to_vec()).map_err(|_| KeyError::Corrupt("tpm object private"))?;
    ctx.execute_with_nullauth_session(|ctx| ctx.load(parent, private, public))
        .map_err(hw)
}

impl Tpm2KeyProvider {
    pub fn available() -> bool {
        match tcti() {
            Ok(conf) => Context::new(conf).is_ok(),
            Err(_) => false,
        }
    }

    pub fn create(dir: &Path) -> Result<Self, KeyError> {
        if dir.join(SEALED_FILE).exists() || dir.join(PUBLIC_FILE).exists() {
            return Err(KeyError::Exists);
        }
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let seal_pcrs = configured_seal_pcrs()?;
        let signing = HybridSigningKeyPair::generate()?;
        let kem = HybridKemKeyPair::generate()?;
        let material = encode_material(&signing, &kem);

        let mut wrap = Zeroizing::new(vec![0u8; WRAP_KEY_BYTES]);
        rand::thread_rng().fill_bytes(&mut wrap);
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut ct = material.to_vec();
        aead(&wrap)?
            .seal_in_place(&nonce, WRAP_AAD, &mut ct)
            .map_err(|_| hw("could not wrap the PQ material"))?;

        let (sealed, hw_spki, ak_spki) = with_primary(|ctx, primary| {
            let binding = create_child(ctx, primary, signing_template(false)?, None)?;
            let ak = create_child(ctx, primary, signing_template(true)?, None)?;

            let policy = if seal_pcrs.is_empty() {
                None
            } else {
                let slots = seal_pcrs
                    .iter()
                    .copied()
                    .map(slot)
                    .collect::<Result<Vec<_>, _>>()?;
                Some(pcr_policy_digest(ctx, &slots)?)
            };
            let sensitive = SensitiveData::try_from(wrap.to_vec())
                .map_err(|e| hw(format!("wrapping key: {e}")))?;
            let seal = create_child(ctx, primary, seal_template(policy)?, Some(sensitive))?;

            let hw_spki = spki_of(&binding.out_public)?;
            let ak_spki = spki_of(&ak.out_public)?;
            Ok((
                SealedBlob {
                    seal_public: seal.out_public.marshall().map_err(hw)?,
                    seal_private: seal.out_private.value().to_vec(),
                    seal_pcrs: seal_pcrs.clone(),
                    nonce: nonce.to_vec(),
                    ct,
                    binding_public: binding.out_public.marshall().map_err(hw)?,
                    binding_private: binding.out_private.value().to_vec(),
                    ak_public: ak.out_public.marshall().map_err(hw)?,
                    ak_private: ak.out_private.value().to_vec(),
                },
                hw_spki,
                ak_spki,
            ))
        })?;

        let tls = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| KeyError::Tls(e.to_string()))?;
        let me = Self {
            dir: dir.to_path_buf(),
            signing,
            kem,
            tls_key_pem: tls.serialize_pem(),
            hw_spki,
            ak_spki,
            sealed,
        };
        me.persist()?;
        Ok(me)
    }

    pub fn open(dir: &Path) -> Result<Self, KeyError> {
        let public: PublicMaterial = serde_json::from_slice(
            &std::fs::read(dir.join(PUBLIC_FILE)).map_err(|_| KeyError::Corrupt(PUBLIC_FILE))?,
        )
        .map_err(|_| KeyError::Corrupt(PUBLIC_FILE))?;
        let sealed: SealedBlob = serde_json::from_slice(
            &std::fs::read(dir.join(SEALED_FILE)).map_err(|_| KeyError::Corrupt(SEALED_FILE))?,
        )
        .map_err(|_| KeyError::Corrupt(SEALED_FILE))?;

        let wrap = with_primary(|ctx, primary| Self::unseal_wrapping_key(ctx, primary, &sealed))?;
        let nonce: [u8; 12] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::Corrupt("sealed nonce"))?;
        let mut buf = sealed.ct.clone();
        aead(&wrap)?
            .open_in_place(&nonce, WRAP_AAD, &mut buf)
            .map_err(|_| KeyError::Corrupt("unwrap failed — a different TPM, or tampered state"))?;
        let material = Zeroizing::new(buf);
        let (signing, kem) = decode_material(&material)?;

        if signing.verifying_key().to_bytes() != public.signing_pk
            || kem.public_key().to_bytes() != public.kem_pk
        {
            return Err(KeyError::Corrupt(
                "sealed material does not match the recorded public keys",
            ));
        }

        let tls_key_pem = String::from_utf8(
            std::fs::read(dir.join(TLS_FILE)).map_err(|_| KeyError::Corrupt(TLS_FILE))?,
        )
        .map_err(|_| KeyError::Corrupt(TLS_FILE))?;

        Ok(Self {
            dir: dir.to_path_buf(),
            signing,
            kem,
            tls_key_pem,
            hw_spki: public.hw_spki,
            ak_spki: public.ak_spki,
            sealed,
        })
    }

    /// `TPM2_Load` then `TPM2_Unseal`. The two commands authorise different
    /// objects: `load` needs the *parent's* auth (the primary, a password/HMAC
    /// session), `unseal` needs the *sealed object's* — which is the PCR policy
    /// when one was baked in, and only then does the PCR binding bite.
    fn unseal_wrapping_key(
        ctx: &mut Context,
        primary: KeyHandle,
        sealed: &SealedBlob,
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let handle = load_child(ctx, primary, &sealed.seal_public, &sealed.seal_private)?;
        let result = (|| -> Result<Zeroizing<Vec<u8>>, KeyError> {
            if sealed.seal_pcrs.is_empty() {
                let data = ctx
                    .execute_with_session(Some(AuthSession::Password), |ctx| {
                        ctx.unseal(handle.into())
                    })
                    .map_err(hw)?;
                return Ok(Zeroizing::new(data.to_vec()));
            }
            let slots = sealed
                .seal_pcrs
                .iter()
                .copied()
                .map(slot)
                .collect::<Result<Vec<_>, _>>()?;
            let session = ctx
                .start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Policy,
                    SymmetricDefinition::AES_128_CFB,
                    HashingAlgorithm::Sha256,
                )
                .map_err(hw)?
                .ok_or_else(|| hw("the TPM returned no policy session"))?;
            let policy = PolicySession::try_from(session).map_err(hw)?;
            let out = (|| -> Result<Zeroizing<Vec<u8>>, KeyError> {
                ctx.policy_pcr(policy, TpmDigest::default(), selection(&slots)?)
                    .map_err(hw)?;
                let data = ctx
                    .execute_with_session(Some(session), |ctx| ctx.unseal(handle.into()))
                    .map_err(|e| {
                        hw(format!(
                            "unseal refused — PCRs no longer match the policy: {e}"
                        ))
                    })?;
                Ok(Zeroizing::new(data.to_vec()))
            })();
            let _ = ctx.flush_context(SessionHandle::from(session).into());
            out
        })();
        let _ = ctx.flush_context(handle.into());
        result
    }

    /// `TPM2_Certify` of the binding key, signed by the attestation key: the
    /// TPM's own statement that the binding key lives inside it, tied to the
    /// same AK the control plane pins for quotes.
    pub fn certify(&self, qualifying: &[u8]) -> Result<Vec<u8>, KeyError> {
        with_children(
            &[
                (&self.sealed.binding_public, &self.sealed.binding_private),
                (&self.sealed.ak_public, &self.sealed.ak_private),
            ],
            |ctx, handles| {
                let [binding, ak] = handles else {
                    return Err(hw("expected the binding key and the AK"));
                };
                let (binding, ak) = (*binding, *ak);
                let data = Data::try_from(qualifying.to_vec())
                    .map_err(|e| hw(format!("qualifying data: {e}")))?;
                // TPM2_Certify authorises two objects — the one being certified
                // and the one signing — so it needs two sessions, not one.
                let (attest, _signature) = ctx
                    .execute_with_sessions(
                        (
                            Some(AuthSession::Password),
                            Some(AuthSession::Password),
                            None,
                        ),
                        |ctx| ctx.certify(binding.into(), ak, data, SignatureScheme::Null),
                    )
                    .map_err(hw)?;
                attest.marshall().map_err(hw)
            },
        )
    }

    /// SHA-256 over the marshalled endorsement-key template this TPM would
    /// produce. The EK is the TPM's manufacturer-rooted identity, so this is a
    /// stable per-machine value the fingerprint can mix in.
    pub fn ek_sha256(&self) -> Result<[u8; 32], KeyError> {
        let mut ctx = context()?;
        let ek = ek::create_ek_object_2(
            &mut ctx,
            AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
            None,
        )
        .map_err(hw)?;
        let public = ctx
            .execute_without_session(|ctx| ctx.read_public(ek))
            .map_err(hw)?
            .0;
        let _ = ctx.flush_context(ek.into());
        Ok(Sha256::digest(public.marshall().map_err(hw)?).into())
    }

    /// The attestation key's SPKI DER — what the control plane pins.
    pub fn attestation_key_spki(&self) -> &[u8] {
        &self.ak_spki
    }
}

impl KeyProvider for Tpm2KeyProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Tpm2
    }

    fn signing_public(&self) -> HybridVerifyingKey {
        self.signing.verifying_key()
    }

    fn kem_public(&self) -> HybridKemPublicKey {
        self.kem.public_key()
    }

    fn sign(&self, domain: Domain, msg: &[u8]) -> Result<HybridSignature, KeyError> {
        Ok(self.signing.sign(domain, msg)?)
    }

    fn decapsulate(&self, ct: &HybridKemCiphertext) -> Result<HybridSharedSecret, KeyError> {
        Ok(self.kem.decapsulate(ct)?)
    }

    fn tls_key_pem(&self) -> &str {
        &self.tls_key_pem
    }

    fn rotate_tls_key(&mut self) -> Result<String, KeyError> {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| KeyError::Tls(e.to_string()))?;
        self.tls_key_pem = kp.serialize_pem();
        self.persist()?;
        Ok(self.tls_key_pem.clone())
    }

    /// `TPM2_Quote` over PCRs 0 and 7 with the challenge nonce as `extraData`.
    ///
    /// The `TPMS_ATTEST` bytes are returned exactly as the TPM marshalled them,
    /// because that is what the signature covers: re-encoding them would mean
    /// the verifier checked a structure the TPM never signed.
    fn attestation_quote(&self, nonce: &[u8]) -> Result<Option<crate::provider::Quote>, KeyError> {
        let quote = with_children(
            &[(&self.sealed.ak_public, &self.sealed.ak_private)],
            |ctx, handles| {
                let [ak] = handles else {
                    return Err(hw("expected the attestation key"));
                };
                let ak = *ak;
                let sel = selection(&QUOTE_PCRS)?;
                let qualifying =
                    Data::try_from(nonce.to_vec()).map_err(|e| hw(format!("nonce: {e}")))?;
                let (attest, signature) = ctx
                    .execute_with_nullauth_session(|ctx| {
                        ctx.quote(ak, qualifying, SignatureScheme::Null, sel.clone())
                    })
                    .map_err(hw)?;

                // The values the verifier recomputes the digest from. Read after
                // the quote so a PCR extended in between shows up as a mismatch
                // rather than as a quote we quietly mis-describe.
                let data = pcr_abstraction::read_all(ctx, sel).map_err(hw)?;
                let bank = data
                    .pcr_bank(HashingAlgorithm::Sha256)
                    .ok_or_else(|| hw("the TPM has no SHA-256 PCR bank"))?;
                let mut pcrs = Vec::new();
                for s in QUOTE_PCRS {
                    let digest = bank
                        .get_digest(s)
                        .ok_or_else(|| hw(format!("PCR {} was not returned", slot_index(s))))?;
                    pcrs.push((slot_index(s), digest.to_vec()));
                }

                Ok(crate::provider::Quote {
                    attest: attest.marshall().map_err(hw)?,
                    signature: signature_der(&signature)?,
                    ak_public: self.ak_spki.clone(),
                    pcrs,
                })
            },
        )?;
        Ok(Some(quote))
    }

    fn hardware_binding(&self, device_hint: &[u8]) -> Result<Option<HardwareBinding>, KeyError> {
        let msg = binding_message(
            &self.signing.verifying_key(),
            &self.kem.public_key(),
            device_hint,
        );
        let digest: [u8; 32] = Sha256::digest(&msg).into();
        let signature = with_children(
            &[(&self.sealed.binding_public, &self.sealed.binding_private)],
            |ctx, handles| {
                let [binding] = handles else {
                    return Err(hw("expected the binding key"));
                };
                let binding = *binding;
                let d =
                    TpmDigest::try_from(digest.to_vec()).map_err(|e| hw(format!("digest: {e}")))?;
                let ticket = null_hashcheck()?;
                let sig = ctx
                    .execute_with_nullauth_session(|ctx| {
                        ctx.sign(
                            binding,
                            d,
                            SignatureScheme::EcDsa {
                                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                            },
                            ticket,
                        )
                    })
                    .map_err(hw)?;
                signature_der(&sig)
            },
        )?;
        let attestation = match self.certify(&digest) {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!(error = %e, "TPM2_Certify failed; the binding goes out without it");
                None
            }
        };
        Ok(Some(HardwareBinding {
            provider: ProviderKind::Tpm2,
            algorithm: "ecdsa-p256-sha256".into(),
            public_key: self.hw_spki.clone(),
            signature,
            attestation,
        }))
    }

    fn persist(&self) -> Result<(), KeyError> {
        write_private(&self.dir.join(TLS_FILE), self.tls_key_pem.as_bytes())?;
        write_private(
            &self.dir.join(SEALED_FILE),
            &serde_json::to_vec(&self.sealed).map_err(|_| KeyError::Corrupt(SEALED_FILE))?,
        )?;
        write_private(
            &self.dir.join(PUBLIC_FILE),
            &serde_json::to_vec(&PublicMaterial {
                signing_pk: self.signing.verifying_key().to_bytes(),
                kem_pk: self.kem.public_key().to_bytes(),
                hw_spki: self.hw_spki.clone(),
                ak_spki: self.ak_spki.clone(),
            })
            .map_err(|_| KeyError::Corrupt(PUBLIC_FILE))?,
        )?;
        // The primary is not stored: it is regenerated from a fixed template on
        // every open, and only this TPM's seed can regenerate it. The file
        // records that, so the directory is self-describing.
        write_private(
            &self.dir.join(PRIMARY_FILE),
            b"owner-hierarchy primary, ECC P-256, regenerated from a fixed template\n",
        )?;
        write_provider_record(&self.dir, ProviderKind::Tpm2)?;
        Ok(())
    }
}
