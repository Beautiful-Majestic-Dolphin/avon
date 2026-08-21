use rcgen::{
    CertificateSigningRequestParams, ExtendedKeyUsagePurpose, KeyUsagePurpose, SanType,
    SerialNumber,
};
use time::OffsetDateTime;

use super::PkiError;
use crate::keys::CaKeys;

/// Sign a PKCS#10 request with the TLS CA. The CA sets SANs, validity, serial
/// and usages itself; nothing from the request except the public key is used.
pub(crate) fn sign_tls_csr(
    keys: &CaKeys,
    csr_pem: &str,
    serial: &[u8; 16],
    sans: &[String],
    not_before: i64,
    not_after: i64,
) -> Result<(String, Vec<u8>), PkiError> {
    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|e| PkiError::X509(e.to_string()))?;
    let params = &mut csr.params;
    params.subject_alt_names.clear();
    for san in sans {
        if san.starts_with("spiffe://") {
            params.subject_alt_names.push(SanType::URI(
                san.as_str()
                    .try_into()
                    .map_err(|_| PkiError::X509("bad uri san".into()))?,
            ));
        } else {
            params.subject_alt_names.push(SanType::DnsName(
                san.as_str()
                    .try_into()
                    .map_err(|_| PkiError::X509("bad dns san".into()))?,
            ));
        }
    }
    params.serial_number = Some(SerialNumber::from_slice(serial));
    params.not_before = OffsetDateTime::from_unix_timestamp(not_before)
        .map_err(|e| PkiError::X509(e.to_string()))?;
    params.not_after = OffsetDateTime::from_unix_timestamp(not_after)
        .map_err(|e| PkiError::X509(e.to_string()))?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params.is_ca = rcgen::IsCa::NoCa;

    let ca_cert = rcgen::CertificateParams::from_ca_cert_der(&keys.tls_ca_cert_der.clone().into())
        .map_err(|e| PkiError::X509(e.to_string()))?
        .self_signed(&keys.tls_ca)
        .map_err(|e| PkiError::X509(e.to_string()))?;
    let cert = csr
        .signed_by(&ca_cert, &keys.tls_ca)
        .map_err(|e| PkiError::X509(e.to_string()))?;
    Ok((cert.pem(), cert.der().to_vec()))
}
