use super::encode::{Certificate, SubjectKind};
use super::CertError;

#[derive(Debug)]
pub struct VerifiedCertificate {
    pub cert: Certificate,
    /// Certificate ids from root to leaf.
    pub chain: Vec<[u8; 32]>,
}

pub struct ChainVerifier {
    roots: Vec<Certificate>,
}

impl ChainVerifier {
    pub fn new(roots: Vec<Certificate>) -> Result<Self, CertError> {
        for root in &roots {
            if root.tbs.kind != SubjectKind::RootCa {
                return Err(CertError::WrongKind {
                    expected: "RootCa",
                    found: root.tbs.kind,
                });
            }
            if root.tbs.issuer_key_id != root.tbs.signing_key.key_id() {
                return Err(CertError::Chain("root is not self-issued".into()));
            }
            root.verify_signature(&root.tbs.signing_key)?;
        }
        Ok(Self { roots })
    }

    fn check_validity(cert: &Certificate, now: i64) -> Result<(), CertError> {
        if now < cert.tbs.not_before {
            return Err(CertError::NotYetValid);
        }
        if now > cert.tbs.not_after {
            return Err(CertError::Expired);
        }
        Ok(())
    }

    /// Verify `leaf` (Device/Gateway/Service) through an IssuingCa to a root.
    pub fn verify(
        &self,
        leaf: &Certificate,
        intermediates: &[Certificate],
        now: i64,
    ) -> Result<VerifiedCertificate, CertError> {
        if !matches!(
            leaf.tbs.kind,
            SubjectKind::Device | SubjectKind::Gateway | SubjectKind::Service
        ) {
            return Err(CertError::WrongKind {
                expected: "Device|Gateway|Service",
                found: leaf.tbs.kind,
            });
        }
        Self::check_validity(leaf, now)?;

        let issuing = intermediates
            .iter()
            .find(|c| c.tbs.signing_key.key_id() == leaf.tbs.issuer_key_id)
            .ok_or(CertError::UnknownIssuer)?;
        if issuing.tbs.kind != SubjectKind::IssuingCa {
            return Err(CertError::WrongKind {
                expected: "IssuingCa",
                found: issuing.tbs.kind,
            });
        }
        Self::check_validity(issuing, now)?;
        leaf.verify_signature(&issuing.tbs.signing_key)?;

        let root = self
            .roots
            .iter()
            .find(|r| r.tbs.signing_key.key_id() == issuing.tbs.issuer_key_id)
            .ok_or(CertError::UnknownIssuer)?;
        Self::check_validity(root, now)?;
        issuing.verify_signature(&root.tbs.signing_key)?;

        Ok(VerifiedCertificate {
            cert: leaf.clone(),
            chain: vec![root.id(), issuing.id(), leaf.id()],
        })
    }
}
