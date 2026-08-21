//! AVON certificate format (spec §5.2): a deterministic, length-prefixed TBS
//! structure signed with the composite signature in domain `Cert`.

mod encode;
mod verify;

pub use encode::{Certificate, SubjectKind, TbsCertificate};
pub use verify::{ChainVerifier, VerifiedCertificate};

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("certificate encoding error: {0}")]
    Encoding(String),
    #[error("certificate signature invalid")]
    Signature,
    #[error("certificate expired")]
    Expired,
    #[error("certificate not yet valid")]
    NotYetValid,
    #[error("certificate issuer unknown")]
    UnknownIssuer,
    #[error("wrong certificate kind: expected {expected}, found {found:?}")]
    WrongKind {
        expected: &'static str,
        found: SubjectKind,
    },
    #[error("chain error: {0}")]
    Chain(String),
}
