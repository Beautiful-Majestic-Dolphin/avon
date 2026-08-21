//! Compatibility shim for legacy HybridKeyExchange API.
//! New code should use `avon_crypto::hybrid::kem`.
pub use crate::hybrid::kem::HybridKemCiphertext as HybridEncapsulation;
pub use crate::hybrid::kem::HybridKemKeyPair as HybridKeyPair;
pub use crate::hybrid::kem::HybridKemPublicKey as HybridPublicKey;
pub use crate::hybrid::kem::HybridSharedSecret;
pub use crate::hybrid::kem::HYBRID_KEM_CIPHERTEXT_BYTES as HYBRID_ENCAPSULATION_BYTES;
pub use crate::hybrid::kem::HYBRID_KEM_PUBLIC_KEY_BYTES as HYBRID_PUBLIC_KEY_BYTES;

/// Legacy alias for encapsulate
pub fn hybrid_encapsulate(
    recipient_public: &HybridPublicKey,
) -> Result<(HybridEncapsulation, HybridSharedSecret), crate::error::CryptoError> {
    recipient_public.encapsulate()
}
