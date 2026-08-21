#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = avon_crypto::hybrid::kem::HybridKemPublicKey::from_bytes(data);
    let _ = avon_crypto::hybrid::kem::HybridKemCiphertext::from_bytes(data);
});
