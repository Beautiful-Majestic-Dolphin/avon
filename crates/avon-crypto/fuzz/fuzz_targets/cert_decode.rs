#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(cert) = avon_crypto::cert::Certificate::decode(data) {
        let again = avon_crypto::cert::Certificate::decode(&cert.encode()).expect("re-decode");
        assert_eq!(again, cert);
    }
});
