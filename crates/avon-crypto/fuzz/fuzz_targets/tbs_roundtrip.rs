#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(tbs) = avon_crypto::cert::TbsCertificate::decode(data) {
        assert_eq!(tbs.encode(), data, "encoding must be canonical");
    }
});
