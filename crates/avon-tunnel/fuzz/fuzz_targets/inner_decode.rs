#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(inner) = avon_tunnel::Inner::decode(data) {
        let mut out = Vec::new();
        inner.encode_into(&mut out);
        assert_eq!(out, data);
    }
});
