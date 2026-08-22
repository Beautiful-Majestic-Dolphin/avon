#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok((header, body)) = avon_tunnel::Header::decode(data) {
        // A header that parsed must re-encode to the same 16 bytes, and the
        // body must be exactly what follows them.
        assert_eq!(&header.encode()[..], &data[..avon_tunnel::HEADER_LEN]);
        assert_eq!(body, &data[avon_tunnel::HEADER_LEN..]);
    }
});
