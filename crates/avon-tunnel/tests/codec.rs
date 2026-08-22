#![allow(clippy::unwrap_used)]
use avon_tunnel::{Header, Inner, TunnelError, HEADER_LEN, TYPE_DATA};
use proptest::prelude::*;

#[test]
fn header_layout_is_big_endian_and_16_bytes() {
    let h = Header {
        kind: TYPE_DATA,
        flags: 1,
        receiver_index: 0x01020304,
        counter: 0x0a0b0c0d0e0f1011,
    };
    let bytes = h.encode();
    assert_eq!(bytes.len(), HEADER_LEN);
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[1], 1);
    assert_eq!(&bytes[2..4], &[0, 0]);
    assert_eq!(&bytes[4..8], &[1, 2, 3, 4]);
    assert_eq!(
        &bytes[8..16],
        &[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11]
    );
    let (decoded, body) = Header::decode(&bytes).unwrap();
    assert_eq!(decoded, h);
    assert!(body.is_empty());
}

#[test]
fn header_rejects_short_and_wrong_type_and_nonzero_reserved() {
    assert!(matches!(
        Header::decode(&[0u8; 15]),
        Err(TunnelError::Short)
    ));
    let mut b = Header {
        kind: TYPE_DATA,
        flags: 0,
        receiver_index: 1,
        counter: 1,
    }
    .encode();
    b[0] = 0x02;
    assert!(matches!(Header::decode(&b), Err(TunnelError::BadType(2))));
    let mut b = Header {
        kind: TYPE_DATA,
        flags: 0,
        receiver_index: 1,
        counter: 1,
    }
    .encode();
    b[2] = 1;
    assert!(Header::decode(&b).is_err());
}

#[test]
fn inner_roundtrips() {
    let mut out = Vec::new();
    Inner::Ip(&[0x45, 0, 0, 20]).encode_into(&mut out);
    assert_eq!(out[0], Inner::IP);
    assert_eq!(Inner::decode(&out).unwrap(), Inner::Ip(&[0x45, 0, 0, 20]));
    let mut out = Vec::new();
    Inner::Keepalive.encode_into(&mut out);
    assert_eq!(out, vec![Inner::KEEPALIVE]);
    assert_eq!(Inner::decode(&out).unwrap(), Inner::Keepalive);
    assert!(matches!(Inner::decode(&[]), Err(TunnelError::Short)));
    assert!(matches!(Inner::decode(&[7]), Err(TunnelError::BadInner(7))));
}

proptest! {
    #[test]
    fn header_roundtrip(
        flags in 0u8..=1,
        idx in any::<u32>(),
        ctr in any::<u64>(),
        body in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let h = Header { kind: TYPE_DATA, flags, receiver_index: idx, counter: ctr };
        let mut bytes = h.encode().to_vec();
        bytes.extend_from_slice(&body);
        let (d, b) = Header::decode(&bytes).unwrap();
        prop_assert_eq!(d, h);
        prop_assert_eq!(b, &body[..]);
    }
}
