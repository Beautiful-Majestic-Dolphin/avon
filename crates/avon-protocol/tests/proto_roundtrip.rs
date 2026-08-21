#![allow(clippy::unwrap_used)]
use avon_protocol::v2::{auth_message, AuthMessage, AuthProof, SessionAnswer, Suite};
use prost::Message;

#[test]
fn auth_message_roundtrip() {
    let m = AuthMessage {
        msg: Some(auth_message::Msg::Proof(AuthProof {
            signature: vec![1, 2, 3],
        })),
    };
    let bytes = m.encode_to_vec();
    assert_eq!(AuthMessage::decode(bytes.as_slice()).unwrap(), m);
}

#[test]
fn suite_enum_values_match_crypto_ids() {
    assert_eq!(Suite::Aes256Gcm as i32, 1);
    assert_eq!(Suite::Chacha20Poly1305 as i32, 2);
    let a = SessionAnswer {
        suite: Suite::Aes256Gcm as i32,
        ..Default::default()
    };
    assert_eq!(a.suite(), Suite::Aes256Gcm);
}
