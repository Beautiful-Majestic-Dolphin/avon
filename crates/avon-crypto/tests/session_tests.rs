#![allow(clippy::unwrap_used, clippy::expect_used)]

use avon_crypto::aead::Suite;
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::session::{nonce_for, Role, SessionCipher, SessionKeys, Transcript};
use avon_crypto::CryptoError;

fn transcript(
    suite: Suite,
) -> (
    Transcript,
    avon_crypto::hybrid::kem::HybridSharedSecret,
    avon_crypto::hybrid::kem::HybridSharedSecret,
) {
    let eph = HybridKemKeyPair::generate().unwrap();
    let stat = HybridKemKeyPair::generate().unwrap();
    let (ct_e, ss_e) = eph.public_key().encapsulate().unwrap();
    let (ct_s, ss_s) = stat.public_key().encapsulate().unwrap();
    let t = Transcript {
        session_id: [9u8; 16],
        initiator_cert_id: [1u8; 32],
        responder_cert_id: [2u8; 32],
        eph_kem_pk: eph.public_key().to_bytes(),
        ct_e: ct_e.to_bytes(),
        ct_s: ct_s.to_bytes(),
        suite,
    };
    (t, ss_e, ss_s)
}

#[test]
fn both_sides_derive_identical_keys_and_can_talk() {
    for suite in [Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
        let (t, ss_e, ss_s) = transcript(suite);
        let ki = SessionKeys::derive(&t, &ss_e, &ss_s).unwrap();
        let kr = SessionKeys::derive(&t, &ss_e, &ss_s).unwrap();
        assert_eq!(ki.k_i2r, kr.k_i2r);
        assert_ne!(ki.k_i2r, ki.k_r2i);

        let init = SessionCipher::new(&ki, Role::Initiator, suite);
        let mut resp = SessionCipher::new(&kr, Role::Responder, suite);
        let mut buf = b"hello".to_vec();
        let counter = init.seal(b"hdr", &mut buf).unwrap();
        assert_eq!(counter, 0);
        resp.open(counter, b"hdr", &mut buf).unwrap();
        assert_eq!(buf, b"hello");
    }
}

#[test]
fn replayed_packet_is_rejected() {
    let (t, ss_e, ss_s) = transcript(Suite::Aes256Gcm);
    let k = SessionKeys::derive(&t, &ss_e, &ss_s).unwrap();
    let init = SessionCipher::new(&k, Role::Initiator, Suite::Aes256Gcm);
    let mut resp = SessionCipher::new(&k, Role::Responder, Suite::Aes256Gcm);
    let mut buf = b"x".to_vec();
    let c = init.seal(b"", &mut buf).unwrap();
    let copy = buf.clone();
    resp.open(c, b"", &mut buf).unwrap();
    let mut again = copy;
    assert!(matches!(
        resp.open(c, b"", &mut again),
        Err(CryptoError::Replay(_))
    ));
}

#[test]
fn transcript_change_changes_keys() {
    let (t, ss_e, ss_s) = transcript(Suite::Aes256Gcm);
    let a = SessionKeys::derive(&t, &ss_e, &ss_s).unwrap();
    let mut t2 = t;
    t2.session_id[0] ^= 1;
    let b = SessionKeys::derive(&t2, &ss_e, &ss_s).unwrap();
    assert_ne!(a.k_i2r, b.k_i2r);
}

#[test]
fn rekey_advances_epoch_and_changes_keys() {
    let (t, ss_e, ss_s) = transcript(Suite::Aes256Gcm);
    let k0 = SessionKeys::derive(&t, &ss_e, &ss_s).unwrap();
    let (_, ss_new) = HybridKemKeyPair::generate()
        .unwrap()
        .public_key()
        .encapsulate()
        .unwrap();
    let k1 = k0.rekey(&ss_new).unwrap();
    assert_eq!(k1.epoch, 1);
    assert_ne!(k0.k_i2r, k1.k_i2r);
    assert_ne!(k0.rekey_secret, k1.rekey_secret);
}

#[test]
fn nonce_layout() {
    assert_eq!(
        nonce_for(0x0102030405060708),
        [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn directions_do_not_cross() {
    let (t, ss_e, ss_s) = transcript(Suite::ChaCha20Poly1305);
    let k = SessionKeys::derive(&t, &ss_e, &ss_s).unwrap();
    let init = SessionCipher::new(&k, Role::Initiator, Suite::ChaCha20Poly1305);
    let mut init_rx = SessionCipher::new(&k, Role::Initiator, Suite::ChaCha20Poly1305);
    let mut buf = b"x".to_vec();
    let c = init.seal(b"", &mut buf).unwrap();
    assert!(
        init_rx.open(c, b"", &mut buf).is_err(),
        "initiator must not decrypt its own direction"
    );
}
