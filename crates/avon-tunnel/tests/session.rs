#![allow(clippy::unwrap_used)]
use std::time::Duration;

use avon_common::ids::SessionId;
use avon_crypto::aead::Suite;
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::session::{Role, SessionKeys, Transcript};
use avon_tunnel::{Header, Inner, Session, SessionTable, TunnelError};

fn keys() -> (SessionKeys, SessionKeys) {
    let eph = HybridKemKeyPair::generate().unwrap();
    let stat = HybridKemKeyPair::generate().unwrap();
    let (ct_e, ss_e) = eph.public_key().encapsulate().unwrap();
    let (ct_s, ss_s) = stat.public_key().encapsulate().unwrap();
    let t = Transcript {
        session_id: [1; 16],
        initiator_cert_id: [2; 32],
        responder_cert_id: [3; 32],
        eph_kem_pk: eph.public_key().to_bytes(),
        ct_e: ct_e.to_bytes(),
        ct_s: ct_s.to_bytes(),
        suite: Suite::ChaCha20Poly1305,
    };
    (
        SessionKeys::derive(&t, &ss_e, &ss_s).unwrap(),
        SessionKeys::derive(&t, &ss_e, &ss_s).unwrap(),
    )
}

fn pair() -> (
    std::sync::Arc<Session>,
    std::sync::Arc<Session>,
    SessionTable,
    SessionTable,
) {
    let (ki, kr) = keys();
    let ti = SessionTable::new();
    let tr = SessionTable::new();
    let ii = ti.allocate_index().unwrap();
    let ri = tr.allocate_index().unwrap();
    let id = SessionId::from_slice(&[1; 16]).unwrap();
    let init = Session::new(
        id,
        Role::Initiator,
        Suite::ChaCha20Poly1305,
        [3; 32],
        ki,
        ii,
        ri,
        None,
    );
    let resp = Session::new(
        id,
        Role::Responder,
        Suite::ChaCha20Poly1305,
        [2; 32],
        kr,
        ri,
        ii,
        None,
    );
    ti.insert(init.clone());
    tr.insert(resp.clone());
    (init, resp, ti, tr)
}

#[test]
fn seal_open_through_tables_and_update_endpoint() {
    let (init, _resp, _ti, tr) = pair();
    let mut dgram = Vec::new();
    init.seal(&Inner::Ip(b"packet"), &mut dgram).unwrap();
    let (h, body) = Header::decode(&dgram).unwrap();
    assert_eq!(h.receiver_index, init.remote_index());
    let s = tr.by_index(h.receiver_index).unwrap();
    let mut scratch = Vec::new();
    assert_eq!(
        s.open(&h, body, &mut scratch).unwrap(),
        Inner::Ip(b"packet")
    );
    assert_eq!(
        s.stats()
            .packets_rx
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[test]
fn replay_is_counted_and_rejected() {
    let (init, resp, _ti, _tr) = pair();
    let mut dgram = Vec::new();
    init.seal(&Inner::Keepalive, &mut dgram).unwrap();
    let (h, body) = Header::decode(&dgram).unwrap();
    let mut scratch = Vec::new();
    resp.open(&h, body, &mut scratch).unwrap();
    assert!(matches!(
        resp.open(&h, body, &mut scratch),
        Err(TunnelError::Replay)
    ));
    assert_eq!(
        resp.stats()
            .replays_dropped
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[test]
fn unknown_index_is_dropped_before_crypto() {
    let (_init, _resp, _ti, tr) = pair();
    assert!(tr.by_index(0xdead_beef).is_none());
    assert_ne!(tr.allocate_index().unwrap(), 0);
}

#[test]
fn rotate_keeps_previous_epoch_for_overlap_then_expires_it() {
    let (init, resp, ti, tr) = pair();
    let (ki2, kr2) = keys();
    let new_ii = ti.allocate_index().unwrap();
    let new_ri = tr.allocate_index().unwrap();
    // Old-epoch packet sealed before rotation
    let mut old = Vec::new();
    init.seal(&Inner::Keepalive, &mut old).unwrap();

    init.rotate(ki2, new_ii, new_ri);
    resp.rotate(kr2, new_ri, new_ii);
    ti.rebind_index(&init, new_ii);
    tr.rebind_index(&resp, new_ri);
    assert_eq!(init.epoch(), 1);

    // Old packet still opens during overlap via the old index.
    let (h, body) = Header::decode(&old).unwrap();
    let s = tr.by_index(h.receiver_index).unwrap();
    let mut scratch = Vec::new();
    s.open(&h, body, &mut scratch).unwrap();

    // New packets use the new index.
    let mut new = Vec::new();
    init.seal(&Inner::Keepalive, &mut new).unwrap();
    let (h2, body2) = Header::decode(&new).unwrap();
    assert_eq!(h2.receiver_index, new_ri);
    tr.by_index(h2.receiver_index)
        .unwrap()
        .open(&h2, body2, &mut scratch)
        .unwrap();

    // After the overlap window the old index is gone.
    resp.expire_previous_epoch(Duration::ZERO);
    tr.release_index(h.receiver_index);
    assert!(tr.by_index(h.receiver_index).is_none());
    assert!(resp.open(&h, body, &mut scratch).is_err());
}

#[test]
fn closed_session_refuses_io() {
    let (init, _resp, _ti, _tr) = pair();
    init.close();
    let mut out = Vec::new();
    assert!(matches!(
        init.seal(&Inner::Keepalive, &mut out),
        Err(TunnelError::Closed)
    ));
}
