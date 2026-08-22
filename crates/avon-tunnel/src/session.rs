use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use avon_common::ids::SessionId;
use avon_crypto::aead::Suite;
pub use avon_crypto::session::Role;
use avon_crypto::session::{SessionCipher, SessionKeys};
use avon_crypto::CryptoError;
use parking_lot::{Mutex, RwLock};

use crate::header::{Header, FLAG_EPOCH_OVERLAP, TYPE_DATA};
use crate::inner::Inner;
use crate::TunnelError;

#[derive(Default)]
pub struct SessionStats {
    pub bytes_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub packets_tx: AtomicU64,
    pub packets_rx: AtomicU64,
    pub replays_dropped: AtomicU64,
}

pub struct Epoch {
    pub local_index: u32,
    pub remote_index: u32,
    pub cipher: SessionCipher,
    pub keys: SessionKeys,
    pub started: Instant,
}

struct Epochs {
    current: Epoch,
    previous: Option<(Epoch, Instant)>,
}

/// One tunnel session. Keys arrive from the control channel; this type only
/// seals, opens and rotates. Both epochs stay addressable during a rekey so
/// packets already in flight are not dropped.
pub struct Session {
    id: SessionId,
    role: Role,
    suite: Suite,
    peer_cert_id: [u8; 32],
    epochs: Mutex<Epochs>,
    /// How many epochs this session has been through, seeded from the initial
    /// key schedule. In the real rekey path this always equals the current
    /// `SessionKeys::epoch`; tracking it here keeps it right regardless of how
    /// the caller derived the new keys.
    epoch: AtomicU32,
    peer_endpoint: RwLock<Option<SocketAddr>>,
    last_rx_ms: AtomicU64,
    last_tx_ms: AtomicU64,
    closed: AtomicBool,
    /// Set when a rekey has been signalled and not yet completed, so the timer
    /// loop asks once rather than every tick.
    rekey_pending: AtomicBool,
    stats: SessionStats,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: SessionId,
        role: Role,
        suite: Suite,
        peer_cert_id: [u8; 32],
        keys: SessionKeys,
        local_index: u32,
        remote_index: u32,
        peer_endpoint: Option<SocketAddr>,
    ) -> Arc<Self> {
        let cipher = SessionCipher::new(&keys, role, suite);
        let initial_epoch = keys.epoch;
        Arc::new(Self {
            id,
            role,
            suite,
            peer_cert_id,
            epoch: AtomicU32::new(initial_epoch),
            epochs: Mutex::new(Epochs {
                current: Epoch {
                    local_index,
                    remote_index,
                    cipher,
                    keys,
                    started: Instant::now(),
                },
                previous: None,
            }),
            peer_endpoint: RwLock::new(peer_endpoint),
            last_rx_ms: AtomicU64::new(now_ms()),
            last_tx_ms: AtomicU64::new(now_ms()),
            closed: AtomicBool::new(false),
            rekey_pending: AtomicBool::new(false),
            stats: SessionStats::default(),
        })
    }

    pub fn id(&self) -> SessionId {
        self.id
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn suite(&self) -> Suite {
        self.suite
    }
    pub fn peer_cert_id(&self) -> [u8; 32] {
        self.peer_cert_id
    }
    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }
    pub fn local_index(&self) -> u32 {
        self.epochs.lock().current.local_index
    }
    pub fn remote_index(&self) -> u32 {
        self.epochs.lock().current.remote_index
    }
    pub fn epoch(&self) -> u32 {
        self.epoch.load(Ordering::Relaxed)
    }
    pub fn epoch_age(&self) -> Duration {
        self.epochs.lock().current.started.elapsed()
    }
    pub fn packets_sent_this_epoch(&self) -> u64 {
        self.epochs.lock().current.cipher.packets_sent()
    }
    pub fn current_rekey_secret(&self) -> [u8; 32] {
        self.epochs.lock().current.keys.rekey_secret
    }
    /// Every local index this session can still be addressed by.
    pub fn indexes(&self) -> Vec<u32> {
        let e = self.epochs.lock();
        let mut v = vec![e.current.local_index];
        if let Some((p, _)) = &e.previous {
            v.push(p.local_index);
        }
        v
    }
    pub fn peer_endpoint(&self) -> Option<SocketAddr> {
        *self.peer_endpoint.read()
    }
    pub fn set_peer_endpoint(&self, addr: SocketAddr) {
        *self.peer_endpoint.write() = Some(addr);
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
    pub fn rekey_pending(&self) -> bool {
        self.rekey_pending.load(Ordering::SeqCst)
    }
    pub fn set_rekey_pending(&self, pending: bool) {
        self.rekey_pending.store(pending, Ordering::SeqCst);
    }
    pub fn idle_for(&self) -> Duration {
        Duration::from_millis(now_ms().saturating_sub(self.last_rx_ms.load(Ordering::Relaxed)))
    }
    pub fn since_last_tx(&self) -> Duration {
        Duration::from_millis(now_ms().saturating_sub(self.last_tx_ms.load(Ordering::Relaxed)))
    }

    /// Encrypt `inner` into a complete datagram in `out`.
    pub fn seal(&self, inner: &Inner<'_>, out: &mut Vec<u8>) -> Result<(), TunnelError> {
        if self.is_closed() {
            return Err(TunnelError::Closed);
        }
        let epochs = self.epochs.lock();
        let flags = if epochs.previous.is_some() {
            FLAG_EPOCH_OVERLAP
        } else {
            0
        };
        let receiver_index = epochs.current.remote_index;

        let mut body = Vec::new();
        inner.encode_into(&mut body);
        // The header is the AAD and carries the counter, so it is built from
        // the counter the cipher allocates.
        let counter = epochs.current.cipher.seal_with(
            |counter| {
                Header {
                    kind: TYPE_DATA,
                    flags,
                    receiver_index,
                    counter,
                }
                .encode()
            },
            &mut body,
        )?;
        drop(epochs);

        out.clear();
        out.extend_from_slice(
            &Header {
                kind: TYPE_DATA,
                flags,
                receiver_index,
                counter,
            }
            .encode(),
        );
        out.extend_from_slice(&body);

        self.stats.packets_tx.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_tx
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        self.last_tx_ms.store(now_ms(), Ordering::Relaxed);
        Ok(())
    }

    /// Decrypt a body whose header named one of our indexes.
    pub fn open<'b>(
        &self,
        header: &Header,
        body: &[u8],
        scratch: &'b mut Vec<u8>,
    ) -> Result<Inner<'b>, TunnelError> {
        if self.is_closed() {
            return Err(TunnelError::Closed);
        }
        let hdr = header.encode();
        scratch.clear();
        scratch.extend_from_slice(body);
        let result = {
            let mut epochs = self.epochs.lock();
            if epochs.current.local_index == header.receiver_index {
                epochs.current.cipher.open(header.counter, &hdr, scratch)
            } else if let Some((prev, _)) = epochs
                .previous
                .as_mut()
                .filter(|(p, _)| p.local_index == header.receiver_index)
            {
                prev.cipher.open(header.counter, &hdr, scratch)
            } else {
                return Err(TunnelError::UnknownIndex(header.receiver_index));
            }
        };
        match result {
            Ok(()) => {
                self.stats.packets_rx.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_rx
                    .fetch_add(body.len() as u64, Ordering::Relaxed);
                self.last_rx_ms.store(now_ms(), Ordering::Relaxed);
                Inner::decode(scratch)
            }
            Err(CryptoError::Replay(_)) => {
                self.stats.replays_dropped.fetch_add(1, Ordering::Relaxed);
                metrics::counter!("avon_tunnel_replays_dropped_total").increment(1);
                Err(TunnelError::Replay)
            }
            Err(e) => Err(TunnelError::Crypto(e)),
        }
    }

    /// Install a new epoch, keeping the old one addressable for the overlap.
    pub fn rotate(&self, new_keys: SessionKeys, new_local_index: u32, new_remote_index: u32) {
        let mut epochs = self.epochs.lock();
        let cipher = SessionCipher::new(&new_keys, self.role, self.suite);
        let new_epoch = Epoch {
            local_index: new_local_index,
            remote_index: new_remote_index,
            cipher,
            keys: new_keys,
            started: Instant::now(),
        };
        let old = std::mem::replace(&mut epochs.current, new_epoch);
        epochs.previous = Some((old, Instant::now()));
        self.epoch.fetch_add(1, Ordering::Relaxed);
        self.rekey_pending.store(false, Ordering::SeqCst);
        metrics::counter!("avon_tunnel_rekeys_total").increment(1);
    }

    /// Drop the previous epoch once `overlap` has passed. Returns the index the
    /// caller should release from its table.
    pub fn expire_previous_epoch(&self, overlap: Duration) -> Option<u32> {
        let mut epochs = self.epochs.lock();
        match &epochs.previous {
            Some((p, since)) if since.elapsed() >= overlap => {
                let idx = p.local_index;
                epochs.previous = None;
                Some(idx)
            }
            _ => None,
        }
    }
}

impl std::fmt::Debug for Session {
    /// Deliberately does not touch the epoch mutex: this is called from event
    /// formatting that may run while another task holds it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("suite", &self.suite)
            .field("epoch", &self.epoch())
            .field("closed", &self.is_closed())
            .finish()
    }
}
