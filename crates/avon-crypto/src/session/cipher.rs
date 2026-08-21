use std::sync::Mutex;

use crate::aead::{AeadKey, Suite};
use crate::error::CryptoError;

use super::keys::SessionKeys;
use super::replay::{ReplayWindow, SendCounter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

pub fn nonce_for(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

/// One epoch of a session: a send key with counter and a receive key with a
/// replay window. `seal` takes `&self` (lock-free); `open` needs `&mut self`
/// for the window.
pub struct SessionCipher {
    send: AeadKey,
    recv: AeadKey,
    counter: SendCounter,
    window: Mutex<ReplayWindow>,
    epoch: u32,
}

impl SessionCipher {
    pub fn new(keys: &SessionKeys, role: Role, suite: Suite) -> Self {
        let (send_key, recv_key) = match role {
            Role::Initiator => (&keys.k_i2r, &keys.k_r2i),
            Role::Responder => (&keys.k_r2i, &keys.k_i2r),
        };
        Self {
            send: AeadKey::new(suite, send_key),
            recv: AeadKey::new(suite, recv_key),
            counter: SendCounter::new(),
            window: Mutex::new(ReplayWindow::new()),
            epoch: keys.epoch,
        }
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    pub fn packets_sent(&self) -> u64 {
        u64::MAX - 1 - self.counter.remaining()
    }

    pub fn seal(&self, aad: &[u8], plaintext: &mut Vec<u8>) -> Result<u64, CryptoError> {
        let counter = self
            .counter
            .next()
            .map_err(|_| CryptoError::CounterExhausted)?;
        self.send
            .seal_in_place(&nonce_for(counter), aad, plaintext)?;
        Ok(counter)
    }

    pub fn open(&mut self, counter: u64, aad: &[u8], buf: &mut Vec<u8>) -> Result<(), CryptoError> {
        // Decrypt first, then commit the counter: a forged packet must not be
        // able to poison the window.
        {
            let window = self
                .window
                .lock()
                .map_err(|_| CryptoError::AuthenticationFailed)?;
            if let Some(highest) = window.highest() {
                if highest >= counter && highest - counter >= ReplayWindow::SIZE {
                    return Err(CryptoError::Replay(super::replay::ReplayError::TooOld));
                }
            }
        }
        self.recv.open_in_place(&nonce_for(counter), aad, buf)?;
        let mut window = self
            .window
            .lock()
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        window
            .check_and_update(counter)
            .map_err(CryptoError::Replay)
    }
}
