use std::sync::Arc;

use avon_common::ids::SessionId;
use dashmap::DashMap;

use crate::session::Session;
use crate::TunnelError;

/// Sessions keyed by receiver index (the only thing a data packet carries in
/// the clear) and by session id.
#[derive(Default)]
pub struct SessionTable {
    by_index: DashMap<u32, Arc<Session>>,
    by_id: DashMap<SessionId, Arc<Session>>,
}

impl SessionTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Random, nonzero, unused receiver index. RNG failure is an error, never
    /// a predictable fallback.
    pub fn allocate_index(&self) -> Result<u32, TunnelError> {
        loop {
            let idx = u32::from_be_bytes(avon_crypto::random::random_bytes_fixed::<4>()?);
            if idx != 0 && !self.by_index.contains_key(&idx) {
                return Ok(idx);
            }
        }
    }

    pub fn insert(&self, s: Arc<Session>) {
        for idx in s.indexes() {
            self.by_index.insert(idx, s.clone());
        }
        self.by_id.insert(s.id(), s);
    }

    pub fn rebind_index(&self, s: &Arc<Session>, new_idx: u32) {
        self.by_index.insert(new_idx, s.clone());
    }

    pub fn release_index(&self, idx: u32) {
        self.by_index.remove(&idx);
    }

    pub fn by_index(&self, idx: u32) -> Option<Arc<Session>> {
        self.by_index.get(&idx).map(|s| s.clone())
    }

    pub fn by_id(&self, id: &SessionId) -> Option<Arc<Session>> {
        self.by_id.get(id).map(|s| s.clone())
    }

    pub fn remove(&self, id: &SessionId) -> Option<Arc<Session>> {
        let s = self.by_id.remove(id).map(|(_, s)| s)?;
        for idx in s.indexes() {
            self.by_index.remove(&idx);
        }
        s.close();
        Some(s)
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn iter(&self) -> Vec<Arc<Session>> {
        self.by_id.iter().map(|e| e.value().clone()).collect()
    }
}
