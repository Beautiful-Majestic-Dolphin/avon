use std::sync::Arc;

use avon_common::ids::{DeviceId, SessionId};
use parking_lot::RwLock;
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct Status {
    pub state: String,
    pub device_id: String,
    pub overlay_v4: Option<String>,
    pub overlay_v6: Option<String>,
    pub session_id: Option<String>,
    pub epoch: Option<u32>,
    pub gateway: Option<String>,
    pub last_pulse_unix: Option<i64>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub cert_not_after: i64,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            state: "enrolled".into(),
            device_id: String::new(),
            overlay_v4: None,
            overlay_v6: None,
            session_id: None,
            epoch: None,
            gateway: None,
            last_pulse_unix: None,
            bytes_tx: 0,
            bytes_rx: 0,
            cert_not_after: 0,
        }
    }
}

#[derive(Clone)]
pub struct StatusHandle(Arc<RwLock<Status>>);

impl StatusHandle {
    pub fn new(device_id: DeviceId, cert_not_after: i64) -> Self {
        Self(Arc::new(RwLock::new(Status {
            device_id: device_id.to_string(),
            cert_not_after,
            ..Default::default()
        })))
    }

    pub fn snapshot(&self) -> Status {
        self.0.read().clone()
    }

    pub fn set_state(&self, state: &str) {
        self.0.write().state = state.to_string();
    }

    pub fn set_connected(
        &self,
        overlay_v4: Option<String>,
        overlay_v6: Option<String>,
        session: Option<SessionId>,
        epoch: Option<u32>,
        gateway: Option<String>,
    ) {
        let mut s = self.0.write();
        s.state = "connected".into();
        s.overlay_v4 = overlay_v4;
        s.overlay_v6 = overlay_v6;
        s.session_id = session.map(|id| hex::encode(id.as_bytes()));
        s.epoch = epoch;
        s.gateway = gateway;
    }

    pub fn set_degraded(&self) {
        self.0.write().state = "degraded".into();
    }

    pub fn set_last_pulse(&self, unix: i64) {
        self.0.write().last_pulse_unix = Some(unix);
    }

    pub fn set_bytes(&self, tx: u64, rx: u64) {
        let mut s = self.0.write();
        s.bytes_tx = tx;
        s.bytes_rx = rx;
    }

    pub fn set_epoch(&self, epoch: u32) {
        self.0.write().epoch = Some(epoch);
    }

    pub fn clear_session(&self) {
        let mut s = self.0.write();
        s.session_id = None;
        s.epoch = None;
        s.gateway = None;
        if s.state == "connected" {
            s.state = "degraded".into();
        }
    }
}
