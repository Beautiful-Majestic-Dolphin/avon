//! Device pulse streams. Heartbeat handling lands in task 2.11; the registry
//! of open downstreams already exists so other modules can address a device.

use std::sync::Arc;

use avon_common::ids::DeviceId;
use avon_protocol::v2::PulseDown;
use dashmap::DashMap;
use tokio::sync::mpsc;

#[derive(Default, Clone)]
pub struct DeviceStreams(Arc<DashMap<DeviceId, mpsc::Sender<PulseDown>>>);

impl DeviceStreams {
    pub fn insert(&self, device: DeviceId, tx: mpsc::Sender<PulseDown>) {
        self.0.insert(device, tx);
    }
    pub fn remove(&self, device: DeviceId) {
        self.0.remove(&device);
    }
    pub fn is_connected(&self, device: DeviceId) -> bool {
        self.0.contains_key(&device)
    }
    pub fn send(&self, device: DeviceId, msg: PulseDown) -> bool {
        match self.0.get(&device) {
            Some(tx) => tx.try_send(msg).is_ok(),
            None => false,
        }
    }
}
