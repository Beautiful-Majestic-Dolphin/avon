use std::sync::Arc;

use avon_common::ids::{DeviceId, SessionId};
use parking_lot::RwLock;
use serde::Serialize;

#[derive(Serialize, serde::Deserialize, Clone, Debug)]
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
    /// Which key provider holds this device's identity — the operator's first
    /// question when a device will not attest.
    pub key_provider: String,
    /// What the agent last did about attestation. The authoritative state lives
    /// in the control plane; this is what the device knows about it.
    pub attestation_state: String,
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
            key_provider: "unknown".into(),
            attestation_state: "none".into(),
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

    pub fn set_key_provider(&self, provider: &str) {
        self.0.write().key_provider = provider.to_string();
    }

    pub fn set_attestation_state(&self, state: &str) {
        self.0.write().attestation_state = state.to_string();
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

/// Serve status snapshots over a Unix socket at `<data_dir>/status.sock`.
/// Each connection receives a single JSON object and is then closed. On
/// Windows this is a named pipe stub returning an error.
#[cfg(unix)]
pub async fn serve_status(
    handle: StatusHandle,
    data_dir: std::path::PathBuf,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;

    let sock = data_dir.join("status.sock");
    // Remove stale socket.
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    // Restrict to owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600));
    }
    loop {
        let (mut stream, _) = listener.accept().await?;
        let snap = handle.snapshot();
        let data = serde_json::to_vec(&snap).unwrap_or_else(|_| b"{}".to_vec());
        let mut out = data;
        out.push(b'\n');
        let _ = stream.write_all(&out).await;
    }
}

#[cfg(not(unix))]
pub async fn serve_status(
    _handle: StatusHandle,
    _data_dir: std::path::PathBuf,
) -> std::io::Result<()> {
    // Windows: named pipe stub.
    std::future::pending::<()>().await;
    Ok(())
}

/// Fetch status from the local socket. Used by `avon-agent status`.
#[cfg(unix)]
pub async fn fetch_status(data_dir: &std::path::Path) -> std::io::Result<Status> {
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;

    let sock = data_dir.join("status.sock");
    let mut stream = UnixStream::connect(&sock).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(not(unix))]
pub async fn fetch_status(_data_dir: &std::path::Path) -> std::io::Result<Status> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "status socket not supported on this platform",
    ))
}
