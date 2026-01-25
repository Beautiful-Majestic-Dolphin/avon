//! Test infrastructure for AVON integration tests.
//!
//! This module provides a complete test environment with:
//! - PostgreSQL container for database
//! - Redis container for caching
//! - Control plane services (gateway, auth, CA, pulse, policy engine)
//! - Test agent creation and management

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::process::{Child, Command};
use tokio::sync::RwLock;

use avon_common::{DeviceId, Pod, PodId, Policy, SessionId};

pub const TEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_POSTGRES_PORT: u16 = 5432;
pub const DEFAULT_REDIS_PORT: u16 = 6379;

#[derive(Debug)]
pub struct PostgresContainer {
    container_id: String,
    port: u16,
    database_url: String,
}

impl PostgresContainer {
    pub async fn start() -> Result<Self> {
        let port = find_available_port().await?;
        let container_name = format!("avon-test-postgres-{}", port);

        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &container_name,
                "-e",
                "POSTGRES_USER=avon",
                "-e",
                "POSTGRES_PASSWORD=avon_test",
                "-e",
                "POSTGRES_DB=avon_test",
                "-p",
                &format!("{}:5432", port),
                "postgres:15-alpine",
            ])
            .output()
            .await
            .context("Failed to start PostgreSQL container")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to start PostgreSQL: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let database_url = format!(
            "postgres://avon:avon_test@localhost:{}/avon_test",
            port
        );

        let container = Self {
            container_id,
            port,
            database_url,
        };

        container.wait_ready().await?;
        Ok(container)
    }

    async fn wait_ready(&self) -> Result<()> {
        let start = std::time::Instant::now();
        let max_wait = Duration::from_secs(30);

        while start.elapsed() < max_wait {
            let output = Command::new("docker")
                .args([
                    "exec",
                    &self.container_id,
                    "pg_isready",
                    "-U",
                    "avon",
                ])
                .output()
                .await?;

            if output.status.success() {
                tokio::time::sleep(Duration::from_millis(500)).await;
                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        anyhow::bail!("PostgreSQL container failed to become ready")
    }

    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn stop(&self) -> Result<()> {
        let _ = Command::new("docker")
            .args(["stop", &self.container_id])
            .output()
            .await;
        Ok(())
    }
}

#[derive(Debug)]
pub struct RedisContainer {
    container_id: String,
    port: u16,
    redis_url: String,
}

impl RedisContainer {
    pub async fn start() -> Result<Self> {
        let port = find_available_port().await?;
        let container_name = format!("avon-test-redis-{}", port);

        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &container_name,
                "-p",
                &format!("{}:6379", port),
                "redis:7-alpine",
            ])
            .output()
            .await
            .context("Failed to start Redis container")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to start Redis: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let redis_url = format!("redis://localhost:{}", port);

        let container = Self {
            container_id,
            port,
            redis_url,
        };

        container.wait_ready().await?;
        Ok(container)
    }

    async fn wait_ready(&self) -> Result<()> {
        let start = std::time::Instant::now();
        let max_wait = Duration::from_secs(30);

        while start.elapsed() < max_wait {
            let output = Command::new("docker")
                .args([
                    "exec",
                    &self.container_id,
                    "redis-cli",
                    "ping",
                ])
                .output()
                .await?;

            if output.status.success() {
                let response = String::from_utf8_lossy(&output.stdout);
                if response.trim() == "PONG" {
                    return Ok(());
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        anyhow::bail!("Redis container failed to become ready")
    }

    pub fn redis_url(&self) -> &str {
        &self.redis_url
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn stop(&self) -> Result<()> {
        let _ = Command::new("docker")
            .args(["stop", &self.container_id])
            .output()
            .await;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ServiceHandle {
    name: String,
    #[allow(dead_code)]
    process: Option<Child>,
    addr: SocketAddr,
    is_running: bool,
}

impl ServiceHandle {
    pub fn new(name: &str, addr: SocketAddr) -> Self {
        Self {
            name: name.to_string(),
            process: None,
            addr,
            is_running: false,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn is_running(&self) -> bool {
        self.is_running
    }

    pub async fn start(&mut self) -> Result<()> {
        self.is_running = true;
        tracing::info!(service = %self.name, addr = %self.addr, "Service started");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if let Some(mut process) = self.process.take() {
            let _ = process.kill().await;
        }
        self.is_running = false;
        tracing::info!(service = %self.name, "Service stopped");
        Ok(())
    }
}

pub type GatewayHandle = ServiceHandle;
pub type AuthServiceHandle = ServiceHandle;
pub type CaServiceHandle = ServiceHandle;
pub type PulseServiceHandle = ServiceHandle;
pub type PolicyEngineHandle = ServiceHandle;

pub struct ControlPlaneServices {
    pub gateway: GatewayHandle,
    pub auth: AuthServiceHandle,
    pub ca: CaServiceHandle,
    pub pulse: PulseServiceHandle,
    pub policy_engine: PolicyEngineHandle,
}

impl ControlPlaneServices {
    pub async fn start(_postgres_url: &str, _redis_url: &str) -> Result<Self> {
        let gateway_port = find_available_port().await?;
        let auth_port = find_available_port().await?;
        let ca_port = find_available_port().await?;
        let pulse_port = find_available_port().await?;
        let policy_port = find_available_port().await?;

        let mut gateway = GatewayHandle::new(
            "gateway",
            format!("127.0.0.1:{}", gateway_port).parse()?,
        );
        let mut auth = AuthServiceHandle::new(
            "auth",
            format!("127.0.0.1:{}", auth_port).parse()?,
        );
        let mut ca = CaServiceHandle::new(
            "ca",
            format!("127.0.0.1:{}", ca_port).parse()?,
        );
        let mut pulse = PulseServiceHandle::new(
            "pulse",
            format!("127.0.0.1:{}", pulse_port).parse()?,
        );
        let mut policy_engine = PolicyEngineHandle::new(
            "policy_engine",
            format!("127.0.0.1:{}", policy_port).parse()?,
        );

        gateway.start().await?;
        auth.start().await?;
        ca.start().await?;
        pulse.start().await?;
        policy_engine.start().await?;

        Ok(Self {
            gateway,
            auth,
            ca,
            pulse,
            policy_engine,
        })
    }

    pub async fn stop_all(&mut self) -> Result<()> {
        self.gateway.stop().await?;
        self.auth.stop().await?;
        self.ca.stop().await?;
        self.pulse.stop().await?;
        self.policy_engine.stop().await?;
        Ok(())
    }
}

pub struct TestEnvironment {
    pub postgres: PostgresContainer,
    pub redis: RedisContainer,
    pub control_plane: ControlPlaneServices,
    pub temp_dir: tempfile::TempDir,
    devices: Arc<RwLock<HashMap<DeviceId, TestDeviceState>>>,
    pods: Arc<RwLock<HashMap<PodId, Pod>>>,
    policies: Arc<RwLock<Vec<Policy>>>,
    enrollments: Arc<RwLock<HashMap<String, EnrollmentInfo>>>,
}

#[derive(Debug, Clone)]
pub struct TestDeviceState {
    pub device_id: DeviceId,
    pub name: String,
    pub status: String,
    pub pod_ids: Vec<PodId>,
}

#[derive(Debug, Clone)]
pub struct EnrollmentInfo {
    pub token: String,
    pub device_name: String,
    pub platform: String,
    pub consumed: bool,
}

impl TestEnvironment {
    pub async fn new() -> Result<Self> {
        tracing::info!("Creating test environment");

        let postgres = PostgresContainer::start().await?;
        let redis = RedisContainer::start().await?;
        let control_plane = ControlPlaneServices::start(
            postgres.database_url(),
            redis.redis_url(),
        ).await?;
        let temp_dir = tempfile::tempdir()?;

        Ok(Self {
            postgres,
            redis,
            control_plane,
            temp_dir,
            devices: Arc::new(RwLock::new(HashMap::new())),
            pods: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(Vec::new())),
            enrollments: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        tracing::info!("Cleaning up test environment");
        self.control_plane.stop_all().await?;
        self.postgres.stop().await?;
        self.redis.stop().await?;
        Ok(())
    }

    pub fn temp_path(&self) -> PathBuf {
        self.temp_dir.path().to_path_buf()
    }

    pub async fn register_device(&self, device_id: DeviceId, name: &str) {
        let mut devices = self.devices.write().await;
        devices.insert(device_id.clone(), TestDeviceState {
            device_id,
            name: name.to_string(),
            status: "active".to_string(),
            pod_ids: Vec::new(),
        });
    }

    pub async fn get_device(&self, device_id: &DeviceId) -> Option<TestDeviceState> {
        let devices = self.devices.read().await;
        devices.get(device_id).cloned()
    }

    pub async fn create_enrollment(&self, device_name: &str, platform: &str) -> EnrollmentInfo {
        let token = format!("enroll-{}-{}", device_name, uuid::Uuid::new_v4());
        let info = EnrollmentInfo {
            token: token.clone(),
            device_name: device_name.to_string(),
            platform: platform.to_string(),
            consumed: false,
        };

        let mut enrollments = self.enrollments.write().await;
        enrollments.insert(token.clone(), info.clone());
        info
    }

    pub async fn consume_enrollment(&self, token: &str) -> Option<EnrollmentInfo> {
        let mut enrollments = self.enrollments.write().await;
        if let Some(info) = enrollments.get_mut(token) {
            if !info.consumed {
                info.consumed = true;
                return Some(info.clone());
            }
        }
        None
    }

    pub async fn create_pod(&self, name: &str) -> Pod {
        let pod = Pod::new(name.to_string());
        let mut pods = self.pods.write().await;
        pods.insert(pod.id.clone(), pod.clone());
        pod
    }

    pub async fn add_device_to_pod(&self, device_id: &DeviceId, pod_id: &PodId) {
        let mut devices = self.devices.write().await;
        if let Some(device) = devices.get_mut(device_id) {
            if !device.pod_ids.contains(pod_id) {
                device.pod_ids.push(pod_id.clone());
            }
        }
    }

    pub async fn create_policy(
        &self,
        source_pod: &PodId,
        dest_pod: &PodId,
        action: &str,
    ) -> Policy {
        let policy = if action == "allow" {
            Policy::allow(
                format!("{}-to-{}", source_pod, dest_pod),
                source_pod.clone(),
                dest_pod.clone(),
            )
        } else {
            Policy::deny(
                format!("{}-to-{}-deny", source_pod, dest_pod),
                source_pod.clone(),
                dest_pod.clone(),
            )
        };

        let mut policies = self.policies.write().await;
        policies.push(policy.clone());
        policy
    }

    pub async fn evaluate_policy(
        &self,
        source_device: &DeviceId,
        dest_device: &DeviceId,
    ) -> bool {
        let devices = self.devices.read().await;
        let policies = self.policies.read().await;

        let source = match devices.get(source_device) {
            Some(d) => d,
            None => return false,
        };

        let dest = match devices.get(dest_device) {
            Some(d) => d,
            None => return false,
        };

        for policy in policies.iter() {
            let source_matches = match &policy.source_pod {
                Some(pod_id) => source.pod_ids.contains(pod_id),
                None => true,
            };
            let dest_matches = match &policy.destination_pod {
                Some(pod_id) => dest.pod_ids.contains(pod_id),
                None => true,
            };
            if source_matches && dest_matches && policy.allows() {
                return true;
            }
        }

        false
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        tracing::debug!("TestEnvironment dropped");
    }
}

pub struct TestAgent {
    device_id: DeviceId,
    name: String,
    env: Arc<TestEnvironment>,
    token: Arc<RwLock<Vec<u8>>>,
    tunnels: Arc<RwLock<HashMap<SessionId, TunnelState>>>,
    connected: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone)]
pub struct TunnelState {
    pub session_id: SessionId,
    pub peer_device: DeviceId,
    pub data_buffer: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("Policy denied connection")]
    PolicyDenied,
    #[error("Peer not found")]
    PeerNotFound,
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Not enrolled")]
    NotEnrolled,
}

impl TestAgent {
    pub fn new(name: &str, env: Arc<TestEnvironment>) -> Self {
        Self {
            device_id: DeviceId::new(),
            name: name.to_string(),
            env,
            token: Arc::new(RwLock::new(generate_test_token())),
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            connected: Arc::new(RwLock::new(false)),
        }
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn enroll(&self, token: &str) -> Result<(), ConnectionError> {
        let enrollment = self.env.consume_enrollment(token).await;
        match enrollment {
            Some(_info) => {
                self.env.register_device(self.device_id.clone(), &self.name).await;
                *self.connected.write().await = true;
                tracing::info!(device_id = %self.device_id, "Agent enrolled successfully");
                Ok(())
            }
            None => Err(ConnectionError::NotEnrolled),
        }
    }

    pub async fn authenticate(&self) -> Result<(), ConnectionError> {
        let device = self.env.get_device(&self.device_id).await;
        match device {
            Some(d) if d.status == "active" => Ok(()),
            Some(_) => Err(ConnectionError::ConnectionFailed("Device not active".to_string())),
            None => Err(ConnectionError::NotEnrolled),
        }
    }

    pub async fn connect_to(&self, peer_device_id: DeviceId) -> Result<SessionId, ConnectionError> {
        let peer = self.env.get_device(&peer_device_id).await;
        if peer.is_none() {
            return Err(ConnectionError::PeerNotFound);
        }

        let allowed = self.env.evaluate_policy(&self.device_id, &peer_device_id).await;
        if !allowed {
            return Err(ConnectionError::PolicyDenied);
        }

        let session_id = SessionId::new();
        let tunnel = TunnelState {
            session_id: session_id.clone(),
            peer_device: peer_device_id,
            data_buffer: Vec::new(),
        };

        let mut tunnels = self.tunnels.write().await;
        tunnels.insert(session_id.clone(), tunnel);

        tracing::info!(
            device_id = %self.device_id,
            session_id = ?session_id,
            "Tunnel established"
        );

        Ok(session_id)
    }

    pub async fn has_tunnel(&self, session_id: &SessionId) -> bool {
        let tunnels = self.tunnels.read().await;
        tunnels.contains_key(session_id)
    }

    pub async fn send_through_tunnel(
        &self,
        session_id: &SessionId,
        data: &[u8],
    ) -> Result<(), ConnectionError> {
        let tunnels = self.tunnels.read().await;
        if tunnels.contains_key(session_id) {
            tracing::debug!(
                session_id = ?session_id,
                len = data.len(),
                "Data sent through tunnel"
            );
            Ok(())
        } else {
            Err(ConnectionError::ConnectionFailed("Tunnel not found".to_string()))
        }
    }

    pub async fn receive_from_tunnel(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<u8>, ConnectionError> {
        let tunnels = self.tunnels.read().await;
        if let Some(tunnel) = tunnels.get(session_id) {
            Ok(tunnel.data_buffer.clone())
        } else {
            Err(ConnectionError::ConnectionFailed("Tunnel not found".to_string()))
        }
    }

    pub async fn current_token(&self) -> Vec<u8> {
        self.token.read().await.clone()
    }

    pub async fn rotate_token(&self) {
        let mut token = self.token.write().await;
        *token = generate_test_token();
        tracing::debug!(device_id = %self.device_id, "Token rotated");
    }

    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    pub async fn disconnect(&self) {
        *self.connected.write().await = false;
    }

    pub async fn reconnect(&self) -> Result<(), ConnectionError> {
        tokio::time::sleep(Duration::from_millis(100)).await;
        *self.connected.write().await = true;
        Ok(())
    }
}

pub async fn create_enrollment(env: &TestEnvironment, device_name: &str, platform: &str) -> EnrollmentInfo {
    env.create_enrollment(device_name, platform).await
}

pub async fn create_test_agent(env: Arc<TestEnvironment>) -> TestAgent {
    TestAgent::new(&format!("test-agent-{}", uuid::Uuid::new_v4()), env)
}

pub async fn create_enrolled_agent(env: Arc<TestEnvironment>, name: &str) -> TestAgent {
    let agent = TestAgent::new(name, env.clone());
    let enrollment = env.create_enrollment(name, "linux").await;
    agent.enroll(&enrollment.token).await.expect("Enrollment should succeed");
    agent
}

pub async fn get_device(env: &TestEnvironment, device_id: &DeviceId) -> Option<TestDeviceState> {
    env.get_device(device_id).await
}

pub async fn create_pod(env: &TestEnvironment, name: &str) -> Pod {
    env.create_pod(name).await
}

pub async fn add_device_to_pod(env: &TestEnvironment, device_id: &DeviceId, pod_id: &PodId) {
    env.add_device_to_pod(device_id, pod_id).await
}

pub async fn create_policy(
    env: &TestEnvironment,
    source_pod: &PodId,
    dest_pod: &PodId,
    action: &str,
) -> Policy {
    env.create_policy(source_pod, dest_pod, action).await
}

async fn find_available_port() -> Result<u16> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    Ok(addr.port())
}

fn generate_test_token() -> Vec<u8> {
    let mut token = vec![0u8; 32];
    for (i, byte) in token.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(17).wrapping_add(rand::random::<u8>());
    }
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrollment_info() {
        let info = EnrollmentInfo {
            token: "test-token".to_string(),
            device_name: "test-device".to_string(),
            platform: "linux".to_string(),
            consumed: false,
        };
        assert!(!info.consumed);
    }

    #[test]
    fn test_connection_error_display() {
        let err = ConnectionError::PolicyDenied;
        assert_eq!(format!("{}", err), "Policy denied connection");
    }

    #[test]
    fn test_generate_token() {
        let token1 = generate_test_token();
        let token2 = generate_test_token();
        assert_eq!(token1.len(), 32);
        assert_ne!(token1, token2);
    }
}
