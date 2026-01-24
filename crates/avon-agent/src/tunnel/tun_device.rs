//! TUN device management for AVON tunnels.
//!
//! Provides platform-specific TUN device creation and packet I/O.
//! Currently supports Linux, with stubs for macOS and Windows.

use std::net::IpAddr;

use anyhow::{Context, Result};

/// A TUN device for packet routing.
pub struct TunDevice {
    name: String,
    mtu: u32,
    #[cfg(target_os = "linux")]
    handle: linux::LinuxTunHandle,
    #[cfg(target_os = "macos")]
    handle: macos::MacOsTunHandle,
    #[cfg(target_os = "windows")]
    handle: windows::WindowsTunHandle,
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    handle: StubTunHandle,
}

impl TunDevice {
    /// Creates a new TUN device.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the TUN device (e.g., "avon0")
    /// * `address` - IP address to assign to the device
    /// * `netmask` - Netmask for the device
    /// * `mtu` - Maximum transmission unit
    pub async fn create(
        name: &str,
        address: IpAddr,
        netmask: IpAddr,
        mtu: u32,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        let handle = linux::LinuxTunHandle::create(name, address, netmask, mtu)
            .await
            .context("Failed to create Linux TUN device")?;

        #[cfg(target_os = "macos")]
        let handle = macos::MacOsTunHandle::create(name, address, netmask, mtu)
            .await
            .context("Failed to create macOS TUN device")?;

        #[cfg(target_os = "windows")]
        let handle = windows::WindowsTunHandle::create(name, address, netmask, mtu)
            .await
            .context("Failed to create Windows TUN device")?;

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let handle = StubTunHandle::create(name, address, netmask, mtu)
            .await
            .context("Failed to create stub TUN device")?;

        Ok(Self {
            name: name.to_string(),
            mtu,
            handle,
        })
    }

    /// Returns the device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the MTU.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Reads a packet from the TUN device.
    ///
    /// # Returns
    ///
    /// The raw IP packet read from the device.
    pub async fn read_packet(&self) -> Result<Vec<u8>> {
        self.handle.read_packet().await
    }

    /// Writes a packet to the TUN device.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw IP packet to write
    pub async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        self.handle.write_packet(packet).await
    }
}

/// Linux TUN device implementation.
#[cfg(target_os = "linux")]
mod linux {
    use std::net::IpAddr;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::process::Command;

    use anyhow::{Context, Result};
    use tokio::fs::OpenOptions;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    const TUN_PATH: &str = "/dev/net/tun";
    const IFF_TUN: i32 = 0x0001;
    const IFF_NO_PI: i32 = 0x1000;
    const TUNSETIFF: u64 = 0x400454ca;

    /// Linux TUN device handle.
    pub struct LinuxTunHandle {
        fd: RawFd,
        file: Mutex<tokio::fs::File>,
    }

    impl LinuxTunHandle {
        /// Creates a new Linux TUN device.
        pub async fn create(
            name: &str,
            address: IpAddr,
            netmask: IpAddr,
            mtu: u32,
        ) -> Result<Self> {
            // Open /dev/net/tun
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(TUN_PATH)
                .await
                .context("Failed to open /dev/net/tun")?;

            let fd = file.as_raw_fd();

            // Set up the TUN device using ioctl
            let mut ifr = [0u8; 40]; // struct ifreq
            let name_bytes = name.as_bytes();
            let name_len = std::cmp::min(name_bytes.len(), 15);
            ifr[..name_len].copy_from_slice(&name_bytes[..name_len]);

            // Set flags: IFF_TUN | IFF_NO_PI
            let flags = (IFF_TUN | IFF_NO_PI) as i16;
            ifr[16..18].copy_from_slice(&flags.to_ne_bytes());

            // SAFETY: We're calling ioctl with a valid fd and properly sized buffer
            let result = unsafe {
                libc::ioctl(fd, TUNSETIFF as libc::c_ulong, ifr.as_mut_ptr())
            };

            if result < 0 {
                anyhow::bail!("ioctl TUNSETIFF failed: {}", std::io::Error::last_os_error());
            }

            // Configure the interface using ip commands
            Self::configure_interface(name, address, netmask, mtu)?;

            Ok(Self { fd, file: Mutex::new(file) })
        }

        /// Configures the network interface.
        fn configure_interface(
            name: &str,
            address: IpAddr,
            netmask: IpAddr,
            mtu: u32,
        ) -> Result<()> {
            // Calculate prefix length from netmask
            let prefix_len = Self::netmask_to_prefix(netmask);

            // Set IP address
            let output = Command::new("ip")
                .args(["addr", "add", &format!("{}/{}", address, prefix_len), "dev", name])
                .output()
                .context("Failed to run ip addr add")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Ignore "already exists" errors
                if !stderr.contains("RTNETLINK answers: File exists") {
                    anyhow::bail!("ip addr add failed: {}", stderr);
                }
            }

            // Set MTU
            let output = Command::new("ip")
                .args(["link", "set", name, "mtu", &mtu.to_string()])
                .output()
                .context("Failed to run ip link set mtu")?;

            if !output.status.success() {
                anyhow::bail!("ip link set mtu failed: {}", String::from_utf8_lossy(&output.stderr));
            }

            // Bring interface up
            let output = Command::new("ip")
                .args(["link", "set", name, "up"])
                .output()
                .context("Failed to run ip link set up")?;

            if !output.status.success() {
                anyhow::bail!("ip link set up failed: {}", String::from_utf8_lossy(&output.stderr));
            }

            Ok(())
        }

        /// Converts a netmask to prefix length.
        pub fn netmask_to_prefix(netmask: IpAddr) -> u8 {
            match netmask {
                IpAddr::V4(addr) => {
                    let bits = u32::from(addr);
                    bits.count_ones() as u8
                }
                IpAddr::V6(addr) => {
                    let bits = u128::from(addr);
                    bits.count_ones() as u8
                }
            }
        }

        /// Reads a packet from the TUN device.
        pub async fn read_packet(&self) -> Result<Vec<u8>> {
            let mut buf = vec![0u8; 65536];
            
            let mut file = self.file.lock().await;
            let len = file
                .read(&mut buf)
                .await
                .context("Failed to read from TUN device")?;

            buf.truncate(len);
            Ok(buf)
        }

        /// Writes a packet to the TUN device.
        pub async fn write_packet(&self, packet: &[u8]) -> Result<()> {
            let mut file = self.file.lock().await;
            file.write_all(packet)
                .await
                .context("Failed to write to TUN device")?;

            Ok(())
        }
    }

    impl Drop for LinuxTunHandle {
        fn drop(&mut self) {
            // File will be closed automatically, which destroys the TUN device
            let _ = self.fd; // Suppress unused warning
        }
    }
}

/// macOS TUN device implementation (stub).
#[cfg(target_os = "macos")]
mod macos {
    use std::net::IpAddr;

    use anyhow::Result;

    /// macOS TUN device handle (stub implementation).
    pub struct MacOsTunHandle {
        _name: String,
    }

    impl MacOsTunHandle {
        /// Creates a new macOS TUN device.
        pub async fn create(
            name: &str,
            _address: IpAddr,
            _netmask: IpAddr,
            _mtu: u32,
        ) -> Result<Self> {
            // macOS uses utun devices which require different setup
            // This is a stub - full implementation would use utun
            tracing::warn!("macOS TUN support is not fully implemented");
            Ok(Self {
                _name: name.to_string(),
            })
        }

        /// Reads a packet from the TUN device.
        pub async fn read_packet(&self) -> Result<Vec<u8>> {
            anyhow::bail!("macOS TUN read not implemented")
        }

        /// Writes a packet to the TUN device.
        pub async fn write_packet(&self, _packet: &[u8]) -> Result<()> {
            anyhow::bail!("macOS TUN write not implemented")
        }
    }
}

/// Windows TUN device implementation (stub).
#[cfg(target_os = "windows")]
mod windows {
    use std::net::IpAddr;

    use anyhow::Result;

    /// Windows TUN device handle (stub implementation).
    pub struct WindowsTunHandle {
        _name: String,
    }

    impl WindowsTunHandle {
        /// Creates a new Windows TUN device.
        pub async fn create(
            name: &str,
            _address: IpAddr,
            _netmask: IpAddr,
            _mtu: u32,
        ) -> Result<Self> {
            // Windows requires WinTun driver
            // This is a stub - full implementation would use wintun crate
            tracing::warn!("Windows TUN support is not fully implemented");
            Ok(Self {
                _name: name.to_string(),
            })
        }

        /// Reads a packet from the TUN device.
        pub async fn read_packet(&self) -> Result<Vec<u8>> {
            anyhow::bail!("Windows TUN read not implemented")
        }

        /// Writes a packet to the TUN device.
        pub async fn write_packet(&self, _packet: &[u8]) -> Result<()> {
            anyhow::bail!("Windows TUN write not implemented")
        }
    }
}

/// Stub TUN device for unsupported platforms.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
struct StubTunHandle {
    _name: String,
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl StubTunHandle {
    async fn create(
        name: &str,
        _address: IpAddr,
        _netmask: IpAddr,
        _mtu: u32,
    ) -> Result<Self> {
        tracing::warn!("TUN device not supported on this platform");
        Ok(Self {
            _name: name.to_string(),
        })
    }

    async fn read_packet(&self) -> Result<Vec<u8>> {
        anyhow::bail!("TUN device not supported on this platform")
    }

    async fn write_packet(&self, _packet: &[u8]) -> Result<()> {
        anyhow::bail!("TUN device not supported on this platform")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_tun_device_name() {
        // Basic test - actual TUN device tests require root privileges
        let name = "avon0";
        assert_eq!(name.len(), 5);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_netmask_to_prefix() {
        use super::linux::LinuxTunHandle;
        use std::net::IpAddr;

        let netmask: IpAddr = "255.255.255.0".parse().unwrap();
        let prefix = LinuxTunHandle::netmask_to_prefix(netmask);
        assert_eq!(prefix, 24);

        let netmask: IpAddr = "255.255.0.0".parse().unwrap();
        let prefix = LinuxTunHandle::netmask_to_prefix(netmask);
        assert_eq!(prefix, 16);
    }
}
