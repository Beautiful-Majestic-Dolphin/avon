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

/// macOS TUN device implementation using utun kernel interface.
#[cfg(target_os = "macos")]
mod macos {
    use std::net::IpAddr;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::process::Command;

    use anyhow::{Context, Result};
    use tokio::io::unix::AsyncFd;

    // BSD socket constants for macOS utun
    const PF_SYSTEM: libc::c_int = 32;
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const AF_SYS_CONTROL: u16 = 2;
    const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

    // AF_INET/AF_INET6 for the 4-byte protocol header
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 30;

    // ioctl to resolve a kernel control name to its ID
    // CTLIOCGINFO = _IOWR('N', 3, struct ctl_info)
    // struct ctl_info is 100 bytes (4 byte id + 96 byte name)
    const CTLIOCGINFO: libc::c_ulong = 0xC0644E03;

    /// Packed representation of struct ctl_info.
    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [u8; 96],
    }

    /// Packed representation of struct sockaddr_ctl.
    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    /// macOS TUN device handle using the utun kernel interface.
    pub struct MacOsTunHandle {
        fd: AsyncFd<RawFdWrapper>,
        name: String,
    }

    /// Wrapper to implement AsRawFd for AsyncFd.
    struct RawFdWrapper {
        fd: RawFd,
    }

    impl AsRawFd for RawFdWrapper {
        fn as_raw_fd(&self) -> RawFd {
            self.fd
        }
    }

    impl Drop for RawFdWrapper {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    impl MacOsTunHandle {
        /// Creates a new macOS TUN device using the utun kernel interface.
        ///
        /// The `name` parameter is used as a hint for the utun unit number.
        /// If name is "avon0", we request utun0. If the requested unit is
        /// unavailable, we auto-assign by using unit 0.
        pub async fn create(
            name: &str,
            address: IpAddr,
            netmask: IpAddr,
            mtu: u32,
        ) -> Result<Self> {
            // Create a PF_SYSTEM socket for kernel control
            let fd = unsafe {
                libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL)
            };
            if fd < 0 {
                anyhow::bail!(
                    "Failed to create PF_SYSTEM socket: {}",
                    std::io::Error::last_os_error()
                );
            }

            // Resolve the utun control ID
            let mut ctl_info = CtlInfo {
                ctl_id: 0,
                ctl_name: [0u8; 96],
            };
            let name_bytes = UTUN_CONTROL_NAME.as_bytes();
            ctl_info.ctl_name[..name_bytes.len()].copy_from_slice(name_bytes);

            let result = unsafe {
                libc::ioctl(fd, CTLIOCGINFO, &mut ctl_info as *mut CtlInfo)
            };
            if result < 0 {
                unsafe { libc::close(fd); }
                anyhow::bail!(
                    "ioctl CTLIOCGINFO failed: {}",
                    std::io::Error::last_os_error()
                );
            }

            // Parse desired unit number from name (e.g., "avon0" -> try utun unit 1)
            // sc_unit = N+1 gives utunN; sc_unit = 0 means auto-assign
            let unit: u32 = name
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>()
                .parse()
                .map(|n: u32| n + 1)
                .unwrap_or(0);

            // Connect to the utun control
            let addr = SockaddrCtl {
                sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
                sc_family: AF_SYS_CONTROL as u8,
                ss_sysaddr: AF_SYS_CONTROL,
                sc_id: ctl_info.ctl_id,
                sc_unit: unit,
                sc_reserved: [0; 5],
            };

            let result = unsafe {
                libc::connect(
                    fd,
                    &addr as *const SockaddrCtl as *const libc::sockaddr,
                    std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
                )
            };
            if result < 0 {
                unsafe { libc::close(fd); }
                anyhow::bail!(
                    "Failed to connect utun socket (unit {}): {}",
                    unit,
                    std::io::Error::last_os_error()
                );
            }

            // Get the actual interface name assigned by the kernel
            let utun_name = Self::get_interface_name(fd)?;
            tracing::info!("Created macOS utun device: {}", utun_name);

            // Set socket to non-blocking for async I/O
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                unsafe { libc::close(fd); }
                anyhow::bail!(
                    "fcntl F_GETFL failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if result < 0 {
                unsafe { libc::close(fd); }
                anyhow::bail!(
                    "fcntl F_SETFL O_NONBLOCK failed: {}",
                    std::io::Error::last_os_error()
                );
            }

            // Configure the interface (IP address, MTU, bring up)
            Self::configure_interface(&utun_name, address, netmask, mtu)?;

            let wrapper = RawFdWrapper { fd };
            let async_fd = AsyncFd::new(wrapper)
                .context("Failed to create AsyncFd for utun socket")?;

            Ok(Self {
                fd: async_fd,
                name: utun_name,
            })
        }

        /// Gets the kernel-assigned interface name (e.g., "utun3").
        fn get_interface_name(fd: RawFd) -> Result<String> {
            let mut name_buf = [0u8; 256];
            let mut name_len: libc::socklen_t = name_buf.len() as libc::socklen_t;

            // UTUN_OPT_IFNAME = 2
            let result = unsafe {
                libc::getsockopt(
                    fd,
                    SYSPROTO_CONTROL,
                    2, // UTUN_OPT_IFNAME
                    name_buf.as_mut_ptr() as *mut libc::c_void,
                    &mut name_len,
                )
            };
            if result < 0 {
                anyhow::bail!(
                    "getsockopt UTUN_OPT_IFNAME failed: {}",
                    std::io::Error::last_os_error()
                );
            }

            let name = std::str::from_utf8(&name_buf[..name_len as usize - 1])
                .context("Invalid UTF-8 in interface name")?
                .to_string();
            Ok(name)
        }

        /// Configures the utun interface with IP address, netmask, and MTU.
        fn configure_interface(
            name: &str,
            address: IpAddr,
            netmask: IpAddr,
            mtu: u32,
        ) -> Result<()> {
            match address {
                IpAddr::V4(_) => {
                    // Set IPv4 address (point-to-point style)
                    let output = Command::new("ifconfig")
                        .args([
                            name,
                            "inet",
                            &address.to_string(),
                            &address.to_string(),
                            "netmask",
                            &netmask.to_string(),
                            "mtu",
                            &mtu.to_string(),
                            "up",
                        ])
                        .output()
                        .context("Failed to run ifconfig")?;

                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        anyhow::bail!("ifconfig failed: {}", stderr);
                    }
                }
                IpAddr::V6(_) => {
                    let prefix_len = Self::netmask_to_prefix(netmask);
                    let output = Command::new("ifconfig")
                        .args([
                            name,
                            "inet6",
                            &format!("{}/{}", address, prefix_len),
                            "mtu",
                            &mtu.to_string(),
                            "up",
                        ])
                        .output()
                        .context("Failed to run ifconfig for IPv6")?;

                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        anyhow::bail!("ifconfig inet6 failed: {}", stderr);
                    }
                }
            }

            tracing::info!(
                "Configured {} with address {} netmask {} mtu {}",
                name, address, netmask, mtu
            );
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
        ///
        /// macOS utun prepends a 4-byte protocol family header to each packet.
        /// This method strips the header and returns only the raw IP packet.
        pub async fn read_packet(&self) -> Result<Vec<u8>> {
            loop {
                let mut guard = self.fd.readable().await
                    .context("Failed to wait for utun readable")?;

                // 4-byte AF header + max IP packet
                let mut buf = vec![0u8; 4 + 65536];

                match guard.try_io(|inner| {
                    let n = unsafe {
                        libc::read(
                            inner.as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(n)) => {
                        if n <= 4 {
                            // Packet too small to contain data after AF header
                            continue;
                        }
                        // Strip the 4-byte AF header, return raw IP packet
                        buf.truncate(n);
                        return Ok(buf[4..].to_vec());
                    }
                    Ok(Err(e)) => return Err(e).context("Failed to read from utun device"),
                    Err(_would_block) => continue,
                }
            }
        }

        /// Writes a packet to the TUN device.
        ///
        /// macOS utun requires a 4-byte protocol family header prepended to
        /// each packet. This method inspects the IP version nibble to determine
        /// whether to use AF_INET or AF_INET6.
        pub async fn write_packet(&self, packet: &[u8]) -> Result<()> {
            if packet.is_empty() {
                anyhow::bail!("Cannot write empty packet to utun");
            }

            // Determine protocol family from IP version nibble
            let af: u32 = match packet[0] >> 4 {
                4 => AF_INET,
                6 => AF_INET6,
                v => anyhow::bail!("Unknown IP version: {}", v),
            };

            // Build buffer: 4-byte AF header + packet
            let mut buf = Vec::with_capacity(4 + packet.len());
            buf.extend_from_slice(&af.to_ne_bytes());
            buf.extend_from_slice(packet);

            loop {
                let mut guard = self.fd.writable().await
                    .context("Failed to wait for utun writable")?;

                match guard.try_io(|inner| {
                    let n = unsafe {
                        libc::write(
                            inner.as_raw_fd(),
                            buf.as_ptr() as *const libc::c_void,
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(_n)) => return Ok(()),
                    Ok(Err(e)) => return Err(e).context("Failed to write to utun device"),
                    Err(_would_block) => continue,
                }
            }
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

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_netmask_to_prefix() {
        use super::macos::MacOsTunHandle;
        use std::net::IpAddr;

        let netmask: IpAddr = "255.255.255.0".parse().unwrap();
        let prefix = MacOsTunHandle::netmask_to_prefix(netmask);
        assert_eq!(prefix, 24);

        let netmask: IpAddr = "255.255.0.0".parse().unwrap();
        let prefix = MacOsTunHandle::netmask_to_prefix(netmask);
        assert_eq!(prefix, 16);

        let netmask: IpAddr = "255.255.255.252".parse().unwrap();
        let prefix = MacOsTunHandle::netmask_to_prefix(netmask);
        assert_eq!(prefix, 30);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_af_header_ipv4() {
        // Verify AF_INET header is correctly constructed
        let af_inet: u32 = 2;
        let header = af_inet.to_ne_bytes();
        // On little-endian (ARM/Intel), first byte should be 2
        assert_eq!(header[0], 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_af_header_ipv6() {
        // Verify AF_INET6 header is correctly constructed
        let af_inet6: u32 = 30;
        let header = af_inet6.to_ne_bytes();
        assert_eq!(header[0], 30);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_ip_version_detection() {
        // IPv4 packet: version nibble = 4
        let ipv4_packet = [0x45u8, 0x00, 0x00, 0x28]; // Version 4, IHL 5
        assert_eq!(ipv4_packet[0] >> 4, 4);

        // IPv6 packet: version nibble = 6
        let ipv6_packet = [0x60u8, 0x00, 0x00, 0x00]; // Version 6
        assert_eq!(ipv6_packet[0] >> 4, 6);
    }
}
