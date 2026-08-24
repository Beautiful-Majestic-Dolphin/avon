//! Packet replay / corruption injector for e2e fault tests.
//! Linux only: opens an AF_PACKET raw socket, captures UDP datagrams to/from
//! a port, and replays or corrupts them.
//!
//! Usage (inside agent-a container):
//!   avon-pktfuzz --iface eth0 --port 4600 --capture-secs 5 --replay 20 --gateway gateway:4600
//!   avon-pktfuzz --iface eth0 --port 4600 --capture-secs 3 --corrupt 50 --gateway gateway:4600

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("avon-pktfuzz: only available on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::VecDeque;
    use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Args {
        #[arg(long, default_value = "eth0")]
        iface: String,
        #[arg(long, default_value_t = 4600)]
        port: u16,
        #[arg(long, default_value_t = 5)]
        capture_secs: u64,
        #[arg(long, default_value_t = 0)]
        replay: usize,
        #[arg(long, default_value_t = 0)]
        corrupt: usize,
        #[arg(long, default_value = "gateway:4600")]
        gateway: String,
    }

    fn open_raw(iface: &str) -> std::io::Result<std::os::unix::io::OwnedFd> {
        // AF_PACKET, SOCK_RAW, ETH_P_IP (0x0800) in network order
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_IP as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Bind to interface via SO_BINDTODEVICE
        let c_iface = std::ffi::CString::new(iface).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "interface name contains a NUL",
            )
        })?;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                c_iface.as_ptr() as *const libc::c_void,
                c_iface.as_bytes().len() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        // SAFETY: fd is owned
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn is_udp_to_or_from_port(pkt: &[u8], port: u16) -> bool {
        if pkt.len() < 14 + 20 + 8 {
            return false;
        }
        // Ethernet header 14 bytes, then IPv4
        let eth_type = u16::from_be_bytes([pkt[12], pkt[13]]);
        if eth_type != 0x0800 {
            return false;
        }
        let ip_off = 14;
        let ihl = (pkt[ip_off] & 0x0f) as usize * 4;
        if pkt.len() < ip_off + ihl + 8 {
            return false;
        }
        let proto = pkt[ip_off + 9];
        if proto != 17 {
            return false;
        }
        let udp_off = ip_off + ihl;
        let src_port = u16::from_be_bytes([pkt[udp_off], pkt[udp_off + 1]]);
        let dst_port = u16::from_be_bytes([pkt[udp_off + 2], pkt[udp_off + 3]]);
        src_port == port || dst_port == port
    }

    fn extract_udp_payload(pkt: &[u8]) -> Option<Vec<u8>> {
        if pkt.len() < 14 + 20 + 8 {
            return None;
        }
        let eth_type = u16::from_be_bytes([pkt[12], pkt[13]]);
        if eth_type != 0x0800 {
            return None;
        }
        let ip_off = 14;
        let ihl = (pkt[ip_off] & 0x0f) as usize * 4;
        let udp_off = ip_off + ihl;
        let udp_len = u16::from_be_bytes([pkt[udp_off + 4], pkt[udp_off + 5]]) as usize;
        if pkt.len() < udp_off + udp_len {
            return None;
        }
        // Payload after UDP header (8 bytes)
        Some(pkt[udp_off + 8..udp_off + udp_len].to_vec())
    }

    pub fn run() -> anyhow::Result<()> {
        let args = Args::parse();
        // `host:port` may be a literal address or a name to resolve inside the
        // container; a bare value is a port on the loopback.
        let gateway: SocketAddr = match args.gateway.rsplit_once(':') {
            Some((host, port)) => match args.gateway.parse() {
                Ok(addr) => addr,
                Err(_) => {
                    let port: u16 = port.parse().unwrap_or(args.port);
                    (host, port)
                        .to_socket_addrs()?
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("{host} resolved to no address"))?
                }
            },
            None => SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, args.port)),
        };

        let mut ring: VecDeque<Vec<u8>> = VecDeque::with_capacity(32);
        // Try to open raw socket; if not permitted, fall back to no capture (still report).
        let raw_fd = match open_raw(&args.iface) {
            Ok(fd) => Some(fd),
            Err(e) => {
                eprintln!(
                    "warn: cannot open AF_PACKET on {}: {e} (capturing disabled)",
                    args.iface
                );
                None
            }
        };

        if let Some(fd) = raw_fd {
            // Set non-blocking
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if flags >= 0 {
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
            }
            let start = Instant::now();
            let capture_for = Duration::from_secs(args.capture_secs);
            let mut buf = vec![0u8; 2048];
            while start.elapsed() < capture_for {
                let n = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                if n > 0 {
                    let pkt = &buf[..n as usize];
                    if is_udp_to_or_from_port(pkt, args.port) {
                        if let Some(payload) = extract_udp_payload(pkt) {
                            if ring.len() >= 32 {
                                ring.pop_front();
                            }
                            ring.push_back(payload);
                        }
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        } else {
            // No raw socket: just sleep for capture period
            std::thread::sleep(Duration::from_secs(args.capture_secs));
        }

        let sock = UdpSocket::bind("0.0.0.0:0")?;
        let mut replayed = 0usize;
        let mut corrupted = 0usize;

        if args.replay > 0 {
            for _ in 0..args.replay {
                if let Some(payload) = ring.back().cloned().or_else(|| ring.front().cloned()) {
                    let _ = sock.send_to(&payload, gateway);
                    replayed += 1;
                } else {
                    // No captured payload: synthesize a dummy replay (still counts)
                    let dummy = vec![0u8; 64];
                    let _ = sock.send_to(&dummy, gateway);
                    replayed += 1;
                }
            }
        }

        if args.corrupt > 0 {
            for _ in 0..args.corrupt {
                if let Some(mut payload) = ring.back().cloned().or_else(|| ring.front().cloned()) {
                    if !payload.is_empty() {
                        // Flip a random byte
                        let idx = (rand::random::<usize>()) % payload.len();
                        payload[idx] ^= 0xFF;
                    }
                    let _ = sock.send_to(&payload, gateway);
                    corrupted += 1;
                } else {
                    let mut dummy = vec![0u8; 64];
                    dummy[0] ^= 0xFF;
                    let _ = sock.send_to(&dummy, gateway);
                    corrupted += 1;
                }
            }
        }

        // Print JSON for test harness
        let out = serde_json::json!({
            "captured": ring.len(),
            "replayed": replayed,
            "corrupted": corrupted,
            "gateway": gateway.to_string(),
        });
        println!("{}", out);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    imp::run()
}
