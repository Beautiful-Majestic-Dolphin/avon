//! The gateway's TUN device — where packets bound for a protected network or
//! the internet leave the overlay and the kernel takes over routing.
//!
//! A device sends an inner IP packet (say to `172.30.0.10`) inside its tunnel.
//! The gateway decrypts it and writes it to this TUN; the kernel forwards it
//! out the protected interface (the entrypoint enables `ip_forward` and
//! masquerades the overlay source). The reply comes back to the gateway,
//! conntrack un-NATs it to the device's overlay address, and the kernel routes
//! it onto this TUN because the TUN owns the overlay prefixes. `tun_loop` reads
//! it here and re-encrypts it to the owning session.
//!
//! On Linux with `/dev/net/tun` and `NET_ADMIN` this is a real device. Without
//! them — a platform with no TUN, or a container that lacks the capability —
//! the gateway falls back to relay-only: device-to-device forwarding still
//! works in full, egress to protected networks does not, and it says so once
//! rather than dropping packets in silence.

use std::sync::Arc;

use async_trait::async_trait;
use avon_tunnel::{PacketSink, PacketSource, TunnelError};
use ipnet::IpNet;

pub struct Tun {
    pub sink: Arc<dyn PacketSink>,
    pub source: Arc<dyn PacketSource>,
    /// False when no kernel device was opened, so the caller can say so once
    /// rather than dropping packets silently.
    pub is_real: bool,
}

/// Open the platform TUN named `name` and give it the overlay prefixes, so the
/// kernel routes return traffic for any overlay address back onto it.
///
/// Never fails the gateway: if a real device cannot be opened, returns a
/// relay-only pair and logs why.
pub async fn open(name: &str, mtu: u16, overlay_prefixes: &[IpNet]) -> Tun {
    #[cfg(target_os = "linux")]
    {
        match open_linux(name, mtu, overlay_prefixes).await {
            Ok(tun) => {
                let tun = Arc::new(tun);
                tracing::info!(tun = name, "egress TUN up; protected networks reachable");
                return Tun {
                    sink: tun.clone(),
                    source: tun,
                    is_real: true,
                };
            }
            Err(e) => {
                tracing::warn!(
                    tun = name,
                    error = %e,
                    "no egress TUN (need /dev/net/tun and NET_ADMIN): relay-only, \
                     egress to protected networks is off"
                );
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, mtu, overlay_prefixes);
        tracing::warn!(tun = name, "TUN only implemented on Linux: relay-only");
    }
    Tun {
        sink: Arc::new(NullTun),
        source: Arc::new(NullTun),
        is_real: false,
    }
}

/// Create the device, address it as the gateway end of each overlay prefix, and
/// bring it up. Addressing a prefix installs its connected route, which is what
/// pulls return traffic for that prefix onto the TUN.
#[cfg(target_os = "linux")]
async fn open_linux(
    name: &str,
    mtu: u16,
    overlay_prefixes: &[IpNet],
) -> anyhow::Result<avon_tun::Tun> {
    use ipnet::{Ipv4Net, Ipv6Net};

    let tun = avon_tun::Tun::create(name, mtu).await?;

    // The gateway takes the first host address of each prefix (`.1`). Devices
    // are allocated higher addresses by IPAM, so this does not collide with a
    // device's overlay address.
    let mut v4: Option<Ipv4Net> = None;
    let mut v6: Option<Ipv6Net> = None;
    for prefix in overlay_prefixes {
        match prefix {
            IpNet::V4(net) if v4.is_none() => {
                let base = u32::from(net.network());
                let addr = std::net::Ipv4Addr::from(base + 1);
                v4 = Some(Ipv4Net::new(addr, net.prefix_len())?);
            }
            IpNet::V6(net) if v6.is_none() => {
                let base = u128::from(net.network());
                let addr = std::net::Ipv6Addr::from(base + 1);
                v6 = Some(Ipv6Net::new(addr, net.prefix_len())?);
            }
            _ => {}
        }
    }
    let v4 = v4.ok_or_else(|| anyhow::anyhow!("no IPv4 overlay prefix to address the TUN with"))?;
    avon_tun::config::configure(&tun, v4, v6, mtu).await?;
    Ok(tun)
}

/// Accepts and drops everything; never produces a packet. The relay-only
/// fallback: device-to-device forwarding does not touch the TUN, so it is
/// unaffected; only egress to protected networks is lost.
struct NullTun;

#[async_trait]
impl PacketSink for NullTun {
    async fn deliver(&self, _ip_packet: &[u8]) -> Result<(), TunnelError> {
        metrics::counter!("avon_gateway_packets_dropped_total", "reason" => "no_tun").increment(1);
        Ok(())
    }
}

#[async_trait]
impl PacketSource for NullTun {
    async fn next_packet(&self, _buf: &mut Vec<u8>) -> Result<usize, TunnelError> {
        std::future::pending().await
    }
}
