use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::{Tun, TunError};

#[cfg(target_os = "linux")]
pub async fn configure(
    tun: &Tun,
    v4: Ipv4Net,
    v6: Option<Ipv6Net>,
    mtu: u16,
) -> Result<(), TunError> {
    use futures::TryStreamExt;
    use rtnetlink::{new_connection, packet_route::address::AddressAttribute};

    let (connection, handle, _) = new_connection().map_err(|e| TunError::Netlink(e.to_string()))?;
    tokio::spawn(connection);

    // Find link index by name.
    let mut links = handle
        .link()
        .get()
        .match_name(tun.name().to_string())
        .execute();
    let link = links
        .try_next()
        .await
        .map_err(|e| TunError::Netlink(e.to_string()))?
        .ok_or_else(|| TunError::Netlink(format!("link {} not found", tun.name())))?;
    let index = link.header.index;

    // Set MTU and bring up.
    handle
        .link()
        .set(index)
        .mtu(mtu as u32)
        .up()
        .execute()
        .await
        .map_err(|e| TunError::Netlink(e.to_string()))?;

    // Add IPv4 address.
    handle
        .address()
        .add(index, v4.addr(), v4.prefix_len())
        .execute()
        .await
        .map_err(|e| TunError::Netlink(e.to_string()))?;

    // Add IPv6 if present.
    if let Some(v6) = v6 {
        handle
            .address()
            .add(index, v6.addr(), v6.prefix_len())
            .execute()
            .await
            .map_err(|e| TunError::Netlink(e.to_string()))?;
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn configure(
    _tun: &Tun,
    _v4: Ipv4Net,
    _v6: Option<Ipv6Net>,
    _mtu: u16,
) -> Result<(), TunError> {
    Err(TunError::Unsupported(
        "configure not supported on this platform",
    ))
}

#[cfg(target_os = "linux")]
pub async fn set_routes(tun: &Tun, routes: &[IpNet]) -> Result<(), TunError> {
    use futures::TryStreamExt;

    let (connection, handle, _) = new_connection().map_err(|e| TunError::Netlink(e.to_string()))?;
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(tun.name().to_string())
        .execute();
    let link = links
        .try_next()
        .await
        .map_err(|e| TunError::Netlink(e.to_string()))?
        .ok_or_else(|| TunError::Netlink(format!("link {} not found", tun.name())))?;
    let index = link.header.index;

    for route in routes {
        let dst = route.network();
        let prefix = route.prefix_len();
        let mut req = handle.route().add();
        match dst {
            std::net::IpAddr::V4(v4) => {
                req = req
                    .v4()
                    .destination_prefix(v4, prefix)
                    .output_interface(index);
            }
            std::net::IpAddr::V6(v6) => {
                req = req
                    .v6()
                    .destination_prefix(v6, prefix)
                    .output_interface(index);
            }
        }
        // Ignore already exists.
        let _ = req.execute().await;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn set_routes(_tun: &Tun, _routes: &[IpNet]) -> Result<(), TunError> {
    Err(TunError::Unsupported(
        "set_routes not supported on this platform",
    ))
}

// macOS helpers (called from macos.rs)

#[cfg(target_os = "macos")]
pub async fn configure_macos(
    tun: &Tun,
    v4: Ipv4Net,
    v6: Option<Ipv6Net>,
    mtu: u16,
) -> Result<(), TunError> {
    let name = tun.name().to_string();
    // ifconfig <name> inet <v4> <v4.addr> netmask <mask> mtu <mtu> up
    let netmask = ipv4_mask(v4.prefix_len());
    let mut cmd = tokio::process::Command::new("/sbin/ifconfig");
    cmd.args([
        &name,
        "inet",
        &v4.to_string(),
        &v4.addr().to_string(),
        "netmask",
        &netmask,
        "mtu",
        &mtu.to_string(),
        "up",
    ]);
    let st = cmd.status().await.map_err(TunError::Io)?;
    if !st.success() {
        return Err(TunError::Io(std::io::Error::other("ifconfig failed")));
    }
    if let Some(v6) = v6 {
        let mut cmd = tokio::process::Command::new("/sbin/ifconfig");
        cmd.args([
            &name,
            "inet6",
            &v6.to_string(),
            "prefixlen",
            &v6.prefix_len().to_string(),
        ]);
        let st = cmd.status().await.map_err(TunError::Io)?;
        if !st.success() {
            return Err(TunError::Io(std::io::Error::other("ifconfig inet6 failed")));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub async fn set_routes_macos(_tun: &Tun, routes: &[IpNet]) -> Result<(), TunError> {
    for route in routes {
        let mut cmd = tokio::process::Command::new("/sbin/route");
        cmd.args([
            "-n",
            "add",
            "-net",
            &route.to_string(),
            "-interface",
            _tun.name(),
        ]);
        let st = cmd.status().await.map_err(TunError::Io)?;
        if !st.success() {
            // Ignore already exists, but log.
            tracing::warn!(route = %route, "route add failed");
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn ipv4_mask(prefix: u8) -> String {
    let mask = if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix)
    };
    let octets = mask.to_be_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}
