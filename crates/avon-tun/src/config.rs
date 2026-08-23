use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::{Tun, TunError};

#[cfg(target_os = "linux")]
pub async fn configure(
    tun: &Tun,
    v4: Ipv4Net,
    v6: Option<Ipv6Net>,
    mtu: u16,
) -> Result<(), TunError> {
    use rtnetlink::LinkUnspec;

    let (handle, index) = link_index(tun).await?;

    // Set MTU and bring the link up.
    handle
        .link()
        .set(
            LinkUnspec::new_with_index(index)
                .mtu(mtu as u32)
                .up()
                .build(),
        )
        .execute()
        .await
        .map_err(|e| TunError::Netlink(e.to_string()))?;

    // Addresses. Re-running configure on an interface that already carries the
    // address must not be an error: the agent re-configures on every reconnect.
    if let Err(e) = handle
        .address()
        .add(index, v4.addr().into(), v4.prefix_len())
        .execute()
        .await
    {
        if !already_exists(&e) {
            return Err(TunError::Netlink(e.to_string()));
        }
    }
    if let Some(v6) = v6 {
        if let Err(e) = handle
            .address()
            .add(index, v6.addr().into(), v6.prefix_len())
            .execute()
            .await
        {
            if !already_exists(&e) {
                return Err(TunError::Netlink(e.to_string()));
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn already_exists(e: &rtnetlink::Error) -> bool {
    matches!(e, rtnetlink::Error::NetlinkError(err) if err.raw_code() == -17)
}

#[cfg(target_os = "linux")]
async fn link_index(tun: &Tun) -> Result<(rtnetlink::Handle, u32), TunError> {
    use futures::TryStreamExt;
    use rtnetlink::new_connection;

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
    Ok((handle, link.header.index))
}

/// Build the message for a route that leaves through `index` and nothing else:
/// scope `link`, no gateway, exactly as `ip route add <net> dev <tun>` does.
#[cfg(target_os = "linux")]
fn route_message(route: &IpNet, index: u32) -> rtnetlink::packet_route::route::RouteMessage {
    use rtnetlink::packet_route::route::RouteScope;
    use rtnetlink::RouteMessageBuilder;

    match route.network() {
        std::net::IpAddr::V4(v4) => RouteMessageBuilder::<std::net::Ipv4Addr>::new()
            .destination_prefix(v4, route.prefix_len())
            .output_interface(index)
            .scope(RouteScope::Link)
            .build(),
        std::net::IpAddr::V6(v6) => RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .destination_prefix(v6, route.prefix_len())
            .output_interface(index)
            .scope(RouteScope::Link)
            .build(),
    }
}

#[cfg(target_os = "linux")]
pub async fn set_routes(tun: &Tun, routes: &[IpNet]) -> Result<(), TunError> {
    if routes.is_empty() {
        return Ok(());
    }
    let (handle, index) = link_index(tun).await?;
    for route in routes {
        if let Err(e) = handle
            .route()
            .add(route_message(route, index))
            .execute()
            .await
        {
            if already_exists(&e) {
                continue;
            }
            return Err(TunError::Netlink(format!("add route {route}: {e}")));
        }
    }
    Ok(())
}

/// Withdraw routes. A route that is already gone is not an error — the kernel
/// removes them itself when the interface goes down.
#[cfg(target_os = "linux")]
pub async fn remove_routes(tun: &Tun, routes: &[IpNet]) -> Result<(), TunError> {
    if routes.is_empty() {
        return Ok(());
    }
    let (handle, index) = link_index(tun).await?;
    for route in routes {
        if let Err(e) = handle
            .route()
            .del(route_message(route, index))
            .execute()
            .await
        {
            tracing::debug!(route = %route, error = %e, "route delete ignored");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn remove_routes(_tun: &Tun, _routes: &[IpNet]) -> Result<(), TunError> {
    Err(TunError::Unsupported(
        "remove_routes not supported on this platform",
    ))
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

#[cfg(target_os = "macos")]
pub async fn remove_routes_macos(tun: &Tun, routes: &[IpNet]) -> Result<(), TunError> {
    for route in routes {
        let mut cmd = tokio::process::Command::new("/sbin/route");
        cmd.args([
            "-n",
            "delete",
            "-net",
            &route.to_string(),
            "-interface",
            tun.name(),
        ]);
        let st = cmd.status().await.map_err(TunError::Io)?;
        if !st.success() {
            // The kernel drops interface routes with the interface; a route
            // that is already gone is not a failure.
            tracing::debug!(route = %route, "route delete ignored");
        }
    }
    Ok(())
}
