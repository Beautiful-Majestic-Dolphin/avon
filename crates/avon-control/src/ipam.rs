//! Stable overlay addresses. A device keeps the same address for its lifetime,
//! so policy and logs can refer to it.

use std::net::{Ipv4Addr, Ipv6Addr};

use avon_common::ids::{DeviceId, TenantId};
use ipnet::{Ipv4Net, Ipv6Net};
use sqlx::types::ipnetwork::IpNetwork;
use sqlx::{Postgres, Transaction};

#[derive(Debug, thiserror::Error)]
pub enum IpamError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("pool exhausted")]
    Exhausted,
    #[error("pool misconfigured: {0}")]
    Pool(String),
}

/// Allocate (or return the existing) overlay addresses for a device. Locks the
/// tenant's pool row, so concurrent enrollments serialize instead of racing for
/// the same address.
pub async fn allocate(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    device: DeviceId,
) -> Result<(Ipv4Net, Ipv6Net), IpamError> {
    let (v4_pool, v6_pool): (IpNetwork, IpNetwork) = sqlx::query_as(
        "SELECT ipv4_cidr, ipv6_cidr FROM ipam_pools WHERE tenant_id = $1 FOR UPDATE",
    )
    .bind(tenant)
    .fetch_one(&mut **tx)
    .await?;
    let (v4_net, v6_net) = match (v4_pool, v6_pool) {
        (IpNetwork::V4(v4), IpNetwork::V6(v6)) => (
            Ipv4Net::new(v4.ip(), v4.prefix()).map_err(|e| IpamError::Pool(e.to_string()))?,
            Ipv6Net::new(v6.ip(), v6.prefix()).map_err(|e| IpamError::Pool(e.to_string()))?,
        ),
        _ => return Err(IpamError::Pool("pools must be IPv4 and IPv6".into())),
    };

    let existing: Option<(Option<IpNetwork>, Option<IpNetwork>)> = sqlx::query_as(
        "SELECT overlay_ipv4, overlay_ipv6 FROM devices WHERE id = $1 AND tenant_id = $2",
    )
    .bind(device)
    .bind(tenant)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some((Some(IpNetwork::V4(v4)), Some(IpNetwork::V6(v6)))) = existing {
        return Ok((
            Ipv4Net::new(v4.ip(), v4_net.prefix_len())
                .map_err(|e| IpamError::Pool(e.to_string()))?,
            Ipv6Net::new(v6.ip(), v6_net.prefix_len())
                .map_err(|e| IpamError::Pool(e.to_string()))?,
        ));
    }

    // Lowest free host address above .1, which is reserved for gateways.
    let used: Vec<(IpNetwork,)> = sqlx::query_as(
        "SELECT overlay_ipv4 FROM devices \
         WHERE tenant_id = $1 AND overlay_ipv4 IS NOT NULL ORDER BY overlay_ipv4",
    )
    .bind(tenant)
    .fetch_all(&mut **tx)
    .await?;
    let used: std::collections::HashSet<Ipv4Addr> = used
        .into_iter()
        .filter_map(|(n,)| match n {
            IpNetwork::V4(v) => Some(v.ip()),
            _ => None,
        })
        .collect();
    let base = u32::from(v4_net.network());
    let size = 1u64 << (32 - v4_net.prefix_len());
    let mut chosen = None;
    for off in 2..size.saturating_sub(1) {
        let candidate = Ipv4Addr::from(base + off as u32);
        if !used.contains(&candidate) {
            chosen = Some(candidate);
            break;
        }
    }
    let v4 = chosen.ok_or(IpamError::Exhausted)?;
    // IPv6 mirrors the IPv4 host part in the low bits of the pool prefix, so
    // the two addresses of a device are trivially correlated in logs.
    let v6_base = u128::from(v6_net.network());
    let v6 = Ipv6Addr::from(v6_base | (u128::from(u32::from(v4) - base)));

    sqlx::query("UPDATE devices SET overlay_ipv4 = $2, overlay_ipv6 = $3 WHERE id = $1")
        .bind(device)
        .bind(IpNetwork::V4(
            sqlx::types::ipnetwork::Ipv4Network::new(v4, 32)
                .map_err(|e| IpamError::Pool(e.to_string()))?,
        ))
        .bind(IpNetwork::V6(
            sqlx::types::ipnetwork::Ipv6Network::new(v6, 128)
                .map_err(|e| IpamError::Pool(e.to_string()))?,
        ))
        .execute(&mut **tx)
        .await?;
    Ok((
        Ipv4Net::new(v4, v4_net.prefix_len()).map_err(|e| IpamError::Pool(e.to_string()))?,
        Ipv6Net::new(v6, v6_net.prefix_len()).map_err(|e| IpamError::Pool(e.to_string()))?,
    ))
}
