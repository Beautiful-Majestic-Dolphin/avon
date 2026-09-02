//! Turning the gateway endpoint the control plane hands us into an address.
//!
//! `responder_endpoint` is whatever the gateway was configured to advertise
//! (`AVON_PUBLIC_ENDPOINT`), and in any real deployment that is a name, not an
//! address. `str::parse::<SocketAddr>` is a pure string parser: it rejects
//! `gateway:4600`, and even `localhost:4600`, without consulting a resolver.
//! That is the bug layer 3 of the e2e suite found. This module is the one
//! place the agent turns that string into an address, and it does so with the
//! system resolver every time a hub session is opened, never once at startup:
//! a gateway's address changes when instances are replaced or DNS fails over,
//! and caching the first answer forever would be the same bug in a slower
//! form.
//!
//! Which address, when a name yields several: the tunnel has exactly one UDP
//! socket, bound to one address family, and a hub session records exactly one
//! peer endpoint. Addresses in the other family are unusable by construction,
//! so they are filtered out and named in the error if nothing is left. Of the
//! usable ones the first is taken. Trying each in turn would need a probe on
//! the data plane before the session is committed, and the hub path has none
//! today (the peer path's `probe_loop` is the model); until it does, the order
//! the resolver returns is the order the operator's DNS chose.

use std::net::SocketAddr;

/// Why an advertised endpoint could not become an address. Each variant is a
/// different operator action: fix the gateway's configuration, fix DNS, or
/// fix which family the agent's socket is bound to.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("gateway advertised an empty endpoint")]
    Empty,
    #[error("could not resolve gateway endpoint `{endpoint}`: {source}")]
    Unresolvable {
        endpoint: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "gateway endpoint `{endpoint}` resolved only to {found:?}, \
         but the tunnel socket is bound to {wanted} ({local})"
    )]
    NoAddressInFamily {
        endpoint: String,
        wanted: &'static str,
        local: SocketAddr,
        found: Vec<SocketAddr>,
    },
}

/// Resolve `endpoint` (`host:port` or a literal `ip:port`) to one address the
/// socket bound at `local` can send to.
pub async fn resolve_endpoint(
    endpoint: &str,
    local: SocketAddr,
) -> Result<SocketAddr, ResolveError> {
    if endpoint.trim().is_empty() {
        return Err(ResolveError::Empty);
    }
    let found: Vec<SocketAddr> = tokio::net::lookup_host(endpoint)
        .await
        .map_err(|source| ResolveError::Unresolvable {
            endpoint: endpoint.to_string(),
            source,
        })?
        .collect();
    if found.is_empty() {
        return Err(ResolveError::Unresolvable {
            endpoint: endpoint.to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "resolver returned no addresses",
            ),
        });
    }
    let same_family = |a: &SocketAddr| a.is_ipv4() == local.is_ipv4();
    let usable: Vec<SocketAddr> = found.iter().copied().filter(same_family).collect();
    let Some(&chosen) = usable.first() else {
        return Err(ResolveError::NoAddressInFamily {
            endpoint: endpoint.to_string(),
            wanted: if local.is_ipv4() { "IPv4" } else { "IPv6" },
            local,
            found,
        });
    };
    if usable.len() > 1 {
        tracing::debug!(
            %endpoint,
            %chosen,
            others = ?&usable[1..],
            "gateway endpoint resolved to several addresses; using the first"
        );
    }
    Ok(chosen)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const V4_LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 40000);
    const V6_LOCAL: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 40000);

    #[tokio::test]
    async fn literal_address_passes_through_without_a_resolver() {
        let got = resolve_endpoint("172.20.0.5:4600", V4_LOCAL).await.unwrap();
        assert_eq!(got, "172.20.0.5:4600".parse::<SocketAddr>().unwrap());
    }

    /// The regression test for the layer 3 failure: a name, not an address.
    /// `localhost` resolves on every host that has a resolver at all, and the
    /// old `str::parse` rejected it anyway.
    #[tokio::test]
    async fn a_name_is_resolved_not_parsed() {
        let got = resolve_endpoint("localhost:4600", V4_LOCAL).await.unwrap();
        assert!(got.ip().is_loopback(), "got {got}");
        assert!(got.is_ipv4(), "family must match the socket: got {got}");
        assert_eq!(got.port(), 4600);
    }

    #[tokio::test]
    async fn an_unresolvable_name_says_so() {
        // RFC 2606 reserves `.invalid`; no resolver answers for it.
        let err = resolve_endpoint("gateway.invalid:4600", V4_LOCAL)
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::Unresolvable { .. }), "{err:?}");
        let text = err.to_string();
        assert!(text.contains("could not resolve"), "{text}");
        assert!(text.contains("gateway.invalid:4600"), "{text}");
    }

    #[tokio::test]
    async fn a_name_without_a_port_is_unresolvable_not_a_panic() {
        let err = resolve_endpoint("gateway", V4_LOCAL).await.unwrap_err();
        assert!(matches!(err, ResolveError::Unresolvable { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn an_empty_endpoint_is_its_own_error() {
        let err = resolve_endpoint("", V4_LOCAL).await.unwrap_err();
        assert!(matches!(err, ResolveError::Empty), "{err:?}");
        let err = resolve_endpoint("   ", V4_LOCAL).await.unwrap_err();
        assert!(matches!(err, ResolveError::Empty), "{err:?}");
    }

    #[tokio::test]
    async fn the_other_family_is_named_in_the_error_not_silently_dropped() {
        let err = resolve_endpoint("[::1]:4600", V4_LOCAL).await.unwrap_err();
        match &err {
            ResolveError::NoAddressInFamily { wanted, found, .. } => {
                assert_eq!(*wanted, "IPv4");
                assert_eq!(found, &["[::1]:4600".parse::<SocketAddr>().unwrap()]);
            }
            other => panic!("expected NoAddressInFamily, got {other:?}"),
        }
        let text = err.to_string();
        assert!(
            text.contains("IPv4") && text.contains("[::1]:4600"),
            "{text}"
        );

        let err = resolve_endpoint("127.0.0.1:4600", V6_LOCAL)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::NoAddressInFamily { wanted: "IPv6", .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_v6_socket_gets_a_v6_address() {
        let got = resolve_endpoint("[::1]:4600", V6_LOCAL).await.unwrap();
        assert_eq!(got, "[::1]:4600".parse::<SocketAddr>().unwrap());
    }
}
