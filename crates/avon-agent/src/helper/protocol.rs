//! The privileged helper's IPC contract.
//!
//! Two rules make this boundary worth having: the helper accepts *intent*, not
//! commands (a firewall request names CIDRs, never rule text), and every
//! request is validated against state the helper established itself — routes
//! must fall inside the set the agent declared at `Configure` time, so a
//! compromised unprivileged agent cannot ask for a route to the whole Internet.

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

pub use crate::platform::firewall::FirewallRules;

/// Requests are newline-delimited JSON; a longer line closes the connection
/// before a byte of it is parsed.
pub const MAX_LINE_BYTES: usize = 65_536;
pub const MAX_ROUTES: usize = 1_024;

/// MTUs the helper will set. Below 576 IPv4 fragmentation breaks; above 9000 is
/// past every jumbo frame we support.
pub const MIN_MTU: u16 = 576;
pub const MAX_MTU: u16 = 9000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperRequest {
    /// Create the TUN device. The fd is returned out of band (SCM_RIGHTS).
    CreateTun {
        name: String,
        mtu: u16,
    },
    /// Address the interface and declare the route set this session may use.
    Configure {
        v4: String,
        v6: Option<String>,
        mtu: u16,
        allowed_routes: Vec<String>,
    },
    SetRoutes {
        add: Vec<String>,
        remove: Vec<String>,
    },
    ApplyFirewall {
        rules: FirewallRules,
    },
    ClearFirewall,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "res", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperResponse {
    /// The TUN fd rides on the same socket as ancillary data.
    TunReady {
        name: String,
        mtu: u16,
    },
    Ok,
    Error {
        message: String,
    },
}

/// What the helper knows about this connection. Nothing here is taken from the
/// peer without validation: `tun_name` is the name the helper itself created
/// and `allowed_routes` is the set it accepted at `Configure` time.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HelperState {
    pub tun_name: Option<String>,
    pub allowed_routes: Vec<IpNet>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("invalid interface name {0:?}")]
    BadName(String),
    #[error("invalid CIDR {0:?}")]
    BadCidr(String),
    #[error("route {0} is outside the allowed set")]
    RouteNotAllowed(IpNet),
    #[error("too many routes ({0})")]
    TooManyRoutes(usize),
    #[error("request requires a prior Configure")]
    NotConfigured,
    #[error("request exceeds {MAX_LINE_BYTES} bytes ({0})")]
    Oversized(usize),
    #[error("mtu {0} out of range {MIN_MTU}..={MAX_MTU}")]
    BadMtu(u16),
}

/// `^avon[0-9]{0,2}$` — checked byte by byte rather than with a regex so the
/// rejection is total: paths, whitespace, NUL, shell metacharacters, uppercase
/// and every other byte fail by construction.
pub fn validate_ifname(name: &str) -> Result<(), ProtocolError> {
    let bytes = name.as_bytes();
    let ok = (4..=6).contains(&bytes.len())
        && &bytes[..4] == b"avon"
        && bytes[4..].iter().all(u8::is_ascii_digit);
    if ok {
        Ok(())
    } else {
        Err(ProtocolError::BadName(name.to_string()))
    }
}

fn parse_net(s: &str) -> Result<IpNet, ProtocolError> {
    s.parse::<IpNet>()
        .map_err(|_| ProtocolError::BadCidr(s.to_string()))
}

fn check_mtu(mtu: u16) -> Result<(), ProtocolError> {
    if (MIN_MTU..=MAX_MTU).contains(&mtu) {
        Ok(())
    } else {
        Err(ProtocolError::BadMtu(mtu))
    }
}

/// A route is permitted when it is contained in one of the prefixes the agent
/// declared at `Configure` time.
fn check_allowed(route: IpNet, allowed: &[IpNet]) -> Result<(), ProtocolError> {
    if allowed.iter().any(|a| a.contains(&route)) {
        Ok(())
    } else {
        Err(ProtocolError::RouteNotAllowed(route))
    }
}

/// Every request is checked here before the helper acts on it. The state is the
/// helper's own, never the peer's word for it.
pub fn validate(req: &HelperRequest, state: &HelperState) -> Result<(), ProtocolError> {
    match req {
        HelperRequest::CreateTun { name, mtu } => {
            validate_ifname(name)?;
            check_mtu(*mtu)
        }
        HelperRequest::Configure {
            v4,
            v6,
            mtu,
            allowed_routes,
        } => {
            check_mtu(*mtu)?;
            v4.parse::<Ipv4Net>()
                .map_err(|_| ProtocolError::BadCidr(v4.clone()))?;
            if let Some(v6) = v6 {
                v6.parse::<Ipv6Net>()
                    .map_err(|_| ProtocolError::BadCidr(v6.clone()))?;
            }
            if allowed_routes.len() > MAX_ROUTES {
                return Err(ProtocolError::TooManyRoutes(allowed_routes.len()));
            }
            for r in allowed_routes {
                parse_net(r)?;
            }
            Ok(())
        }
        HelperRequest::SetRoutes { add, remove } => {
            if state.tun_name.is_none() || state.allowed_routes.is_empty() {
                return Err(ProtocolError::NotConfigured);
            }
            let total = add.len() + remove.len();
            if total > MAX_ROUTES {
                return Err(ProtocolError::TooManyRoutes(total));
            }
            for r in add.iter().chain(remove.iter()) {
                let net = parse_net(r)?;
                check_allowed(net, &state.allowed_routes)?;
            }
            Ok(())
        }
        HelperRequest::ApplyFirewall { rules } => {
            let tun = state
                .tun_name
                .as_deref()
                .ok_or(ProtocolError::NotConfigured)?;
            validate_ifname(&rules.tun_name)?;
            if rules.tun_name != tun {
                return Err(ProtocolError::BadName(rules.tun_name.clone()));
            }
            if rules.allow_cidrs.len() > MAX_ROUTES {
                return Err(ProtocolError::TooManyRoutes(rules.allow_cidrs.len()));
            }
            for c in &rules.allow_cidrs {
                let net = parse_net(c)?;
                check_allowed(net, &state.allowed_routes)?;
            }
            Ok(())
        }
        HelperRequest::ClearFirewall | HelperRequest::Shutdown => Ok(()),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("request rejected: {0}")]
    Rejected(#[from] ProtocolError),
    #[error("peer uid {0} is not permitted")]
    PeerUid(u32),
    #[error("helper reported: {0}")]
    Remote(String),
    #[error("helper closed the connection")]
    Closed,
    #[error("tun: {0}")]
    Tun(String),
}
