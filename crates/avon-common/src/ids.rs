//! Strongly typed identifiers shared by every service.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum IdError {
    #[error("invalid uuid: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("invalid spiffe id: {0}")]
    Spiffe(String),
    #[error("invalid session id length {0}")]
    SessionLen(usize),
    #[error("random generation failed")]
    Random,
}

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            Serialize,
            Deserialize,
            sqlx::Type,
        )]
        #[sqlx(transparent)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub const fn new(u: Uuid) -> Self {
                Self(u)
            }
            pub fn random() -> Self {
                Self(Uuid::new_v4())
            }
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
            pub fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
        impl FromStr for $name {
            type Err = IdError;
            fn from_str(s: &str) -> Result<Self, IdError> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }
        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }
    };
}

uuid_id!(DeviceId);
uuid_id!(TenantId);
uuid_id!(GatewayId);
uuid_id!(UserId);

/// A 128-bit session identifier drawn from the OS CSPRNG.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub fn random() -> Result<Self, IdError> {
        let mut b = [0u8; 16];
        getrandom::getrandom(&mut b).map_err(|_| IdError::Random)?;
        Ok(Self(b))
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    pub fn from_slice(s: &[u8]) -> Result<Self, IdError> {
        let arr: [u8; 16] = s.try_into().map_err(|_| IdError::SessionLen(s.len()))?;
        Ok(Self(arr))
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", hex::encode(self.0))
    }
}
impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// The only trust domain AVON accepts in a SPIFFE ID.
pub const TRUST_DOMAIN: &str = "avon";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpiffeKind {
    Service {
        name: String,
        instance: Option<Uuid>,
    },
    Device {
        tenant: TenantId,
        device: DeviceId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpiffeId {
    pub raw: String,
    pub kind: SpiffeKind,
}

impl SpiffeId {
    pub fn service(name: &str) -> Self {
        Self {
            raw: format!("spiffe://{TRUST_DOMAIN}/service/{name}"),
            kind: SpiffeKind::Service {
                name: name.to_string(),
                instance: None,
            },
        }
    }
    pub fn gateway(id: GatewayId) -> Self {
        Self {
            raw: format!("spiffe://{TRUST_DOMAIN}/service/gateway/{id}"),
            kind: SpiffeKind::Service {
                name: "gateway".into(),
                instance: Some(id.as_uuid()),
            },
        }
    }
    pub fn device(tenant: TenantId, device: DeviceId) -> Self {
        Self {
            raw: format!("spiffe://{TRUST_DOMAIN}/{tenant}/device/{device}"),
            kind: SpiffeKind::Device { tenant, device },
        }
    }

    pub fn parse(uri: &str) -> Result<Self, IdError> {
        let rest = uri
            .strip_prefix("spiffe://")
            .ok_or_else(|| IdError::Spiffe("scheme".into()))?;
        let mut parts = rest.split('/');
        if parts.next() != Some(TRUST_DOMAIN) {
            return Err(IdError::Spiffe("trust domain".into()));
        }
        let segs: Vec<&str> = parts.collect();
        let kind = match segs.as_slice() {
            ["service", name] => SpiffeKind::Service {
                name: (*name).to_string(),
                instance: None,
            },
            ["service", name, inst] => SpiffeKind::Service {
                name: (*name).to_string(),
                instance: Some(Uuid::parse_str(inst)?),
            },
            [tenant, "device", device] => SpiffeKind::Device {
                tenant: tenant.parse()?,
                device: device.parse()?,
            },
            _ => return Err(IdError::Spiffe(format!("unrecognized path {rest}"))),
        };
        Ok(Self {
            raw: uri.to_string(),
            kind,
        })
    }
}
