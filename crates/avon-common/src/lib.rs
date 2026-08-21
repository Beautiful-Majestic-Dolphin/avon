//! Shared types used by every AVON service.
//!
//! Today this is the identifier vocabulary: UUID newtypes for devices, tenants,
//! gateways and users, a 128-bit [`ids::SessionId`], and [`ids::SpiffeId`] for
//! the workload identities carried in TLS client certificates.

pub mod ids;
