#![allow(clippy::unwrap_used)]
use avon_common::ids::{DeviceId, SessionId, SpiffeId, SpiffeKind, TenantId};
use uuid::Uuid;

#[test]
fn spiffe_device_roundtrip() {
    let t = TenantId::new(Uuid::from_u128(1));
    let d = DeviceId::new(Uuid::from_u128(2));
    let id = SpiffeId::device(t, d);
    assert_eq!(id.raw, "spiffe://avon/00000000-0000-0000-0000-000000000001/device/00000000-0000-0000-0000-000000000002");
    let parsed = SpiffeId::parse(&id.raw).unwrap();
    assert!(
        matches!(parsed.kind, SpiffeKind::Device { tenant, device } if tenant == t && device == d)
    );
}

#[test]
fn spiffe_service_and_gateway() {
    assert!(
        matches!(SpiffeId::parse("spiffe://avon/service/control").unwrap().kind, SpiffeKind::Service { ref name, instance: None } if name == "control")
    );
    let g = SpiffeId::parse("spiffe://avon/service/gateway/00000000-0000-0000-0000-000000000009")
        .unwrap();
    assert!(
        matches!(g.kind, SpiffeKind::Service { ref name, instance: Some(_) } if name == "gateway")
    );
}

#[test]
fn spiffe_rejects_foreign_trust_domain_and_garbage() {
    assert!(SpiffeId::parse("spiffe://evil/service/control").is_err());
    assert!(SpiffeId::parse("https://avon/service/control").is_err());
    assert!(SpiffeId::parse("spiffe://avon/not-a-uuid/device/x").is_err());
}

#[test]
fn session_id_is_16_random_bytes() {
    let a = SessionId::random().unwrap();
    let b = SessionId::random().unwrap();
    assert_ne!(a, b);
    assert_eq!(SessionId::from_slice(a.as_bytes()).unwrap(), a);
    assert!(SessionId::from_slice(&[0; 3]).is_err());
}
