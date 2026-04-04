# avon-mobile-core: Shared Agent Library Crate

## Purpose

Extract platform-independent agent logic from `avon-agent` into a reusable `avon-mobile-core` library crate. This crate provides tunnel encryption, control plane communication, identity management, and agent orchestration that can be shared between desktop agents (Linux, macOS, Windows) and future mobile agents (iOS, Android).

## Architecture

```
avon-mobile-core (library crate)
  |-- tunnel/       Tunnel, TunnelManager, Handshake, RoutingTable, PacketLoop
  |-- control/      ControlPlaneClient, PulseHandler, ReconnectManager
  |-- identity/     IdentityManager, SoftwareKeystore
  |-- agent.rs      AvonAgent orchestration, AgentState, AgentStatus
  |-- config.rs     AgentConfig (core struct)
  |-- traits.rs     TunProvider, PostureProvider, FingerprintProvider

avon-agent (binary crate, depends on avon-mobile-core)
  |-- tun_device.rs     Linux/macOS/Windows TUN implementations (impl TunProvider)
  |-- posture.rs        Platform posture collection (impl PostureProvider)
  |-- hardware.rs       Platform fingerprinting (impl FingerprintProvider)
  |-- tpm.rs            TPM integration
  |-- fido2.rs          FIDO2 USB HID
  |-- main.rs           CLI entry point

Future: avon-ios (depends on avon-mobile-core)
  |-- NEPacketTunnelProvider impl TunProvider
  |-- iOS posture impl PostureProvider
  |-- UniFFI bindings

Future: avon-android (depends on avon-mobile-core)
  |-- VpnService impl TunProvider
  |-- Android posture impl PostureProvider
  |-- UniFFI bindings
```

## Platform Abstraction Traits

Defined in `avon-mobile-core/src/traits.rs`:

```rust
/// Trait for platform-specific TUN device I/O.
#[async_trait]
pub trait TunProvider: Send + Sync {
    async fn create(name: &str, address: IpAddr, netmask: IpAddr, mtu: u32) -> Result<Self>
        where Self: Sized;
    async fn read_packet(&self) -> Result<Vec<u8>>;
    async fn write_packet(&self, packet: &[u8]) -> Result<()>;
    fn name(&self) -> &str;
    fn mtu(&self) -> u32;
}

/// Trait for platform-specific device posture collection.
pub trait PostureProvider: Send + Sync {
    fn collect(&self) -> DevicePosture;
}

/// Trait for platform-specific hardware fingerprint collection.
pub trait FingerprintProvider: Send + Sync {
    fn collect(&self) -> HardwareFingerprint;
    fn to_hash(&self) -> [u8; 32];  // Default impl using HMAC-SHA256
}
```

## Modules Extracted (from avon-agent)

### Fully moved (no modification needed)
| Module | Key Types | Status |
|--------|-----------|--------|
| `tunnel/tunnel.rs` | `Tunnel`, `TunnelState`, `TunnelStats`, `SessionId` | Pure crypto |
| `tunnel/handshake.rs` | `TunnelHandshake` | Pure protocol |
| `tunnel/routing.rs` | `RoutingTable` | Pure data structure |
| `tunnel/packet_loop.rs` | `PacketLoop`, `extract_destination_ip()` | Pure packet parsing |
| `tunnel/mod.rs` | `TunnelManager`, `TunnelManagerConfig` | Pure orchestration |
| `control/requests.rs` | `ControlResponse`, `MessageType` | Type definitions |
| `control/reconnect.rs` | `ReconnectManager`, `ReconnectConfig` | Pure state machine |
| `control/mod.rs` | `ControlPlaneClient`, `ConnectionState` | Pure networking |
| `identity/software.rs` | `SoftwareKeystore` | Pure crypto |

### Moved with abstraction changes
| Module | Change |
|--------|--------|
| `control/pulse.rs` | Takes `dyn PostureProvider` instead of concrete `PostureCollector` |
| `identity/mod.rs` | Takes `dyn FingerprintProvider` instead of concrete `HardwareFingerprint::collect()` |
| `agent.rs` | Takes `dyn TunProvider` factory; shutdown signal abstracted to callback |
| `config.rs` | Core struct portable; `default_data_dir()` moved to avon-agent |

### Stays in avon-agent (platform-specific)
| Module | Reason |
|--------|--------|
| `tunnel/tun_device.rs` | Linux ioctl, macOS utun, Windows wintun -- implements `TunProvider` |
| `control/posture.rs` | Linux/macOS/Windows system commands -- implements `PostureProvider` |
| `identity/hardware.rs` | Platform-specific hardware collection -- implements `FingerprintProvider` |
| `identity/tpm.rs` | Linux/Windows TPM integration |
| `identity/fido2.rs` | USB HID CTAP2 interaction |
| `main.rs` | CLI, platform defaults |

## Dependencies

### avon-mobile-core Cargo.toml
```toml
[dependencies]
tokio = { workspace }
serde = { workspace }
serde_json = "1.0"
tracing = { workspace }
anyhow = { workspace }
avon-crypto = { workspace }
avon-protocol = { workspace }
avon-common = { workspace }
prost = { workspace }
async-trait = "0.1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1.7", features = ["v4"] }
zeroize = { version = "1.7", features = ["derive"] }
dashmap = "5.5"
config = "0.14"
```

No platform-specific dependencies. No libc, wintun, tss-esapi, ctap-hid-fido2.

### avon-agent Cargo.toml changes
```toml
[dependencies]
avon-mobile-core = { workspace }  # NEW - replaces extracted modules
# Keep platform-specific deps: libc, tss-esapi, ctap-hid-fido2, sysinfo
# Remove deps that moved: dashmap, config (now in mobile-core)
```

## Re-export Strategy

`avon-agent/src/lib.rs` re-exports all public types from `avon-mobile-core`:

```rust
pub use avon_mobile_core::*;
```

This ensures any code importing from `avon_agent` continues to work. The migration is transparent to consumers.

## Workspace Changes

Add to root `Cargo.toml`:
```toml
[workspace]
members = [
    # ... existing crates ...
    "crates/avon-mobile-core",
]

[workspace.dependencies]
avon-mobile-core = { path = "crates/avon-mobile-core" }
```

## Verification

1. `cargo check -p avon-mobile-core` compiles with zero platform-specific code
2. `cargo check -p avon-agent` compiles using re-exported types from mobile-core
3. `cargo test -p avon-mobile-core` passes all extracted tests
4. `cargo test -p avon-agent` passes all existing tests (no regressions)
5. `cargo check -p avon-mobile-core --target aarch64-apple-ios` cross-compiles for iOS
6. `cargo check -p avon-mobile-core --target aarch64-linux-android` cross-compiles for Android

## Success Criteria

- Zero code duplication between avon-mobile-core and avon-agent
- avon-mobile-core has no `#[cfg(target_os)]` directives
- avon-agent's public API is unchanged (re-exports)
- All existing tests pass without modification
- Mobile targets compile (even if untested at runtime)
