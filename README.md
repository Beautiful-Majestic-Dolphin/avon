# AVON - Authenticated Vector Ownership Network

AVON (Authenticated Vector Ownership Network) is a post-quantum compliant zero trust network access platform. It provides secure, authenticated peer-to-peer communication with quantum-resistant cryptography.

## Architecture

AVON consists of three main components:

- **Control Plane**: Kubernetes-deployed services handling authentication, policy, and certificates (Rust + Python)
- **Endpoint Agent**: Cross-platform client installed on devices (Rust)
- **Data Plane**: Direct P2P encrypted tunnels between endpoints (no central routing)

## Project Structure

```
avon/
├── crates/                    # Rust workspace crates
│   ├── avon-crypto/          # Cryptographic primitives
│   ├── avon-protocol/        # Wire protocol definitions
│   ├── avon-common/          # Shared types and utilities
│   ├── avon-agent/           # Endpoint agent binary
│   ├── avon-gateway/         # UDP gateway service
│   ├── avon-auth/            # Authentication service
│   ├── avon-ca/              # Certificate authority
│   └── avon-pulse/           # Pulse manager service
├── services/
│   └── policy-engine/        # Python policy engine
├── api/
│   └── admin-api/            # Python admin API (FastAPI)
├── deploy/
│   ├── docker/               # Dockerfiles
│   ├── helm/                 # Helm charts
│   └── k8s/                  # Kubernetes manifests
├── proto/                    # Protocol buffer definitions
├── docs/                     # Documentation
└── tests/
    ├── integration/          # Integration tests
    └── e2e/                  # End-to-end tests
```

## Building

```bash
# Build all crates
cargo build

# Build in release mode
cargo build --release

# Run tests
cargo test
```

## License

MIT
