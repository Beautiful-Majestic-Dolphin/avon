```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     █████╗ ██╗   ██╗ ██████╗ ███╗   ██╗                      ║
║    ██╔══██╗██║   ██║██╔═══██╗████╗  ██║                      ║
║    ███████║██║   ██║██║   ██║██╔██╗ ██║                      ║
║    ██╔══██║╚██╗ ██╔╝██║   ██║██║╚██╗██║                      ║
║    ██║  ██║ ╚████╔╝ ╚██████╔╝██║ ╚████║                      ║
║    ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═══╝                      ║
║                                                               ║
║    Authenticated Vector Ownership Network                     ║
║    Own Your Corners.                                          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

# AVON - Authenticated Vector Ownership Network

[![CI](https://github.com/Beautiful-Majestic-Dolphin/avon/actions/workflows/ci.yml/badge.svg)](https://github.com/Beautiful-Majestic-Dolphin/avon/actions/workflows/ci.yml)
[![E2E Tests](https://github.com/Beautiful-Majestic-Dolphin/avon/actions/workflows/e2e.yml/badge.svg)](https://github.com/Beautiful-Majestic-Dolphin/avon/actions/workflows/e2e.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AVON is a **post-quantum zero trust network access (ZTNA)** platform that provides secure, authenticated connectivity without implicit network trust. Built with quantum-resistant cryptography, AVON ensures your network remains secure against both current and future threats.

## Key Features

- **Post-Quantum Security**: Hybrid post-quantum cryptography: X25519 + ML-KEM-768 key exchange, Ed25519 + ML-DSA-65 signatures, AES-256-GCM / ChaCha20-Poly1305 transport
- **Zero Trust Architecture**: Never trust, always verify - every connection is authenticated
- **Continuous Verification**: Sessions are validated continuously, not just at connection time
- **Policy-Based Access**: Fine-grained, context-aware access control
- **Cloud Native**: Kubernetes-first deployment with Helm charts
- **Cross-Platform Agent**: Single binary for Linux, macOS, and Windows

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         AVON Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐                        │
│   │ Agent 1 │  │ Agent 2 │  │ Agent N │    Endpoints           │
│   └────┬────┘  └────┬────┘  └────┬────┘                        │
│        │            │            │                              │
│        └────────────┼────────────┘                              │
│                     │                                           │
│              ┌──────▼──────┐                                    │
│              │   Gateway   │◄──── UDP (Post-Quantum Encrypted)  │
│              └──────┬──────┘                                    │
│                     │                                           │
│   ┌─────────────────┼─────────────────┐                        │
│   │                 │                 │                        │
│   ▼                 ▼                 ▼                        │
│ ┌──────┐      ┌─────────┐      ┌──────┐                       │
│ │ Auth │      │  Pulse  │      │  CA  │    Control Plane      │
│ └──────┘      └─────────┘      └──────┘                       │
│                     │                                           │
│   ┌─────────────────┼─────────────────┐                        │
│   │                 │                 │                        │
│   ▼                 ▼                 ▼                        │
│ ┌────────────┐ ┌──────────┐ ┌───────────────┐                 │
│ │  Policy    │ │ Admin    │ │  PostgreSQL   │                 │
│ │  Engine    │ │ API      │ │  + Redis      │                 │
│ └────────────┘ └──────────┘ └───────────────┘                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Kubernetes cluster (for production) or Kind/Minikube (for development)
- Helm 3.12+

### Local Development

```bash
# Clone the repository
git clone https://github.com/Beautiful-Majestic-Dolphin/avon.git
cd avon

# Start all services with Docker Compose
docker compose up -d

# Verify services are running
docker compose ps

# View logs
docker compose logs -f gateway
```

### Kubernetes Deployment

```bash
# Create namespace
kubectl create namespace avon

# Install with Helm
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-dev.yaml \
  --namespace avon

# Check deployment status
kubectl get pods -n avon

# Get gateway external IP
kubectl get svc avon-gateway -n avon
```

### Agent Installation

```bash
# Download agent (Linux example)
curl -LO https://github.com/Beautiful-Majestic-Dolphin/avon/releases/latest/download/avon-agent-linux-amd64.tar.gz
tar -xzf avon-agent-linux-amd64.tar.gz
sudo mv avon-agent /usr/local/bin/

# Enroll agent
sudo avon-agent enroll \
  --gateway gateway.avon.example.com:4600 \
  --token "YOUR_ENROLLMENT_TOKEN"

# Start agent
sudo systemctl start avon-agent
```

## Project Structure

```
avons-corners/
├── crates/                    # Rust workspace
│   ├── avon-crypto/           # Post-quantum cryptography (ML-KEM-768, ML-DSA-65)
│   ├── avon-protocol/         # Wire protocol implementation
│   ├── avon-common/           # Shared types and utilities
│   ├── avon-gateway/          # UDP gateway service
│   ├── avon-auth/             # Authentication service (gRPC)
│   ├── avon-ca/               # Certificate authority
│   ├── avon-pulse/            # Heartbeat/session service
│   └── avon-agent/            # Endpoint agent binary
├── services/                  # Python services
│   ├── policy-engine/         # Policy evaluation (FastAPI)
│   └── admin-api/             # Admin REST API (FastAPI)
├── proto/                     # Protocol Buffer definitions
├── deploy/
│   ├── docker/                # Dockerfiles for all services
│   └── helm/                  # Helm charts with env-specific values
├── tests/
│   ├── integration/           # Integration tests
│   └── e2e/                   # End-to-end tests (Docker Compose)
├── docs/                      # Comprehensive documentation
└── .github/workflows/         # CI/CD pipelines
```

## Building from Source

### Rust Services

```bash
# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install protoc
# macOS: brew install protobuf
# Ubuntu: apt install protobuf-compiler

# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Build release
cargo build --workspace --release
```

### Python Services

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install services
pip install -e services/policy-engine[dev]
pip install -e api/admin-api[dev]

# Run tests
pytest services/
```

### Docker Images

```bash
# Build all images
docker compose build

# Or build specific image
docker build -f deploy/docker/Dockerfile.gateway -t avon/gateway .
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, components, data flows |
| [Deployment](docs/deployment.md) | Kubernetes/Helm installation guide |
| [Operations](docs/operations.md) | Monitoring, troubleshooting, performance |
| [Agent Installation](docs/agent-installation.md) | Cross-platform agent setup |
| [API Reference](docs/api-reference.md) | REST API and gRPC documentation |
| [Security](docs/security.md) | Threat model, cryptography, compliance |
| [Development](docs/development.md) | Contributing and building from source |

## Configuration

### Control Plane

The control plane is configured via Helm values. Environment-specific files are provided:

| Environment | File | Description |
|-------------|------|-------------|
| Development | `values-dev.yaml` | Single replicas, debug logging |
| Staging | `values-staging.yaml` | HA setup, TLS enabled |
| Production | `values-production.yaml` | Full HA, HSM, external DBs |

### Agent

Agent configuration (`/etc/avon/agent.toml`):

```toml
[gateway]
address = "gateway.avon.example.com:4600"

[pulse]
interval = "10s"

[logging]
level = "info"
```

## Security

AVON implements defense-in-depth with:

- **Post-Quantum Cryptography**: Hybrid post-quantum cryptography: X25519 + ML-KEM-768 key exchange, Ed25519 + ML-DSA-65 signatures, AES-256-GCM / ChaCha20-Poly1305 transport
- **Zero Trust Model**: No implicit trust based on network location
- **Continuous Authentication**: Session tokens rotated every 30 seconds
- **Policy-Based Access Control**: Context-aware authorization decisions
- **Audit Logging**: Comprehensive logging of all security events

See [Security Documentation](docs/security.md) for threat model and compliance details.

## Contributing

We welcome contributions! Please see our [Development Guide](docs/development.md) for:

- Setting up your development environment
- Code style and conventions
- Running tests
- Submitting pull requests

### Quick Contribution Steps

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes and add tests
4. Run tests: `cargo test --workspace && pytest services/`
5. Submit a pull request

## Roadmap

- [ ] Windows agent with TPM 2.0 support
- [ ] Mobile agents (iOS, Android)
- [ ] Service mesh integration (Istio, Linkerd)
- [ ] Hardware security key support (YubiKey, SoloKey)
- [ ] SCIM provisioning
- [ ] Advanced analytics dashboard

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [pqcrypto](https://github.com/rustpq/pqcrypto) - Post-quantum cryptography implementations
- [tokio](https://tokio.rs/) - Async runtime for Rust
- [tonic](https://github.com/hyperium/tonic) - gRPC framework
- [FastAPI](https://fastapi.tiangolo.com/) - Python web framework

---

**AVON** - Secure access for the post-quantum era.
