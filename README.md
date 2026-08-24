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
- **Cross-Platform Agent**: Linux, macOS and Windows, with platform-native data
  planes (TUN, utun, WinTun) and packaging (deb/rpm, signed pkg, MSI). Hardware
  key custody currently varies by platform — see Project status

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
│ ┌─────────┐   ┌──────────┐    ┌──────┐                        │
│ │ Control │   │  Attest  │    │  CA  │    Control Plane       │
│ └─────────┘   └──────────┘    └──────┘                        │
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

## Project status

AVON is under active development and is **not yet production-ready**. This
section records what is currently proven, what is known to be incomplete, and how
to check for yourself — so the claims above can be read with the right
expectations.

A layered end-to-end harness (`tests/e2e/`) brings the system up one layer at a
time and reports a verdict per layer. It is deliberately built to refuse to
report success it has not earned: a scenario that asserts nothing fails, a
skipped scenario fails, and a known gap is reported as `MISSING` rather than
quietly passing.

```bash
cd tests/e2e && uv run python runner.py       # walk every layer
cd tests/e2e && uv run python runner.py --layer l2   # one layer plus prerequisites
```

**Proven by that harness today:**

| Layer | What it covers | Verdict |
|---|---|---|
| Build | Workspace compiles, images build | pass |
| Crypto | Hybrid PQ primitives, AEAD suites, replay window, test vectors | pass |
| Control plane | Enrollment, single-use and expiring tokens, uniform rejection | pass |
| Data plane | Tunnel carries HTTP, SSH, Postgres, UDP; rekey; relay | under repair |
| Policy, device trust, network | — | blocked on the data plane |

**Known gaps, stated plainly:**

- **An agent cannot reach a gateway advertised by DNS name.** The responder
  endpoint is parsed as a literal socket address and never resolved, so a gateway
  published as `host:port` is rejected (`avon-agent-core/src/session_manager.rs`).
  Use a literal address for the gateway's public endpoint until this is fixed.
- **Peer-to-peer direct paths are not wired.** `PeerManager` exists and the
  forwarding path prefers a direct session, but nothing in the run loop dials a
  peer, so all agent-to-agent traffic relays through the gateway. The harness
  records this as `MISSING` rather than pretending otherwise.
- **Hardware key custody is real only on Linux.** The TPM 2.0 provider seals key
  material against a real TPM and produces genuine `TPM2_Quote` attestations. The
  macOS Keychain and Windows CNG providers are currently **simulations** that do
  not call `SecKeyCreateRandomKey` or `NCryptCreatePersistedKey`; each says so in
  its own module header. Use `--key-provider tpm2` on Linux for hardware-backed
  identity, and treat macOS and Windows as software custody until those land.
- **Kubernetes deployment is not yet exercised** by the harness. The Helm chart
  installs, but no automated test proves a working deployment from it.

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

# Passwords for Postgres, Redis and the first owner account
cp .env.example .env && $EDITOR .env

# TLS for the Postgres and Redis listeners. These cannot be AVON-issued: both
# databases must be up before avon-ca exists. Written to
# deploy/compose/infra-certs/ (gitignored), trusted only by this stack.
./deploy/compose/gen-infra-certs.sh

# Start the stack. A one-shot `bootstrap` container applies the schema, creates
# the CA master key and chain, issues every service certificate, and prints an
# enrollment token for the first agent.
docker compose up -d

# Verify services are running
docker compose ps

# The enrollment token is printed once, here
docker compose logs bootstrap

# Control reports database, Redis and CA health on /ready
curl -fsS http://localhost:8080/ready
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

# Enroll agent. --control is the control plane, not the gateway; the agent
# learns its gateway from the control plane after enrolling.
sudo avon-agent enroll \
  --control https://control.avon.example.com:50051 \
  --token "YOUR_ENROLLMENT_TOKEN" \
  --ca-file /etc/avon/trust-ca.crt \
  --key-provider auto

# `--key-provider auto` prefers hardware key custody where it is available and
# falls back to the software provider with a warning naming the reason.

# Start agent
sudo systemctl start avon-agent
```

## Project Structure

```
avons-corners/
├── crates/                    # Rust workspace (19 crates)
│   ├── avon-crypto/           # Post-quantum cryptography (ML-KEM-768, ML-DSA-65)
│   ├── avon-protocol/         # Wire protocol definitions (protobuf v2)
│   ├── avon-tunnel/           # ATP/2 data-plane transport
│   ├── avon-common/           # Shared types and utilities
│   ├── avon-config/           # Configuration loading
│   ├── avon-db/               # Schema and database access
│   ├── avon-tls/              # TLS/mTLS setup for every service
│   ├── avon-control/          # Control plane: enroll, authenticate, pulse, sessions
│   ├── avon-ca/               # Certificate authority and key custody
│   ├── avon-policy/           # Policy engine (Cedar)
│   ├── avon-attest/           # Attestation evidence and TPM quote verification
│   ├── avon-keystore/         # Key providers: software, TPM 2.0, Keychain, CNG
│   ├── avon-gateway/          # UDP gateway service
│   ├── avon-tun/              # Platform TUN devices (Linux, macOS, WinTun)
│   ├── avon-agent-core/       # Agent run loop, shared with future mobile agents
│   ├── avon-agent/            # Endpoint agent binary and privileged helper
│   ├── avon-bootstrap/        # One-shot cluster bootstrap
│   ├── avon-observability/    # Health, readiness, metrics, tracing
│   └── avon-testkit/          # Test fixtures and fault injection
├── services/                  # Python services
│   └── admin-api/             # Admin REST API (FastAPI)
├── proto/                     # Protocol Buffer definitions
├── deploy/
│   ├── docker/                # Dockerfiles for all services
│   └── helm/                  # Helm charts with env-specific values
├── migrations/                # SQL schema
├── tests/
│   ├── compose/               # Compose smoke tests
│   ├── golden/                # Golden files for generated firewall rules
│   └── e2e/                   # Layered end-to-end harness (Docker Compose)
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

- [x] Windows agent (WinTun data plane, service, MSI installer)
- [x] macOS agent (utun, signed pkg, launchd)
- [x] TPM 2.0 key custody and attestation (Linux)
- [ ] Hardware-backed key custody on macOS and Windows — see Project status
- [ ] Peer-to-peer direct paths (the mechanism exists; it is not wired into the run loop)
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
