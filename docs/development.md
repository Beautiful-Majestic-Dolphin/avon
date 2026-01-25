# AVON Development Guide

This guide covers setting up a development environment and contributing to AVON.

## Table of Contents

- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Building from Source](#building-from-source)
- [Running Locally](#running-locally)
- [Testing](#testing)
- [Code Style](#code-style)
- [Contributing](#contributing)
- [Release Process](#release-process)

## Development Environment

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.75+ | Rust services |
| Python | 3.11+ | Python services |
| Docker | 24+ | Containerization |
| Docker Compose | 2.20+ | Local development |
| protoc | 25+ | Protocol Buffers |
| Helm | 3.12+ | Kubernetes charts |
| kubectl | 1.28+ | Kubernetes CLI |

### Quick Setup (macOS)

```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install development tools
brew install rust python@3.11 protobuf docker docker-compose helm kubectl

# Install Python development tools
pip3 install black ruff mypy pytest pytest-asyncio

# Clone repository
git clone https://github.com/ShaneDolphin/avons-corners.git
cd avons-corners

# Install pre-commit hooks
pip3 install pre-commit
pre-commit install
```

### Quick Setup (Ubuntu/Debian)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install system dependencies
sudo apt update
sudo apt install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  protobuf-compiler \
  python3.11 \
  python3.11-venv \
  python3-pip

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Clone and setup
git clone https://github.com/ShaneDolphin/avons-corners.git
cd avons-corners
pip3 install pre-commit black ruff mypy pytest pytest-asyncio
pre-commit install
```

### IDE Setup

#### VS Code

Recommended extensions:
```json
{
  "recommendations": [
    "rust-lang.rust-analyzer",
    "ms-python.python",
    "ms-python.black-formatter",
    "charliermarsh.ruff",
    "zxh404.vscode-proto3",
    "redhat.vscode-yaml",
    "ms-kubernetes-tools.vscode-kubernetes-tools"
  ]
}
```

Settings (`.vscode/settings.json`):
```json
{
  "rust-analyzer.check.command": "clippy",
  "rust-analyzer.check.allTargets": true,
  "python.formatting.provider": "black",
  "python.linting.enabled": true,
  "python.linting.ruffEnabled": true,
  "[rust]": {
    "editor.formatOnSave": true
  },
  "[python]": {
    "editor.formatOnSave": true
  }
}
```

#### JetBrains (RustRover/PyCharm)

1. Install Rust plugin (for PyCharm)
2. Enable Clippy for Rust linting
3. Configure Black as Python formatter
4. Install Protocol Buffers plugin

## Project Structure

```
avons-corners/
├── crates/                    # Rust workspace
│   ├── avon-crypto/           # Cryptographic primitives
│   ├── avon-protocol/         # Wire protocol implementation
│   ├── avon-common/           # Shared types and utilities
│   ├── avon-gateway/          # Gateway service
│   ├── avon-auth/             # Authentication service
│   ├── avon-ca/               # Certificate authority
│   ├── avon-pulse/            # Heartbeat/pulse service
│   └── avon-agent/            # Endpoint agent
├── services/                  # Python services
│   ├── policy-engine/         # Policy evaluation engine
│   └── admin-api/             # Admin REST API
├── proto/                     # Protocol Buffer definitions
│   ├── auth.proto
│   ├── ca.proto
│   ├── pulse.proto
│   └── policy.proto
├── deploy/                    # Deployment configurations
│   ├── docker/                # Dockerfiles
│   └── helm/                  # Helm charts
├── tests/                     # Test suites
│   ├── e2e/                   # End-to-end tests
│   └── integration/           # Integration tests
├── docs/                      # Documentation
└── .github/                   # GitHub Actions workflows
```

### Crate Dependencies

```
┌──────────────────────────────────────────────────────────────┐
│                    Crate Dependency Graph                     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  avon-agent ──────┬──────────────────────────────────────┐   │
│                   │                                      │   │
│  avon-gateway ────┼─────┬────────────────────────────┐   │   │
│                   │     │                            │   │   │
│  avon-auth ───────┼─────┼────┬───────────────────┐   │   │   │
│                   │     │    │                   │   │   │   │
│  avon-ca ─────────┼─────┼────┼────┬──────────┐   │   │   │   │
│                   │     │    │    │          │   │   │   │   │
│  avon-pulse ──────┼─────┼────┼────┼────┐     │   │   │   │   │
│                   │     │    │    │    │     │   │   │   │   │
│                   ▼     ▼    ▼    ▼    ▼     ▼   ▼   ▼   │   │
│               avon-protocol                              │   │
│                   │                                      │   │
│                   ▼                                      │   │
│               avon-common ◄──────────────────────────────┘   │
│                   │                                          │
│                   ▼                                          │
│               avon-crypto                                    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

## Building from Source

### Rust Services

```bash
# Build all crates
cargo build --workspace

# Build specific crate
cargo build -p avon-gateway

# Build release version
cargo build --workspace --release

# Build with all features
cargo build --workspace --all-features
```

### Python Services

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e services/policy-engine[dev]
pip install -e services/admin-api[dev]
```

### Protocol Buffers

```bash
# Generate Rust code (done automatically by build.rs)
cargo build -p avon-protocol

# Generate Python code
python -m grpc_tools.protoc \
  -I proto \
  --python_out=services/policy-engine/src \
  --grpc_python_out=services/policy-engine/src \
  proto/*.proto
```

### Docker Images

```bash
# Build all images
docker compose build

# Build specific image
docker build -f deploy/docker/Dockerfile.gateway -t avon/gateway .

# Build with BuildKit (faster)
DOCKER_BUILDKIT=1 docker build -f deploy/docker/Dockerfile.gateway -t avon/gateway .
```

## Running Locally

### Using Docker Compose

```bash
# Start all services
docker compose up -d

# Start with logs
docker compose up

# Start specific services
docker compose up gateway auth ca pulse

# View logs
docker compose logs -f gateway

# Stop all services
docker compose down

# Stop and remove volumes
docker compose down -v
```

### Running Individual Services

```bash
# Terminal 1: Gateway
cargo run -p avon-gateway

# Terminal 2: Auth
cargo run -p avon-auth

# Terminal 3: CA
cargo run -p avon-ca

# Terminal 4: Pulse
cargo run -p avon-pulse

# Terminal 5: Policy Engine
cd services/policy-engine
uvicorn main:app --reload --port 8081

# Terminal 6: Admin API
cd services/admin-api
uvicorn main:app --reload --port 8080
```

### Environment Variables

Create `.env` file for local development:

```bash
# .env
AVON_LOG_LEVEL=debug
AVON_GRPC_PORT=50051
DATABASE_URL=postgresql://avon:avon@localhost:5432/avon
REDIS_URL=redis://localhost:6379
JWT_SECRET=dev-secret-do-not-use-in-production
```

### Local Kubernetes (Kind/Minikube)

```bash
# Create cluster
kind create cluster --name avon-dev

# Load images
kind load docker-image avon/gateway:dev --name avon-dev

# Install chart
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-dev.yaml \
  --namespace avon \
  --create-namespace

# Port forward
kubectl port-forward svc/avon-admin-api 8080:8080 -n avon
```

## Testing

### Unit Tests

```bash
# Run all Rust tests
cargo test --workspace

# Run tests for specific crate
cargo test -p avon-crypto

# Run tests with output
cargo test --workspace -- --nocapture

# Run specific test
cargo test -p avon-auth test_authentication

# Run Python tests
pytest services/policy-engine
pytest services/admin-api
```

### Integration Tests

```bash
# Start dependencies
docker compose up -d postgres redis

# Run integration tests
cargo test --test '*' -- --test-threads=1

# Or use the test script
./scripts/run-integration-tests.sh
```

### End-to-End Tests

```bash
# Run E2E test suite
cd tests/e2e
./run_e2e.sh

# Run specific scenario
docker compose -f docker-compose.e2e.yml run test-runner \
  python -m pytest scenarios/test_full_flow.py -v

# Run with debug output
./run_e2e.sh -v --tb=long
```

### Test Coverage

```bash
# Install coverage tools
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --workspace --out Html

# Python coverage
pytest services/policy-engine --cov=policy_engine --cov-report=html
```

### Benchmarks

```bash
# Run benchmarks
cargo bench -p avon-crypto

# Run specific benchmark
cargo bench -p avon-crypto -- kyber
```

## Code Style

### Rust

Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/):

```bash
# Format code
cargo fmt --all

# Check formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
```

Key conventions:
- Use `snake_case` for functions and variables
- Use `CamelCase` for types and traits
- Document public APIs with `///` comments
- Use `#[must_use]` for functions with important return values
- Prefer `Result` over `panic!`

### Python

Follow [PEP 8](https://peps.python.org/pep-0008/) with Black formatting:

```bash
# Format code
black services/

# Check formatting
black --check services/

# Lint with ruff
ruff check services/

# Type check with mypy
mypy services/
```

Key conventions:
- Use type hints for all function signatures
- Use `async`/`await` for I/O operations
- Document functions with docstrings
- Use `pydantic` for data validation

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: cargo-fmt
        name: cargo fmt
        entry: cargo fmt --all --
        language: system
        types: [rust]
        pass_filenames: false

      - id: cargo-clippy
        name: cargo clippy
        entry: cargo clippy --all-targets -- -D warnings
        language: system
        types: [rust]
        pass_filenames: false

  - repo: https://github.com/psf/black
    rev: 24.1.0
    hooks:
      - id: black

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.0
    hooks:
      - id: ruff
```

## Contributing

### Workflow

1. **Fork** the repository
2. **Create branch**: `git checkout -b feature/my-feature`
3. **Make changes** and add tests
4. **Run tests**: `cargo test --workspace && pytest services/`
5. **Commit**: Use conventional commits
6. **Push**: `git push origin feature/my-feature`
7. **Open PR**: Against `main` branch

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(gateway): add UDP connection pooling

- Implement connection pool for better resource management
- Add configuration for pool size
- Include metrics for pool utilization

Closes #123
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code refactoring
- `test`: Tests
- `chore`: Maintenance

### Pull Request Guidelines

- Fill out the PR template completely
- Include tests for new functionality
- Update documentation as needed
- Ensure CI passes
- Request review from maintainers

### Code Review

Reviewers will check:
- [ ] Code quality and style
- [ ] Test coverage
- [ ] Security implications
- [ ] Performance impact
- [ ] Documentation updates

## Release Process

### Version Numbering

AVON follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking API changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Release Steps

1. **Update version** in `Cargo.toml` and `Chart.yaml`
2. **Update CHANGELOG.md**
3. **Create release branch**: `git checkout -b release/v1.2.0`
4. **Run full test suite**
5. **Create PR** and merge to main
6. **Tag release**: `git tag v1.2.0`
7. **Push tag**: `git push origin v1.2.0`
8. **CI builds and publishes** Docker images and Helm chart

### Changelog Format

```markdown
## [1.2.0] - 2024-01-15

### Added
- Feature A description (#123)
- Feature B description (#124)

### Changed
- Change C description (#125)

### Fixed
- Bug D fix description (#126)

### Security
- Security fix E description (#127)
```

## Related Documentation

- [Architecture Overview](architecture.md)
- [API Reference](api-reference.md)
- [Security Documentation](security.md)
