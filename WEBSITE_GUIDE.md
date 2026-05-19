# AVON — Post-Quantum Zero Trust Network Access

## What is AVON?

AVON (Authenticated Vector Ownership Network) is a post-quantum zero trust network access platform that replaces traditional VPNs with a modern, cryptographically-forward security model. Every connection is authenticated, authorized, and continuously verified — no implicit trust is ever granted based on network location.

AVON uses NIST-standardized post-quantum cryptographic algorithms to protect your network against both current threats and future quantum computing attacks. It is built in Rust for performance and safety, deploys natively on Kubernetes, and runs a single-binary agent on Linux, macOS, and Windows endpoints.

---

## Core Concepts

### Zero Trust Architecture

AVON operates on three principles:

- **Never trust, always verify** — every connection is authenticated regardless of where it originates
- **Least privilege** — agents only access resources explicitly permitted by policy
- **Assume breach** — the system limits blast radius through continuous verification and session binding

Unlike traditional VPNs that grant broad network access after a single authentication event, AVON re-evaluates every session continuously. Sessions are validated every 10 seconds through a cryptographic heartbeat protocol, and session tokens rotate every 30 seconds.

### Post-Quantum Cryptography

AVON implements NIST-standardized post-quantum algorithms:

| Algorithm | Standard | Purpose | Security Level |
|-----------|----------|---------|----------------|
| Kyber-1024 | FIPS 203 | Key exchange | NIST Level 5 |
| Dilithium-5 | FIPS 204 | Digital signatures | NIST Level 5 |
| AES-256-GCM | — | Tunnel encryption | 256-bit |
| HKDF-SHA3-256 | — | Key derivation | — |
| HMAC-SHA3-256 | — | Token integrity | — |

These algorithms protect against "harvest now, decrypt later" attacks where adversaries capture encrypted traffic today to decrypt it with future quantum computers.

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         AVON Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐                         │
│   │ Agent 1 │  │ Agent 2 │  │ Agent N │    Endpoints             │
│   └────┬────┘  └────┬────┘  └────┬────┘                         │
│        │            │            │                                │
│        └────────────┼────────────┘                                │
│                     │  UDP 4600 (Post-Quantum Encrypted)          │
│              ┌──────▼──────┐                                      │
│              │   Gateway   │  Load Balanced Entry Point           │
│              └──────┬──────┘                                      │
│                     │  gRPC (mTLS)                                │
│   ┌─────────────────┼─────────────────┐                          │
│   │                 │                 │                           │
│   ▼                 ▼                 ▼                           │
│ ┌──────┐      ┌─────────┐      ┌──────┐                         │
│ │ Auth │      │  Pulse  │      │  CA  │    Control Plane         │
│ └──────┘      └─────────┘      └──────┘                         │
│                     │                                             │
│   ┌─────────────────┼─────────────────┐                          │
│   │                 │                 │                           │
│   ▼                 ▼                 ▼                           │
│ ┌────────────┐ ┌──────────┐ ┌───────────────┐                   │
│ │  Policy    │ │  Admin   │ │  PostgreSQL   │                   │
│ │  Engine    │ │  API     │ │  + Redis      │                   │
│ └────────────┘ └──────────┘ └───────────────┘                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Language | Purpose | Scaling |
|-----------|----------|---------|---------|
| **Gateway** | Rust | UDP entry point for all agent connections. Handles packet validation, rate limiting, and connection multiplexing. | Horizontal, stateless (3+ replicas) |
| **Auth Service** | Rust | Agent authentication, session token generation, credential verification. | Horizontal, stateless |
| **CA Service** | Rust | Post-quantum certificate issuance and revocation using Dilithium signatures. Integrates with HSMs. | Limited horizontal (2 replicas), stateful |
| **Pulse Service** | Rust | Continuous session verification via heartbeat protocol. Manages token rotation and dead session cleanup. | Horizontal, stateless |
| **Policy Engine** | Python/FastAPI | Attribute-based access control (ABAC) evaluation. Context-aware authorization decisions. | Horizontal, stateless |
| **Admin API** | Python/FastAPI | RESTful management interface for agent, policy, and session administration. | Horizontal, stateless |
| **Agent** | Rust | Single-binary endpoint client. Establishes encrypted tunnels, manages TUN interface, and maintains heartbeats. | One per endpoint |

### Data Layer

- **PostgreSQL 14+** — persistent storage for agents, sessions, certificates, and policies
- **Redis 7+** — session caching and ephemeral state

Both support managed cloud services (AWS RDS, Cloud SQL, ElastiCache, Memorystore) or self-hosted deployments.

---

## Features

### Continuous Verification

AVON does not rely on a single authentication event. Once a tunnel is established:

- A cryptographic heartbeat is sent every **10 seconds** (configurable)
- Session tokens rotate every **30 seconds**
- Policy is re-evaluated on every heartbeat — if a device falls out of compliance or policy changes, access is revoked in real time
- Dead sessions are automatically cleaned up

### Attribute-Based Access Control

Policies are evaluated based on multiple contextual attributes:

```yaml
policy:
  name: engineering-production
  rules:
    - name: allow-ssh-production
      action: allow
      subjects:
        groups: [engineering]
        attributes:
          role: senior-engineer
      resources:
        networks: [10.100.0.0/16]
        ports: [22]
        protocols: [tcp]
      conditions:
        time:
          days: [monday, tuesday, wednesday, thursday, friday]
          hours: {start: "08:00", end: "20:00", timezone: "America/New_York"}
        device:
          os: [macOS, Linux]
          posture: compliant

    - name: deny-all
      action: deny
      subjects: {}
      resources: {}
```

Policy evaluation order:
1. Explicit **DENY** rules (highest priority)
2. Explicit **ALLOW** rules
3. Default **DENY** (implicit)

### Cross-Platform Agent

The agent is a single Rust binary with minimal footprint:

| Requirement | Value |
|-------------|-------|
| CPU | 1 core |
| Memory | 128 MB RAM |
| Disk | 50 MB |
| Network | UDP outbound to port 4600 |

Supported platforms:

| Platform | Architecture | Minimum Version |
|----------|-------------|-----------------|
| Linux | x86_64, aarch64 | Kernel 4.19+ |
| macOS | x86_64, arm64 (Apple Silicon) | 11.0+ (Big Sur) |
| Windows | x86_64 | 10/11, Server 2019+ |
| FreeBSD | x86_64 | 13.0+ (Beta) |

### Key Management & Certificate Authority

AVON operates its own post-quantum certificate authority:

```
Root CA Key (Dilithium)
├── Storage: HSM (production) or encrypted file (dev)
├── Validity: 10 years
└── Signs → Intermediate CA

Intermediate CA Key (Dilithium)
├── Validity: 2 years, rotated annually
└── Signs → Agent Certificates

Agent Certificates (Dilithium)
├── Generated on-device during enrollment
├── Private key never leaves the device
├── Validity: 1 year, auto-renewed
└── Storage: OS-native secure storage
    ├── Linux: System keyring
    ├── macOS: Keychain Services
    ├── Windows: DPAPI + Credential Manager
    └── TPM 2.0 (when available)

Session Keys (AES-256)
├── Derived from Kyber key exchange
├── Ephemeral, per-session
└── Rotated every 24 hours
```

### Monitoring & Observability

Every AVON service exposes:

- **Prometheus metrics** on port 9090
- **Health checks** on port 8080 (`/health` and `/ready`)
- **Structured JSON logging** via `tracing-subscriber`

Key metrics include active connections, authentication latency, heartbeat rates, policy decision distributions, and error rates. A Grafana dashboard is included for real-time visibility.

### Compliance Readiness

AVON's architecture supports compliance with:

- SOC 2 Type II
- HIPAA
- PCI DSS
- GDPR
- FedRAMP
- NIST 800-53

All security events are logged with actor, action, resource, outcome, and context for full audit trails.

---

## How It Works

### Enrollment

When a new device is onboarded to AVON:

1. An administrator generates an **enrollment token** via the Admin API or UI
2. The agent generates a **Dilithium-5 key pair** locally — the private key never leaves the device
3. The agent sends its public key and enrollment token to the CA service
4. The CA validates the token, issues a **post-quantum certificate**, and returns it to the agent
5. The agent stores its credentials in OS-native secure storage

```bash
sudo avon-agent enroll \
  --gateway gateway.avon.example.com:4600 \
  --token "ENROLLMENT_TOKEN_HERE" \
  --name "alice-laptop"
```

### Tunnel Establishment

Once enrolled, the agent establishes a secure tunnel:

1. **Key Exchange** — Agent and Gateway perform a Kyber-1024 key encapsulation to derive a shared secret
2. **Authentication** — Agent presents its Dilithium certificate and signs a challenge to prove identity
3. **Policy Check** — The Policy Engine evaluates whether this device should be granted access based on identity, groups, device posture, time, and location
4. **Session Creation** — Auth Service issues a session token bound to the certificate fingerprint
5. **Tunnel Active** — Traffic flows through an AES-256-GCM encrypted UDP tunnel via the TUN interface (`avon0`)

### Continuous Verification (Pulse)

Every 10 seconds while a session is active:

1. Agent sends an encrypted **heartbeat** with a fresh Dilithium signature
2. Pulse Service validates the session and signature
3. Policy Engine **re-evaluates** access — if policy has changed or the device is no longer compliant, the session is terminated
4. Session token is **rotated** and a new token is sent back to the agent

If a heartbeat is missed, the session is marked for cleanup. There is no silent persistence — access requires continuous proof.

---

## Deployment Guide

### Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Kubernetes | 1.26+ | 1.28+ |
| Nodes | 3 | 5+ |
| CPU (total) | 8 cores | 16+ cores |
| Memory (total) | 16 GB | 32+ GB |
| Helm | 3.12+ | Latest |
| Storage Class | Standard | SSD-backed |

External dependencies:
- **PostgreSQL 14+** — AWS RDS, GCP Cloud SQL, Azure Database, or self-hosted
- **Redis 7+** — AWS ElastiCache, GCP Memorystore, or self-hosted
- **Load Balancer** — AWS NLB, GCP Network LB, Azure LB, or MetalLB (on-premise)
- **TLS Certificates** — cert-manager with Let's Encrypt (recommended) or manual

### Quick Start (Docker Compose)

For local development and evaluation:

```bash
git clone https://github.com/ShaneDolphin/avons-corners.git
cd avons-corners

docker compose up -d

docker compose ps
```

This starts all services locally:

| Service | Port | Protocol |
|---------|------|----------|
| Gateway | 4600 | UDP |
| Auth | 50051 | gRPC |
| CA | 50052 | gRPC |
| Pulse | 50053 | gRPC |
| Policy Engine | 8081 | HTTP |
| Admin API | 8080 | HTTP |
| PostgreSQL | 5432 | TCP |
| Redis | 6379 | TCP |

---

### Kubernetes Deployment

#### Step 1: Create Namespace

```bash
kubectl create namespace avon
```

#### Step 2: Configure Secrets

Create a secrets file — do **not** commit this to version control:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: avon-secrets
  namespace: avon
type: Opaque
stringData:
  jwt-secret: "your-secure-jwt-secret-minimum-32-characters"
  database-url: "postgresql://avon:password@postgres-host:5432/avon"
  redis-url: "redis://:password@redis-host:6379"
  database-password: "your-database-password"
  redis-password: "your-redis-password"
```

```bash
kubectl apply -f secrets.yaml
```

#### Step 3: Install with Helm

**Development:**

```bash
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-dev.yaml \
  --namespace avon \
  --set secrets.existingSecret=avon-secrets
```

**Staging:**

```bash
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-staging.yaml \
  --namespace avon \
  --set secrets.existingSecret=avon-secrets
```

**Production:**

```bash
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-production.yaml \
  --namespace avon \
  --set secrets.existingSecret=avon-secrets \
  --set externalDatabase.host=your-rds-endpoint.amazonaws.com \
  --set externalRedis.host=your-elasticache-endpoint.amazonaws.com
```

#### Step 4: Verify

```bash
kubectl get pods -n avon
```

Expected output:

```
NAME                                  READY   STATUS    RESTARTS   AGE
avon-gateway-xxxxx                    1/1     Running   0          2m
avon-gateway-xxxxx                    1/1     Running   0          2m
avon-gateway-xxxxx                    1/1     Running   0          2m
avon-auth-xxxxx                       1/1     Running   0          2m
avon-ca-0                             1/1     Running   0          2m
avon-pulse-xxxxx                      1/1     Running   0          2m
avon-policy-engine-xxxxx              1/1     Running   0          2m
avon-admin-api-xxxxx                  1/1     Running   0          2m
```

Get the gateway external IP:

```bash
kubectl get svc avon-gateway -n avon \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

---

### Cloud-Specific Deployments

#### AWS (EKS)

```yaml
# values-aws.yaml
gateway:
  service:
    type: LoadBalancer
    annotations:
      service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
      service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled: "true"
      service.beta.kubernetes.io/aws-load-balancer-scheme: "internet-facing"

ca:
  hsm:
    enabled: true
    provider: "aws-cloudhsm"

adminApi:
  ingress:
    enabled: true
    className: alb
    annotations:
      alb.ingress.kubernetes.io/scheme: internet-facing
      alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT-ID
    hosts:
      - host: admin.avon.example.com
        paths:
          - path: /
            pathType: Prefix
```

```bash
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-production.yaml \
  -f values-aws.yaml \
  --namespace avon \
  --set secrets.existingSecret=avon-secrets \
  --set externalDatabase.host=avon-db.cluster-xxxxx.us-east-1.rds.amazonaws.com \
  --set externalRedis.host=avon-cache.xxxxx.0001.use1.cache.amazonaws.com
```

#### GCP (GKE)

```yaml
# values-gcp.yaml
gateway:
  service:
    type: LoadBalancer
    annotations:
      cloud.google.com/l4-rbs: "enabled"
      networking.gke.io/load-balancer-type: "External"

ca:
  hsm:
    enabled: true
    provider: "gcp-kms"

adminApi:
  ingress:
    enabled: true
    className: gce
    annotations:
      kubernetes.io/ingress.global-static-ip-name: avon-admin-ip
      networking.gke.io/managed-certificates: avon-admin-cert
    hosts:
      - host: admin.avon.example.com
        paths:
          - path: /
            pathType: Prefix
```

```bash
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-production.yaml \
  -f values-gcp.yaml \
  --namespace avon \
  --set secrets.existingSecret=avon-secrets \
  --set externalDatabase.host=/cloudsql/PROJECT:REGION:INSTANCE \
  --set externalRedis.host=10.0.0.3
```

#### Azure (AKS)

```yaml
# values-azure.yaml
gateway:
  service:
    type: LoadBalancer
    annotations:
      service.beta.kubernetes.io/azure-load-balancer-external: "true"

ca:
  hsm:
    enabled: true
    provider: "azure-dedicated-hsm"

adminApi:
  ingress:
    enabled: true
    className: nginx
    annotations:
      cert-manager.io/cluster-issuer: "letsencrypt-prod"
    hosts:
      - host: admin.avon.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: admin-tls
        hosts:
          - admin.avon.example.com
```

```bash
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-production.yaml \
  -f values-azure.yaml \
  --namespace avon \
  --set secrets.existingSecret=avon-secrets \
  --set externalDatabase.host=avon-db.postgres.database.azure.com \
  --set externalRedis.host=avon-cache.redis.cache.windows.net
```

---

### Bare Metal / On-Premise Deployment

For environments without cloud load balancers, use MetalLB and self-hosted databases.

#### Prerequisites

Install MetalLB for LoadBalancer service support:

```bash
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.14.5/config/manifests/metallb-native.yaml
```

Configure an IP address pool:

```yaml
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: avon-pool
  namespace: metallb-system
spec:
  addresses:
    - 192.168.1.200-192.168.1.210
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: avon-l2
  namespace: metallb-system
spec:
  ipAddressPools:
    - avon-pool
```

#### Deployment

```yaml
# values-bare-metal.yaml
gateway:
  service:
    type: LoadBalancer
    port: 4600

ca:
  persistence:
    enabled: true
    size: 10Gi
    storageClass: "local-path"

adminApi:
  ingress:
    enabled: true
    className: nginx
    annotations:
      cert-manager.io/cluster-issuer: "letsencrypt-prod"
    hosts:
      - host: admin.avon.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: admin-tls
        hosts:
          - admin.avon.example.com
```

```bash
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-production.yaml \
  -f values-bare-metal.yaml \
  --namespace avon \
  --set secrets.existingSecret=avon-secrets \
  --set externalDatabase.host=postgres.internal.example.com \
  --set externalRedis.host=redis.internal.example.com
```

#### Firewall Rules

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Agents (any) | Gateway | 4600 | UDP | Agent tunnels |
| Gateway | Auth | 50051 | TCP | Authentication |
| Gateway | Pulse | 50053 | TCP | Heartbeats |
| Auth | CA | 50052 | TCP | Certificate operations |
| Admins | Admin API | 443 | TCP | Management interface |

---

## Configuration Reference

### Helm Values

```yaml
global:
  imageRegistry: "ghcr.io/shanedolphin/avons-corners"

gateway:
  replicaCount: 3
  service:
    type: LoadBalancer
    port: 4600
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 20
    targetCPUUtilizationPercentage: 70

auth:
  replicaCount: 3
  logLevel: info

ca:
  replicaCount: 2
  persistence:
    enabled: true
    size: 10Gi
    storageClass: "gp3"
  hsm:
    enabled: true
    provider: "aws-cloudhsm"

pulse:
  replicaCount: 3
  pulseInterval: "10s"
  tokenRotationInterval: "30s"

policyEngine:
  replicaCount: 3

adminApi:
  replicaCount: 2
  ingress:
    enabled: true
    className: nginx
    annotations:
      cert-manager.io/cluster-issuer: "letsencrypt-prod"
    hosts:
      - host: admin.avon.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: admin-tls
        hosts:
          - admin.avon.example.com
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AVON_LOG_LEVEL` | `info` | Logging level: `trace`, `debug`, `info`, `warn`, `error` |
| `AVON_GRPC_PORT` | Service-specific | gRPC listen port |
| `AVON_HEALTH_PORT` | `8080` | Health check endpoint port |
| `AVON_METRICS_PORT` | `9090` | Prometheus metrics port |
| `AVON_PULSE_INTERVAL` | `10s` | Agent heartbeat interval |
| `AVON_TOKEN_ROTATION_INTERVAL` | `30s` | Session token rotation period |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `REDIS_URL` | — | Redis connection string |
| `JWT_SECRET` | — | Token signing secret (minimum 32 characters) |

### Resource Allocation by Environment

| Environment | Gateway | Auth | CA | Pulse | Policy Engine | Admin API |
|-------------|---------|------|----|-------|---------------|-----------|
| Development | 50m / 64Mi | 50m / 64Mi | 50m / 64Mi | 50m / 64Mi | 50m / 64Mi | 50m / 64Mi |
| Staging | 100m / 128Mi | 100m / 128Mi | 100m / 128Mi | 100m / 128Mi | 100m / 128Mi | 100m / 128Mi |
| Production | 500m / 512Mi | 250m / 256Mi | 250m / 256Mi | 250m / 256Mi | 250m / 256Mi | 250m / 256Mi |

---

## Agent Installation

### Linux (Debian/Ubuntu)

```bash
# Add AVON repository
curl -fsSL https://packages.avon.example.com/gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/avon-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/avon-archive-keyring.gpg] \
  https://packages.avon.example.com/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/avon.list

sudo apt update && sudo apt install avon-agent
```

### Linux (RHEL/CentOS/Fedora)

```bash
sudo tee /etc/yum.repos.d/avon.repo << 'EOF'
[avon]
name=AVON Repository
baseurl=https://packages.avon.example.com/rpm
enabled=1
gpgcheck=1
gpgkey=https://packages.avon.example.com/gpg
EOF

sudo dnf install avon-agent
```

### Linux (Manual/Binary)

```bash
curl -LO https://github.com/ShaneDolphin/avons-corners/releases/latest/download/avon-agent-linux-amd64.tar.gz

tar -xzf avon-agent-linux-amd64.tar.gz

sudo mv avon-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/avon-agent

avon-agent --version
```

### macOS (Homebrew)

```bash
brew tap shanedolphin/avon
brew install avon-agent
```

After installation, approve the system extension in **System Settings > Privacy & Security**.

### macOS (Manual)

```bash
curl -LO https://github.com/ShaneDolphin/avons-corners/releases/latest/download/avon-agent-macos.dmg

hdiutil attach avon-agent-macos.dmg
sudo installer -pkg "/Volumes/AVON Agent/AVON Agent.pkg" -target /
hdiutil detach "/Volumes/AVON Agent"
```

### Windows (MSI)

Download `avon-agent-windows-amd64.msi` from [releases](https://github.com/ShaneDolphin/avons-corners/releases) and run as Administrator.

**Silent install via PowerShell:**

```powershell
Invoke-WebRequest `
  -Uri "https://github.com/ShaneDolphin/avons-corners/releases/latest/download/avon-agent-windows-amd64.msi" `
  -OutFile "avon-agent.msi"

Start-Process msiexec.exe -Wait -ArgumentList '/i avon-agent.msi /qn'
```

### Windows (Chocolatey)

```powershell
choco install avon-agent
```

### Docker (Testing Only)

```bash
docker run -it --rm \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  ghcr.io/shanedolphin/avons-corners/agent:latest \
  avon-agent --help
```

---

## Agent Usage

### Enroll a Device

Generate an enrollment token from the Admin API:

```bash
curl -X POST https://admin.avon.example.com/api/v1/enrollment-tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "workstation-batch",
    "groups": ["engineering"],
    "expires_in": "24h",
    "max_uses": 10
  }'
```

Then enroll the agent:

```bash
sudo avon-agent enroll \
  --gateway gateway.avon.example.com:4600 \
  --token "ENROLLMENT_TOKEN_HERE" \
  --name "alice-laptop"
```

With a corporate proxy:

```bash
sudo avon-agent enroll \
  --gateway gateway.avon.example.com:4600 \
  --token "ENROLLMENT_TOKEN_HERE" \
  --http-proxy http://proxy.corp.example.com:8080
```

### Check Status

```bash
avon-agent status
```

```
Agent ID:     a1b2c3d4-e5f6-7890-abcd-ef1234567890
Name:         alice-laptop
Status:       Connected
Gateway:      gateway.avon.example.com:4600
Session:      Active (expires in 29m 45s)
Certificate:  Valid (expires in 364 days)
Groups:       engineering, vpn-users
```

### Run as a Service

**Linux (systemd):**

```bash
sudo systemctl enable --now avon-agent
sudo systemctl status avon-agent
sudo journalctl -u avon-agent -f
```

**macOS (launchd):**

```bash
sudo launchctl load /Library/LaunchDaemons/com.avon.agent.plist
sudo launchctl list | grep avon
```

**Windows:**

```powershell
Set-Service -Name AvonAgent -StartupType Automatic
Start-Service AvonAgent
Get-Service AvonAgent
```

### Agent Configuration

Configuration file locations:

| Platform | Path |
|----------|------|
| Linux | `/etc/avon/agent.toml` |
| macOS | `/Library/Application Support/AVON/agent.toml` |
| Windows | `C:\ProgramData\AVON\agent.toml` |

```toml
[gateway]
address = "gateway.avon.example.com:4600"
fallback = [
  "gateway-backup.avon.example.com:4600",
  "gateway-dr.avon.example.com:4600"
]

[connection]
max_retries = 10
retry_delay = "5s"
keepalive_interval = "30s"

[pulse]
interval = "10s"
timeout = "5s"

[interface]
name = "avon0"
mtu = 1400
dns = ["10.100.0.53", "10.100.0.54"]

[logging]
level = "info"
file = "/var/log/avon/agent.log"
format = "json"

[advanced]
metrics_enabled = true
metrics_port = 9091
```

Configuration can also be set via environment variables:

```bash
export AVON_GATEWAY_ADDRESS="gateway.avon.example.com:4600"
export AVON_LOG_LEVEL="debug"
export AVON_PULSE_INTERVAL="10s"
```

---

## Enterprise Deployment Patterns

### Mass Enrollment

For large-scale deployments, create enrollment tokens with multiple uses and distribute via your configuration management tool:

```bash
# Generate a batch token
curl -X POST https://admin.avon.example.com/api/v1/enrollment-tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fleet-rollout-q1",
    "groups": ["default", "corporate"],
    "expires_in": "72h",
    "max_uses": 500
  }'
```

**Ansible playbook:**

```yaml
- name: Install and enroll AVON agent
  hosts: workstations
  become: true
  tasks:
    - name: Install AVON agent
      apt:
        name: avon-agent
        state: present

    - name: Enroll agent
      command: >
        avon-agent enroll
        --gateway gateway.avon.example.com:4600
        --token "{{ avon_enrollment_token }}"
        --name "{{ inventory_hostname }}"
      args:
        creates: /var/lib/avon/agent.pem

    - name: Enable and start service
      systemd:
        name: avon-agent
        enabled: true
        state: started
```

**Terraform (infrastructure provisioning):**

```hcl
resource "helm_release" "avon" {
  name       = "avon"
  namespace  = "avon"
  chart      = "./deploy/helm/avon"

  values = [
    file("values-production.yaml"),
    file("values-aws.yaml")
  ]

  set {
    name  = "secrets.existingSecret"
    value = "avon-secrets"
  }

  set {
    name  = "externalDatabase.host"
    value = aws_rds_cluster.avon.endpoint
  }

  set {
    name  = "externalRedis.host"
    value = aws_elasticache_replication_group.avon.primary_endpoint_address
  }
}
```

### MDM Integration (macOS/Windows)

Distribute the agent and enrollment token via your MDM solution:

**Jamf (macOS):** Deploy the `.pkg` installer and a configuration profile that writes `/Library/Application Support/AVON/agent.toml` with the gateway address and enrollment token.

**Intune (Windows):** Deploy the `.msi` installer as a Win32 app. Use a PowerShell script to run the enrollment command post-install.

**SCCM (Windows):** Create a deployment package with the MSI and a task sequence that installs and enrolls.

### Multi-Region Deployment

For global organizations, deploy AVON in multiple regions with DNS-based routing:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Global DNS                                │
│                   (Latency-based routing)                        │
└─────────────────────────────────────────────────────────────────┘
                    │                   │
        ┌───────────▼───────────┐ ┌─────▼─────────────┐
        │     Region: US-East   │ │  Region: EU-West   │
        │                       │ │                    │
        │  ┌─────────────────┐  │ │ ┌──────────────┐   │
        │  │   Gateway Pool  │  │ │ │ Gateway Pool │   │
        │  └────────┬────────┘  │ │ └──────┬───────┘   │
        │           │           │ │        │           │
        │  ┌────────▼────────┐  │ │ ┌──────▼───────┐   │
        │  │  Control Plane  │  │ │ │Control Plane │   │
        │  └────────┬────────┘  │ │ └──────┬───────┘   │
        │           │           │ │        │           │
        │  ┌────────▼────────┐  │ │ ┌──────▼───────┐   │
        │  │   PostgreSQL    │◄─┼─┼─┤ PostgreSQL   │   │
        │  │    (Primary)    │  │ │ │  (Replica)   │   │
        │  └─────────────────┘  │ │ └──────────────┘   │
        └───────────────────────┘ └────────────────────┘
```

Configure the agent with fallback gateways:

```toml
[gateway]
address = "gateway-us.avon.example.com:4600"
fallback = [
  "gateway-eu.avon.example.com:4600",
  "gateway-ap.avon.example.com:4600"
]
```

---

## Scaling & High Availability

### Capacity Planning

| Connected Agents | Gateway Pods | Auth Pods | Pulse Pods | Database Connections |
|------------------|--------------|-----------|------------|----------------------|
| 100 | 2 | 2 | 2 | 20 |
| 1,000 | 3 | 3 | 3 | 50 |
| 10,000 | 5 | 5 | 5 | 100 |
| 100,000 | 15 | 10 | 10 | 300 |

### Horizontal Pod Autoscaling

```yaml
gateway:
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 20
    targetCPUUtilizationPercentage: 60

auth:
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
```

Or manually:

```bash
kubectl scale deployment avon-gateway -n avon --replicas=5
```

### Pod Disruption Budgets

Enabled by default to ensure availability during upgrades and node maintenance:

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

For stricter HA requirements:

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 2
```

### Zone-Aware Spreading

Production deployments should spread pods across availability zones:

```yaml
gateway:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app.kubernetes.io/component: gateway
```

### Database High Availability

- **PostgreSQL:** Use Multi-AZ managed services (RDS, Cloud SQL). Configure read replicas for read-heavy workloads. Enable automated backups.
- **Redis:** Use managed services with replication (ElastiCache, Memorystore). Enable Redis Cluster mode for deployments over 10,000 agents.

---

## Operations

### Upgrades

**Rolling upgrade:**

```bash
helm upgrade avon deploy/helm/avon \
  -f deploy/helm/avon/values-production.yaml \
  --namespace avon \
  --set global.imageTag=v1.2.0

kubectl rollout status deployment/avon-gateway -n avon
kubectl rollout status deployment/avon-auth -n avon
```

**Rollback:**

```bash
helm history avon -n avon
helm rollback avon 1 -n avon
```

### Backup & Recovery

**Database backup (automated CronJob):**

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: avon-db-backup
  namespace: avon
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: postgres:16
              command:
                - /bin/sh
                - -c
                - |
                  pg_dump -h $DB_HOST -U avon -d avon | \
                  gzip | \
                  aws s3 cp - s3://avon-backups/postgres/backup-$(date +%Y%m%d).sql.gz
              envFrom:
                - secretRef:
                    name: avon-secrets
          restartPolicy: OnFailure
```

**CA key backup:**

```bash
kubectl exec -n avon avon-ca-0 -- \
  avon-ca export --encrypt --output /data/ca-export.enc

kubectl cp avon/avon-ca-0:/data/ca-export.enc ./ca-backup.enc
```

Store CA backups in HSM-protected or offline storage. This is your most critical asset.

### Monitoring

All services expose Prometheus metrics on port 9090. Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `avon_gateway_connections_active` | Gauge | Currently connected agents |
| `avon_gateway_packets_total` | Counter | Total packets processed |
| `avon_auth_requests_total` | Counter | Authentication requests by status |
| `avon_auth_duration_seconds` | Histogram | Authentication latency |
| `avon_pulse_heartbeats_total` | Counter | Heartbeats processed |
| `avon_pulse_sessions_expired` | Counter | Sessions terminated |
| `avon_policy_evaluations_total` | Counter | Policy decisions by result |

A Grafana dashboard ConfigMap is included in the Helm chart with panels for connected agents, active tunnels, auth latency, packet rate, and policy decision distribution.

### Log Aggregation

All services emit structured JSON logs compatible with any log aggregation platform:

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "info",
  "target": "avon_gateway::handler",
  "message": "connection.established",
  "agent_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "session_id": "sess_xyz789",
  "source_ip": "203.0.113.42"
}
```

Supported aggregation targets:
- Loki + Promtail (recommended for Kubernetes)
- Elasticsearch + Logstash + Kibana (ELK)
- Splunk (via HTTP Event Collector)
- Datadog
- AWS CloudWatch
- New Relic

---

## Admin API Reference

**Base URL:** `https://admin.avon.example.com/api/v1`

**Authentication:** Bearer token (JWT) in the `Authorization` header.

### Agents

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/agents` | List all agents (supports `?status=online&page=1&per_page=20`) |
| `GET` | `/agents/{id}` | Get agent details |
| `DELETE` | `/agents/{id}` | Remove an agent |
| `POST` | `/agents/{id}/revoke` | Revoke agent certificate |

**Example — List online agents:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://admin.avon.example.com/api/v1/agents?status=online"
```

### Enrollment Tokens

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/enrollment-tokens` | List tokens |
| `POST` | `/enrollment-tokens` | Create a token |
| `DELETE` | `/enrollment-tokens/{id}` | Revoke a token |

**Example — Create an enrollment token:**

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "batch-engineering",
    "groups": ["engineering"],
    "expires_in": "24h",
    "max_uses": 50
  }' \
  "https://admin.avon.example.com/api/v1/enrollment-tokens"
```

### Policies

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/policies` | List all policies |
| `POST` | `/policies` | Create a policy |
| `PUT` | `/policies/{id}` | Update a policy |
| `DELETE` | `/policies/{id}` | Delete a policy |
| `POST` | `/policies/evaluate` | Dry-run policy evaluation |

**Example — Dry-run a policy check:**

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "resource": {
      "network": "10.100.5.0/24",
      "port": 443,
      "protocol": "tcp"
    }
  }' \
  "https://admin.avon.example.com/api/v1/policies/evaluate"
```

### Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/sessions` | List active sessions |
| `DELETE` | `/sessions/{id}` | Terminate a session |
| `POST` | `/sessions/terminate-all` | Emergency: terminate all sessions |

### Groups

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/groups` | List groups |
| `POST` | `/groups` | Create a group |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |

---

## Security Model

### Defense in Depth

```
Layer 7: Application Security
├── Input validation
├── Rate limiting
└── Audit logging

Layer 6: Authentication & Authorization
├── Post-quantum certificates (Dilithium-5)
├── Continuous session verification (Pulse)
└── Attribute-based access control (ABAC)

Layer 5: Cryptographic Protection
├── Post-quantum key exchange (Kyber-1024)
├── AES-256-GCM tunnel encryption
└── HMAC-SHA3-256 token integrity

Layer 4: Network Security
├── mTLS for all internal service communication
├── Kubernetes network policies
└── Firewall rules (UDP 4600 only external surface)

Layer 3: Infrastructure Security
├── Pod security policies (non-root, read-only filesystem)
├── Kubernetes RBAC
└── Secret encryption at rest
```

### Trust Boundaries

```
┌─ Internet (Untrusted) ────────┬─ Gateway DMZ ────────┬─ Cluster (Trusted) ──┐
│                                │                      │                       │
│  Agents ↔ Gateway              │  Gateway ↔ Control   │  Service ↔ Service    │
│  UDP 4600                      │  gRPC 50051-50053    │  Service Mesh mTLS    │
│  Post-quantum encrypted        │  mTLS certificates   │  Network policies     │
│                                │                      │                       │
└────────────────────────────────┴──────────────────────┴───────────────────────┘
```

### HSM Integration

Production deployments should protect CA keys with Hardware Security Modules:

| Provider | Integration Method |
|----------|--------------------|
| AWS CloudHSM | Native |
| Azure Dedicated HSM | PKCS#11 |
| Google Cloud HSM | Cloud KMS |
| Thales Luna | PKCS#11 |
| YubiHSM 2 | Native (small deployments) |

### Audit Logging

All security events are emitted as structured JSON with full context:

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "event_type": "authentication.success",
  "severity": "info",
  "actor": {
    "type": "agent",
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "alice-laptop"
  },
  "action": "authenticate",
  "resource": {
    "type": "session",
    "id": "sess_xyz789"
  },
  "outcome": "success",
  "context": {
    "source_ip": "192.168.1.100",
    "user_agent": "avon-agent/1.0.0",
    "certificate_fingerprint": "SHA256:abc123..."
  }
}
```

### Incident Response

**Revoke a compromised agent immediately:**

```bash
curl -X POST https://admin.avon.example.com/api/v1/agents/{id}/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"reason": "compromised", "immediate": true}'
```

**Emergency CA key rotation:**

```bash
kubectl exec -n avon avon-ca-0 -- \
  avon-ca emergency-rotate --reason "key compromise"
```

**Terminate all active sessions:**

```bash
curl -X POST https://admin.avon.example.com/api/v1/sessions/terminate-all \
  -H "Authorization: Bearer $TOKEN"
```

---

## Troubleshooting

### Agent Cannot Reach Gateway

```bash
# Test UDP connectivity
nc -u -v gateway.avon.example.com 4600

# Check DNS resolution
dig gateway.avon.example.com

# Run agent with debug logging
sudo avon-agent run --log-level debug
```

### Firewall Configuration

**Linux:**
```bash
sudo ufw allow out 4600/udp
```

**macOS:**
```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw \
  --add /usr/local/bin/avon-agent
```

**Windows (PowerShell as Admin):**
```powershell
New-NetFirewallRule -DisplayName "AVON Agent" `
  -Direction Outbound -Protocol UDP -LocalPort 4600 -Action Allow
```

### TUN Device Issues

**Linux:**
```bash
lsmod | grep tun
sudo modprobe tun
echo "tun" | sudo tee /etc/modules-load.d/tun.conf
```

**macOS:** Open System Settings > Privacy & Security and approve the AVON system extension.

**Windows:** Reinstall the TAP driver from `C:\Program Files\AVON\tap-installer.exe`.

### Certificate Issues

```bash
# Check certificate validity
avon-agent cert info

# Re-enroll with a new token
sudo avon-agent enroll --force \
  --gateway gateway.avon.example.com:4600 \
  --token "NEW_TOKEN"
```

### Diagnostic Commands

```bash
# Full diagnostic report
avon-agent diagnostics

# Network connectivity test
avon-agent diagnostics --network

# Validate configuration
avon-agent config validate

# Export debug bundle for support
avon-agent diagnostics --export /tmp/avon-debug.zip
```

### Kubernetes Troubleshooting

**Pods stuck in Pending:**
```bash
kubectl describe pod <pod-name> -n avon
```

**Database connectivity:**
```bash
kubectl run -it --rm debug --image=postgres:16 -n avon -- \
  psql -h avon-postgresql -U avon -d avon -c "SELECT 1"
```

**Gateway not getting external IP:**
```bash
kubectl describe svc avon-gateway -n avon
```

For on-premise deployments, verify MetalLB is configured and an IP address pool is available.

### Log Locations

| Platform | Path |
|----------|------|
| Linux | `/var/log/avon/agent.log` or `journalctl -u avon-agent` |
| macOS | `/Library/Logs/AVON/agent.log` or Console.app |
| Windows | `C:\ProgramData\AVON\logs\agent.log` or Event Viewer |
