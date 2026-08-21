# AVON Security Documentation

This document describes the security architecture, threat model, and cryptographic implementation of AVON.

## Table of Contents

- [Security Overview](#security-overview)
- [Threat Model](#threat-model)
- [Cryptographic Algorithms](#cryptographic-algorithms)
- [Key Management](#key-management)
- [Authentication](#authentication)
- [Authorization](#authorization)
- [Network Security](#network-security)
- [Compliance Considerations](#compliance-considerations)
- [Security Best Practices](#security-best-practices)
- [Incident Response](#incident-response)

## Security Overview

AVON implements a defense-in-depth security model with multiple layers of protection:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Security Layers                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 7: Application Security                                  │
│  ├── Input validation                                           │
│  ├── Rate limiting                                              │
│  └── Audit logging                                              │
│                                                                 │
│  Layer 6: Authentication & Authorization                        │
│  ├── Post-quantum certificates (ML-DSA-65)                      │
│  ├── Continuous session verification                            │
│  └── Policy-based access control                                │
│                                                                 │
│  Layer 5: Cryptographic Protection                              │
│  ├── Hybrid key exchange (X25519 + ML-KEM-768)                          │
│  ├── AES-256-GCM encryption                                     │
│  └── HMAC-SHA3 integrity                                        │
│                                                                 │
│  Layer 4: Network Security                                      │
│  ├── mTLS for service communication                             │
│  ├── Network policies (Kubernetes)                              │
│  └── Firewall rules                                             │
│                                                                 │
│  Layer 3: Infrastructure Security                               │
│  ├── Pod security policies                                      │
│  ├── Read-only containers                                       │
│  └── Non-root execution                                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Security Principles

1. **Zero Trust**: No implicit trust based on network location
2. **Least Privilege**: Minimum necessary permissions
3. **Defense in Depth**: Multiple security layers
4. **Post-Quantum Ready**: Quantum-resistant cryptography
5. **Continuous Verification**: Ongoing session validation

## Threat Model

### Assets

| Asset | Sensitivity | Description |
|-------|-------------|-------------|
| CA Private Key | Critical | Signs all agent certificates |
| Agent Certificates | High | Authenticate agents to network |
| Session Tokens | High | Grant temporary access |
| Policies | Medium | Define access rules |
| Audit Logs | Medium | Evidence of actions |
| Traffic Data | Varies | User network traffic |

### Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| Nation State | High | Espionage, sabotage |
| Organized Crime | Medium | Financial gain |
| Insider Threat | Medium | Data theft, sabotage |
| Opportunistic Attacker | Low | Random exploitation |

### Attack Vectors

#### 1. Network-Based Attacks

| Attack | Risk | Mitigation |
|--------|------|------------|
| Traffic Interception | High | Post-quantum encryption, perfect forward secrecy |
| Replay Attacks | Medium | Sequence numbers, timestamps, nonces |
| DDoS | Medium | Rate limiting, cloud DDoS protection |
| Man-in-the-Middle | High | Certificate pinning, mutual authentication |

#### 2. Cryptographic Attacks

| Attack | Risk | Mitigation |
|--------|------|------------|
| Quantum Computer (Future) | High | ML-KEM-768/ML-DSA-65 post-quantum algorithms |
| Key Compromise | Critical | HSM storage, key rotation |
| Side-Channel | Low | Constant-time implementations |

#### 3. Application-Level Attacks

| Attack | Risk | Mitigation |
|--------|------|------------|
| Injection | Medium | Input validation, parameterized queries |
| Authentication Bypass | High | Multi-factor auth, certificate validation |
| Session Hijacking | High | Token rotation, binding to device |

#### 4. Endpoint Attacks

| Attack | Risk | Mitigation |
|--------|------|------------|
| Agent Compromise | High | Secure key storage, attestation |
| Credential Theft | High | Short-lived tokens, TPM storage |
| Malware | Medium | Device posture checking |

### STRIDE Analysis

| Threat | Component | Mitigation |
|--------|-----------|------------|
| **S**poofing | Agent Identity | ML-DSA-65 certificates, device binding |
| **T**ampering | Network Traffic | AES-GCM authenticated encryption |
| **R**epudiation | Actions | Comprehensive audit logging |
| **I**nformation Disclosure | Sensitive Data | Encryption at rest and in transit |
| **D**enial of Service | Gateway | Rate limiting, horizontal scaling |
| **E**levation of Privilege | Policy Engine | RBAC, principle of least privilege |

## Cryptographic Algorithms

### Profile (NIST Category 3 + 128-bit classical)

| Primitive | Algorithm | Standard | Size |
|-----------|-----------|----------|------|
| KEM | ML-KEM-768 | FIPS 203 | pk 1184, sk 2400, ct 1088, ss 32 |
| Signature | ML-DSA-65 | FIPS 204 | pk 1952, sk 4032, sig 3309 |
| Classical KEM | X25519 | RFC 7748 | pk 32, ss 32 |
| Classical Sig | Ed25519 | RFC 8032 | pk 32, sig 64 |
| Hybrid KEM | X25519 + ML-KEM-768 | AVON-HYBRID-KEM-V2 | pk 1216, ct 1120 |
| Hybrid Sig | Ed25519 + ML-DSA-65 | AVON-CERT-V2 etc | pk 1984, sig 3373 |
| AEAD | AES-256-GCM / ChaCha20-Poly1305 | - | key 32, nonce 12, tag 16 |
| Hash/KDF | SHA-256, HKDF-SHA256 | RFC 5869 | - |
| HMAC | HMAC-SHA256 | RFC 2104 | - |

### Hybrid KEM Combiner (AVON-HYBRID-KEM-V2)

```
ss = SHA-256("AVON-HYBRID-KEM-V2" || ss_x25519 || ss_mlkem || eph_x25519_pk || x25519_pk || mlkem_ct || mlkem_pk)
```

### Composite Signatures with Domain Separation

Each component signs `label || u32_be(len(msg)) || msg`:

- `AVON-CERT-V2`, `AVON-CSR-V2`, `AVON-AUTH-V2`, `AVON-SESSION-V2`, `AVON-CRL-V2`, `AVON-OFFER-V2`
- Verification requires both Ed25519 and ML-DSA-65 to verify.

### Symmetric Cryptography

#### AES-256-GCM / ChaCha20-Poly1305

- **Key Size**: 256 bits
- **Nonce Size**: 96 bits (12 bytes)
- **Tag Size**: 128 bits (16 bytes)
- **Use Case**: ATP/2 data plane (Suite 1 = AES, Suite 2 = ChaCha)

#### Key Derivation (ATP/2)

```
transcript = SHA-256("AVON-ATP2" || session_id || initiator_cert_id || responder_cert_id || len(eph_kem_pk) || eph_kem_pk || len(ct_e) || ct_e || len(ct_s) || ct_s || suite)
prk = HKDF-Extract(salt=transcript, ikm=ss_e || ss_s)
k_i2r = HKDF-Expand(prk, "i2r" || epoch_be32, 32)
k_r2i = HKDF-Expand(prk, "r2i" || epoch_be32, 32)
rekey_secret = HKDF-Expand(prk, "rekey" || epoch_be32, 32)
```

### Hash Functions

| Algorithm | Use Case |
|-----------|----------|
| SHA-256 | Hashing, HKDF, combiner, transcript |
| Argon2id | Password hashing (admin accounts) |

### Cryptographic Agility

AVON supports suite negotiation:

```protobuf
message CryptoSuite {
  KemAlgorithm kem = 1;         // ML_KEM_768 + X25519
  SignatureAlgorithm sig = 2;   // ML_DSA_65 + Ed25519
  CipherAlgorithm cipher = 3;   // AES_256_GCM / ChaCha20Poly1305
}
```

## Key Management

### Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                      Key Hierarchy                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Root CA Key (Dilithium)                                        │
│  ├── Stored in HSM (production)                                 │
│  ├── Used to sign intermediate CA                               │
│  └── 10-year validity                                           │
│                                                                 │
│  Intermediate CA Key (Dilithium)                                │
│  ├── Signs agent certificates                                   │
│  ├── Rotated annually                                           │
│  └── 2-year validity                                            │
│                                                                 │
│  Agent Keys (Dilithium)                                         │
│  ├── Generated on enrollment                                    │
│  ├── Private key never leaves device                            │
│  └── 1-year certificate validity                                │
│                                                                 │
│  Session Keys (AES-256)                                         │
│  ├── Derived from Kyber key exchange                            │
│  ├── Per-session, ephemeral                                     │
│  └── Rotated every 24 hours                                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### HSM Integration

Production deployments should use Hardware Security Modules:

| Provider | Integration | Key Types |
|----------|-------------|-----------|
| AWS CloudHSM | Native | Root CA, Intermediate CA |
| Azure Dedicated HSM | PKCS#11 | Root CA, Intermediate CA |
| Google Cloud HSM | Cloud KMS | Root CA, Intermediate CA |
| Thales Luna | PKCS#11 | Root CA, Intermediate CA |
| YubiHSM 2 | Native | Root CA (small deployments) |

### Key Rotation

| Key Type | Rotation Period | Procedure |
|----------|-----------------|-----------|
| Root CA | 5 years | Manual, with ceremony |
| Intermediate CA | 1 year | Automated, overlap period |
| Agent Certificate | 1 year | Automatic renewal |
| Session Key | 24 hours | Automatic rekeying |
| Token Signing | 30 days | Automatic |

### Secure Key Storage

**Agent Keys**:
- Linux: Encrypted file with system keyring
- macOS: Keychain Services
- Windows: DPAPI + Credential Manager
- TPM: When available, prefer TPM 2.0 storage

**Server Keys**:
- Kubernetes Secrets (encrypted at rest)
- HSM (production)
- Vault (alternative)

## Authentication

### Agent Authentication

```
┌─────────────────────────────────────────────────────────────────┐
│              Agent Authentication Flow                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Certificate Presentation                                    │
│     Agent presents Dilithium certificate to Gateway             │
│                                                                 │
│  2. Certificate Validation                                      │
│     ├── Check signature chain to trusted CA                     │
│     ├── Verify not revoked (CRL/OCSP)                           │
│     ├── Check validity period                                   │
│     └── Verify certificate extensions                           │
│                                                                 │
│  3. Proof of Possession                                         │
│     Agent signs challenge with private key                      │
│     Gateway verifies signature                                  │
│                                                                 │
│  4. Device Binding (optional)                                   │
│     Verify device attestation                                   │
│     Check device posture                                        │
│                                                                 │
│  5. Session Establishment                                       │
│     Issue session token                                         │
│     Bind to certificate fingerprint                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Multi-Factor Authentication

For administrative access:

1. **Primary**: Username/password or SSO (OIDC/SAML)
2. **Secondary**: TOTP, WebAuthn, or hardware token
3. **Conditional**: Additional factors based on risk

### Session Management

- **Session Token**: JWT with 30-minute validity
- **Refresh Token**: 24-hour validity, single use
- **Token Binding**: Bound to certificate fingerprint
- **Rotation**: Every 30 seconds via heartbeat

## Authorization

### Policy Model

AVON uses attribute-based access control (ABAC):

```yaml
# Example Policy
policy:
  name: engineering-production
  description: Engineering team production access

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

### Policy Evaluation Order

1. Explicit DENY rules (highest priority)
2. Explicit ALLOW rules
3. Default DENY (implicit)

### Context-Aware Authorization

Factors considered in policy decisions:

| Factor | Description | Example |
|--------|-------------|---------|
| User Identity | Who is requesting | user@company.com |
| Device Identity | Which device | laptop-12345 |
| Device Posture | Security state | compliant/non-compliant |
| Time | When requested | Business hours |
| Location | Where from | IP geolocation |
| Risk Score | Calculated risk | Low/Medium/High |
| Resource Sensitivity | Target classification | Public/Internal/Confidential |

## Network Security

### Service Mesh Security

Internal services communicate via mTLS:

```yaml
# Istio PeerAuthentication
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: avon-mtls
  namespace: avon
spec:
  mtls:
    mode: STRICT
```

### Network Policies

```yaml
# Restrict ingress to gateway only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: avon-gateway-ingress
  namespace: avon
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: gateway
  policyTypes:
    - Ingress
  ingress:
    - ports:
        - protocol: UDP
          port: 4600
```

### Firewall Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Agents | Gateway | 4600 | UDP | Control plane |
| Gateway | Auth | 50051 | TCP | Authentication |
| Gateway | Pulse | 50053 | TCP | Heartbeats |
| Auth | CA | 50052 | TCP | Certificate ops |
| * | Admin API | 443 | TCP | Management |

## Compliance Considerations

### Regulatory Frameworks

| Framework | Relevance | Key Requirements |
|-----------|-----------|------------------|
| SOC 2 Type II | High | Access controls, encryption, logging |
| HIPAA | Medium | PHI protection, audit trails |
| PCI DSS | Medium | Network segmentation, encryption |
| GDPR | Medium | Data protection, privacy |
| FedRAMP | High | Government deployments |
| NIST 800-53 | High | Security controls baseline |

### Audit Logging

All security-relevant events are logged:

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

### Data Retention

| Data Type | Retention | Justification |
|-----------|-----------|---------------|
| Audit Logs | 1 year | Compliance requirements |
| Session Logs | 90 days | Troubleshooting |
| Metrics | 30 days | Performance analysis |
| Certificates | Until expiry + 1 year | Revocation tracking |

## Security Best Practices

### Deployment Hardening

1. **Enable HSM** for CA private keys in production
2. **Use dedicated nodes** for control plane components
3. **Enable network policies** to restrict traffic
4. **Configure pod security policies** (non-root, read-only)
5. **Enable audit logging** and ship to SIEM
6. **Regular security updates** for all components

### Operational Security

1. **Principle of Least Privilege**: Minimal admin access
2. **Separation of Duties**: Different admins for different functions
3. **Regular Access Reviews**: Quarterly access audits
4. **Incident Response Plan**: Documented and tested
5. **Security Training**: For all administrators

### Agent Security

1. **Keep agents updated**: Enable auto-update where possible
2. **Monitor agent health**: Detect compromised agents
3. **Implement device posture**: Check endpoint security
4. **Use TPM**: When available for key storage
5. **Network isolation**: Agent-only networks if possible

## Incident Response

### Security Incident Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| Critical | Active breach, data exfiltration | Immediate |
| High | Vulnerability exploitation attempt | 1 hour |
| Medium | Policy violation, anomalous behavior | 4 hours |
| Low | Failed attack, minor misconfiguration | 24 hours |

### Incident Response Procedures

1. **Detection**: Monitor alerts, logs, anomalies
2. **Containment**: Isolate affected systems
3. **Eradication**: Remove threat
4. **Recovery**: Restore normal operations
5. **Lessons Learned**: Post-incident review

### Emergency Procedures

**Revoke Compromised Agent**:
```bash
curl -X POST https://admin.avon.example.com/api/v1/agents/{id}/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"reason": "compromised", "immediate": true}'
```

**Emergency CA Key Rotation**:
```bash
kubectl exec -n avon avon-ca-0 -- \
  avon-ca emergency-rotate --reason "key compromise"
```

**Terminate All Sessions**:
```bash
curl -X POST https://admin.avon.example.com/api/v1/sessions/terminate-all \
  -H "Authorization: Bearer $TOKEN"
```

## Related Documentation

- [Architecture Overview](architecture.md)
- [Deployment Guide](deployment.md)
- [Operations Guide](operations.md)
