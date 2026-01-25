# AVON Architecture

This document describes the high-level architecture of AVON (Authenticated Vector Ownership Network), a post-quantum zero trust network access (ZTNA) platform.

## Table of Contents

- [Overview](#overview)
- [Design Principles](#design-principles)
- [System Architecture](#system-architecture)
- [Component Descriptions](#component-descriptions)
- [Data Flow](#data-flow)
- [Security Model](#security-model)
- [Network Topology](#network-topology)

## Overview

AVON implements a zero trust architecture where no network connection is implicitly trusted. Every connection must be authenticated, authorized, and continuously validated. The system uses post-quantum cryptographic algorithms to ensure long-term security against quantum computer attacks.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AVON Architecture                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                   │
│  │   Agent 1   │     │   Agent 2   │     │   Agent N   │   Endpoints       │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘                   │
│         │                   │                   │                           │
│         └───────────────────┼───────────────────┘                           │
│                             │                                               │
│                    ┌────────▼────────┐                                      │
│                    │    Gateway      │◄─── UDP Control Plane                │
│                    │  (Load Balanced)│                                      │
│                    └────────┬────────┘                                      │
│                             │                                               │
│         ┌───────────────────┼───────────────────┐                           │
│         │                   │                   │                           │
│  ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐                   │
│  │    Auth     │     │    Pulse    │     │     CA      │   Control Plane   │
│  │   Service   │     │   Service   │     │   Service   │                   │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘                   │
│         │                   │                   │                           │
│         └───────────────────┼───────────────────┘                           │
│                             │                                               │
│         ┌───────────────────┼───────────────────┐                           │
│         │                   │                   │                           │
│  ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐                   │
│  │   Policy    │     │   Admin     │     │  PostgreSQL │   Management      │
│  │   Engine    │     │    API      │     │  + Redis    │                   │
│  └─────────────┘     └─────────────┘     └─────────────┘                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Design Principles

### 1. Zero Trust

- **Never trust, always verify**: Every request is authenticated regardless of source
- **Least privilege**: Agents only access resources explicitly permitted by policy
- **Assume breach**: System designed to limit blast radius of compromises

### 2. Post-Quantum Security

- **Kyber-1024**: Key encapsulation for key exchange (NIST PQC standard)
- **Dilithium-5**: Digital signatures for authentication (NIST PQC standard)
- **Hybrid mode**: Optional classical + post-quantum for transition period

### 3. Defense in Depth

- Multiple layers of authentication and authorization
- Continuous verification through heartbeat protocol
- Cryptographic binding of sessions to device identity

### 4. Operational Simplicity

- Single binary agent deployment
- Kubernetes-native control plane
- GitOps-friendly configuration

## System Architecture

### Control Plane Components

The control plane runs in Kubernetes and manages all aspects of the AVON network:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Kubernetes Cluster                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Control Plane                         │   │
│  │                                                          │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐│   │
│  │  │ Gateway  │  │   Auth   │  │    CA    │  │  Pulse   ││   │
│  │  │ (3 pods) │  │ (3 pods) │  │ (2 pods) │  │ (3 pods) ││   │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘│   │
│  │       │             │             │             │       │   │
│  │       └─────────────┴─────────────┴─────────────┘       │   │
│  │                           │                              │   │
│  │                    ┌──────▼──────┐                       │   │
│  │                    │    gRPC     │                       │   │
│  │                    │  Internal   │                       │   │
│  │                    └──────┬──────┘                       │   │
│  │                           │                              │   │
│  │  ┌────────────────────────┴────────────────────────┐    │   │
│  │  │                                                  │    │   │
│  │  │  ┌──────────────┐          ┌──────────────┐     │    │   │
│  │  │  │Policy Engine │          │  Admin API   │     │    │   │
│  │  │  │   (3 pods)   │          │   (2 pods)   │     │    │   │
│  │  │  └──────────────┘          └──────────────┘     │    │   │
│  │  │                                                  │    │   │
│  │  └──────────────────────────────────────────────────┘    │   │
│  │                                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Data Plane                            │   │
│  │                                                          │   │
│  │  ┌──────────────┐          ┌──────────────┐             │   │
│  │  │  PostgreSQL  │          │    Redis     │             │   │
│  │  │   (Primary)  │          │   (Master)   │             │   │
│  │  └──────────────┘          └──────────────┘             │   │
│  │                                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Agent Architecture

Each agent runs as a system service on endpoints:

```
┌─────────────────────────────────────────────────────┐
│                    AVON Agent                        │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │              User Space                      │   │
│  │                                              │   │
│  │  ┌──────────────┐    ┌──────────────┐       │   │
│  │  │   Control    │    │    Tunnel    │       │   │
│  │  │   Manager    │    │   Manager    │       │   │
│  │  └──────┬───────┘    └──────┬───────┘       │   │
│  │         │                   │               │   │
│  │  ┌──────▼───────────────────▼───────┐       │   │
│  │  │         Crypto Engine            │       │   │
│  │  │  (Kyber + Dilithium + AES-GCM)   │       │   │
│  │  └──────────────────────────────────┘       │   │
│  │                                              │   │
│  └──────────────────┬──────────────────────────┘   │
│                     │                              │
│  ┌──────────────────▼──────────────────────────┐   │
│  │              Kernel Space                    │   │
│  │                                              │   │
│  │  ┌──────────────────────────────────┐       │   │
│  │  │         TUN/TAP Device           │       │   │
│  │  │         (avon0 interface)        │       │   │
│  │  └──────────────────────────────────┘       │   │
│  │                                              │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Component Descriptions

### Gateway Service

**Purpose**: Entry point for all agent communications

**Responsibilities**:
- UDP packet handling for control plane protocol
- Connection multiplexing and load distribution
- Initial packet validation and rate limiting
- TLS termination for management interfaces

**Technology**: Rust, async/await with Tokio

**Scaling**: Horizontal, stateless (3+ replicas recommended)

### Auth Service

**Purpose**: Authentication and session management

**Responsibilities**:
- Agent enrollment and device registration
- Session token generation and validation
- Credential verification (certificates, tokens)
- Session state management via Redis

**Technology**: Rust, gRPC

**Scaling**: Horizontal, stateless (state in Redis)

### CA Service

**Purpose**: Certificate authority for agent identities

**Responsibilities**:
- Post-quantum certificate issuance (Dilithium signatures)
- Certificate revocation list (CRL) management
- Key escrow and recovery (optional)
- HSM integration for root key protection

**Technology**: Rust, gRPC

**Scaling**: Limited horizontal (2 replicas), stateful

### Pulse Service

**Purpose**: Continuous verification and session management

**Responsibilities**:
- Heartbeat processing from agents
- Session validity monitoring
- Token rotation coordination
- Dead session cleanup

**Technology**: Rust, gRPC

**Scaling**: Horizontal, stateless

### Policy Engine

**Purpose**: Access control and authorization decisions

**Responsibilities**:
- Policy evaluation for access requests
- Context-aware authorization (user, device, time, location)
- Policy version management
- Audit logging of decisions

**Technology**: Python, FastAPI

**Scaling**: Horizontal, stateless

### Admin API

**Purpose**: Management interface for administrators

**Responsibilities**:
- RESTful API for configuration management
- Agent and policy CRUD operations
- Reporting and analytics
- Webhook integrations

**Technology**: Python, FastAPI

**Scaling**: Horizontal, stateless

### Agent

**Purpose**: Endpoint software establishing secure tunnels

**Responsibilities**:
- Secure tunnel establishment to gateway
- Local traffic interception via TUN device
- Cryptographic operations (encryption, signing)
- Heartbeat transmission

**Technology**: Rust, single binary

**Deployment**: System service on Windows, macOS, Linux

## Data Flow

### Agent Enrollment Flow

```
┌───────┐          ┌─────────┐          ┌──────┐          ┌────┐
│ Agent │          │ Gateway │          │ Auth │          │ CA │
└───┬───┘          └────┬────┘          └───┬──┘          └──┬─┘
    │                   │                   │                │
    │ 1. Enrollment     │                   │                │
    │   Request         │                   │                │
    │──────────────────>│                   │                │
    │                   │                   │                │
    │                   │ 2. Forward to     │                │
    │                   │    Auth           │                │
    │                   │──────────────────>│                │
    │                   │                   │                │
    │                   │                   │ 3. Validate    │
    │                   │                   │    enrollment  │
    │                   │                   │    token       │
    │                   │                   │                │
    │                   │                   │ 4. Request     │
    │                   │                   │    certificate │
    │                   │                   │───────────────>│
    │                   │                   │                │
    │                   │                   │ 5. Issue PQ    │
    │                   │                   │    certificate │
    │                   │                   │<───────────────│
    │                   │                   │                │
    │                   │ 6. Return         │                │
    │                   │    credentials    │                │
    │                   │<──────────────────│                │
    │                   │                   │                │
    │ 7. Enrollment     │                   │                │
    │    complete       │                   │                │
    │<──────────────────│                   │                │
    │                   │                   │                │
```

### Tunnel Establishment Flow

```
┌───────┐          ┌─────────┐          ┌──────┐          ┌────────┐
│ Agent │          │ Gateway │          │ Auth │          │ Policy │
└───┬───┘          └────┬────┘          └───┬──┘          └────┬───┘
    │                   │                   │                  │
    │ 1. Key Exchange   │                   │                  │
    │    (Kyber KEM)    │                   │                  │
    │──────────────────>│                   │                  │
    │                   │                   │                  │
    │ 2. Shared secret  │                   │                  │
    │    established    │                   │                  │
    │<──────────────────│                   │                  │
    │                   │                   │                  │
    │ 3. Auth Request   │                   │                  │
    │    (signed)       │                   │                  │
    │──────────────────>│                   │                  │
    │                   │                   │                  │
    │                   │ 4. Verify         │                  │
    │                   │    signature      │                  │
    │                   │──────────────────>│                  │
    │                   │                   │                  │
    │                   │                   │ 5. Check        │
    │                   │                   │    policy       │
    │                   │                   │─────────────────>│
    │                   │                   │                  │
    │                   │                   │ 6. Policy       │
    │                   │                   │    decision     │
    │                   │                   │<─────────────────│
    │                   │                   │                  │
    │                   │ 7. Session        │                  │
    │                   │    created        │                  │
    │                   │<──────────────────│                  │
    │                   │                   │                  │
    │ 8. Tunnel active  │                   │                  │
    │<──────────────────│                   │                  │
    │                   │                   │                  │
```

### Continuous Verification (Pulse)

```
┌───────┐          ┌─────────┐          ┌───────┐          ┌────────┐
│ Agent │          │ Gateway │          │ Pulse │          │ Policy │
└───┬───┘          └────┬────┘          └───┬───┘          └────┬───┘
    │                   │                   │                   │
    │                   │                   │                   │
    ├───────────────────┴───────────────────┴───────────────────┤
    │              Every 10 seconds (configurable)              │
    ├───────────────────┬───────────────────┬───────────────────┤
    │                   │                   │                   │
    │ 1. Heartbeat      │                   │                   │
    │    (encrypted)    │                   │                   │
    │──────────────────>│                   │                   │
    │                   │                   │                   │
    │                   │ 2. Forward        │                   │
    │                   │    heartbeat      │                   │
    │                   │──────────────────>│                   │
    │                   │                   │                   │
    │                   │                   │ 3. Validate      │
    │                   │                   │    session       │
    │                   │                   │                   │
    │                   │                   │ 4. Re-evaluate   │
    │                   │                   │    policy        │
    │                   │                   │─────────────────>│
    │                   │                   │                   │
    │                   │                   │ 5. Policy        │
    │                   │                   │    result        │
    │                   │                   │<─────────────────│
    │                   │                   │                   │
    │                   │ 6. Session        │                   │
    │                   │    status         │                   │
    │                   │<──────────────────│                   │
    │                   │                   │                   │
    │ 7. Ack/Token      │                   │                   │
    │    rotation       │                   │                   │
    │<──────────────────│                   │                   │
    │                   │                   │                   │
```

## Security Model

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                      Internet (Untrusted)                        │
│                                                                 │
│    ┌─────────┐                              ┌─────────┐         │
│    │ Agent A │                              │ Agent B │         │
│    └────┬────┘                              └────┬────┘         │
│         │                                       │               │
└─────────┼───────────────────────────────────────┼───────────────┘
          │         Trust Boundary 1              │
          │     (Authenticated & Encrypted)       │
┌─────────┼───────────────────────────────────────┼───────────────┐
│         │                                       │               │
│         └───────────────┬───────────────────────┘               │
│                         │                                       │
│                  ┌──────▼──────┐                                │
│                  │   Gateway   │                                │
│                  │    (DMZ)    │                                │
│                  └──────┬──────┘                                │
│                         │                                       │
│         Trust Boundary 2│(mTLS + Network Policy)                │
│ ┌───────────────────────┼───────────────────────────────────┐   │
│ │                       │                                   │   │
│ │    ┌──────────────────┼──────────────────┐               │   │
│ │    │                  │                  │               │   │
│ │    ▼                  ▼                  ▼               │   │
│ │ ┌──────┐          ┌───────┐          ┌──────┐           │   │
│ │ │ Auth │          │ Pulse │          │  CA  │           │   │
│ │ └──────┘          └───────┘          └──────┘           │   │
│ │                                                          │   │
│ │              Control Plane (Trusted)                     │   │
│ └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│                 Kubernetes Cluster                              │
└─────────────────────────────────────────────────────────────────┘
```

### Cryptographic Protections

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key Exchange | Kyber-1024 | Post-quantum key encapsulation |
| Authentication | Dilithium-5 | Post-quantum signatures |
| Transport | AES-256-GCM | Symmetric encryption |
| Session Tokens | HMAC-SHA3-256 | Token integrity |
| Certificates | Dilithium-5 | Identity binding |

### Authentication Factors

1. **Device Identity**: Post-quantum certificate issued during enrollment
2. **User Identity**: Integrated with IdP (OIDC/SAML)
3. **Session Token**: Short-lived, rotated every 30 seconds
4. **Continuous Verification**: Heartbeat with fresh signatures

### Authorization Model

Policy decisions consider:

- **Subject**: User identity, device identity, agent version
- **Resource**: Target network, service, or application
- **Context**: Time, location, device posture, risk score
- **Action**: Connect, maintain session, access specific resource

## Network Topology

### Single Region Deployment

```
                    ┌─────────────────────────────────┐
                    │         Internet/WAN            │
                    └───────────────┬─────────────────┘
                                    │
                    ┌───────────────▼─────────────────┐
                    │      Cloud Load Balancer        │
                    │        (UDP + TCP)              │
                    └───────────────┬─────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐         ┌───────────────┐         ┌───────────────┐
│   Gateway-1   │         │   Gateway-2   │         │   Gateway-3   │
│   (Zone A)    │         │   (Zone B)    │         │   (Zone C)    │
└───────────────┘         └───────────────┘         └───────────────┘
        │                           │                           │
        └───────────────────────────┼───────────────────────────┘
                                    │
                    ┌───────────────▼─────────────────┐
                    │     Internal Service Mesh       │
                    │          (Istio/Linkerd)        │
                    └───────────────┬─────────────────┘
                                    │
                    ┌───────────────▼─────────────────┐
                    │      Control Plane Services     │
                    └─────────────────────────────────┘
```

### Multi-Region Deployment

```
┌─────────────────────────────────────────────────────────────────┐
│                        Global DNS                                │
│                   (Latency-based routing)                        │
└─────────────────────────────────────────────────────────────────┘
                    │                   │
        ┌───────────▼───────────┐ ┌─────▼─────────────┐
        │                       │ │                   │
        │     Region: US-East   │ │  Region: EU-West  │
        │                       │ │                   │
        │  ┌─────────────────┐  │ │ ┌─────────────┐   │
        │  │   Gateway Pool  │  │ │ │Gateway Pool │   │
        │  └────────┬────────┘  │ │ └──────┬──────┘   │
        │           │           │ │        │          │
        │  ┌────────▼────────┐  │ │ ┌──────▼──────┐   │
        │  │  Control Plane  │  │ │ │Control Plane│   │
        │  └────────┬────────┘  │ │ └──────┬──────┘   │
        │           │           │ │        │          │
        │  ┌────────▼────────┐  │ │ ┌──────▼──────┐   │
        │  │   PostgreSQL    │◄─┼─┼─┤ PostgreSQL  │   │
        │  │    (Primary)    │  │ │ │  (Replica)  │   │
        │  └─────────────────┘  │ │ └─────────────┘   │
        │                       │ │                   │
        └───────────────────────┘ └───────────────────┘
```

## Related Documentation

- [Deployment Guide](deployment.md)
- [Security Documentation](security.md)
- [API Reference](api-reference.md)
- [Operations Guide](operations.md)
