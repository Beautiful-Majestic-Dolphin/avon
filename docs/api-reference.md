# AVON API Reference

This document provides complete API documentation for AVON services.

## Table of Contents

- [Admin REST API](#admin-rest-api)
- [gRPC Services](#grpc-services)
- [Wire Protocol](#wire-protocol)
- [Authentication](#authentication)
- [Error Handling](#error-handling)

## Admin REST API

The Admin API provides management capabilities for AVON deployments.

**Base URL**: `https://admin.avon.example.com/api/v1`

### Authentication

All API requests require a Bearer token:

```bash
curl -H "Authorization: Bearer $TOKEN" https://admin.avon.example.com/api/v1/agents
```

### Agents

#### List Agents

```http
GET /agents
```

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | integer | Page number (default: 1) |
| `per_page` | integer | Items per page (default: 20, max: 100) |
| `status` | string | Filter by status: `online`, `offline`, `pending` |
| `group` | string | Filter by group |
| `search` | string | Search by name or ID |

**Response**:
```json
{
  "data": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "name": "alice-laptop",
      "status": "online",
      "groups": ["engineering", "vpn-users"],
      "last_seen": "2024-01-15T10:30:45Z",
      "enrolled_at": "2024-01-01T09:00:00Z",
      "version": "1.0.0",
      "os": "macOS 14.2",
      "ip_address": "192.168.1.100"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 150,
    "total_pages": 8
  }
}
```

#### Get Agent

```http
GET /agents/{agent_id}
```

**Response**:
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "alice-laptop",
  "status": "online",
  "groups": ["engineering", "vpn-users"],
  "last_seen": "2024-01-15T10:30:45Z",
  "enrolled_at": "2024-01-01T09:00:00Z",
  "certificate": {
    "serial": "1234567890",
    "issued_at": "2024-01-01T09:00:00Z",
    "expires_at": "2025-01-01T09:00:00Z",
    "fingerprint": "SHA256:abc123..."
  },
  "device_info": {
    "hostname": "alice-laptop.local",
    "os": "macOS",
    "os_version": "14.2",
    "architecture": "arm64"
  },
  "session": {
    "id": "sess_xyz789",
    "started_at": "2024-01-15T08:00:00Z",
    "last_heartbeat": "2024-01-15T10:30:45Z",
    "gateway": "gateway-1.avon.example.com"
  }
}
```

#### Update Agent

```http
PATCH /agents/{agent_id}
```

**Request Body**:
```json
{
  "name": "alice-laptop-new",
  "groups": ["engineering", "admins"]
}
```

#### Delete Agent

```http
DELETE /agents/{agent_id}
```

**Response**: `204 No Content`

#### Revoke Agent Certificate

```http
POST /agents/{agent_id}/revoke
```

**Request Body**:
```json
{
  "reason": "compromised"
}
```

### Enrollment Tokens

#### Create Enrollment Token

```http
POST /enrollment-tokens
```

**Request Body**:
```json
{
  "name": "batch-enrollment-jan",
  "groups": ["engineering"],
  "expires_in": "24h",
  "max_uses": 10
}
```

**Response**:
```json
{
  "id": "tok_abc123",
  "token": "AVON_ENROLL_eyJhbGciOiJIUzI1NiIs...",
  "expires_at": "2024-01-16T10:30:45Z",
  "max_uses": 10,
  "uses_remaining": 10
}
```

#### List Enrollment Tokens

```http
GET /enrollment-tokens
```

#### Delete Enrollment Token

```http
DELETE /enrollment-tokens/{token_id}
```

### Policies

#### List Policies

```http
GET /policies
```

**Response**:
```json
{
  "data": [
    {
      "id": "pol_abc123",
      "name": "engineering-access",
      "description": "Access rules for engineering team",
      "version": 3,
      "enabled": true,
      "rules": [
        {
          "id": "rule_1",
          "action": "allow",
          "subjects": {
            "groups": ["engineering"]
          },
          "resources": {
            "networks": ["10.100.0.0/16"]
          },
          "conditions": {
            "time_window": {
              "days": ["monday", "tuesday", "wednesday", "thursday", "friday"],
              "hours": {"start": "08:00", "end": "20:00"}
            }
          }
        }
      ],
      "created_at": "2024-01-01T09:00:00Z",
      "updated_at": "2024-01-15T10:00:00Z"
    }
  ]
}
```

#### Create Policy

```http
POST /policies
```

**Request Body**:
```json
{
  "name": "new-policy",
  "description": "Policy description",
  "rules": [
    {
      "action": "allow",
      "subjects": {
        "groups": ["group-name"],
        "agents": ["agent-id"]
      },
      "resources": {
        "networks": ["10.0.0.0/8"],
        "ports": [443, 8080]
      },
      "conditions": {}
    }
  ]
}
```

#### Update Policy

```http
PUT /policies/{policy_id}
```

#### Delete Policy

```http
DELETE /policies/{policy_id}
```

#### Evaluate Policy (Dry Run)

```http
POST /policies/evaluate
```

**Request Body**:
```json
{
  "agent_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "resource": {
    "network": "10.100.5.0/24",
    "port": 443
  },
  "context": {
    "time": "2024-01-15T14:30:00Z"
  }
}
```

**Response**:
```json
{
  "decision": "allow",
  "matched_policy": "pol_abc123",
  "matched_rule": "rule_1",
  "evaluation_time_ms": 2
}
```

### Sessions

#### List Active Sessions

```http
GET /sessions
```

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_id` | string | Filter by agent |
| `gateway` | string | Filter by gateway |

#### Terminate Session

```http
DELETE /sessions/{session_id}
```

#### Terminate All Agent Sessions

```http
DELETE /agents/{agent_id}/sessions
```

### Groups

#### List Groups

```http
GET /groups
```

#### Create Group

```http
POST /groups
```

**Request Body**:
```json
{
  "name": "contractors",
  "description": "External contractors"
}
```

#### Update Group

```http
PUT /groups/{group_id}
```

#### Delete Group

```http
DELETE /groups/{group_id}
```

### System

#### Health Check

```http
GET /health
```

**Response**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "components": {
    "database": "healthy",
    "redis": "healthy",
    "auth": "healthy",
    "ca": "healthy"
  }
}
```

#### Metrics

```http
GET /metrics
```

Returns Prometheus-formatted metrics.

## gRPC Services

AVON uses gRPC for internal service communication. All services use Protocol Buffers v3.

### Auth Service

**File**: `proto/auth.proto`

```protobuf
syntax = "proto3";
package avon.auth;

service AuthService {
  // Authenticate an agent
  rpc Authenticate(AuthenticateRequest) returns (AuthenticateResponse);

  // Validate a session token
  rpc ValidateSession(ValidateSessionRequest) returns (ValidateSessionResponse);

  // Create a new session
  rpc CreateSession(CreateSessionRequest) returns (CreateSessionResponse);

  // Terminate a session
  rpc TerminateSession(TerminateSessionRequest) returns (TerminateSessionResponse);

  // Rotate session token
  rpc RotateToken(RotateTokenRequest) returns (RotateTokenResponse);
}

message AuthenticateRequest {
  bytes certificate = 1;           // Agent's certificate (DER encoded)
  bytes signature = 2;             // Signature over challenge
  bytes challenge = 3;             // Server-provided challenge
  DeviceInfo device_info = 4;      // Device information
}

message AuthenticateResponse {
  string session_id = 1;
  string session_token = 2;
  int64 expires_at = 3;            // Unix timestamp
  repeated string groups = 4;
}

message DeviceInfo {
  string hostname = 1;
  string os = 2;
  string os_version = 3;
  string architecture = 4;
  string agent_version = 5;
}
```

### CA Service

**File**: `proto/ca.proto`

```protobuf
syntax = "proto3";
package avon.ca;

service CAService {
  // Enroll a new agent
  rpc Enroll(EnrollRequest) returns (EnrollResponse);

  // Renew an agent's certificate
  rpc RenewCertificate(RenewRequest) returns (RenewResponse);

  // Revoke a certificate
  rpc RevokeCertificate(RevokeRequest) returns (RevokeResponse);

  // Get Certificate Revocation List
  rpc GetCRL(GetCRLRequest) returns (GetCRLResponse);

  // Verify a certificate
  rpc VerifyCertificate(VerifyRequest) returns (VerifyResponse);
}

message EnrollRequest {
  string enrollment_token = 1;
  bytes public_key = 2;            // Dilithium public key
  DeviceInfo device_info = 3;
  string requested_name = 4;
}

message EnrollResponse {
  string agent_id = 1;
  bytes certificate = 2;           // DER encoded certificate
  bytes ca_certificate = 3;        // CA certificate chain
  int64 expires_at = 4;
}
```

### Pulse Service

**File**: `proto/pulse.proto`

```protobuf
syntax = "proto3";
package avon.pulse;

service PulseService {
  // Bidirectional streaming for heartbeats
  rpc Heartbeat(stream HeartbeatRequest) returns (stream HeartbeatResponse);

  // Get session status
  rpc GetSessionStatus(GetSessionStatusRequest) returns (GetSessionStatusResponse);
}

message HeartbeatRequest {
  string session_id = 1;
  string token = 2;
  int64 timestamp = 3;
  bytes signature = 4;             // Signature over (session_id || timestamp)
  SessionMetrics metrics = 5;
}

message HeartbeatResponse {
  bool valid = 1;
  string new_token = 2;            // Rotated token (if applicable)
  int64 next_heartbeat = 3;        // Next expected heartbeat time
  repeated Command commands = 4;   // Commands for agent to execute
}

message SessionMetrics {
  int64 bytes_sent = 1;
  int64 bytes_received = 2;
  int32 active_connections = 3;
  float cpu_usage = 4;
  float memory_usage = 5;
}
```

### Policy Service

**File**: `proto/policy.proto`

```protobuf
syntax = "proto3";
package avon.policy;

service PolicyService {
  // Evaluate policy for an access request
  rpc Evaluate(EvaluateRequest) returns (EvaluateResponse);

  // Batch evaluate multiple requests
  rpc BatchEvaluate(BatchEvaluateRequest) returns (BatchEvaluateResponse);
}

message EvaluateRequest {
  string agent_id = 1;
  string session_id = 2;
  Resource resource = 3;
  EvaluationContext context = 4;
}

message EvaluateResponse {
  Decision decision = 1;
  string matched_policy_id = 2;
  string matched_rule_id = 3;
  string reason = 4;
}

enum Decision {
  DECISION_UNSPECIFIED = 0;
  ALLOW = 1;
  DENY = 2;
}

message Resource {
  string network = 1;              // CIDR notation
  int32 port = 2;
  string protocol = 3;             // tcp, udp
  string fqdn = 4;                 // Optional FQDN
}

message EvaluationContext {
  int64 timestamp = 1;
  string source_ip = 2;
  map<string, string> attributes = 3;
}
```

## Wire Protocol

The AVON wire protocol operates over UDP for the control plane and encrypted tunnels.

### Packet Structure

```
┌─────────────────────────────────────────────────────────┐
│                    AVON Packet                          │
├─────────────────────────────────────────────────────────┤
│ Magic (4 bytes)    │ Version (1) │ Type (1) │ Flags (2) │
├─────────────────────────────────────────────────────────┤
│ Session ID (16 bytes)                                   │
├─────────────────────────────────────────────────────────┤
│ Sequence Number (8 bytes)                               │
├─────────────────────────────────────────────────────────┤
│ Payload Length (4 bytes)                                │
├─────────────────────────────────────────────────────────┤
│ Payload (variable)                                      │
├─────────────────────────────────────────────────────────┤
│ Authentication Tag (16 bytes) - for encrypted packets   │
└─────────────────────────────────────────────────────────┘
```

### Header Fields

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 bytes | `0x41564F4E` ("AVON") |
| Version | 1 byte | Protocol version (currently `0x01`) |
| Type | 1 byte | Packet type (see below) |
| Flags | 2 bytes | Packet flags |
| Session ID | 16 bytes | Session identifier (UUID) |
| Sequence | 8 bytes | Monotonic sequence number |
| Length | 4 bytes | Payload length |

### Packet Types

| Type | Value | Description |
|------|-------|-------------|
| HANDSHAKE_INIT | 0x01 | Initiate handshake |
| HANDSHAKE_RESPONSE | 0x02 | Handshake response |
| HANDSHAKE_COMPLETE | 0x03 | Handshake completion |
| DATA | 0x10 | Encrypted data packet |
| HEARTBEAT | 0x20 | Keepalive/heartbeat |
| HEARTBEAT_ACK | 0x21 | Heartbeat acknowledgment |
| REKEY | 0x30 | Session rekey request |
| REKEY_ACK | 0x31 | Rekey acknowledgment |
| DISCONNECT | 0x40 | Graceful disconnect |
| ERROR | 0xFF | Error notification |

### Handshake Sequence

```
Agent                                          Gateway
  │                                               │
  │─────────── HANDSHAKE_INIT ──────────────────>│
  │  (Kyber public key, agent certificate)       │
  │                                               │
  │<────────── HANDSHAKE_RESPONSE ───────────────│
  │  (Kyber ciphertext, server certificate)      │
  │                                               │
  │─────────── HANDSHAKE_COMPLETE ──────────────>│
  │  (Encrypted: auth proof, device info)        │
  │                                               │
  │<────────── DATA (session established) ───────│
  │                                               │
```

### Encryption

After handshake, all DATA packets are encrypted:

- **Algorithm**: AES-256-GCM
- **Nonce**: 12 bytes (session_id[0:4] || sequence_number)
- **AAD**: Packet header (32 bytes)

### Key Derivation

From Kyber shared secret:

```
traffic_key = HKDF-SHA3-256(
  ikm = kyber_shared_secret,
  salt = session_id,
  info = "avon-traffic-key",
  length = 32
)

traffic_nonce_prefix = HKDF-SHA3-256(
  ikm = kyber_shared_secret,
  salt = session_id,
  info = "avon-traffic-nonce",
  length = 4
)
```

## Authentication

### API Token Authentication

Admin API uses JWT tokens:

```bash
# Request token (OAuth2 client credentials)
curl -X POST https://admin.avon.example.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"

# Response
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Service-to-Service Authentication

Internal gRPC services use mTLS with certificates issued by the AVON CA.

## Error Handling

### HTTP Error Responses

```json
{
  "error": {
    "code": "AGENT_NOT_FOUND",
    "message": "Agent with ID 'abc123' not found",
    "details": {
      "agent_id": "abc123"
    },
    "request_id": "req_xyz789"
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AGENT_NOT_FOUND` | 404 | Agent does not exist |
| `POLICY_NOT_FOUND` | 404 | Policy does not exist |
| `TOKEN_EXPIRED` | 401 | Enrollment token has expired |
| `TOKEN_INVALID` | 401 | Enrollment token is invalid |
| `CERTIFICATE_REVOKED` | 403 | Agent certificate has been revoked |
| `POLICY_DENIED` | 403 | Access denied by policy |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Internal server error |

### gRPC Error Codes

| gRPC Code | Description |
|-----------|-------------|
| `UNAUTHENTICATED` | Invalid or missing credentials |
| `PERMISSION_DENIED` | Operation not permitted |
| `NOT_FOUND` | Resource not found |
| `ALREADY_EXISTS` | Resource already exists |
| `RESOURCE_EXHAUSTED` | Rate limit exceeded |
| `INTERNAL` | Internal error |

## Related Documentation

- [Architecture Overview](architecture.md)
- [Security Documentation](security.md)
- [Development Guide](development.md)
