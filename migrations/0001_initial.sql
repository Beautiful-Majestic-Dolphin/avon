-- AVON v2 schema. Single owner: crates/avon-db (sqlx::migrate!).
-- Tenant-owned tables carry tenant_id and row-level security keyed by
-- current_setting('avon.tenant_id'). Service roles created by ops with
-- BYPASSRLS see every tenant; the admin API sets the setting per transaction.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO tenants (id, name) VALUES ('00000000-0000-0000-0000-000000000001', 'default');

CREATE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END $$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------- users
CREATE TYPE user_role AS ENUM ('owner', 'admin', 'viewer');
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    email           TEXT NOT NULL,
    password_hash   TEXT,
    full_name       TEXT,
    role            user_role NOT NULL DEFAULT 'viewer',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_required    BOOLEAN NOT NULL DEFAULT FALSE,
    external_id     TEXT,
    managed_by      TEXT NOT NULL DEFAULT 'local' CHECK (managed_by IN ('local', 'scim')),
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ,
    UNIQUE (tenant_id, external_id)
);
CREATE UNIQUE INDEX users_tenant_email_idx ON users (tenant_id, lower(email));
CREATE TRIGGER users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE webauthn_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   BYTEA NOT NULL UNIQUE,
    public_key      BYTEA NOT NULL,
    sign_count      BIGINT NOT NULL DEFAULT 0,
    transports      TEXT[] NOT NULL DEFAULT '{}',
    aaguid          BYTEA,
    name            TEXT NOT NULL DEFAULT 'Security Key',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials (user_id);

CREATE TABLE refresh_tokens (
    jti             UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    replaced_by     UUID
);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id) WHERE revoked_at IS NULL;

CREATE TABLE scim_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    token_hash      BYTEA NOT NULL UNIQUE,
    description     TEXT NOT NULL,
    scopes          TEXT[] NOT NULL DEFAULT '{users:read,users:write,groups:read,groups:write}',
    expires_at      TIMESTAMPTZ NOT NULL,
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);

-- ---------------------------------------------------------------- pods & classes
CREATE TABLE pods (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            TEXT NOT NULL,
    parent_id       UUID REFERENCES pods(id) ON DELETE RESTRICT,
    description     TEXT,
    external_id     TEXT,
    managed_by      TEXT NOT NULL DEFAULT 'local' CHECK (managed_by IN ('local', 'scim')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, external_id)
);
CREATE TRIGGER pods_updated_at BEFORE UPDATE ON pods FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE user_pods (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pod_id  UUID NOT NULL REFERENCES pods(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, pod_id)
);

CREATE TABLE device_classes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            TEXT NOT NULL,
    description     TEXT,
    match_rules     JSONB NOT NULL DEFAULT '{}',
    mud_url         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE TRIGGER device_classes_updated_at BEFORE UPDATE ON device_classes FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------- devices
CREATE TYPE device_status AS ENUM ('pending', 'active', 'suspended', 'revoked');
CREATE TYPE device_kind   AS ENUM ('agent', 'gateway', 'router', 'ikev2', 'agentless');
CREATE TYPE liveness      AS ENUM ('unknown', 'online', 'stale', 'offline');
CREATE TYPE attestation_state AS ENUM ('none', 'unverified', 'verified', 'failed');

CREATE TABLE devices (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    name                TEXT NOT NULL,
    kind                device_kind NOT NULL DEFAULT 'agent',
    status              device_status NOT NULL DEFAULT 'active',
    liveness            liveness NOT NULL DEFAULT 'unknown',
    device_class_id     UUID REFERENCES device_classes(id) ON DELETE SET NULL,
    key_provider        TEXT NOT NULL DEFAULT 'software',
    fingerprint         BYTEA,
    fingerprint_version SMALLINT NOT NULL DEFAULT 2,
    posture             JSONB,
    posture_updated_at  TIMESTAMPTZ,
    attestation         JSONB,
    attestation_state   attestation_state NOT NULL DEFAULT 'none',
    risk_score          SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    overlay_ipv4        INET UNIQUE,
    overlay_ipv6        INET UNIQUE,
    advertised_routes   CIDR[] NOT NULL DEFAULT '{}',
    enrolled_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    enrolled_by         UUID REFERENCES users(id),
    last_seen_at        TIMESTAMPTZ,
    last_endpoint       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX devices_tenant_status_idx ON devices (tenant_id, status);
CREATE INDEX devices_liveness_idx ON devices (liveness, last_seen_at);
CREATE TRIGGER devices_updated_at BEFORE UPDATE ON devices FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE device_pods (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    pod_id    UUID NOT NULL REFERENCES pods(id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, pod_id)
);
CREATE INDEX device_pods_pod_idx ON device_pods (pod_id);

-- ---------------------------------------------------------------- enrollment
CREATE TABLE enrollment_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    token_hash          BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    device_name         TEXT,
    device_kind         device_kind NOT NULL DEFAULT 'agent',
    pod_ids             UUID[] NOT NULL DEFAULT '{}',
    device_class_id     UUID REFERENCES device_classes(id),
    require_attestation BOOLEAN NOT NULL DEFAULT FALSE,
    require_approval    BOOLEAN NOT NULL DEFAULT FALSE,
    expected_fingerprint BYTEA,
    max_uses            INTEGER NOT NULL DEFAULT 1 CHECK (max_uses >= 1),
    use_count           INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    expires_at          TIMESTAMPTZ NOT NULL,
    created_by          UUID REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ
);
CREATE INDEX enrollment_tokens_tenant_idx ON enrollment_tokens (tenant_id, expires_at);

CREATE TABLE enrollments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id    UUID NOT NULL REFERENCES enrollment_tokens(id),
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    client_ip   INET,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- PKI
CREATE TABLE ca_keys (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                TEXT NOT NULL CHECK (kind IN ('root', 'issuing', 'tls')),
    key_id              BYTEA NOT NULL UNIQUE CHECK (octet_length(key_id) = 32),
    certificate         BYTEA NOT NULL,
    sealed_private_key  BYTEA NOT NULL,
    provider            TEXT NOT NULL,
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ca_keys_one_active_per_kind ON ca_keys (kind) WHERE active;

CREATE TYPE cert_kind AS ENUM ('device', 'gateway', 'service');
CREATE TABLE certificates (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial              BYTEA NOT NULL UNIQUE CHECK (octet_length(serial) = 16),
    tenant_id           UUID REFERENCES tenants(id),
    subject_id          UUID NOT NULL,
    kind                cert_kind NOT NULL,
    certificate         BYTEA NOT NULL,
    tls_certificate_der BYTEA NOT NULL,
    not_before          TIMESTAMPTZ NOT NULL,
    not_after           TIMESTAMPTZ NOT NULL,
    issuer_key_id       BYTEA NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX certificates_subject_idx ON certificates (subject_id, not_after DESC);
CREATE INDEX certificates_revoked_idx ON certificates (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TABLE crl_versions (
    version     BIGSERIAL PRIMARY KEY,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    crl         BYTEA NOT NULL
);

-- ---------------------------------------------------------------- gateways & sessions
CREATE TABLE gateways (
    id              UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    public_endpoint TEXT NOT NULL,
    region          TEXT NOT NULL DEFAULT 'default',
    capacity        INTEGER NOT NULL DEFAULT 10000,
    active_sessions INTEGER NOT NULL DEFAULT 0,
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TYPE session_state AS ENUM ('offered', 'active', 'closed');
CREATE TABLE sessions (
    id              BYTEA PRIMARY KEY CHECK (octet_length(id) = 16),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    gateway_id      UUID REFERENCES gateways(id) ON DELETE SET NULL,
    peer_device_id  UUID REFERENCES devices(id) ON DELETE SET NULL,
    state           session_state NOT NULL DEFAULT 'offered',
    suite           TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at    TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    close_reason    TEXT,
    bytes_tx        BIGINT NOT NULL DEFAULT 0,
    bytes_rx        BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX sessions_device_idx ON sessions (device_id, state);
CREATE INDEX sessions_gateway_idx ON sessions (gateway_id) WHERE state = 'active';

CREATE TABLE ipam_pools (
    tenant_id   UUID PRIMARY KEY REFERENCES tenants(id),
    ipv4_cidr   CIDR NOT NULL DEFAULT '100.64.0.0/10',
    ipv6_cidr   CIDR NOT NULL DEFAULT 'fd00:a70::/48'
);
INSERT INTO ipam_pools (tenant_id) VALUES ('00000000-0000-0000-0000-000000000001');

-- ---------------------------------------------------------------- policy
CREATE TABLE policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    name        TEXT NOT NULL,
    description TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    priority    INTEGER NOT NULL DEFAULT 100,
    spec        JSONB NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE TRIGGER policies_updated_at BEFORE UPDATE ON policies FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE policy_snapshots (
    tenant_id   UUID PRIMARY KEY REFERENCES tenants(id),
    version     BIGINT NOT NULL DEFAULT 1,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO policy_snapshots (tenant_id) VALUES ('00000000-0000-0000-0000-000000000001');

CREATE FUNCTION bump_policy_snapshot() RETURNS trigger AS $$
DECLARE t UUID;
BEGIN
    t := COALESCE(NEW.tenant_id, OLD.tenant_id);
    IF t IS NULL THEN
        -- device_pods / user_pods carry no tenant_id; resolve through the pod
        SELECT tenant_id INTO t FROM pods WHERE id = COALESCE(NEW.pod_id, OLD.pod_id);
    END IF;
    INSERT INTO policy_snapshots (tenant_id, version) VALUES (t, 1)
        ON CONFLICT (tenant_id) DO UPDATE SET version = policy_snapshots.version + 1, updated_at = now();
    PERFORM pg_notify('avon_policy_changed', t::text);
    RETURN NULL;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER policies_bump      AFTER INSERT OR UPDATE OR DELETE ON policies       FOR EACH ROW EXECUTE FUNCTION bump_policy_snapshot();
CREATE TRIGGER pods_bump          AFTER INSERT OR UPDATE OR DELETE ON pods           FOR EACH ROW EXECUTE FUNCTION bump_policy_snapshot();
CREATE TRIGGER device_pods_bump   AFTER INSERT OR DELETE ON device_pods              FOR EACH ROW EXECUTE FUNCTION bump_policy_snapshot();
CREATE TRIGGER device_classes_bump AFTER INSERT OR UPDATE OR DELETE ON device_classes FOR EACH ROW EXECUTE FUNCTION bump_policy_snapshot();
CREATE TRIGGER devices_bump       AFTER UPDATE OF status, device_class_id, attestation_state, risk_score ON devices
                                  FOR EACH ROW EXECUTE FUNCTION bump_policy_snapshot();

CREATE TABLE policy_decisions (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID NOT NULL,
    decided_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    device_id   UUID NOT NULL,
    session_id  BYTEA,
    destination TEXT NOT NULL,
    effect      TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    policy_ids  UUID[] NOT NULL DEFAULT '{}',
    reason      TEXT NOT NULL
);
CREATE INDEX policy_decisions_tenant_time_idx ON policy_decisions (tenant_id, decided_at DESC);

-- ---------------------------------------------------------------- audit & analytics
CREATE TABLE activity_logs (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID NOT NULL,
    event_type  TEXT NOT NULL,
    actor_id    UUID,
    actor_type  TEXT NOT NULL CHECK (actor_type IN ('user', 'device', 'service', 'system')),
    target_id   UUID,
    target_type TEXT,
    details     JSONB,
    ip_address  INET,
    request_id  TEXT,
    prev_hash   BYTEA,
    hash        BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX activity_logs_tenant_time_idx ON activity_logs (tenant_id, created_at DESC);

CREATE TABLE analytics_snapshots (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    UUID NOT NULL,
    metric_name  TEXT NOT NULL,
    metric_value DOUBLE PRECISION NOT NULL,
    labels       JSONB,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX analytics_snapshots_idx ON analytics_snapshots (tenant_id, metric_name, collected_at);

CREATE TABLE analytics_hourly (
    tenant_id    UUID NOT NULL,
    metric_name  TEXT NOT NULL,
    hour         TIMESTAMPTZ NOT NULL,
    avg_value    DOUBLE PRECISION,
    min_value    DOUBLE PRECISION,
    max_value    DOUBLE PRECISION,
    sample_count INTEGER,
    PRIMARY KEY (tenant_id, metric_name, hour)
);

CREATE TABLE anomaly_events (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    metric_name     TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'warning' CHECK (severity IN ('warning', 'critical')),
    current_value   DOUBLE PRECISION NOT NULL,
    expected_value  DOUBLE PRECISION NOT NULL,
    deviation       DOUBLE PRECISION NOT NULL,
    message         TEXT,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by UUID
);
CREATE INDEX anomaly_events_open_idx ON anomaly_events (tenant_id, metric_name) WHERE acknowledged_at IS NULL;

-- ---------------------------------------------------------------- row-level security
-- Applies to roles WITHOUT BYPASSRLS (the admin API). Services use a BYPASSRLS role.
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['users','scim_tokens','pods','device_classes','devices','enrollment_tokens',
                             'sessions','policies','policy_decisions','activity_logs',
                             'analytics_snapshots','analytics_hourly','anomaly_events']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
                           USING (tenant_id = current_setting('avon.tenant_id', true)::uuid)
                           WITH CHECK (tenant_id = current_setting('avon.tenant_id', true)::uuid)$p$, t);
    END LOOP;
END $$;
