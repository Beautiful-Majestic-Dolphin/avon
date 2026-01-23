-- Migration: Create revocations table
-- Tracks certificate revocations

CREATE TABLE IF NOT EXISTS revocations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number BIGINT NOT NULL UNIQUE,
    certificate_id UUID REFERENCES certificates(id),
    reason VARCHAR(255) NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_revocations_serial_number ON revocations(serial_number);
CREATE INDEX idx_revocations_revoked_at ON revocations(revoked_at);

COMMENT ON TABLE revocations IS 'Tracks certificate revocations for OCSP responses';
COMMENT ON COLUMN revocations.reason IS 'Reason for revocation (e.g., key compromise, affiliation changed)';
COMMENT ON COLUMN revocations.revoked_by IS 'UUID of admin who revoked the certificate';
