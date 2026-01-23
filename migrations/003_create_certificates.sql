-- Migration: Create certificates table
-- Tracks issued certificates for auditing and revocation

CREATE TABLE IF NOT EXISTS certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number BIGINT NOT NULL UNIQUE,
    device_id UUID NOT NULL REFERENCES devices(id),
    subject_cn VARCHAR(255) NOT NULL,
    issuer_cn VARCHAR(255) NOT NULL DEFAULT 'AVON Intermediate CA',
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    public_key_classical BYTEA NOT NULL,
    public_key_pqc BYTEA NOT NULL,
    certificate_der BYTEA NOT NULL,
    signature_classical BYTEA NOT NULL,
    signature_pqc BYTEA NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_certificates_serial_number ON certificates(serial_number);
CREATE INDEX idx_certificates_device_id ON certificates(device_id);
CREATE INDEX idx_certificates_status ON certificates(status);
CREATE INDEX idx_certificates_not_after ON certificates(not_after);

COMMENT ON TABLE certificates IS 'Tracks all issued certificates for auditing and revocation';
COMMENT ON COLUMN certificates.serial_number IS 'Unique monotonic serial number';
COMMENT ON COLUMN certificates.status IS 'Certificate status: active, revoked, expired';
