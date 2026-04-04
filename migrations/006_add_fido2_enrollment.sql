-- Add FIDO2 hardware security key support to device enrollment
-- Allows enrollment tokens to require FIDO2 attestation and stores
-- attestation metadata on enrolled devices

-- Add FIDO2 requirement flag to enrollment tokens
ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS require_fido2 BOOLEAN NOT NULL DEFAULT FALSE;

-- Add FIDO2 attestation metadata to devices
ALTER TABLE devices ADD COLUMN IF NOT EXISTS fido2_credential_id BYTEA;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS fido2_aaguid BYTEA;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS fido2_attestation_format VARCHAR(50);

CREATE INDEX IF NOT EXISTS idx_devices_fido2_credential_id
    ON devices(fido2_credential_id)
    WHERE fido2_credential_id IS NOT NULL;
