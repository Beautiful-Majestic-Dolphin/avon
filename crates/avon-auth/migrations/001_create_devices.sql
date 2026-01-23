-- Create devices table for storing device authentication state
-- This migration creates the core table for device management

CREATE TABLE IF NOT EXISTS devices (
    -- Primary key: UUID for the device
    id UUID PRIMARY KEY,
    
    -- Human-readable device name
    name VARCHAR(255) NOT NULL,
    
    -- Hardware fingerprint for device binding (prevents token theft)
    hardware_fingerprint BYTEA NOT NULL,
    
    -- Current authentication token (32 bytes)
    current_token BYTEA NOT NULL,
    
    -- Previous authentication token for grace period (32 bytes, nullable)
    previous_token BYTEA,
    
    -- Token sequence number (increments on each rotation)
    token_sequence BIGINT NOT NULL DEFAULT 0,
    
    -- Device status: 'active', 'suspended', 'revoked'
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    
    -- Last time the device was seen
    last_seen_at TIMESTAMPTZ,
    
    -- Last known IP address
    last_known_ip VARCHAR(45),
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for hardware fingerprint lookups (enrollment checks)
CREATE INDEX IF NOT EXISTS idx_devices_hardware_fingerprint ON devices(hardware_fingerprint);

-- Index for status queries
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);

-- Index for last seen queries (for cleanup/monitoring)
CREATE INDEX IF NOT EXISTS idx_devices_last_seen_at ON devices(last_seen_at);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_devices_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
