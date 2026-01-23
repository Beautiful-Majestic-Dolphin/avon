-- Create enrollment_tokens table for device enrollment
-- Enrollment tokens are single-use tokens provided out-of-band for device onboarding

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    -- The enrollment token string (unique identifier)
    token VARCHAR(255) PRIMARY KEY,
    
    -- Expected hardware fingerprint (optional, for pre-registered devices)
    expected_fingerprint BYTEA,
    
    -- Pod ID to assign the device to (optional)
    pod_id UUID,
    
    -- Token expiration timestamp
    expires_at TIMESTAMPTZ NOT NULL,
    
    -- Whether the token has been used
    used BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Maximum number of uses (usually 1)
    max_uses INTEGER NOT NULL DEFAULT 1,
    
    -- Current number of uses
    use_count INTEGER NOT NULL DEFAULT 0,
    
    -- Who created this token (admin user ID or system)
    created_by VARCHAR(255),
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for expiration queries (cleanup of expired tokens)
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_expires_at ON enrollment_tokens(expires_at);

-- Index for unused token lookups
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_used ON enrollment_tokens(used) WHERE NOT used;

-- Partial index for active (unused, not expired) tokens
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_active 
    ON enrollment_tokens(token) 
    WHERE NOT used AND expires_at > NOW();
