-- SCIM 2.0 Provisioning Support
-- Adds external IdP identifiers, user-pod memberships, and SCIM bearer tokens

-- Add external IdP identifiers and management tracking to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id VARCHAR(255) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS managed_by VARCHAR(20) NOT NULL DEFAULT 'local';

-- Add external IdP identifiers and management tracking to pods
ALTER TABLE pods ADD COLUMN IF NOT EXISTS external_id VARCHAR(255) UNIQUE;
ALTER TABLE pods ADD COLUMN IF NOT EXISTS managed_by VARCHAR(20) NOT NULL DEFAULT 'local';

-- User-to-pod membership for SCIM Group membership
-- Separate from device_pods which manages network access
CREATE TABLE IF NOT EXISTS user_pods (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pod_id UUID NOT NULL REFERENCES pods(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, pod_id)
);

CREATE INDEX IF NOT EXISTS idx_user_pods_pod_id ON user_pods(pod_id);

-- SCIM bearer tokens for IdP authentication
CREATE TABLE IF NOT EXISTS scim_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash VARCHAR(128) NOT NULL,
    description VARCHAR(255) NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_scim_tokens_active ON scim_tokens(is_active) WHERE is_active = TRUE;

-- Indexes for SCIM queries
CREATE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pods_external_id ON pods(external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_managed_by ON users(managed_by);
