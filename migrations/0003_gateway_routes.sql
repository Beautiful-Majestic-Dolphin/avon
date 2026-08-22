-- Networks a gateway will route into on behalf of its sessions. Reported by
-- the gateway at registration; control hands them to devices as routes.
ALTER TABLE gateways ADD COLUMN protected_cidrs CIDR[] NOT NULL DEFAULT '{}';
