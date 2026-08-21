-- bump_policy_snapshot() read NEW.tenant_id unconditionally. In PL/pgSQL that
-- raises `record "new" has no field "tenant_id"` on tables that do not have the
-- column, so every INSERT into device_pods (and user_pods, once it is wired up)
-- failed instead of falling through to the pod lookup the function intended.
-- Resolve the row as JSONB so a missing column is NULL rather than an error.
CREATE OR REPLACE FUNCTION bump_policy_snapshot() RETURNS trigger AS $$
DECLARE
    t   UUID;
    rec JSONB;
BEGIN
    IF TG_OP = 'DELETE' THEN
        rec := to_jsonb(OLD);
    ELSE
        rec := to_jsonb(NEW);
    END IF;
    t := (rec ->> 'tenant_id')::UUID;
    IF t IS NULL THEN
        -- device_pods / user_pods carry no tenant_id; resolve through the pod
        SELECT tenant_id INTO t FROM pods WHERE id = (rec ->> 'pod_id')::UUID;
    END IF;
    IF t IS NULL THEN
        RETURN NULL;
    END IF;
    INSERT INTO policy_snapshots (tenant_id, version) VALUES (t, 1)
        ON CONFLICT (tenant_id) DO UPDATE SET version = policy_snapshots.version + 1, updated_at = now();
    PERFORM pg_notify('avon_policy_changed', t::text);
    RETURN NULL;
END $$ LANGUAGE plpgsql;
