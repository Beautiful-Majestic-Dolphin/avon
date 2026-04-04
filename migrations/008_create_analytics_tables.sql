-- Advanced analytics tables for time-series rollups and anomaly detection

-- Raw metric snapshots collected from Prometheus every 5 minutes
CREATE TABLE IF NOT EXISTS analytics_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_name VARCHAR(255) NOT NULL,
    metric_value DOUBLE PRECISION NOT NULL,
    labels JSONB,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analytics_snapshots_metric
    ON analytics_snapshots(metric_name, collected_at);

-- Hourly rollups for trend analysis
CREATE TABLE IF NOT EXISTS analytics_hourly (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_name VARCHAR(255) NOT NULL,
    hour TIMESTAMPTZ NOT NULL,
    avg_value DOUBLE PRECISION,
    min_value DOUBLE PRECISION,
    max_value DOUBLE PRECISION,
    sample_count INTEGER,
    UNIQUE (metric_name, hour)
);

CREATE INDEX IF NOT EXISTS idx_analytics_hourly_lookup
    ON analytics_hourly(metric_name, hour);

-- Detected anomaly events
CREATE TABLE IF NOT EXISTS anomaly_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_name VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'warning',
    current_value DOUBLE PRECISION NOT NULL,
    expected_value DOUBLE PRECISION NOT NULL,
    deviation DOUBLE PRECISION NOT NULL,
    message TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_metric
    ON anomaly_events(metric_name, detected_at);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_severity
    ON anomaly_events(severity, detected_at);
