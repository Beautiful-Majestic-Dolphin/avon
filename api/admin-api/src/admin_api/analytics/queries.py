"""Analytics database queries."""

from datetime import UTC, datetime, timedelta

import asyncpg

from admin_api.analytics.models import AnalyticsHourly, AnomalyEvent


class AnalyticsQueries:
    """Database queries for analytics data."""

    @staticmethod
    async def store_snapshot(
        conn: asyncpg.Connection,
        metric_name: str,
        metric_value: float,
        labels: dict | None = None,
    ) -> None:
        """Store a raw metric snapshot."""
        await conn.execute(
            """INSERT INTO analytics_snapshots (metric_name, metric_value, labels)
               VALUES ($1, $2, $3)""",
            metric_name,
            metric_value,
            labels,
        )

    @staticmethod
    async def get_hourly_trends(
        conn: asyncpg.Connection,
        metric_name: str,
        hours: int = 24,
    ) -> list[AnalyticsHourly]:
        """Get hourly trend data for a metric."""
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = await conn.fetch(
            """SELECT * FROM analytics_hourly
               WHERE metric_name = $1 AND hour >= $2
               ORDER BY hour""",
            metric_name,
            since,
        )
        return [AnalyticsHourly(**dict(row)) for row in rows]

    @staticmethod
    async def rollup_hourly(conn: asyncpg.Connection) -> int:
        """Roll up recent snapshots into hourly aggregates. Returns count of new rollups."""
        result = await conn.execute(
            """INSERT INTO analytics_hourly (metric_name, hour, avg_value, min_value, max_value, sample_count)
               SELECT
                   metric_name,
                   date_trunc('hour', collected_at) AS hour,
                   AVG(metric_value),
                   MIN(metric_value),
                   MAX(metric_value),
                   COUNT(*)
               FROM analytics_snapshots
               WHERE collected_at >= NOW() - INTERVAL '2 hours'
               GROUP BY metric_name, date_trunc('hour', collected_at)
               ON CONFLICT (metric_name, hour) DO UPDATE SET
                   avg_value = EXCLUDED.avg_value,
                   min_value = EXCLUDED.min_value,
                   max_value = EXCLUDED.max_value,
                   sample_count = EXCLUDED.sample_count"""
        )
        return int(result.split()[-1]) if result else 0

    @staticmethod
    async def cleanup_old_snapshots(
        conn: asyncpg.Connection, retention_days: int = 7
    ) -> int:
        """Delete snapshots older than retention period."""
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        result = await conn.execute(
            "DELETE FROM analytics_snapshots WHERE collected_at < $1", cutoff
        )
        return int(result.split()[-1]) if result else 0

    @staticmethod
    async def get_metric_stats(
        conn: asyncpg.Connection,
        metric_name: str,
        days: int = 7,
    ) -> tuple[float, float]:
        """Get mean and stddev for a metric over the last N days. Returns (mean, stddev)."""
        since = datetime.now(UTC) - timedelta(days=days)
        row = await conn.fetchrow(
            """SELECT AVG(avg_value) AS mean, STDDEV(avg_value) AS stddev
               FROM analytics_hourly
               WHERE metric_name = $1 AND hour >= $2""",
            metric_name,
            since,
        )
        mean = row["mean"] if row and row["mean"] is not None else 0.0
        stddev = row["stddev"] if row and row["stddev"] is not None else 0.0
        return mean, stddev

    @staticmethod
    async def store_anomaly(
        conn: asyncpg.Connection,
        metric_name: str,
        severity: str,
        current_value: float,
        expected_value: float,
        deviation: float,
        message: str,
    ) -> None:
        """Store a detected anomaly event."""
        await conn.execute(
            """INSERT INTO anomaly_events
               (metric_name, severity, current_value, expected_value, deviation, message)
               VALUES ($1, $2, $3, $4, $5, $6)""",
            metric_name,
            severity,
            current_value,
            expected_value,
            deviation,
            message,
        )

    @staticmethod
    async def get_anomalies(
        conn: asyncpg.Connection,
        severity: str | None = None,
        days: int = 30,
        limit: int = 100,
    ) -> list[AnomalyEvent]:
        """Get recent anomaly events."""
        since = datetime.now(UTC) - timedelta(days=days)
        if severity:
            rows = await conn.fetch(
                """SELECT * FROM anomaly_events
                   WHERE severity = $1 AND detected_at >= $2
                   ORDER BY detected_at DESC LIMIT $3""",
                severity,
                since,
                limit,
            )
        else:
            rows = await conn.fetch(
                """SELECT * FROM anomaly_events
                   WHERE detected_at >= $1
                   ORDER BY detected_at DESC LIMIT $2""",
                since,
                limit,
            )
        return [AnomalyEvent(**dict(row)) for row in rows]
