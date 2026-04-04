"""Anomaly detection for AVON analytics.

Uses Z-score deviation to detect unusual metric values.
Warning at 2-sigma, critical at 3-sigma from 7-day rolling average.
"""

import asyncpg
import structlog

from admin_api.analytics.queries import AnalyticsQueries

logger = structlog.get_logger()

# Metrics to monitor for anomalies
MONITORED_METRICS = [
    "auth_failure_rate",
    "enrollment_rate",
    "gateway_drop_rate",
    "tunnel_churn_rate",
]

WARNING_THRESHOLD = 2.0  # 2-sigma
CRITICAL_THRESHOLD = 3.0  # 3-sigma


async def detect_anomalies(
    conn: asyncpg.Connection,
    metric_name: str,
    current_value: float,
) -> None:
    """Check if a metric value is anomalous and store the event if so."""
    mean, stddev = await AnalyticsQueries.get_metric_stats(conn, metric_name)

    if stddev == 0 or mean == 0:
        return

    z_score = abs(current_value - mean) / stddev

    if z_score >= CRITICAL_THRESHOLD:
        await AnalyticsQueries.store_anomaly(
            conn,
            metric_name=metric_name,
            severity="critical",
            current_value=current_value,
            expected_value=mean,
            deviation=z_score,
            message=f"{metric_name} is {z_score:.1f} standard deviations from the 7-day average ({current_value:.2f} vs expected {mean:.2f})",
        )
        logger.warning(
            "anomaly_detected",
            metric=metric_name,
            severity="critical",
            z_score=round(z_score, 2),
            current=round(current_value, 4),
            expected=round(mean, 4),
        )
    elif z_score >= WARNING_THRESHOLD:
        await AnalyticsQueries.store_anomaly(
            conn,
            metric_name=metric_name,
            severity="warning",
            current_value=current_value,
            expected_value=mean,
            deviation=z_score,
            message=f"{metric_name} is {z_score:.1f} standard deviations from the 7-day average ({current_value:.2f} vs expected {mean:.2f})",
        )
        logger.info(
            "anomaly_detected",
            metric=metric_name,
            severity="warning",
            z_score=round(z_score, 2),
        )


async def run_anomaly_detection(conn: asyncpg.Connection) -> None:
    """Run anomaly detection on all monitored metrics using latest snapshot values."""
    for metric in MONITORED_METRICS:
        row = await conn.fetchrow(
            """SELECT metric_value FROM analytics_snapshots
               WHERE metric_name = $1
               ORDER BY collected_at DESC LIMIT 1""",
            metric,
        )
        if row:
            await detect_anomalies(conn, metric, row["metric_value"])
