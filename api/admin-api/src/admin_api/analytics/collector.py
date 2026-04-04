"""Analytics data collector for AVON.

Background task that periodically queries Prometheus for key metrics,
stores snapshots, performs hourly rollups, and runs anomaly detection.
"""

import asyncio

import httpx
import structlog

from admin_api.analytics.detector import run_anomaly_detection
from admin_api.analytics.queries import AnalyticsQueries
from admin_api.config import settings
from admin_api.db.connection import DatabasePool

logger = structlog.get_logger()

# Prometheus queries to collect
METRIC_QUERIES = {
    "connected_agents": "sum(avon_connected_agents) or vector(0)",
    "active_tunnels": "sum(avon_active_tunnels) or vector(0)",
    "auth_request_rate": "sum(rate(avon_auth_requests_total[5m])) or vector(0)",
    "auth_failure_rate": 'sum(rate(avon_auth_verifications_total{result="failure"}[5m])) or vector(0)',
    "gateway_packet_rate": "sum(rate(gateway_packets_received_total[5m])) or vector(0)",
    "gateway_drop_rate": "sum(rate(gateway_packets_dropped_rate_limit_total[5m])) or vector(0)",
    "enrollment_rate": "sum(rate(avon_auth_enrollments_total[5m])) or vector(0)",
    "cert_issuance_rate": "sum(rate(avon_ca_certificates_issued_total[5m])) or vector(0)",
    "auth_p95_latency": "histogram_quantile(0.95, sum(rate(avon_auth_duration_seconds_bucket[5m])) by (le)) or vector(0)",
    "tunnel_churn_rate": "sum(rate(avon_active_tunnels[5m])) or vector(0)",
}


async def query_prometheus(
    client: httpx.AsyncClient, query: str
) -> float | None:
    """Query Prometheus and return the scalar value."""
    try:
        response = await client.get(
            f"{settings.analytics_prometheus_url}/api/v1/query",
            params={"query": query},
            timeout=10.0,
        )
        if response.status_code != 200:
            return None

        data = response.json()
        if data.get("status") != "success":
            return None

        results = data.get("data", {}).get("result", [])
        if not results:
            return None

        # Extract scalar value from instant query result
        value = results[0].get("value", [None, None])
        if len(value) >= 2 and value[1] != "NaN":
            return float(value[1])
        return None
    except Exception as e:
        logger.debug("prometheus_query_failed", query=query[:50], error=str(e))
        return None


async def collect_metrics() -> None:
    """Collect all metrics from Prometheus and store snapshots."""
    pool = DatabasePool._pool
    if pool is None:
        logger.warning("analytics_collector_no_db")
        return

    async with httpx.AsyncClient() as client:
        async with pool.acquire() as conn:
            collected = 0
            for metric_name, query in METRIC_QUERIES.items():
                value = await query_prometheus(client, query)
                if value is not None:
                    await AnalyticsQueries.store_snapshot(
                        conn, metric_name, value
                    )
                    collected += 1

            if collected > 0:
                logger.debug("analytics_collected", metrics=collected)

            # Hourly rollup
            rollups = await AnalyticsQueries.rollup_hourly(conn)
            if rollups > 0:
                logger.debug("analytics_rollup", new_rollups=rollups)

            # Anomaly detection
            await run_anomaly_detection(conn)

            # Cleanup old snapshots
            deleted = await AnalyticsQueries.cleanup_old_snapshots(
                conn, retention_days=settings.analytics_retention_days
            )
            if deleted > 0:
                logger.debug("analytics_cleanup", deleted=deleted)


async def collector_loop() -> None:
    """Background loop that collects analytics on a schedule."""
    interval = settings.analytics_collection_interval_seconds
    logger.info(
        "analytics_collector_started",
        interval_seconds=interval,
        prometheus_url=settings.analytics_prometheus_url,
    )

    while True:
        try:
            await collect_metrics()
        except Exception as e:
            logger.error("analytics_collection_error", error=str(e))

        await asyncio.sleep(interval)
