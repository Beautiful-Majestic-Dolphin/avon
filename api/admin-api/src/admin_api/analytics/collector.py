"""Analytics data collector for AVON — leader-elected."""

import asyncio

import httpx
import structlog

from admin_api.analytics.detector import run_anomaly_detection
from admin_api.analytics.queries import AnalyticsQueries
from admin_api.config import settings
from admin_api.db.connection import DatabasePool

logger = structlog.get_logger()

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


async def query_prometheus(client: httpx.AsyncClient, query: str) -> float | None:
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
        value = results[0].get("value", [None, None])
        if len(value) >= 2 and value[1] != "NaN":
            return float(value[1])
        return None
    except Exception as e:
        logger.debug("prometheus_query_failed", query=query[:50], error=str(e))
        return None


async def collect_metrics() -> None:
    pool = DatabasePool._pool
    if pool is None:
        logger.warning("analytics_collector_no_db")
        return
    async with httpx.AsyncClient() as client, pool.acquire() as conn:
        collected = 0
        for metric_name, query in METRIC_QUERIES.items():
            value = await query_prometheus(client, query)
            if value is not None:
                await AnalyticsQueries.store_snapshot(conn, metric_name, value)
                collected += 1
        if collected > 0:
            logger.debug("analytics_collected", metrics=collected)
        rollups = await AnalyticsQueries.rollup_hourly(conn)
        if rollups > 0:
            logger.debug("analytics_rollup", new_rollups=rollups)
        await run_anomaly_detection(conn)
        deleted = await AnalyticsQueries.cleanup_old_snapshots(
            conn, retention_days=settings.analytics_retention_days
        )
        if deleted > 0:
            logger.debug("analytics_cleanup", deleted=deleted)


async def collector_loop() -> None:
    """Background loop — leader-elected via SET NX EX 330."""
    interval = settings.analytics_collection_interval_seconds
    logger.info(
        "analytics_collector_started",
        interval_seconds=interval,
        prometheus_url=settings.analytics_prometheus_url,
    )
    # Try to use Redis for leader election if available
    try:
        import redis.asyncio as redis

        redis_client = redis.from_url(settings.redis_url)
        instance_id = (
            settings.instance_id if hasattr(settings, "instance_id") else "admin-api"
        )
        while True:
            try:
                acquired = await redis_client.set(
                    "avon:admin:analytics-leader", instance_id, nx=True, ex=330
                )
                if acquired:
                    logger.info("analytics_leader_acquired", instance=instance_id)
                    try:
                        await collect_metrics()
                    finally:
                        # Extend while running — keep key alive, but let it expire if we die
                        await redis_client.expire("avon:admin:analytics-leader", 330)
                else:
                    logger.debug("analytics_not_leader_skip")
            except Exception as e:
                logger.debug("analytics_leader_error", error=str(e))
                # Fallback: run anyway if Redis unavailable (single replica dev)
                try:
                    await collect_metrics()
                except Exception as ce:
                    logger.error("analytics_collection_error", error=str(ce))
            await asyncio.sleep(interval)
    except Exception:
        # No redis — simple loop
        while True:
            try:
                await collect_metrics()
            except Exception as e:
                logger.error("analytics_collection_error", error=str(e))
            await asyncio.sleep(interval)
