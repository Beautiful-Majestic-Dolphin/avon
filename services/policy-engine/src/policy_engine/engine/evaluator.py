"""Policy evaluator for the AVON Policy Engine."""

import time
from typing import Optional

import structlog

from policy_engine.cache.redis_cache import PolicyCache
from policy_engine.config import Settings
from policy_engine.db.queries import PolicyQueries
from policy_engine.engine.conditions import ConditionEvaluator
from policy_engine.engine.pod_hierarchy import PodHierarchy
from policy_engine.models.device import DevicePosture
from policy_engine.models.policy import Policy, PolicyAction, PolicyDecision

logger = structlog.get_logger()


class PolicyEvaluator:
    """Evaluates policies for connection requests."""

    def __init__(
        self,
        queries: PolicyQueries,
        cache: PolicyCache,
        settings: Optional[Settings] = None,
    ):
        self.queries = queries
        self.cache = cache
        self.settings = settings or Settings()
        self.pod_hierarchy = PodHierarchy(queries, cache)
        self.condition_evaluator = ConditionEvaluator()

    async def evaluate(
        self,
        source_device_id: str,
        destination_device_id: str,
        context: Optional[dict] = None,
    ) -> PolicyDecision:
        """Evaluate policy for a connection request.

        1. Get pod memberships for both devices
        2. Expand pod hierarchy (include parent pods)
        3. Find matching policies ordered by priority
        4. Evaluate conditions for each policy
        5. Return first matching policy's action (default: DENY)
        """
        start_time = time.monotonic()
        context = context or {}

        logger.info(
            "Evaluating policy",
            source_device=source_device_id,
            destination_device=destination_device_id,
        )

        try:
            source_pods = await self.pod_hierarchy.get_expanded_device_pods(
                source_device_id
            )
            dest_pods = await self.pod_hierarchy.get_expanded_device_pods(
                destination_device_id
            )

            if not source_pods:
                return self._create_decision(
                    action=PolicyAction.DENY,
                    reason="Source device has no pod membership",
                    start_time=start_time,
                    source_pods=list(source_pods),
                    dest_pods=list(dest_pods),
                )

            if not dest_pods:
                return self._create_decision(
                    action=PolicyAction.DENY,
                    reason="Destination device has no pod membership",
                    start_time=start_time,
                    source_pods=list(source_pods),
                    dest_pods=list(dest_pods),
                )

            policies = await self._get_matching_policies(
                list(source_pods), list(dest_pods)
            )

            if not policies:
                return self._create_decision(
                    action=PolicyAction.DENY,
                    reason="No matching policies found",
                    start_time=start_time,
                    source_pods=list(source_pods),
                    dest_pods=list(dest_pods),
                )

            source_posture = await self._get_device_posture(
                source_device_id, context.get("source_posture")
            )
            dest_posture = await self._get_device_posture(
                destination_device_id, context.get("dest_posture")
            )

            for policy in policies:
                passed, condition_reason = (
                    self.condition_evaluator.evaluate_all_conditions(
                        policy.conditions, source_posture, dest_posture
                    )
                )

                if passed:
                    decision = self._create_decision(
                        action=policy.action,
                        policy_id=policy.id,
                        reason=f"Matched policy '{policy.name}' (priority {policy.priority})",
                        start_time=start_time,
                        matched_count=len(policies),
                        source_pods=list(source_pods),
                        dest_pods=list(dest_pods),
                    )

                    if self.settings.enable_audit_logging:
                        await self._log_decision(
                            source_device_id, destination_device_id, decision
                        )

                    return decision

                logger.debug(
                    "Policy conditions not met",
                    policy_id=policy.id,
                    policy_name=policy.name,
                    reason=condition_reason,
                )

            decision = self._create_decision(
                action=PolicyAction.DENY,
                reason="No policies matched after condition evaluation",
                start_time=start_time,
                matched_count=len(policies),
                source_pods=list(source_pods),
                dest_pods=list(dest_pods),
            )

            if self.settings.enable_audit_logging:
                await self._log_decision(
                    source_device_id, destination_device_id, decision
                )

            return decision

        except Exception as e:
            logger.error(
                "Policy evaluation failed",
                source_device=source_device_id,
                destination_device=destination_device_id,
                error=str(e),
            )

            return self._create_decision(
                action=PolicyAction.DENY,
                reason=f"Evaluation error: {str(e)}",
                start_time=start_time,
            )

    async def _get_matching_policies(
        self, source_pods: list[str], dest_pods: list[str]
    ) -> list[Policy]:
        """Get matching policies with caching."""
        cached = await self.cache.get_matching_policies(source_pods, dest_pods)
        if cached is not None:
            logger.debug("Using cached policies", count=len(cached))
            return cached

        policies = await self.queries.get_matching_policies(source_pods, dest_pods)
        await self.cache.set_matching_policies(source_pods, dest_pods, policies)

        logger.debug("Fetched policies from database", count=len(policies))
        return policies

    async def _get_device_posture(
        self, device_id: str, context_posture: Optional[dict] = None
    ) -> Optional[DevicePosture]:
        """Get device posture from context or database."""
        if context_posture:
            try:
                return DevicePosture.model_validate(context_posture)
            except Exception as e:
                logger.warning(
                    "Failed to parse context posture",
                    device_id=device_id,
                    error=str(e),
                )

        posture_data = await self.queries.get_device_posture(device_id)
        if posture_data:
            try:
                return DevicePosture.model_validate(posture_data)
            except Exception as e:
                logger.warning(
                    "Failed to parse database posture",
                    device_id=device_id,
                    error=str(e),
                )

        return None

    async def _log_decision(
        self,
        source_device_id: str,
        destination_device_id: str,
        decision: PolicyDecision,
    ) -> None:
        """Log policy decision for audit."""
        try:
            await self.queries.log_policy_decision(
                source_device=source_device_id,
                dest_device=destination_device_id,
                action=decision.action.value,
                policy_id=decision.policy_id,
                reason=decision.reason,
                evaluation_time_ms=decision.evaluation_time_ms,
            )
        except Exception as e:
            logger.error(
                "Failed to log policy decision",
                source_device=source_device_id,
                destination_device=destination_device_id,
                error=str(e),
            )

    def _create_decision(
        self,
        action: PolicyAction,
        reason: str,
        start_time: float,
        policy_id: Optional[str] = None,
        matched_count: int = 0,
        source_pods: Optional[list[str]] = None,
        dest_pods: Optional[list[str]] = None,
    ) -> PolicyDecision:
        """Create a policy decision with timing information."""
        evaluation_time_ms = (time.monotonic() - start_time) * 1000

        decision = PolicyDecision(
            action=action,
            policy_id=policy_id,
            reason=reason,
            evaluation_time_ms=evaluation_time_ms,
            matched_policies_count=matched_count,
            source_pods=source_pods or [],
            destination_pods=dest_pods or [],
        )

        logger.info(
            "Policy decision",
            action=action.value,
            policy_id=policy_id,
            reason=reason,
            evaluation_time_ms=f"{evaluation_time_ms:.2f}",
        )

        return decision
