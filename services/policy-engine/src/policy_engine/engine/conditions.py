"""Condition evaluation for the AVON Policy Engine."""

from datetime import datetime, time, timezone
from typing import Optional

import structlog

from policy_engine.models.device import DevicePosture
from policy_engine.models.policy import RequiredPosture, TimeWindow

logger = structlog.get_logger()


class ConditionEvaluator:
    """Evaluates policy conditions."""

    def evaluate_time_window(self, window: TimeWindow) -> bool:
        """Check if current time is within allowed window."""
        try:
            import zoneinfo
            tz = zoneinfo.ZoneInfo(window.timezone)
        except Exception:
            tz = timezone.utc

        now = datetime.now(tz)
        current_time = now.time()
        current_day = now.weekday()

        if current_day not in window.days_of_week:
            logger.debug(
                "Time window check failed: day not allowed",
                current_day=current_day,
                allowed_days=window.days_of_week,
            )
            return False

        if window.start_time <= window.end_time:
            in_window = window.start_time <= current_time <= window.end_time
        else:
            in_window = current_time >= window.start_time or current_time <= window.end_time

        if not in_window:
            logger.debug(
                "Time window check failed: outside time range",
                current_time=str(current_time),
                start_time=str(window.start_time),
                end_time=str(window.end_time),
            )

        return in_window

    def evaluate_posture(
        self,
        required: RequiredPosture,
        actual: Optional[DevicePosture],
    ) -> bool:
        """Check if device meets posture requirements."""
        if actual is None:
            logger.debug("Posture check failed: no posture data available")
            return False

        if required.firewall_enabled is not None:
            if required.firewall_enabled and not actual.firewall_enabled:
                logger.debug("Posture check failed: firewall not enabled")
                return False

        if required.disk_encrypted is not None:
            if required.disk_encrypted and not actual.disk_encrypted:
                logger.debug("Posture check failed: disk not encrypted")
                return False

        if required.antivirus_enabled is not None:
            if required.antivirus_enabled and not actual.antivirus_enabled:
                logger.debug("Posture check failed: antivirus not enabled")
                return False

        if required.screen_lock_enabled is not None:
            if required.screen_lock_enabled and not actual.screen_lock_enabled:
                logger.debug("Posture check failed: screen lock not enabled")
                return False

        if required.min_os_version is not None:
            if not self._version_meets_minimum(actual.os_version, required.min_os_version):
                logger.debug(
                    "Posture check failed: OS version too old",
                    actual=actual.os_version,
                    required=required.min_os_version,
                )
                return False

        if required.min_agent_version is not None:
            if not self._version_meets_minimum(
                actual.agent_version, required.min_agent_version
            ):
                logger.debug(
                    "Posture check failed: agent version too old",
                    actual=actual.agent_version,
                    required=required.min_agent_version,
                )
                return False

        if required.max_hours_since_update_check is not None:
            if actual.last_update_check is None:
                logger.debug("Posture check failed: no update check recorded")
                return False

            hours_since_check = (
                datetime.now(timezone.utc) - actual.last_update_check
            ).total_seconds() / 3600

            if hours_since_check > required.max_hours_since_update_check:
                logger.debug(
                    "Posture check failed: update check too old",
                    hours_since_check=hours_since_check,
                    max_hours=required.max_hours_since_update_check,
                )
                return False

        return True

    def _version_meets_minimum(self, actual: str, minimum: str) -> bool:
        """Compare version strings."""
        if not actual or not minimum:
            return False

        try:
            actual_parts = [int(p) for p in actual.split(".")]
            minimum_parts = [int(p) for p in minimum.split(".")]

            while len(actual_parts) < len(minimum_parts):
                actual_parts.append(0)
            while len(minimum_parts) < len(actual_parts):
                minimum_parts.append(0)

            return actual_parts >= minimum_parts
        except ValueError:
            return actual >= minimum

    def evaluate_all_conditions(
        self,
        conditions: Optional["PolicyConditions"],
        source_posture: Optional[DevicePosture],
        dest_posture: Optional[DevicePosture],
    ) -> tuple[bool, str]:
        """Evaluate all conditions for a policy.
        
        Returns (passed, reason) tuple.
        """
        from policy_engine.models.policy import PolicyConditions

        if conditions is None:
            return True, "No conditions to evaluate"

        if conditions.time_window is not None:
            if not self.evaluate_time_window(conditions.time_window):
                return False, "Outside allowed time window"

        if conditions.required_posture is not None:
            if not self.evaluate_posture(conditions.required_posture, source_posture):
                return False, "Source device does not meet posture requirements"

        return True, "All conditions met"
