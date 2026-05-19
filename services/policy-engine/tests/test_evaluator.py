"""Tests for the AVON Policy Engine evaluator."""

import pytest
from datetime import time
from unittest.mock import AsyncMock, MagicMock

from policy_engine.engine.conditions import ConditionEvaluator
from policy_engine.engine.evaluator import PolicyEvaluator
from policy_engine.models.device import DevicePosture
from policy_engine.models.policy import (
    Policy,
    PolicyAction,
    PolicyConditions,
    PolicyDecision,
    RequiredPosture,
    TimeWindow,
)


class TestConditionEvaluator:
    """Tests for ConditionEvaluator."""

    def setup_method(self):
        self.evaluator = ConditionEvaluator()

    def test_evaluate_time_window_within_range(self):
        """Test time window evaluation when current time is within range."""
        window = TimeWindow(
            start_time=time(0, 0),
            end_time=time(23, 59),
            days_of_week=[0, 1, 2, 3, 4, 5, 6],
            timezone="UTC",
        )
        assert self.evaluator.evaluate_time_window(window) is True

    def test_evaluate_time_window_outside_range(self):
        """Test time window evaluation when current time is outside range."""
        window = TimeWindow(
            start_time=time(2, 0),
            end_time=time(3, 0),
            days_of_week=[0, 1, 2, 3, 4, 5, 6],
            timezone="UTC",
        )
        result = self.evaluator.evaluate_time_window(window)
        assert isinstance(result, bool)

    def test_evaluate_time_window_wrong_day(self):
        """Test time window evaluation when current day is not allowed."""
        window = TimeWindow(
            start_time=time(0, 0),
            end_time=time(23, 59),
            days_of_week=[],
            timezone="UTC",
        )
        assert self.evaluator.evaluate_time_window(window) is False

    def test_evaluate_posture_all_requirements_met(self):
        """Test posture evaluation when all requirements are met."""
        required = RequiredPosture(
            firewall_enabled=True,
            disk_encrypted=True,
        )
        actual = DevicePosture(
            firewall_enabled=True,
            disk_encrypted=True,
        )
        assert self.evaluator.evaluate_posture(required, actual) is True

    def test_evaluate_posture_firewall_not_enabled(self):
        """Test posture evaluation when firewall is not enabled."""
        required = RequiredPosture(firewall_enabled=True)
        actual = DevicePosture(firewall_enabled=False)
        assert self.evaluator.evaluate_posture(required, actual) is False

    def test_evaluate_posture_disk_not_encrypted(self):
        """Test posture evaluation when disk is not encrypted."""
        required = RequiredPosture(disk_encrypted=True)
        actual = DevicePosture(disk_encrypted=False)
        assert self.evaluator.evaluate_posture(required, actual) is False

    def test_evaluate_posture_no_posture_data(self):
        """Test posture evaluation when no posture data is available."""
        required = RequiredPosture(firewall_enabled=True)
        assert self.evaluator.evaluate_posture(required, None) is False

    def test_evaluate_posture_no_requirements(self):
        """Test posture evaluation when no requirements are specified."""
        required = RequiredPosture()
        actual = DevicePosture()
        assert self.evaluator.evaluate_posture(required, actual) is True

    def test_version_meets_minimum_equal(self):
        """Test version comparison when versions are equal."""
        assert self.evaluator._version_meets_minimum("1.0.0", "1.0.0") is True

    def test_version_meets_minimum_greater(self):
        """Test version comparison when actual is greater."""
        assert self.evaluator._version_meets_minimum("2.0.0", "1.0.0") is True

    def test_version_meets_minimum_less(self):
        """Test version comparison when actual is less."""
        assert self.evaluator._version_meets_minimum("1.0.0", "2.0.0") is False

    def test_version_meets_minimum_empty(self):
        """Test version comparison with empty strings."""
        assert self.evaluator._version_meets_minimum("", "1.0.0") is False
        assert self.evaluator._version_meets_minimum("1.0.0", "") is False

    def test_evaluate_all_conditions_no_conditions(self):
        """Test evaluating when no conditions are specified."""
        passed, reason = self.evaluator.evaluate_all_conditions(None, None, None)
        assert passed is True
        assert reason == "No conditions to evaluate"

    def test_evaluate_all_conditions_time_window_fails(self):
        """Test evaluating when time window condition fails."""
        conditions = PolicyConditions(
            time_window=TimeWindow(
                start_time=time(2, 0),
                end_time=time(3, 0),
                days_of_week=[],
                timezone="UTC",
            )
        )
        passed, reason = self.evaluator.evaluate_all_conditions(conditions, None, None)
        assert passed is False
        assert "time window" in reason.lower()


class TestPolicyEvaluator:
    """Tests for PolicyEvaluator."""

    @pytest.fixture
    def mock_queries(self):
        queries = MagicMock()
        queries.get_device_pods = AsyncMock(return_value=["pod-1"])
        queries.get_pod_hierarchy = AsyncMock(return_value=["pod-1", "parent-pod"])
        queries.get_matching_policies = AsyncMock(return_value=[])
        queries.get_device_posture = AsyncMock(return_value=None)
        queries.log_policy_decision = AsyncMock()
        return queries

    @pytest.fixture
    def mock_cache(self):
        cache = MagicMock()
        cache.get_device_pods = AsyncMock(return_value=None)
        cache.set_device_pods = AsyncMock()
        cache.get_pod_hierarchy = AsyncMock(return_value=None)
        cache.set_pod_hierarchy = AsyncMock()
        cache.get_matching_policies = AsyncMock(return_value=None)
        cache.set_matching_policies = AsyncMock()
        return cache

    @pytest.fixture
    def evaluator(self, mock_queries, mock_cache):
        return PolicyEvaluator(mock_queries, mock_cache)

    @pytest.mark.asyncio
    async def test_evaluate_no_matching_policies(self, evaluator, mock_queries):
        """Test evaluation when no policies match."""
        mock_queries.get_matching_policies = AsyncMock(return_value=[])

        decision = await evaluator.evaluate(
            source_device_id="device-1",
            destination_device_id="device-2",
        )

        assert decision.action == PolicyAction.DENY
        assert "No matching policies" in decision.reason

    @pytest.mark.asyncio
    async def test_evaluate_with_matching_allow_policy(self, evaluator, mock_queries):
        """Test evaluation with a matching ALLOW policy."""
        policy = Policy(
            id="policy-1",
            name="Allow Policy",
            source_pod_id="pod-1",
            destination_pod_id="pod-1",
            action=PolicyAction.ALLOW,
            priority=100,
            enabled=True,
        )
        mock_queries.get_matching_policies = AsyncMock(return_value=[policy])

        decision = await evaluator.evaluate(
            source_device_id="device-1",
            destination_device_id="device-2",
        )

        assert decision.action == PolicyAction.ALLOW
        assert decision.policy_id == "policy-1"

    @pytest.mark.asyncio
    async def test_evaluate_with_matching_deny_policy(self, evaluator, mock_queries):
        """Test evaluation with a matching DENY policy."""
        policy = Policy(
            id="policy-1",
            name="Deny Policy",
            source_pod_id="pod-1",
            destination_pod_id="pod-1",
            action=PolicyAction.DENY,
            priority=100,
            enabled=True,
        )
        mock_queries.get_matching_policies = AsyncMock(return_value=[policy])

        decision = await evaluator.evaluate(
            source_device_id="device-1",
            destination_device_id="device-2",
        )

        assert decision.action == PolicyAction.DENY
        assert decision.policy_id == "policy-1"

    @pytest.mark.asyncio
    async def test_evaluate_policy_priority_order(self, evaluator, mock_queries):
        """Test that policies are evaluated in priority order."""
        policies = [
            Policy(
                id="policy-low",
                name="Low Priority Allow",
                source_pod_id="pod-1",
                destination_pod_id="pod-1",
                action=PolicyAction.ALLOW,
                priority=10,
                enabled=True,
            ),
            Policy(
                id="policy-high",
                name="High Priority Deny",
                source_pod_id="pod-1",
                destination_pod_id="pod-1",
                action=PolicyAction.DENY,
                priority=100,
                enabled=True,
            ),
        ]
        mock_queries.get_matching_policies = AsyncMock(return_value=policies)

        decision = await evaluator.evaluate(
            source_device_id="device-1",
            destination_device_id="device-2",
        )

        assert decision.action == PolicyAction.ALLOW
        assert decision.policy_id == "policy-low"

    @pytest.mark.asyncio
    async def test_evaluate_no_source_pods(self, evaluator, mock_queries):
        """Test evaluation when source device has no pods."""
        mock_queries.get_device_pods = AsyncMock(return_value=[])

        decision = await evaluator.evaluate(
            source_device_id="device-1",
            destination_device_id="device-2",
        )

        assert decision.action == PolicyAction.DENY
        assert "no pod membership" in decision.reason.lower()

    @pytest.mark.asyncio
    async def test_evaluate_with_posture_context(self, evaluator, mock_queries):
        """Test evaluation with posture context provided."""
        policy = Policy(
            id="policy-1",
            name="Posture Policy",
            source_pod_id="pod-1",
            destination_pod_id="pod-1",
            action=PolicyAction.ALLOW,
            priority=100,
            enabled=True,
            conditions=PolicyConditions(
                required_posture=RequiredPosture(firewall_enabled=True)
            ),
        )
        mock_queries.get_matching_policies = AsyncMock(return_value=[policy])

        decision = await evaluator.evaluate(
            source_device_id="device-1",
            destination_device_id="device-2",
            context={
                "source_posture": {
                    "firewall_enabled": True,
                    "disk_encrypted": False,
                }
            },
        )

        assert decision.action == PolicyAction.ALLOW

    @pytest.mark.asyncio
    async def test_evaluate_posture_requirement_not_met(self, evaluator, mock_queries):
        """Test evaluation when posture requirement is not met."""
        policy = Policy(
            id="policy-1",
            name="Posture Policy",
            source_pod_id="pod-1",
            destination_pod_id="pod-1",
            action=PolicyAction.ALLOW,
            priority=100,
            enabled=True,
            conditions=PolicyConditions(
                required_posture=RequiredPosture(firewall_enabled=True)
            ),
        )
        mock_queries.get_matching_policies = AsyncMock(return_value=[policy])

        decision = await evaluator.evaluate(
            source_device_id="device-1",
            destination_device_id="device-2",
            context={
                "source_posture": {
                    "firewall_enabled": False,
                }
            },
        )

        assert decision.action == PolicyAction.DENY

    @pytest.mark.asyncio
    async def test_evaluate_records_timing(self, evaluator, mock_queries):
        """Test that evaluation records timing information."""
        mock_queries.get_matching_policies = AsyncMock(return_value=[])

        decision = await evaluator.evaluate(
            source_device_id="device-1",
            destination_device_id="device-2",
        )

        assert decision.evaluation_time_ms >= 0


class TestPolicyDecision:
    """Tests for PolicyDecision model."""

    def test_policy_decision_defaults(self):
        """Test PolicyDecision default values."""
        decision = PolicyDecision(
            action=PolicyAction.DENY,
            reason="Test reason",
        )
        assert decision.policy_id is None
        assert decision.evaluation_time_ms == 0.0
        assert decision.matched_policies_count == 0
        assert decision.source_pods == []
        assert decision.destination_pods == []

    def test_policy_decision_with_all_fields(self):
        """Test PolicyDecision with all fields populated."""
        decision = PolicyDecision(
            action=PolicyAction.ALLOW,
            policy_id="policy-123",
            reason="Matched policy",
            evaluation_time_ms=1.5,
            matched_policies_count=3,
            source_pods=["pod-1", "pod-2"],
            destination_pods=["pod-3"],
        )
        assert decision.action == PolicyAction.ALLOW
        assert decision.policy_id == "policy-123"
        assert decision.evaluation_time_ms == 1.5
        assert len(decision.source_pods) == 2


class TestTimeWindow:
    """Tests for TimeWindow model."""

    def test_time_window_defaults(self):
        """Test TimeWindow default values."""
        window = TimeWindow(
            start_time=time(9, 0),
            end_time=time(17, 0),
        )
        assert window.days_of_week == [0, 1, 2, 3, 4, 5, 6]
        assert window.timezone == "UTC"

    def test_time_window_custom_days(self):
        """Test TimeWindow with custom days."""
        window = TimeWindow(
            start_time=time(9, 0),
            end_time=time(17, 0),
            days_of_week=[0, 1, 2, 3, 4],
        )
        assert window.days_of_week == [0, 1, 2, 3, 4]


class TestRequiredPosture:
    """Tests for RequiredPosture model."""

    def test_required_posture_all_none(self):
        """Test RequiredPosture with no requirements."""
        posture = RequiredPosture()
        assert posture.firewall_enabled is None
        assert posture.disk_encrypted is None

    def test_required_posture_with_requirements(self):
        """Test RequiredPosture with specific requirements."""
        posture = RequiredPosture(
            firewall_enabled=True,
            disk_encrypted=True,
            min_os_version="10.0.0",
        )
        assert posture.firewall_enabled is True
        assert posture.min_os_version == "10.0.0"
