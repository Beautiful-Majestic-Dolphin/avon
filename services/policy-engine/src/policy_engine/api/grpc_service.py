"""gRPC service implementation for the AVON Policy Engine."""

import grpc
import structlog

from policy_engine.engine.evaluator import PolicyEvaluator
from policy_engine.engine.pod_hierarchy import PodHierarchy
from policy_engine.models.device import DevicePosture
from policy_engine.models.policy import PolicyAction

logger = structlog.get_logger()


class PolicyServiceImpl:
    """gRPC service implementation for PolicyService."""

    def __init__(
        self,
        evaluator: PolicyEvaluator,
        pod_hierarchy: PodHierarchy,
    ):
        self.evaluator = evaluator
        self.pod_hierarchy = pod_hierarchy

    async def EvaluatePolicy(
        self,
        request,
        context: grpc.aio.ServicerContext,
    ):
        """Evaluate policy for a connection request."""
        from policy_engine.api import policy_pb2

        try:
            source_device_id = request.source_device_id.hex()
            destination_device_id = request.destination_device_id.hex()

            eval_context = {}

            if request.HasField("source_posture"):
                eval_context["source_posture"] = {
                    "os_version": request.source_posture.os_version,
                    "agent_version": request.source_posture.agent_version,
                    "firewall_enabled": request.source_posture.firewall_enabled,
                    "disk_encrypted": request.source_posture.disk_encrypted,
                }

            if request.HasField("destination_posture"):
                eval_context["dest_posture"] = {
                    "os_version": request.destination_posture.os_version,
                    "agent_version": request.destination_posture.agent_version,
                    "firewall_enabled": request.destination_posture.firewall_enabled,
                    "disk_encrypted": request.destination_posture.disk_encrypted,
                }

            for key, value in request.context.items():
                eval_context[key] = value

            decision = await self.evaluator.evaluate(
                source_device_id=source_device_id,
                destination_device_id=destination_device_id,
                context=eval_context,
            )

            proto_action = (
                policy_pb2.POLICY_ACTION_ALLOW
                if decision.action == PolicyAction.ALLOW
                else policy_pb2.POLICY_ACTION_DENY
            )

            return policy_pb2.EvaluatePolicyResponse(
                action=proto_action,
                policy_id=decision.policy_id or "",
                reason=decision.reason,
                evaluation_time_ms=decision.evaluation_time_ms,
                matched_policies_count=decision.matched_policies_count,
                source_pods=decision.source_pods,
                destination_pods=decision.destination_pods,
            )

        except Exception as e:
            logger.error("EvaluatePolicy failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return policy_pb2.EvaluatePolicyResponse(
                action=policy_pb2.POLICY_ACTION_DENY,
                reason=f"Internal error: {str(e)}",
            )

    async def GetDevicePods(
        self,
        request,
        context: grpc.aio.ServicerContext,
    ):
        """Get pods for a device."""
        from policy_engine.api import policy_pb2

        try:
            device_id = request.device_id.hex()

            if request.expand_hierarchy:
                pods = await self.pod_hierarchy.get_expanded_device_pods(device_id)
                pod_ids = list(pods)
            else:
                pod_ids = await self.pod_hierarchy.get_device_pods(device_id)

            return policy_pb2.GetDevicePodsResponse(pod_ids=pod_ids)

        except Exception as e:
            logger.error("GetDevicePods failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return policy_pb2.GetDevicePodsResponse()

    async def InvalidateCache(
        self,
        request,
        context: grpc.aio.ServicerContext,
    ):
        """Invalidate cache entries."""
        from policy_engine.api import policy_pb2

        try:
            target = request.WhichOneof("target")

            if target == "device_id":
                await self.evaluator.cache.invalidate_device(request.device_id)
                return policy_pb2.InvalidateCacheResponse(
                    success=True,
                    message=f"Invalidated cache for device {request.device_id}",
                )

            elif target == "pod_id":
                await self.evaluator.cache.invalidate_pod(request.pod_id)
                return policy_pb2.InvalidateCacheResponse(
                    success=True,
                    message=f"Invalidated cache for pod {request.pod_id}",
                )

            elif target == "all":
                return policy_pb2.InvalidateCacheResponse(
                    success=False,
                    message="Full cache invalidation not implemented",
                )

            else:
                return policy_pb2.InvalidateCacheResponse(
                    success=False,
                    message="No target specified",
                )

        except Exception as e:
            logger.error("InvalidateCache failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return policy_pb2.InvalidateCacheResponse(
                success=False,
                message=str(e),
            )


def create_grpc_server(
    evaluator: PolicyEvaluator,
    pod_hierarchy: PodHierarchy,
    port: int = 8081,
) -> grpc.aio.Server:
    """Create and configure the gRPC server."""
    from policy_engine.api import policy_pb2_grpc

    server = grpc.aio.server()
    service = PolicyServiceImpl(evaluator, pod_hierarchy)
    policy_pb2_grpc.add_PolicyServiceServicer_to_server(service, server)
    server.add_insecure_port(f"[::]:{port}")

    logger.info("gRPC server configured", port=port)
    return server
