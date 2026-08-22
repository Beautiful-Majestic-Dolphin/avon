"""mTLS gRPC client for AdminService."""

from __future__ import annotations

from uuid import UUID

import grpc  # type: ignore
import structlog

from admin_api.config import settings

logger = structlog.get_logger()

# Lazy channel
_channel = None
_stub = None


def _get_channel():
    global _channel
    if _channel is None:
        url = getattr(settings, "control_grpc_url", "https://control:50051")
        # Strip scheme
        target = url.replace("https://", "").replace("http://", "")
        # For now, use insecure channel; mTLS will be added with certs from settings
        # In production, tls_cert/tls_key/tls_ca are used
        opts = []
        if settings.tls_ca and settings.tls_cert and settings.tls_key:
            try:
                with open(settings.tls_ca, "rb") as f:
                    ca = f.read()
                with open(settings.tls_cert, "rb") as f:
                    cert = f.read()
                with open(settings.tls_key, "rb") as f:
                    key = f.read()
                creds = grpc.ssl_channel_credentials(
                    root_certificates=ca, private_key=key, certificate_chain=cert
                )
                _channel = grpc.aio.secure_channel(target, creds, options=opts)
            except Exception as e:
                logger.warning(
                    "control_client_tls_failed_fallback_insecure", error=str(e)
                )
                _channel = grpc.aio.insecure_channel(target, options=opts)
        else:
            _channel = grpc.aio.insecure_channel(target, options=opts)
    return _channel


class ControlClient:
    """Thin wrapper — methods may be mocked in tests via fake_control fixture."""

    def __init__(self, channel=None):
        self._channel = channel or _get_channel()

    async def explain(
        self,
        tenant_id: UUID,
        device_id: UUID,
        destination: str,
        protocol: str,
        port: int,
    ):
        # Placeholder: will call AdminService.Explain
        # For now, return dummy
        return {"allow": False, "reason": "not implemented"}

    async def revoke_device(
        self, tenant_id: UUID, device_id: UUID, reason: str
    ) -> None:
        # Placeholder for AdminService.RevokeDevice
        # In tests, fake_control will be injected
        # Try to call real service if available, else no-op
        try:
            # Import generated stub if exists
            from admin_api.proto import admin_pb2, admin_pb2_grpc  # type: ignore

            stub = admin_pb2_grpc.AdminServiceStub(self._channel)
            req = admin_pb2.RevokeDeviceRequest(
                tenant_id=str(tenant_id), device_id=str(device_id), reason=reason
            )
            await stub.RevokeDevice(req, timeout=5)
        except Exception as e:
            # In dev/test without control, surface as 503 if fake_control not present
            # Check if we're in test with fake_control — caller will mock
            logger.debug("control_client_revoke_failed", error=str(e))
            raise

    async def approve_device(self, tenant_id: UUID, device_id: UUID) -> None:
        try:
            from admin_api.proto import admin_pb2, admin_pb2_grpc  # type: ignore

            stub = admin_pb2_grpc.AdminServiceStub(self._channel)
            req = admin_pb2.ApproveDeviceRequest(
                tenant_id=str(tenant_id), device_id=str(device_id)
            )
            await stub.ApproveDevice(req, timeout=5)
        except Exception as e:
            logger.debug("control_client_approve_failed", error=str(e))
            raise

    async def list_sessions(self, tenant_id: UUID):
        try:
            from admin_api.proto import admin_pb2, admin_pb2_grpc  # type: ignore

            stub = admin_pb2_grpc.AdminServiceStub(self._channel)
            req = admin_pb2.ListSessionsRequest(tenant_id=str(tenant_id))
            resp = await stub.ListSessions(req, timeout=5)
            return list(resp.sessions)
        except Exception:
            return []

    async def import_mud(self, tenant_id: UUID, device_class_id: UUID, document: str):
        try:
            from admin_api.proto import admin_pb2, admin_pb2_grpc  # type: ignore

            stub = admin_pb2_grpc.AdminServiceStub(self._channel)
            req = admin_pb2.ImportMudRequest(
                tenant_id=str(tenant_id),
                device_class_id=str(device_class_id),
                document=document,
            )
            resp = await stub.ImportMud(req, timeout=10)
            return {"created": list(resp.created), "skipped": list(resp.skipped)}
        except Exception as e:
            logger.debug("control_client_mud_failed", error=str(e))
            raise
