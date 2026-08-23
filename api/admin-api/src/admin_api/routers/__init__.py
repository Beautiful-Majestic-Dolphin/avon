"""API routers for AVON Admin API."""

from admin_api.routers.dashboard import router as dashboard_router
from admin_api.routers.device_classes import router as device_classes_router
from admin_api.routers.devices import router as devices_router
from admin_api.routers.pods import router as pods_router
from admin_api.routers.policies import router as policies_router
from admin_api.routers.tunnels import router as tunnels_router
from admin_api.routers.users import router as users_router

__all__ = [
    "dashboard_router",
    "device_classes_router",
    "devices_router",
    "pods_router",
    "policies_router",
    "tunnels_router",
    "users_router",
]
