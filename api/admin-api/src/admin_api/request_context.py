"""Per-request context for code that has no `Request` in hand.

The audit log wants an actor IP and a request id on every row, but most of
its writers are query helpers called from deep inside a handler. A contextvar
set by a tiny ASGI middleware lets them find both without threading a Request
through every signature.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True)
class RequestContext:
    ip: str | None
    request_id: str


_current: ContextVar[RequestContext | None] = ContextVar(
    "avon_request_context", default=None
)


def current_request() -> RequestContext | None:
    return _current.get()


class RequestContextMiddleware:
    """Pure ASGI middleware: records the client IP and the X-Request-ID header
    (or a fresh id) for the duration of one HTTP request."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        headers = dict(scope.get("headers") or [])
        header_id = headers.get(b"x-request-id", b"").decode("latin-1").strip()
        ctx = RequestContext(
            ip=client[0] if client else None,
            request_id=header_id or uuid.uuid4().hex[:16],
        )
        token = _current.set(ctx)
        try:
            await self.app(scope, receive, send)
        finally:
            _current.reset(token)
