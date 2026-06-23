"""Single entry point for recording security-relevant events.

``log_event`` does two things atomically from the caller's perspective:
  1. Persists an :class:`audit.models.AuditLog` row.
  2. Emits a structured JSON line on the ``security`` logger.

Callers must never pass secrets, tokens, passwords, or session/JWT ids in
``detail`` — only stable identifiers and outcome metadata.
"""
import logging

from .models import AuditLog

_logger = logging.getLogger("security")


def client_ip(request):
    """Best-effort client IP. Trusts X-Forwarded-For only when present; in a
    real deployment the proxy must strip/normalise this header."""
    if request is None:
        return None
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def log_event(event, *, request=None, actor=None, target="", success=True, **detail):
    ip = client_ip(request)
    AuditLog.objects.create(
        event=event,
        actor=actor if (actor is not None and getattr(actor, "is_authenticated", False)) else None,
        target=target or "",
        ip_address=ip,
        success=success,
        detail=detail,
    )
    _logger.info(
        event,
        extra={
            "event": event,
            "success": success,
            "actor_id": getattr(actor, "id", None) if getattr(actor, "is_authenticated", False) else None,
            "target": target or "",
            "ip": ip,
            **detail,
        },
    )
