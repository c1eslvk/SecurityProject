from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    """Persisted, tamper-evident-ish record of security-relevant events.

    Rows are append-only by convention (no update/delete endpoints exist).
    Never store secrets, tokens, passwords, or session/JWT identifiers here.
    """

    class Event(models.TextChoices):
        LOGIN_SUCCESS = "login_success"
        LOGIN_FAILED = "login_failed"
        LOGIN_LOCKED = "login_locked"
        LOGOUT = "logout"
        TOKEN_REFRESH = "token_refresh"
        REGISTER = "register"
        ROLE_CHANGE = "role_change"
        USER_DELETE = "user_delete"
        PERMISSION_DENIED = "permission_denied"
        PAGE_ACCESS = "page_access"

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    event = models.CharField(max_length=32, choices=Event.choices, db_index=True)
    success = models.BooleanField(default=True)
    # Actor may be null for anonymous/failed-auth events; SET_NULL keeps history
    # if the account is later removed.
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_events",
    )
    # Free-form, non-PII description of the affected subject (e.g. "user:42").
    target = models.CharField(max_length=255, blank=True, default="")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self) -> str:
        actor = self.actor_id or "anonymous"
        return f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] {self.event} actor={actor}"
