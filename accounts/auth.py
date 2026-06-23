"""Cookie-based JWT authentication for DRF.

The JWT access token is delivered in an HttpOnly cookie (so it is invisible to
JavaScript and therefore not stealable via XSS). Because the credential now
travels automatically with every same-site request, we MUST add CSRF
protection for unsafe methods — exactly as DRF's SessionAuthentication does.
We therefore re-run Django's CsrfViewMiddleware check here (double-submit
cookie: the SPA echoes the readable ``csrftoken`` cookie in ``X-CSRFToken``).
"""
from django.conf import settings
from django.middleware.csrf import CsrfViewMiddleware
from rest_framework import exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken


class _ForbiddenCsrf(CsrfViewMiddleware):
    def _reject(self, request, reason):
        return reason


def _enforce_csrf(request):
    """Run Django's CSRF checks for the current request. No-op for safe
    methods (GET/HEAD/OPTIONS/TRACE)."""
    check = _ForbiddenCsrf(lambda req: None)
    check.process_request(request)
    reason = check.process_view(request, None, (), {})
    if reason:
        raise exceptions.PermissionDenied(f"CSRF check failed: {reason}")


class CookieJWTAuthentication(JWTAuthentication):
    """Authenticate from the access-token cookie and enforce CSRF."""

    def authenticate(self, request):
        raw_token = request.COOKIES.get(settings.SIMPLE_JWT["AUTH_COOKIE"])
        if not raw_token:
            # Header (Bearer) auth: no ambient credential, so CSRF-exempt.
            return super().authenticate(request)

        validated_token = self.get_validated_token(raw_token)
        _enforce_csrf(request)
        return self.get_user(validated_token), validated_token

    def get_user(self, validated_token):
        user = super().get_user(validated_token)
        # Reject tokens minted before the latest privilege change / logout.
        if validated_token.get("tv") != user.token_version:
            raise InvalidToken("Token has been revoked.")
        return user
