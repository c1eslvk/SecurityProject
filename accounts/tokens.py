"""JWT issuance/cookie helpers.

Every token embeds the user's ``token_version`` as the ``tv`` claim so it can be
revoked instantly (see accounts.models.User.bump_token_version and
accounts.auth.CookieJWTAuthentication.get_user).
"""
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken

_JWT = settings.SIMPLE_JWT


def tokens_for_user(user):
    """Return (access_token, refresh_token) carrying the revocation stamp."""
    refresh = RefreshToken.for_user(user)
    refresh["tv"] = user.token_version
    access = refresh.access_token
    access["tv"] = user.token_version
    return access, refresh


def _set_cookie(response, name, value, *, path, max_age):
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        path=path,
        secure=settings.COOKIE_SECURE,
        httponly=True,  # tokens are never exposed to JavaScript
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )


def set_auth_cookies(response, access, refresh):
    _set_cookie(
        response,
        _JWT["AUTH_COOKIE"],
        str(access),
        path=_JWT["AUTH_COOKIE_PATH"],
        max_age=int(_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()),
    )
    _set_cookie(
        response,
        _JWT["REFRESH_COOKIE"],
        str(refresh),
        path=_JWT["REFRESH_COOKIE_PATH"],
        max_age=int(_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()),
    )


def clear_auth_cookies(response):
    response.delete_cookie(_JWT["AUTH_COOKIE"], path=_JWT["AUTH_COOKIE_PATH"])
    response.delete_cookie(_JWT["REFRESH_COOKIE"], path=_JWT["REFRESH_COOKIE_PATH"])
