"""
Django settings for the RBAC authorization system.

Security posture (summary; see README.md for the full rationale):
  * Deny-by-default authorization (DRF DEFAULT_PERMISSION_CLASSES = IsAuthenticated).
  * JWT stored in HttpOnly/Secure/SameSite cookies, with rotation + blacklist revocation.
  * Argon2 password hashing.
  * Strict security headers + CSP (django-csp), clickjacking protection.
  * All secrets read from the environment; never hard-coded.
"""
import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env (developer convenience). Real secrets must come from the environment.
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def env_list(name: str, default):
    val = os.environ.get(name)
    if not val:
        return default
    return [item.strip() for item in val.split(",") if item.strip()]


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
# SECRET_KEY has NO default in production. A throwaway default is used only when
# DEBUG is on, so a missing key fails loudly before reaching production.
DEBUG = env_bool("DJANGO_DEBUG", False)

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "dev-only-insecure-key-do-not-use-in-production"
    else:
        raise RuntimeError(
            "DJANGO_SECRET_KEY environment variable is required when DEBUG is off."
        )

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", ["localhost", "127.0.0.1"])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    # Local
    "accounts",
    "audit",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "csp.middleware.CSPMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "rbac_project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "frontend" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "rbac_project.wsgi.application"

# ---------------------------------------------------------------------------
# Database (SQLite for the demo). The app should connect with a least-privilege
# account in production; with SQLite this maps to filesystem permissions on the
# database file. See README.md "Least-privilege database".
# ---------------------------------------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_USER_MODEL = "accounts.User"

# ---------------------------------------------------------------------------
# Password hashing & validation
# ---------------------------------------------------------------------------
# Argon2id first. Fast/unsalted hashes (MD5/SHA1) are never configured.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",  # fallback only
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---------------------------------------------------------------------------
# Django REST Framework: deny-by-default
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "accounts.auth.CookieJWTAuthentication",
    ],
    # Deny by default: a request must be authenticated unless a view explicitly
    # relaxes this (only the login/register/csrf endpoints do).
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.ScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "login": "10/min",
        "register": "5/min",
    },
    "EXCEPTION_HANDLER": "accounts.exceptions.safe_exception_handler",
}

# ---------------------------------------------------------------------------
# SimpleJWT: short-lived, signed, rotated, revocable
# ---------------------------------------------------------------------------
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=10),   # idle/access window
    "REFRESH_TOKEN_LIFETIME": timedelta(hours=8),     # absolute session ceiling
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,                 # old refresh is revoked on use
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    # Cookie configuration consumed by accounts.auth / accounts.views
    "AUTH_COOKIE": "access_token",
    "REFRESH_COOKIE": "refresh_token",
    "AUTH_COOKIE_PATH": "/",
    "REFRESH_COOKIE_PATH": "/api/auth/",
}

# ---------------------------------------------------------------------------
# Cookies & transport security
# ---------------------------------------------------------------------------
# COOKIE_SECURE must be True in production. It is overridable for local HTTP
# development only (set COOKIE_SECURE=False in .env), and is forced on when
# DEBUG is off.
COOKIE_SECURE = env_bool("COOKIE_SECURE", not DEBUG) or (not DEBUG)
SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SECURE = COOKIE_SECURE
CSRF_COOKIE_SECURE = COOKIE_SECURE
SESSION_COOKIE_HTTPONLY = True
# CSRF cookie must be readable by JS so the SPA can echo it in the X-CSRFToken
# header (double-submit). This is the documented, safe Django pattern.
CSRF_COOKIE_HTTPONLY = False

# Idle + absolute session timeout for the Django session (used by admin).
SESSION_COOKIE_AGE = 60 * 60  # 1 hour idle
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True

# Transport security headers
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"  # clickjacking: app must never be framed
# HSTS is only emitted over HTTPS (Django checks request.is_secure()).
SECURE_HSTS_SECONDS = int(os.environ.get("SECURE_HSTS_SECONDS", 31536000))
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", not DEBUG)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS", [])

# ---------------------------------------------------------------------------
# Content Security Policy (django-csp 3.x). No inline scripts; nothing framed.
# ---------------------------------------------------------------------------
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'",)
CSP_IMG_SRC = ("'self'", "data:")
CSP_CONNECT_SRC = ("'self'",)
CSP_FONT_SRC = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_BASE_URI = ("'none'",)
CSP_FRAME_ANCESTORS = ("'none'",)  # belt-and-suspenders with X-Frame-Options
CSP_FORM_ACTION = ("'self'",)

# ---------------------------------------------------------------------------
# Application security knobs
# ---------------------------------------------------------------------------
# Account lockout after repeated failed logins (in addition to DRF throttling).
LOGIN_MAX_FAILED_ATTEMPTS = int(os.environ.get("LOGIN_MAX_FAILED_ATTEMPTS", 5))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", 300))

# Allowlist for any server-side outbound HTTP request (SSRF protection).
# The app makes no outbound requests today; the allowlist is enforced by
# accounts.ssrf.validate_outbound_url should one ever be added.
OUTBOUND_HTTP_ALLOWLIST = env_list("OUTBOUND_HTTP_ALLOWLIST", [])

# ---------------------------------------------------------------------------
# i18n / static
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "frontend" / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Structured logging (security/audit). Never logs secrets/tokens/passwords.
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "audit.logging.JSONFormatter",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        },
    },
    "loggers": {
        "security": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
