from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.core.management import call_command
from django.test import override_settings
from rest_framework.test import APITestCase

from accounts.tokens import tokens_for_user

User = get_user_model()

# A password that satisfies every configured validator.
STRONG_PASSWORD = "Tr0ub4dor-Xy7q!"


# Disable DRF rate throttling during tests so unrelated tests don't 429 each
# other; the per-account lockout (a separate mechanism) is still exercised.
@override_settings(
    REST_FRAMEWORK={
        "DEFAULT_AUTHENTICATION_CLASSES": ["accounts.auth.CookieJWTAuthentication"],
        "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
        # DRF throttling is exercised separately; disable it here so the
        # request-history cache shared across the process can't 429 unrelated
        # tests. The per-account lockout (a distinct mechanism) still applies.
        "DEFAULT_THROTTLE_CLASSES": [],
        "DEFAULT_THROTTLE_RATES": {},
        "EXCEPTION_HANDLER": "accounts.exceptions.safe_exception_handler",
    }
)
class RBACTestCase(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        call_command("seed_rbac")

    def setUp(self):
        super().setUp()
        cache.clear()  # drop any throttle history between tests

    def make_user(self, username, *, roles=(), password=STRONG_PASSWORD,
                  is_superuser=False):
        user = User.objects.create_user(username=username, password=password)
        if is_superuser:
            user.is_superuser = True
            user.is_staff = True
        user.save()
        for role in roles:
            user.groups.add(Group.objects.get(name=role))
        return user

    def auth(self, user):
        """Authenticate the test client as `user` via a Bearer token (header
        auth, which is not subject to CSRF — keeps authz tests focused)."""
        access, _ = tokens_for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    def logout(self):
        self.client.credentials()
