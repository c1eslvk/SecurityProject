"""The login endpoint is IP-rate-limited (a layer independent of the
per-account lockout). Exercises the real configured rate (login = 10/min)."""
from django.core.cache import cache
from rest_framework.test import APITestCase

from .base import STRONG_PASSWORD


class LoginThrottleTests(APITestCase):
    def setUp(self):
        cache.clear()  # start from an empty throttle history

    def tearDown(self):
        cache.clear()

    def test_login_is_rate_limited_by_ip(self):
        # The configured rate is 10/min; the 11th request in the window trips.
        statuses = [
            self.client.post(
                "/api/auth/login/",
                {"username": "nobody", "password": STRONG_PASSWORD},
                format="json",
            ).status_code
            for _ in range(12)
        ]
        self.assertIn(429, statuses)
