"""Cookie-authenticated, state-changing requests must carry a valid CSRF token.
Header (Bearer) auth is exempt because it has no ambient credential."""
from rest_framework.test import APIClient

from accounts.tokens import tokens_for_user

from .base import RBACTestCase

LOGOUT = "/api/auth/logout/"


class CSRFTests(RBACTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user("ed_csrf")
        # enforce_csrf_checks=True makes Django actually run the CSRF check that
        # CookieJWTAuthentication triggers for cookie-authenticated requests.
        self.client = APIClient(enforce_csrf_checks=True)
        access, _ = tokens_for_user(self.user)
        self.client.get("/")  # prime the csrftoken cookie
        self.client.cookies["access_token"] = str(access)

    def test_cookie_auth_post_without_csrf_token_is_rejected(self):
        res = self.client.post(LOGOUT)
        self.assertEqual(res.status_code, 403)

    def test_cookie_auth_post_with_csrf_token_succeeds(self):
        token = self.client.cookies["csrftoken"].value
        res = self.client.post(LOGOUT, HTTP_X_CSRFTOKEN=token)
        self.assertEqual(res.status_code, 200)
