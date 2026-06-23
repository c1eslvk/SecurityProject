from .base import STRONG_PASSWORD, RBACTestCase

ME = "/api/auth/me/"
LOGIN = "/api/auth/login/"
LOGOUT = "/api/auth/logout/"


class TokenRevocationTests(RBACTestCase):
    def test_bumping_token_version_revokes_access_token(self):
        user = self.make_user("dave", roles=["User"])
        self.auth(user)
        self.assertEqual(self.client.get(ME).status_code, 200)
        # A privilege change / logout increments token_version.
        user.bump_token_version()
        self.assertEqual(self.client.get(ME).status_code, 401)

    def test_logout_invalidates_session(self):
        self.make_user("erin", roles=["User"])
        login = self.client.post(LOGIN, {"username": "erin", "password": STRONG_PASSWORD},
                                 format="json")
        self.assertEqual(login.status_code, 200)
        self.assertEqual(self.client.get(ME).status_code, 200)

        logout = self.client.post(LOGOUT)
        self.assertEqual(logout.status_code, 200)
        # Cookies cleared + token_version bumped -> fully invalidated.
        self.assertEqual(self.client.get(ME).status_code, 401)
