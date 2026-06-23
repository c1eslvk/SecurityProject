from django.contrib.auth import get_user_model

from .base import STRONG_PASSWORD, RBACTestCase

User = get_user_model()

REGISTER = "/api/auth/register/"
LOGIN = "/api/auth/login/"
ME = "/api/auth/me/"


class PasswordHashingTests(RBACTestCase):
    def test_password_is_hashed_with_argon2(self):
        user = self.make_user("alice")
        self.assertTrue(user.password.startswith("argon2"))
        self.assertNotIn(STRONG_PASSWORD, user.password)


class RegistrationTests(RBACTestCase):
    def test_register_assigns_only_the_base_user_role(self):
        res = self.client.post(REGISTER, {
            "username": "newbie", "email": "n@example.com", "password": STRONG_PASSWORD,
        }, format="json")
        self.assertEqual(res.status_code, 201)
        user = User.objects.get(username="newbie")
        # Everyone starts with exactly the base "User" role — nothing elevated.
        self.assertEqual(
            sorted(user.groups.values_list("name", flat=True)), ["User"]
        )

    def test_weak_password_rejected(self):
        res = self.client.post(REGISTER, {
            "username": "weakling", "email": "w@example.com", "password": "password",
        }, format="json")
        self.assertEqual(res.status_code, 400)
        self.assertFalse(User.objects.filter(username="weakling").exists())

    def test_duplicate_username_rejected(self):
        self.make_user("dupe")
        res = self.client.post(REGISTER, {
            "username": "dupe", "email": "d@example.com", "password": STRONG_PASSWORD,
        }, format="json")
        self.assertEqual(res.status_code, 400)

    def test_invalid_username_format_rejected(self):
        res = self.client.post(REGISTER, {
            "username": "has spaces!", "email": "x@example.com", "password": STRONG_PASSWORD,
        }, format="json")
        self.assertEqual(res.status_code, 400)


class LoginTests(RBACTestCase):
    def setUp(self):
        self.user = self.make_user("bob")

    def test_login_success_sets_httponly_cookies(self):
        res = self.client.post(LOGIN, {"username": "bob", "password": STRONG_PASSWORD},
                               format="json")
        self.assertEqual(res.status_code, 200)
        for name in ("access_token", "refresh_token"):
            self.assertIn(name, res.cookies)
            self.assertTrue(res.cookies[name]["httponly"])
            self.assertEqual(res.cookies[name]["samesite"], "Strict")
        # No token is ever returned in the response body.
        self.assertNotIn("access", res.json())
        self.assertNotIn("token", res.json())

    def test_wrong_password_is_generic_401(self):
        res = self.client.post(LOGIN, {"username": "bob", "password": "WrongPass!123"},
                               format="json")
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()["detail"], "Invalid username or password.")

    def test_unknown_user_returns_identical_message(self):
        wrong = self.client.post(LOGIN, {"username": "bob", "password": "WrongPass!123"},
                                 format="json")
        unknown = self.client.post(LOGIN, {"username": "ghost", "password": "WrongPass!123"},
                                   format="json")
        # Must not reveal which field was wrong / whether the account exists.
        self.assertEqual(wrong.status_code, unknown.status_code)
        self.assertEqual(wrong.json()["detail"], unknown.json()["detail"])

    def test_lockout_after_repeated_failures(self):
        for _ in range(5):
            res = self.client.post(LOGIN, {"username": "bob", "password": "WrongPass!123"},
                                   format="json")
            self.assertEqual(res.status_code, 401)
        # Account is now locked: even the correct password is refused with 429.
        res = self.client.post(LOGIN, {"username": "bob", "password": STRONG_PASSWORD},
                               format="json")
        self.assertEqual(res.status_code, 429)


class UnauthenticatedAccessTests(RBACTestCase):
    def test_me_requires_authentication(self):
        res = self.client.get(ME)
        self.assertEqual(res.status_code, 401)

    def test_user_page_requires_authentication(self):
        res = self.client.get("/api/auth/pages/user/")
        self.assertEqual(res.status_code, 401)

    def test_user_list_requires_authentication(self):
        res = self.client.get("/api/auth/users/")
        self.assertEqual(res.status_code, 401)
