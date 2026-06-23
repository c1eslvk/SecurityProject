"""Deny-by-default, hierarchical page authorization. Each test proves an
under-privileged user is rejected (403), not only that a privileged one passes.

Access model (checked via permissions, not role names):
    User     -> User page
    Manager  -> User + Manager pages
    Admin    -> User + Manager + Admin (user list) pages
"""
from .base import RBACTestCase

USER_PAGE = "/api/auth/pages/user/"
MANAGER_PAGE = "/api/auth/pages/manager/"
USERS = "/api/auth/users/"  # the Admin page's data


class PageAccessTests(RBACTestCase):
    def setUp(self):
        super().setUp()
        self.norole = self.make_user("norole")
        self.user = self.make_user("u", roles=["User"])
        self.manager = self.make_user("m", roles=["Manager"])
        self.admin = self.make_user("a", roles=["Admin"])

    # --- deny by default ---------------------------------------------------
    def test_user_without_roles_is_denied_every_page(self):
        self.auth(self.norole)
        self.assertEqual(self.client.get(USER_PAGE).status_code, 403)
        self.assertEqual(self.client.get(MANAGER_PAGE).status_code, 403)
        self.assertEqual(self.client.get(USERS).status_code, 403)

    # --- User role ---------------------------------------------------------
    def test_user_can_access_user_page(self):
        self.auth(self.user)
        res = self.client.get(USER_PAGE)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["message"], "Hello on User page u")

    def test_user_cannot_access_manager_page(self):
        self.auth(self.user)
        self.assertEqual(self.client.get(MANAGER_PAGE).status_code, 403)

    def test_user_cannot_access_admin_page(self):
        self.auth(self.user)
        self.assertEqual(self.client.get(USERS).status_code, 403)

    # --- Manager role ------------------------------------------------------
    def test_manager_can_access_user_and_manager_pages(self):
        self.auth(self.manager)
        self.assertEqual(self.client.get(USER_PAGE).status_code, 200)
        man = self.client.get(MANAGER_PAGE)
        self.assertEqual(man.status_code, 200)
        self.assertEqual(man.json()["message"], "Hello on Manager page m")

    def test_manager_cannot_access_admin_page(self):
        self.auth(self.manager)
        self.assertEqual(self.client.get(USERS).status_code, 403)

    # --- Admin role --------------------------------------------------------
    def test_admin_can_access_all_pages(self):
        self.auth(self.admin)
        self.assertEqual(self.client.get(USER_PAGE).status_code, 200)
        self.assertEqual(self.client.get(MANAGER_PAGE).status_code, 200)
        listing = self.client.get(USERS)
        self.assertEqual(listing.status_code, 200)
        self.assertGreaterEqual(len(listing.json()), 4)  # sees all users
