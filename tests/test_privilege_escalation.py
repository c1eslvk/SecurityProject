"""No privilege-escalation path: a user can neither grant themselves a role nor
act on a higher-privileged account through any endpoint."""
from .base import RBACTestCase

USERS = "/api/auth/users/"


def roles_url(user_id):
    return f"/api/auth/users/{user_id}/roles/"


def user_url(user_id):
    return f"/api/auth/users/{user_id}/"


class RoleAdministrationTests(RBACTestCase):
    def setUp(self):
        super().setUp()
        self.manager = self.make_user("mgr", roles=["Manager"])
        self.plain = self.make_user("usr", roles=["User"])
        self.admin = self.make_user("adm", roles=["Admin"])
        self.superadmin = self.make_user("root", roles=["Admin"],
                                         is_superuser=True)

    # --- access to the admin surface --------------------------------------
    def test_non_admin_cannot_list_users(self):
        self.auth(self.manager)
        self.assertEqual(self.client.get(USERS).status_code, 403)

    def test_non_admin_cannot_assign_roles(self):
        self.auth(self.manager)
        res = self.client.post(roles_url(self.plain.id), {"roles": ["Manager"]},
                               format="json")
        self.assertEqual(res.status_code, 403)
        self.assertEqual(
            sorted(self.plain.groups.values_list("name", flat=True)), ["User"]
        )

    def test_user_cannot_self_grant_admin(self):
        # No manage_roles permission -> rejected at the permission gate even when
        # targeting themselves.
        self.auth(self.plain)
        res = self.client.post(roles_url(self.plain.id), {"roles": ["Admin"]},
                               format="json")
        self.assertEqual(res.status_code, 403)

    # --- admin abilities + their limits -----------------------------------
    def test_admin_cannot_change_own_roles(self):
        self.auth(self.admin)
        res = self.client.post(roles_url(self.admin.id), {"roles": ["Admin"]},
                               format="json")
        self.assertEqual(res.status_code, 403)

    def test_admin_cannot_modify_another_admin(self):
        self.auth(self.admin)
        res = self.client.post(roles_url(self.superadmin.id), {"roles": ["User"]},
                               format="json")
        self.assertEqual(res.status_code, 403)

    def test_admin_cannot_modify_superuser(self):
        target = self.make_user("su2", is_superuser=True)
        self.auth(self.admin)
        res = self.client.post(roles_url(target.id), {"roles": ["User"]},
                               format="json")
        self.assertEqual(res.status_code, 403)

    def test_admin_can_grant_admin_to_another_user(self):
        self.auth(self.admin)
        res = self.client.post(roles_url(self.plain.id), {"roles": ["Admin"]},
                               format="json")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(self.plain.groups.filter(name="Admin").exists())

    def test_unknown_role_rejected(self):
        self.auth(self.admin)
        res = self.client.post(roles_url(self.plain.id), {"roles": ["superuser"]},
                               format="json")
        self.assertEqual(res.status_code, 400)

    def test_admin_can_assign_role_and_revokes_target_tokens(self):
        before = self.plain.token_version
        self.auth(self.admin)
        res = self.client.post(roles_url(self.plain.id), {"roles": ["Manager"]},
                               format="json")
        self.assertEqual(res.status_code, 200)
        self.plain.refresh_from_db()
        # Manager added; the base User role is always preserved.
        self.assertEqual(
            sorted(self.plain.groups.values_list("name", flat=True)),
            ["Manager", "User"],
        )
        self.assertGreater(self.plain.token_version, before)  # tokens revoked

    def test_base_user_role_cannot_be_granted_via_api(self):
        self.auth(self.admin)
        res = self.client.post(roles_url(self.plain.id), {"roles": ["User"]},
                               format="json")
        self.assertEqual(res.status_code, 400)  # not in the assignable set

    def test_clearing_roles_leaves_the_base_user_role(self):
        # Promote then demote: even an empty submission keeps the base role.
        self.auth(self.admin)
        self.client.post(roles_url(self.plain.id), {"roles": ["Manager"]}, format="json")
        res = self.client.post(roles_url(self.plain.id), {"roles": []}, format="json")
        self.assertEqual(res.status_code, 200)
        self.plain.refresh_from_db()
        self.assertEqual(
            sorted(self.plain.groups.values_list("name", flat=True)), ["User"]
        )


class UserDeletionTests(RBACTestCase):
    def setUp(self):
        super().setUp()
        self.manager = self.make_user("mgr2", roles=["Manager"])
        self.plain = self.make_user("victim", roles=["User"])
        self.admin = self.make_user("adm2", roles=["Admin"])
        self.other_admin = self.make_user("adm3", roles=["Admin"])
        self.superadmin = self.make_user("root2", roles=["Admin"],
                                         is_superuser=True)

    def test_non_admin_cannot_delete_users(self):
        self.auth(self.manager)
        res = self.client.delete(user_url(self.plain.id))
        self.assertEqual(res.status_code, 403)
        self.assertTrue(type(self.plain).objects.filter(id=self.plain.id).exists())

    def test_admin_can_delete_normal_user(self):
        self.auth(self.admin)
        res = self.client.delete(user_url(self.plain.id))
        self.assertEqual(res.status_code, 204)
        self.assertFalse(type(self.plain).objects.filter(id=self.plain.id).exists())

    def test_admin_cannot_delete_self(self):
        self.auth(self.admin)
        res = self.client.delete(user_url(self.admin.id))
        self.assertEqual(res.status_code, 403)

    def test_admin_cannot_delete_another_admin(self):
        self.auth(self.admin)
        res = self.client.delete(user_url(self.other_admin.id))
        self.assertEqual(res.status_code, 403)
        self.assertTrue(type(self.admin).objects.filter(id=self.other_admin.id).exists())

    def test_admin_cannot_delete_superuser(self):
        self.auth(self.admin)
        res = self.client.delete(user_url(self.superadmin.id))
        self.assertEqual(res.status_code, 403)

    def test_superuser_can_delete_an_admin(self):
        self.auth(self.superadmin)
        res = self.client.delete(user_url(self.other_admin.id))
        self.assertEqual(res.status_code, 204)
