"""Single source of truth for permissions and roles, plus the deny-by-default
DRF permission class.

Authorization is permission-based, never role-name-based: a page asks
``user.has_perm("accounts.access_manager_page")``, not ``"Manager" in roles``.
Roles are bundles of permissions (``ROLES``), materialised as Django Groups by
the ``seed_rbac`` management command. Access is hierarchical purely because the
higher roles bundle the lower roles' permissions.
"""
from rest_framework.permissions import BasePermission


class Perm:
    """Permission codenames in Django's ``<app_label>.<codename>`` form."""

    # Page access
    ACCESS_USER_PAGE = "accounts.access_user_page"
    ACCESS_MANAGER_PAGE = "accounts.access_manager_page"
    ACCESS_ADMIN_PAGE = "accounts.access_admin_page"

    # User administration (the Admin page)
    VIEW_USERS = "accounts.view_users"
    MANAGE_ROLES = "accounts.manage_roles"
    DELETE_USERS = "accounts.delete_users"


# role name -> set of permission codenames it grants.
ROLES = {
    "User": {
        Perm.ACCESS_USER_PAGE,
    },
    "Manager": {
        Perm.ACCESS_USER_PAGE,
        Perm.ACCESS_MANAGER_PAGE,
    },
    "Admin": {
        Perm.ACCESS_USER_PAGE,
        Perm.ACCESS_MANAGER_PAGE,
        Perm.ACCESS_ADMIN_PAGE,
        Perm.VIEW_USERS,
        Perm.MANAGE_ROLES,
        Perm.DELETE_USERS,
    },
}

# The base role every account holds. It is granted automatically at
# registration and can never be added or removed through the API.
BASE_ROLE = "User"

# Roles the API is permitted to assign/remove. The base role and Django
# superuser/staff status are NOT in this set and are never grantable through any
# endpoint.
ASSIGNABLE_ROLES = frozenset(ROLES.keys()) - {BASE_ROLE}


class HasActionPermission(BasePermission):
    """Deny-by-default RBAC gate.

    The view must implement ``get_required_permissions()`` returning the list of
    permission codenames required for the current action. An empty list / None
    DENIES access, so a view that forgets to declare a rule fails closed.
    """

    message = "You do not have permission to access this resource."

    def has_permission(self, request, view):
        user = request.user
        if not (user and user.is_authenticated):
            return False
        required = view.get_required_permissions()
        if not required:
            return False  # fail closed
        return all(user.has_perm(perm) for perm in required)
