from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    """Custom user with a server-side lockout counter and a token-revocation
    stamp.

    Roles and permissions are NOT stored here — they live in Django's Group
    (= role) and Permission tables, queried via ``user.has_perm(...)``. This
    keeps authorization checks permission-based, not role-name-based.
    """

    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    # Embedded as the "tv" JWT claim; bumping it instantly revokes all of the
    # user's outstanding access and refresh tokens.
    token_version = models.PositiveIntegerField(default=0)

    def bump_token_version(self):
        self.token_version = models.F("token_version") + 1
        self.save(update_fields=["token_version"])
        self.refresh_from_db(fields=["token_version"])

    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > timezone.now()

    class Meta:
        permissions = [
            ("access_user_page", "Can access the User page"),
            ("access_manager_page", "Can access the Manager page"),
            ("access_admin_page", "Can access the Admin page"),
            ("view_users", "Can view the user list"),
            ("manage_roles", "Can assign/remove roles"),
            ("delete_users", "Can delete users"),
        ]
