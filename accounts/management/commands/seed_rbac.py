"""Materialise the ROLES definition into Django Groups + Permissions.

Idempotent: running it repeatedly converges each group to exactly the
permissions declared in accounts.permissions.ROLES (extra perms are removed).
"""
from django.contrib.auth.models import Group, Permission
from django.core.management.base import BaseCommand

from accounts.permissions import ROLES


class Command(BaseCommand):
    help = "Create/update RBAC roles (Groups) and their permissions."

    def handle(self, *args, **options):
        for role_name, perm_codenames in ROLES.items():
            group, created = Group.objects.get_or_create(name=role_name)
            perms = []
            for dotted in sorted(perm_codenames):
                app_label, codename = dotted.split(".", 1)
                try:
                    perms.append(
                        Permission.objects.get(
                            content_type__app_label=app_label, codename=codename
                        )
                    )
                except Permission.DoesNotExist:
                    raise SystemExit(
                        f"Permission {dotted!r} does not exist. Run migrations first."
                    )
            group.permissions.set(perms)
            status = "created" if created else "updated"
            self.stdout.write(
                self.style.SUCCESS(f"Role '{role_name}' {status} ({len(perms)} permissions).")
            )
