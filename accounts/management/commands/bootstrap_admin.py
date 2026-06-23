"""Create an administrator account, server-side.

Admin accounts are NOT creatable through the public API, so the initial admin is
provisioned here by a trusted operator. The command prints the (one-time)
password so the operator can log in.

Usage:
    python manage.py bootstrap_admin --username admin --email admin@example.com
    python manage.py bootstrap_admin --username admin --password '<your-strong-pw>'
"""
import secrets

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

User = get_user_model()


def _generate_password() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(20))
        try:
            validate_password(pw)
            return pw
        except ValidationError:
            continue


class Command(BaseCommand):
    help = "Create an admin user (server-side only)."

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)
        parser.add_argument("--email", default="")
        parser.add_argument("--password", default=None,
                            help="If omitted, a strong password is generated and printed.")
        parser.add_argument("--superuser", action="store_true",
                            help="Also grant Django superuser status.")

    def handle(self, *args, **options):
        call_command("seed_rbac")  # ensure roles exist

        username = options["username"]
        if User.objects.filter(username__iexact=username).exists():
            raise CommandError(f"User {username!r} already exists.")

        password = options["password"] or _generate_password()
        try:
            validate_password(password)
        except ValidationError as exc:
            raise CommandError("; ".join(exc.messages))

        user = User(username=username, email=options["email"], is_active=True)
        user.set_password(password)
        if options["superuser"]:
            user.is_superuser = True
            user.is_staff = True
        user.save()

        # Base role (everyone has it) + Admin.
        base = Group.objects.get(name="User")
        admin_group = Group.objects.get(name="Admin")
        user.groups.add(base, admin_group)

        self.stdout.write(self.style.SUCCESS("\nAdmin account created.\n"))
        self.stdout.write(f"  username:  {username}")
        self.stdout.write(f"  password:  {password}")
        self.stdout.write(self.style.WARNING(
            "\nStore the password securely; it is shown only now.\n"
        ))
