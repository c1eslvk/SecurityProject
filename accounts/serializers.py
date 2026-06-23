import re

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from .permissions import ASSIGNABLE_ROLES, BASE_ROLE

User = get_user_model()

# Whitelist: 3-30 chars, letters/digits/._- only.
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,30}$")


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=30)
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(write_only=True, max_length=128, trim_whitespace=False)

    def validate_username(self, value):
        if not USERNAME_RE.match(value):
            raise serializers.ValidationError(
                "Username must be 3-30 characters: letters, digits, '.', '_' or '-'."
            )
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("That username is taken.")
        return value

    def validate_password(self, value):
        validate_password(value)
        return value

    def create(self, validated_data):
        user = User(username=validated_data["username"], email=validated_data["email"])
        user.set_password(validated_data["password"])
        user.save()
        # Every account gets the base role; elevated roles are granted by an admin.
        base, _ = Group.objects.get_or_create(name=BASE_ROLE)
        user.groups.add(base)
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=30)
    password = serializers.CharField(write_only=True, max_length=128, trim_whitespace=False)


class UserSerializer(serializers.ModelSerializer):
    """Read-only projection. Never exposes the password hash."""

    roles = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ("id", "username", "email", "roles", "permissions", "is_active")
        read_only_fields = fields

    def get_roles(self, obj):
        return sorted(obj.groups.values_list("name", flat=True))

    def get_permissions(self, obj):
        # Effective permissions, used by the frontend only for UI hints — the
        # server re-checks on every request regardless.
        return sorted(obj.get_all_permissions())


class RoleAssignmentSerializer(serializers.Serializer):
    """Whitelisted role set. Cannot express superuser/staff — those are not
    grantable via the API."""

    roles = serializers.ListField(
        child=serializers.CharField(max_length=30),
        allow_empty=True,
    )

    def validate_roles(self, value):
        unknown = sorted(set(value) - ASSIGNABLE_ROLES)
        if unknown:
            raise serializers.ValidationError(f"Unknown or non-assignable roles: {unknown}")
        return sorted(set(value))
