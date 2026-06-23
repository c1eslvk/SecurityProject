from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin

User = get_user_model()


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ("username", "email", "is_staff", "is_superuser")
    list_filter = ("is_staff", "is_superuser", "groups")
    # The revocation stamp is never editable through the admin.
    readonly_fields = ("token_version", "last_login", "date_joined")
    fieldsets = UserAdmin.fieldsets + (
        ("Security", {"fields": ("token_version", "failed_login_attempts",
                                  "locked_until")}),
    )
