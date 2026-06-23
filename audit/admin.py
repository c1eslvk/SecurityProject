from django.contrib import admin

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "event", "success", "actor", "target", "ip_address")
    list_filter = ("event", "success")
    search_fields = ("target", "ip_address")
    readonly_fields = (
        "timestamp", "event", "success", "actor", "target", "ip_address", "detail",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
