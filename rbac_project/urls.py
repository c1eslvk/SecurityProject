from django.contrib import admin
from django.urls import include, path

from frontend.views import index

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/", include("accounts.urls")),
    # Single-page frontend (login / register / role-gated pages).
    path("", index, name="index"),
]
