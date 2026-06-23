from django.urls import path

from . import views

urlpatterns = [
    path("csrf/", views.CsrfTokenView.as_view(), name="csrf"),
    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("refresh/", views.RefreshView.as_view(), name="refresh"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("me/", views.MeView.as_view(), name="me"),
    # Role-gated pages
    path("pages/user/", views.UserPageView.as_view(), name="page-user"),
    path("pages/manager/", views.ManagerPageView.as_view(), name="page-manager"),
    # User administration (Admin page)
    path("users/", views.UserListView.as_view(), name="user-list"),
    path("users/<int:user_id>/roles/", views.UserRolesView.as_view(), name="user-roles"),
    path("users/<int:user_id>/", views.UserDeleteView.as_view(), name="user-delete"),
]
