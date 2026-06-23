"""Authentication and user/role administration endpoints.

Security notes that apply throughout this module:
  * All auth failures use a generic message and never reveal which field was
    wrong, nor whether an account exists (except the unavoidable lockout signal).
  * Tokens live only in HttpOnly cookies; responses carry no token in the body.
  * Every unsafe request is CSRF-protected (see CsrfProtectedAPIView).
  * Credentials, secrets, and tokens are never written to logs or audit detail.
"""
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from audit.events import log_event
from audit.models import AuditLog

from .auth import _enforce_csrf
from .permissions import BASE_ROLE, HasActionPermission, Perm
from .serializers import (
    LoginSerializer,
    RegisterSerializer,
    RoleAssignmentSerializer,
    UserSerializer,
)
from .tokens import clear_auth_cookies, set_auth_cookies, tokens_for_user

User = get_user_model()

GENERIC_AUTH_ERROR = {"detail": "Invalid username or password."}


class CsrfProtectedAPIView(APIView):
    """Base view that enforces CSRF on every state-changing request, including
    the unauthenticated ones (login/register/refresh) that DRF would otherwise
    leave unprotected."""

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if request.method not in ("GET", "HEAD", "OPTIONS", "TRACE"):
            _enforce_csrf(request)


@method_decorator(ensure_csrf_cookie, name="get")
class CsrfTokenView(APIView):
    """Issues the readable ``csrftoken`` cookie the SPA echoes in X-CSRFToken."""

    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        return Response({"detail": "CSRF cookie set."})


class RegisterView(CsrfProtectedAPIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "register"

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        log_event(AuditLog.Event.REGISTER, request=request, actor=user,
                  target=f"user:{user.id}")
        return Response(
            {"detail": "Account created. You can now log in."},
            status=status.HTTP_201_CREATED,
        )


class LoginView(CsrfProtectedAPIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "login"

    def _register_failure(self, request, user, event):
        if user is not None:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.LOGIN_MAX_FAILED_ATTEMPTS:
                user.locked_until = timezone.now() + timedelta(
                    seconds=settings.LOGIN_LOCKOUT_SECONDS
                )
                user.failed_login_attempts = 0
                user.save(update_fields=["failed_login_attempts", "locked_until"])
                log_event(event, request=request, actor=None,
                          target=getattr(user, "username", ""), success=False,
                          locked=True)
                return
            user.save(update_fields=["failed_login_attempts"])
        log_event(event, request=request, actor=None,
                  target=getattr(user, "username", ""), success=False)

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        user = User.objects.filter(username__iexact=data["username"]).first()

        if user is not None and user.is_locked():
            log_event(AuditLog.Event.LOGIN_LOCKED, request=request, actor=None,
                      target=user.username, success=False)
            return Response(
                {"detail": "Too many failed attempts. Try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        password_ok = user is not None and user.is_active and user.check_password(data["password"])
        if not password_ok:
            self._register_failure(request, user, AuditLog.Event.LOGIN_FAILED)
            return Response(GENERIC_AUTH_ERROR, status=status.HTTP_401_UNAUTHORIZED)

        # Fresh tokens on each login (session regeneration); reset lockout.
        user.failed_login_attempts = 0
        user.locked_until = None
        user.save(update_fields=["failed_login_attempts", "locked_until"])

        access, refresh = tokens_for_user(user)
        response = Response(UserSerializer(user).data, status=status.HTTP_200_OK)
        set_auth_cookies(response, access, refresh)
        log_event(AuditLog.Event.LOGIN_SUCCESS, request=request, actor=user,
                  target=f"user:{user.id}")
        return response


class RefreshView(CsrfProtectedAPIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        raw = request.COOKIES.get(settings.SIMPLE_JWT["REFRESH_COOKIE"])
        if not raw:
            return Response({"detail": "No refresh token."},
                            status=status.HTTP_401_UNAUTHORIZED)
        try:
            refresh = RefreshToken(raw)
            user = User.objects.get(id=refresh["user_id"])
            if refresh.get("tv") != user.token_version or not user.is_active:
                raise TokenError("revoked")
            refresh.blacklist()  # rotation: the presented token is single-use
        except (TokenError, User.DoesNotExist, KeyError):
            response = Response({"detail": "Invalid refresh token."},
                                status=status.HTTP_401_UNAUTHORIZED)
            clear_auth_cookies(response)
            return response

        access, new_refresh = tokens_for_user(user)
        response = Response({"detail": "Refreshed."}, status=status.HTTP_200_OK)
        set_auth_cookies(response, access, new_refresh)
        log_event(AuditLog.Event.TOKEN_REFRESH, request=request, actor=user,
                  target=f"user:{user.id}")
        return response


class LogoutView(CsrfProtectedAPIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        raw = request.COOKIES.get(settings.SIMPLE_JWT["REFRESH_COOKIE"])
        if raw:
            try:
                RefreshToken(raw).blacklist()
            except TokenError:
                pass
        # Fully invalidate the session (all access + refresh tokens at once).
        request.user.bump_token_version()
        log_event(AuditLog.Event.LOGOUT, request=request, actor=request.user,
                  target=f"user:{request.user.id}")
        response = Response({"detail": "Logged out."}, status=status.HTTP_200_OK)
        clear_auth_cookies(response)
        return response


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)


class UserListView(APIView):
    """Admin-only listing of users + their roles. Requires accounts.view_users."""

    permission_classes = [IsAuthenticated, HasActionPermission]

    def get_required_permissions(self):
        return [Perm.VIEW_USERS]

    def get(self, request):
        users = User.objects.all().order_by("id").prefetch_related("groups")
        return Response(UserSerializer(users, many=True).data)


class UserRolesView(CsrfProtectedAPIView):
    """Assign the set of roles for a user. Requires accounts.manage_roles.

    Privilege-escalation defences enforced here:
      * You cannot change your OWN roles (no self-escalation).
      * You cannot act on a higher-privileged account (superuser, or an admin)
        unless you are a superuser.
      * Only whitelisted roles are assignable; the base role, superuser, and
        staff are never grantable/removable. The base role is always preserved.
    On success the target's tokens are revoked so the new privileges take effect
    on their next login.
    """

    permission_classes = [IsAuthenticated, HasActionPermission]

    def get_required_permissions(self):
        return [Perm.MANAGE_ROLES]

    def post(self, request, user_id):
        target = get_object_or_404(User, id=user_id)

        if target.id == request.user.id:
            return self._denied(request, target, "self_modification")

        target_is_privileged = (
            target.is_superuser or target.groups.filter(name="Admin").exists()
        )
        if target_is_privileged and not request.user.is_superuser:
            return self._denied(request, target, "target_higher_privileged")

        serializer = RoleAssignmentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        roles = serializer.validated_data["roles"]

        # The base role is always retained; assignable roles are added on top.
        final_roles = set(roles) | {BASE_ROLE}
        groups = list(Group.objects.filter(name__in=final_roles))
        previous = sorted(target.groups.values_list("name", flat=True))
        target.groups.set(groups)
        target.bump_token_version()  # privilege change revokes existing tokens

        after = sorted(final_roles)
        log_event(AuditLog.Event.ROLE_CHANGE, request=request, actor=request.user,
                  target=f"user:{target.id}", before=previous, after=after)
        return Response({"detail": "Roles updated.", "roles": after})

    def _denied(self, request, target, reason):
        log_event(AuditLog.Event.PERMISSION_DENIED, request=request,
                  actor=request.user, target=f"user:{target.id}",
                  success=False, action="role_change", reason=reason)
        return Response(
            {"detail": "You are not allowed to modify this account."},
            status=status.HTTP_403_FORBIDDEN,
        )


class UserDeleteView(APIView):
    """Delete a user. Requires accounts.delete_users.

    Privilege-escalation defences:
      * You cannot delete your OWN account.
      * You cannot delete a higher-privileged account (superuser or an Admin)
        unless you are a superuser.
    CSRF for this unsafe request is enforced by CookieJWTAuthentication.
    """

    permission_classes = [IsAuthenticated, HasActionPermission]

    def get_required_permissions(self):
        return [Perm.DELETE_USERS]

    def delete(self, request, user_id):
        target = get_object_or_404(User, id=user_id)

        if target.id == request.user.id:
            return self._denied(request, target, "self_deletion")

        target_is_privileged = (
            target.is_superuser or target.groups.filter(name="Admin").exists()
        )
        if target_is_privileged and not request.user.is_superuser:
            return self._denied(request, target, "target_higher_privileged")

        deleted_id = target.id
        username = target.username
        target.delete()
        log_event(AuditLog.Event.USER_DELETE, request=request, actor=request.user,
                  target=f"user:{deleted_id}", username=username)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def _denied(self, request, target, reason):
        log_event(AuditLog.Event.PERMISSION_DENIED, request=request,
                  actor=request.user, target=f"user:{target.id}",
                  success=False, action="user_delete", reason=reason)
        return Response(
            {"detail": "You are not allowed to delete this account."},
            status=status.HTTP_403_FORBIDDEN,
        )


class _RoleGatedPage(APIView):
    """Base for pages authorized on the server by a permission (not a role name)."""


    permission_classes = [IsAuthenticated, HasActionPermission]
    required_permission = None
    page_name = ""

    def get_required_permissions(self):
        return [self.required_permission] if self.required_permission else None

    def get(self, request):
        log_event(AuditLog.Event.PAGE_ACCESS, request=request, actor=request.user,
                  target=self.page_name)
        return Response({"message": f"Hello on {self.page_name} page {request.user.username}"})


class UserPageView(_RoleGatedPage):
    required_permission = Perm.ACCESS_USER_PAGE
    page_name = "User"


class ManagerPageView(_RoleGatedPage):
    required_permission = Perm.ACCESS_MANAGER_PAGE
    page_name = "Manager"
