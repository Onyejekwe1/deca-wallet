from rest_framework import permissions
from rest_framework.exceptions import NotFound

from ..models import User


class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user

        try:
            user_instance = User.objects.get(email=user)
        except NotFound:
            return False

        if user_instance.is_admin or user_instance.is_admin:
            return True
        return False