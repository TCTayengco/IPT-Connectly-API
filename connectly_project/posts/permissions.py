from rest_framework.permissions import BasePermission

class IsAdminUser(BasePermission):
    """Allows access only to users in the Admin group."""

    def has_permission(self, request, view):
        return request.user.groups.filter(name="Admin").exists()

class IsPostAuthor(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.author == request.user
