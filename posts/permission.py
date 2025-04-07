from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsAdmin(BasePermission):
    """
    Allows access only to admin users.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'

class IsSelfOrAdmin(BasePermission):
    """
    Allows access only to admin users or the user themselves.
    """
    def has_object_permission(self, request, view, obj):
        return request.user.is_authenticated and (obj == request.user or request.user.role == 'admin')

class IsPostOwnerOrAdmin(BasePermission):
    """
    Allows access to post owner or admin users.
    """
    def has_object_permission(self, request, view, obj):
        return request.user.is_authenticated and (obj.author == request.user or request.user.role == 'admin')

class IsCommentOwnerOrAdmin(BasePermission):
    """
    Allows access to comment owner or admin users.
    """
    def has_object_permission(self, request, view, obj):
        return request.user.is_authenticated and (obj.author == request.user or request.user.role == 'admin')

class CanViewPost(BasePermission):
    """
    Allows access to public posts or private posts if user is the owner or admin.
    """
    def has_object_permission(self, request, view, obj):
        # Anyone can view public posts
        if obj.privacy == 'public':
            return True
        # Only owner and admin can view private posts
        return request.user.is_authenticated and (obj.author == request.user or request.user.role == 'admin')