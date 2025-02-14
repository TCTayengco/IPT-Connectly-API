from django.urls import path
from . import views
from .views import UserListCreate, PostListCreate, CommentListCreate, LoginView, ProtectedView, AdminOnlyView, PostDetailView

#Potentially can remove all commented out code here not sure yet

urlpatterns = [
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    path('users/update/<int:id>/', views.update_user, name='update_user'),
    path('users/delete/<int:id>/', views.delete_user, name='delete_user'),
    path('posts/', PostListCreate.as_view(), name='post-list-create'),
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
    # Test views for security
    path("login/", LoginView.as_view(), name="login"),
    path("protected/", ProtectedView.as_view(), name="protected_view"),
    path("admin-only/", AdminOnlyView.as_view(), name="admin_view"),
    path("post-detail/", PostDetailView.as_view(), name="post_detail_view"),
]