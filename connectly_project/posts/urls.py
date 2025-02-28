from django.urls import path
from . import views
from .views import UserListCreate, PostListCreate, CommentListCreate, LoginView, ProtectedView, AdminOnlyView, PostDetailView

#Potentially can remove all commented out code here not sure yet

urlpatterns = [
    # Users
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    path('users/update/<int:id>/', views.update_user, name='update_user'),
    path('users/delete/<int:id>/', views.delete_user, name='delete_user'),

    # Posts
    path('posts/', PostListCreate.as_view(), name='post-list-create'),  # For listing and creating posts
    path('posts/<int:post_id>/', PostListCreate.as_view(), name='post-detail'),  # For updating and deleting posts

    # Comments
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),  # For listing and creating comments
    path('comments/<int:comment_id>/', CommentListCreate.as_view(), name='comment-detail'),  # For updating and deleting comments

    # Test views for security
    path("login/", LoginView.as_view(), name="login"),
    path("protected/", ProtectedView.as_view(), name="protected_view"),
    path("admin-only/", AdminOnlyView.as_view(), name="admin_view"),
    path("post-detail/<int:pk>/", PostDetailView.as_view(), name="post_detail_view"),
]