from django.urls import path, include
from . import views
from .views import UserListCreate, PostListCreate, CommentListCreate, RegisterUser, LoginUser, UserListCreate, PostLike, PostComment, PostCommentsList, PostDetail, GoogleLoginView, LogoutUser
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('users/', views.get_users, name='get_users'),
    path('users/create/', views.create_user, name='create_user'),
    path('users/update/<int:id>/', views.update_user, name='update_user'),
    path('users/delete/<int:id>/', views.delete_user, name='delete_user'),
    path('user/', UserListCreate.as_view(), name='user-list-create'),
    path('posts/', PostListCreate.as_view(), name='post-list-create'),
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
    path('posts/<int:pk>/', PostListCreate.as_view(), name='post-update-delete'),
    path('comments/<int:pk>/', CommentListCreate.as_view(), name='comment-update-delete'),
    path('register/', RegisterUser.as_view(), name='register'),
    path('login/', LoginUser.as_view(), name='login'),
    path('logout/', LogoutUser.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('posts/<int:pk>/posts/', views.PostDetail.as_view(), name='post-detail'),
    path('posts/<int:pk>/like/', views.PostLike.as_view(), name='post-like'),
    path('posts/<int:pk>/comment/', views.PostComment.as_view(), name='post-comment'),
    path('posts/<int:pk>/comments/', views.PostCommentsList.as_view(), name='post-comments'),
    path("feed/", views.FeedView.as_view(), name="feed"),
     # Google OAuth URLs
    path('auth/google/login/', GoogleLoginView.as_view(), name='google-login'),
    
    # Include allauth URLs
    path('accounts/', include('allauth.urls')),
    path('api-auth/', include('dj_rest_auth.urls')),
  ]

