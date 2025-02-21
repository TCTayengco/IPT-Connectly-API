from django.urls import path
from . import views
from .views import UserListCreate, PostListCreate, CommentListCreate, RegisterUser, LoginUser, UserListCreate, PostLike, PostComment, PostCommentsList, PostDetail
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('users/', views.get_users, name='get_users'),
    path('users/create/', views.create_user, name='create_user'),
    path('users/update/<int:id>/', views.update_user, name='update_user'),
    path('users/delete/<int:id>/', views.delete_user, name='delete_user'),
    path('user/', UserListCreate.as_view(), name='user-list-create'),
    path('posts/', PostListCreate.as_view(), name='post-list-create'),
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
    path('register/', RegisterUser.as_view(), name='register'),
    path('login/', LoginUser.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('posts/<int:pk>/', views.PostDetail.as_view(), name='post-detail'),
    path('posts/<int:pk>/like/', views.PostLike.as_view(), name='post-like'),
    path('posts/<int:pk>/comment/', views.PostComment.as_view(), name='post-comment'),
    path('posts/<int:pk>/comments/', views.PostCommentsList.as_view(), name='post-comments'),

  ]

