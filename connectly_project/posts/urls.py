from django.urls import path
from . import views
from .views import UserListCreate, PostListCreate, CommentListCreate

#Potentially can remove all commented out code here not sure yet

urlpatterns = [
    # path('users/', views.get_users, name='get_users'),
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    # path('users/create/', views.create_user, name='create_user'),
    path('users/update/<int:id>/', views.update_user, name='update_user'),
    path('users/delete/<int:id>/', views.delete_user, name='delete_user'),
    # path('posts/', views.get_posts, name='get_posts'),
    path('posts/', PostListCreate.as_view(), name='post-list-create'),
    # path('posts/create/', views.create_post, name='create_post'),
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
]