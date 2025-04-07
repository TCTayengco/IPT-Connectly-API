import json
import bcrypt
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

from rest_framework.pagination import PageNumberPagination  
from rest_framework import permissions, status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication

from posts.permission import CanViewPost, IsAdmin, IsSelfOrAdmin, IsPostOwnerOrAdmin, IsCommentOwnerOrAdmin

from .models import User, Post, Comment, Like
from .serializers import UserSerializer, PostSerializer, CommentSerializer

from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth import get_user_model

from .serializers import CommentPagination, PostDetailSerializer, LikeSerializer

from django.core.cache import cache

from django.conf import settings
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from allauth.socialaccount.models import SocialAccount

from .utils import PasswordFactory, InvalidateCachePatterns
from posts import models

from django.db import models  # For Q objects
import logging
from .monitor import CacheMonitor

from rest_framework_simplejwt.exceptions import TokenError
# Set up custom logger
cache_logger = logging.getLogger('cache_logger')
cache_logger.setLevel(logging.DEBUG)

# Create handlers
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# Create formatter and add it to the handler
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)

# Add handler to the logger
cache_logger.addHandler(console_handler)

# Update the utility class to include logging
class InvalidateCachePatterns:
    @staticmethod
    def invalidate_cache_patterns(pattern):
        keys = cache.keys(pattern)
        if keys:
            cache_logger.info(f"Invalidating cache keys matching pattern: {pattern}")
            for key in keys:
                cache_logger.debug(f"Deleting cache key: {key}")
                cache.delete(key)
            cache_logger.info(f"Invalidated {len(keys)} cache keys")
        else:
            cache_logger.debug(f"No cache keys found matching pattern: {pattern}")

# ========================================================
# Function-Based Views for User Management
# ========================================================

def get_users(request):
    try:
        users = list(
            User.objects.values('id', 'username', 'email', 'date_joined', 'role', 'password')
         )
        return JsonResponse(users, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def create_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            # Hash the password using bcrypt
            password = data.get('password', '').encode('utf-8')
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password, salt)

            # Create the user with the hashed password
            user = User.objects.create(
                username=data['username'],
                email=data['email'],
                password=hashed_password.decode('utf-8')  # Store as a string
            )

            return JsonResponse(
                {'id': user.id, 'message': 'User created successfully'},
                status=201
            )
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def update_user(request, id):
    if request.method == 'PUT':
        try:
            user = get_object_or_404(User, id=id)
            data = json.loads(request.body)
            user.email = data.get('email', user.email)
            user.save()
            return JsonResponse({'message': 'User updated successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def delete_user(request, id):
    if request.method == 'DELETE':
        try:
            user = get_object_or_404(User, id=id)
            user.delete()
            return JsonResponse({'message': 'User deleted successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

# ========================================================
# Class-Based Views (DRF APIViews)
# ========================================================

class RegisterUser(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from .utils import PasswordFactory

class LoginUser(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        User = get_user_model()

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        if not PasswordFactory.verify_password(password, user.password):
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'role': user.role
        })

    
class LogoutUser(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Get the refresh token from the request data
            refresh_token = request.data.get('refresh')
            
            # Check if the refresh token is provided
            if not refresh_token:
                return Response(
                    {'error': 'Refresh token is required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create a RefreshToken object and blacklist it
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return Response(
                {'message': 'Successfully logged out'}, 
                status=status.HTTP_200_OK
            )
            
        except TokenError as e:
            # Catch specific token errors for better error handling
            return Response(
                {'error': f'Invalid token: {str(e)}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            # Catch any other unexpected errors
            return Response(
                {'error': f'Logout failed: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        
class UserListCreate(APIView):
    permission_classes = [permissions.IsAuthenticated]  # Require authentication

    def get(self, request):
        if request.user.role != 'admin':  # Only admins can see all users
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        if request.user.role != 'admin':  # Only admins can create users
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserRoleUpdate(APIView):
    permission_classes = [permissions.IsAuthenticated]  # Require authentication

    def put(self, request, pk):
        if request.user.role != 'admin':  # Only admins can update user roles
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        new_role = request.data.get("role")
        if new_role not in ["user", "admin"]:
            return Response({"error": "Invalid role"}, status=status.HTTP_400_BAD_REQUEST)
        
        user.role = new_role
        user.save()
        return Response({"message": "User role updated successfully"}, status=status.HTTP_200_OK)

class UserDelete(APIView):
    permission_classes = [permissions.IsAuthenticated]  # Require authentication

    def delete(self, request, pk):
        if request.user.role != 'admin':
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        user.delete()
        return Response({"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT)    
    
class PostListCreate(APIView):
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get(self, request):
        # Check cache
        cache_key = "all_posts_list"
        if request.user.is_authenticated:
            cache_key = f"all_posts_list_user_{request.user.id}"
        
        cached_data = cache.get(cache_key)
        if cached_data:
            return Response(cached_data)
        
        # If user is authenticated, show public posts + their own private posts
        if request.user.is_authenticated:
            if request.user.role == 'admin':
                # Admins can see all posts
                posts = Post.objects.all()
            else:
                # Regular users see public posts and their own private posts
                posts = Post.objects.filter(
                    models.Q(privacy='public') | 
                    models.Q(privacy='private', author=request.user)
                )
        else:
            # Unauthenticated users only see public posts
            posts = Post.objects.filter(privacy='public')
                    
        serializer = PostSerializer(posts, many=True)
        
        # Cache the result
        cache.set(cache_key, serializer.data, timeout=300)  # 5 minutes cache
        
        return Response(serializer.data)

    def post(self, request):
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            if self.request.user.is_authenticated:
                post = serializer.save(author=self.request.user)
                
                # Invalidate relevant caches using our utility class
                InvalidateCachePatterns.invalidate_cache_patterns("all_posts_list*")
                InvalidateCachePatterns.invalidate_cache_patterns(f"user_{self.request.user.id}_feed")
                
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({"error": "Authentication required to create posts"}, 
                            status=status.HTTP_401_UNAUTHORIZED)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        if not request.user.is_authenticated:
            return Response({"error": "Authentication required"}, 
                        status=status.HTTP_401_UNAUTHORIZED)

        post = get_object_or_404(Post, pk=pk)
        
        # Check if user has permission to modify this post
        if post.author != request.user and request.user.role != 'admin':
            return Response({"error": "You can only update your own posts"}, 
                        status=status.HTTP_403_FORBIDDEN)

        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            
            # Invalidate caches
            cache.delete(f"post_{post.id}_details")
            InvalidateCachePatterns.invalidate_cache_patterns("all_posts_list*")
            InvalidateCachePatterns.invalidate_cache_patterns(f"user_{post.author.id}_feed")
            
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        if not request.user.is_authenticated:
            return Response({"error": "Authentication required"}, 
                        status=status.HTTP_401_UNAUTHORIZED)

        post = get_object_or_404(Post, pk=pk)
        
        # Only the post owner or admin can delete a post
        if post.author != request.user and request.user.role != 'admin':
            return Response({"error": "You can only delete your own posts"}, 
                        status=status.HTTP_403_FORBIDDEN)
            
        # Store author ID before deletion for cache invalidation
        author_id = post.author.id
        post_id = post.id
        
        post.delete()
        
        # Invalidate caches
        cache.delete(f"post_{post_id}_details")
        InvalidateCachePatterns.invalidate_cache_patterns("all_posts_list*")
        InvalidateCachePatterns.invalidate_cache_patterns(f"user_{author_id}_feed")
        
        return Response({"message": "Post deleted successfully"}, 
                    status=status.HTTP_204_NO_CONTENT)

class CommentListCreate(APIView):
    def get(self, request):
        comments = Comment.objects.all()
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, pk):
        comment = get_object_or_404(Comment, pk=pk)
    
        if comment.author != request.user and not getattr(request.user, "role", None) == "admin":
            return Response({"error": "You can only update your own comments"}, status=status.HTTP_403_FORBIDDEN)

        serializer = CommentSerializer(comment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        comment = get_object_or_404(Comment, pk=pk)
        if comment.author != request.user and not getattr(request.user, "role", None) == "admin":
            return Response({"error": "You can only delete your own comments"}, status=status.HTTP_403_FORBIDDEN)

        comment.delete()
        return Response({"message": "Comment deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

class PostDetail(APIView):
    permission_classes = [permissions.IsAuthenticated, CanViewPost]

    def get(self, request, pk):
        post = get_object_or_404(Post, pk=pk)
            
        # Check permissions
        self.check_object_permissions(request, post)
        
        serializer = PostDetailSerializer(post)
        return Response(serializer.data)

class PostLike(APIView):
    permission_classes = [IsAuthenticated, CanViewPost]

    def post(self, request, pk):
        post = get_object_or_404(Post, pk=pk)
        
        # Check if user can view/like the post
        self.check_object_permissions(request, post)

        if request.user in post.likes.all():
            post.likes.remove(request.user)  # Remove like
            response_status = 'unliked'
            status_code = status.HTTP_200_OK
        else:
            post.likes.add(request.user)  # Add like
            response_status = 'liked'
            status_code = status.HTTP_201_CREATED

        # Save post
        post.save()

        # Invalidate cache
        cache.delete(f"post_{post.id}_likes")
        cache.delete(f"post_{post.id}_details")
        
        # Use the utility function for pattern invalidation
        InvalidateCachePatterns(f"user_{request.user.id}_feed")
        InvalidateCachePatterns(f"user_{post.author.id}_feed")
        InvalidateCachePatterns("all_posts_list*")

        return Response({'status': response_status}, status=status_code)

class PostComment(APIView):
    permission_classes = [IsAuthenticated, CanViewPost]
    
    def post(self, request, pk):
        post = get_object_or_404(Post, pk=pk)
        
        # Check if user can view/comment on the post
        self.check_object_permissions(request, post)
        
        serializer = CommentSerializer(data={
            **request.data,
            'post': post.id,
            'author': request.user.id
        })
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PostCommentsList(APIView):
    permission_classes = [IsAuthenticated]
    pagination_class = CommentPagination

    def get(self, request, pk):
        post = get_object_or_404(Post, pk=pk)
        paginator = self.pagination_class()
        comments = post.comments.all().order_by('-created_at')
        result_page = paginator.paginate_queryset(comments, request)
        serializer = CommentSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)
    

class FeedPagination(PageNumberPagination):
    page_size = 10  # Adjust as needed
    page_size_query_param = 'page_size'
    max_page_size = 50    

class FeedView(generics.ListAPIView):
    serializer_class = PostSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = FeedPagination

    @CacheMonitor.cache_performance_decorator
    def get_queryset(self):
        user = self.request.user
        liked_only = self.request.query_params.get("liked", None)
        sort_order = self.request.query_params.get("sort", "desc")  # Default: Newest first

        # Modify cache key to include sorting preference and privacy
        cache_key = f"user_{user.id}_feed_{sort_order}"
        if liked_only:
            cache_key += "_liked"

        # Check cache first
        cache_logger.debug(f"Checking cache for key: {cache_key}")
        cached_feed = cache.get(cache_key)
        if cached_feed:
            cache_logger.info(f"Cache HIT: {cache_key}")
            return cached_feed

        cache_logger.info(f"Cache MISS: {cache_key}")
        
        # Sort direction
        order_by_field = "-created_at" if sort_order == "desc" else "created_at"

        # Query posts with privacy filtering
        if user.role == 'admin':
            # Admins can see all posts
            cache_logger.debug(f"Admin user {user.id} requesting feed, showing all posts")
            queryset = Post.objects.select_related("author").prefetch_related(
                "likes", "comments"
            ).order_by(order_by_field)
        else:
            # Regular users see public posts and their own private posts
            cache_logger.debug(f"Regular user {user.id} requesting feed, showing public + own private posts")
            queryset = Post.objects.select_related("author").prefetch_related(
                "likes", "comments"
            ).filter(
                models.Q(privacy='public') | 
                models.Q(privacy='private', author=user)
            ).order_by(order_by_field)

        # Apply filtering for liked posts
        if liked_only:
            cache_logger.debug(f"Filtering feed for liked posts only")
            queryset = queryset.filter(likes=user)

        # Store filtered results in cache for 5 minutes
        cache_logger.info(f"Setting cache for key: {cache_key} (timeout: 300s)")
        cache.set(cache_key, queryset, timeout=300)

        # Log cache stats after updating the cache
        CacheMonitor.log_cache_stats()

        return queryset
    
    User = get_user_model()

    @CacheMonitor.cache_performance_decorator
    def list(self, request, *args, **kwargs):
        """Override list method to add cache for the paginated and serialized response"""
        user = self.request.user
        liked_only = self.request.query_params.get("liked", None)
        sort_order = self.request.query_params.get("sort", "desc")
        page = self.request.query_params.get(self.pagination_class.page_query_param, 1)
        page_size = self.request.query_params.get(self.pagination_class.page_size_query_param, 
                                              self.pagination_class.page_size)
        
        # Create a comprehensive response cache key
        response_cache_key = f"user_{user.id}_feed_response_{sort_order}_page_{page}_size_{page_size}"
        if liked_only:
            response_cache_key += "_liked"
            
        # Try to get the response from cache
        cached_response = cache.get(response_cache_key)
        if cached_response:
            cache_logger.info(f"Cache HIT: {response_cache_key}")
            return Response(cached_response)
            
        cache_logger.info(f"Cache MISS: {response_cache_key}")
        
        # If not in cache, proceed with normal operation
        response = super().list(request, *args, **kwargs)
        
        # Cache the response data
        cache_logger.info(f"Setting cache for key: {response_cache_key} (timeout: 300s)")
        cache.set(response_cache_key, response.data, timeout=300)  # 5 minutes cache
        
        # Log cache stats after updating the cache
        CacheMonitor.log_cache_stats()
        
        return response
        
    def invalidate_feed_cache(self, user_id=None):
        """Utility method to invalidate feed cache when posts are modified"""
        cache_logger.info(f"Invalidating feed cache for user_id: {user_id if user_id else 'all users'}")
        
        if user_id:
            # Clear pattern for specific user
            keys_pattern = f"user_{user_id}_feed_*"
            cache_keys = cache.keys(keys_pattern)
            for key in cache_keys:
                cache_logger.debug(f"Deleting cache key: {key}")
                cache.delete(key)
            cache_logger.info(f"Invalidated {len(cache_keys)} cache keys for user {user_id}")
        else:
            # Clear all feed cache if no specific user
            keys_pattern = "user_*_feed_*"
            cache_keys = cache.keys(keys_pattern)
            for key in cache_keys:
                cache_logger.debug(f"Deleting cache key: {key}")
                cache.delete(key)
            cache_logger.info(f"Invalidated {len(cache_keys)} cache keys globally")
            
        # Log cache stats after invalidation
        CacheMonitor.log_cache_stats()

class GoogleLoginView(APIView):

    permission_classes = []

    def post(self, request):
        # Get the Google token from the request
        token = request.data.get('token')
        
        if not token:
            return Response(
                {'error': 'Google token is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Verify the Google token
            idinfo = id_token.verify_oauth2_token(
                token, 
                google_requests.Request(), 
                settings.SOCIALACCOUNT_PROVIDERS['google']['APP']['client_id']
            )
            
            # Extract user information from the token
            email = idinfo.get('email')
            if not email:
                return Response(
                    {'error': 'Email not found in token'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if user already exists
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                username = email.split('@')[0]
                if User.objects.filter(username=username).exists():
                    username = f"{username}_{idinfo.get('sub')[-6:]}"
                
                user = User.objects.create(
                    username=username,
                    email=email,
                    # Set a random password since it won't be used
                    password=get_user_model().objects.make_random_password(),
                    role='user'  # Default role
                )
                
                # Link the new user to the Google account
                SocialAccount.objects.create(
                    user=user,
                    provider='google',
                    uid=idinfo.get('sub'),
                    extra_data=idinfo
                )
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'role': user.role,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                }
            })
            
        except ValueError as e:
            return Response(
                {'error': f'Invalid token: {str(e)}'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )