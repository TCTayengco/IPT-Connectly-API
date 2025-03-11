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

from .models import User, Post, Comment, PasswordSingleton, PasswordClass, PasswordFactory, Like
from .serializers import UserSerializer, PostSerializer, CommentSerializer
from .permission import IsAdmin, IsSelfOrAdmin
from django.contrib.auth.hashers import make_password, check_password 

from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth import get_user_model

from rest_framework.decorators import api_view, permission_classes
from .serializers import CommentPagination, PostDetailSerializer, LikeSerializer

from django.db.models import Prefetch
from django.core.cache import cache

from django.conf import settings
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from allauth.socialaccount.models import SocialAccount


# ========================================================
# Function-Based Views for User Management
# ========================================================

def get_users(request):
    try:
        users = list(
            User.objects.values('id', 'username', 'email', 'date_joined','password')
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

class LoginUser(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        User = get_user_model()

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.check_password(password):
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
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            token.blacklist()  # Blacklist the refresh token to log out the user

            return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': 'Invalid token or logout failed'}, status=status.HTTP_400_BAD_REQUEST)    
        
        
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
    
class PostListCreate(APIView):
    def get(self, request):
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)


    def post(self, request):
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            if self.request.user.is_authenticated:  # Assign author only if user is authenticated
                serializer.save(author=self.request.user)
            else:
                serializer.save()  # Allow unauthenticated posts but requires manual author input
        
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        if not request.user.is_authenticated:
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)

        post = get_object_or_404(Post, pk=pk)
        if post.author != request.user:
            return Response({"error": "You can only update your own posts"}, status=status.HTTP_403_FORBIDDEN)

        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        if not request.user.is_authenticated:
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)

        post = get_object_or_404(Post, pk=pk)
        if post.author != request.user:
            return Response({"error": "You can only delete your own posts"}, status=status.HTTP_403_FORBIDDEN)

        post.delete()
        return Response({"message": "Post deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

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
        if comment.author != request.user:
            return Response({"error": "You can only update your own comments"}, status=status.HTTP_403_FORBIDDEN)

        serializer = CommentSerializer(comment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        comment = get_object_or_404(Comment, pk=pk)
        if comment.author != request.user:
            return Response({"error": "You can only delete your own comments"}, status=status.HTTP_403_FORBIDDEN)

        comment.delete()
        return Response({"message": "Comment deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

class PostDetail(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        post = get_object_or_404(Post, pk=pk)
        serializer = PostDetailSerializer(post)
        return Response(serializer.data)

class PostLike(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        post = get_object_or_404(Post, pk=pk)

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

        # Clear cache
        cache.delete(f"user_{request.user.id}_feed")  
        cache.delete(f"post_{post.id}_likes")  
        cache.delete("all_posts_list")  # Ensures GET /posts/ fetches fresh data

        return Response({'status': response_status}, status=status_code)

class PostComment(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, pk):
        post = get_object_or_404(Post, pk=pk)
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

    def get_queryset(self):
        user = self.request.user
        liked_only = self.request.query_params.get("liked", None)
        sort_order = self.request.query_params.get("sort", "desc")  # Default: Newest first

        # Modify cache key to include sorting preference
        cache_key = f"user_{user.id}_feed_{sort_order}"
        if liked_only:
            cache_key += "_liked"

        # Check cache first
        cached_feed = cache.get(cache_key)
        if cached_feed:
            return cached_feed

        # Sort direction
        order_by_field = "-created_at" if sort_order == "desc" else "created_at"

        # Query posts
        queryset = Post.objects.select_related("author").prefetch_related(
            "likes", "comments"
        ).order_by(order_by_field)

        # Apply filtering for liked posts
        if liked_only:
            queryset = queryset.filter(likes=user)

        # Store filtered results in cache for 5 minutes
        cache.set(cache_key, queryset, timeout=300)

        return queryset
    
    User = get_user_model()

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