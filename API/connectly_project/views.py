import json
import bcrypt
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from django.contrib.auth.models import User

from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication

from posts.models import User, Post, Comment, PasswordSingleton, PasswordClass, PasswordFactory, Like
from .serializers import UserSerializer, PostSerializer, CommentSerializer
from posts.permission import IsAdmin, IsSelfOrAdmin
from django.contrib.auth.hashers import make_password, check_password 

from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth import get_user_model

from rest_framework.decorators import api_view, permission_classes
from .serializers import CommentPagination, PostDetailSerializer, LikeSerializer


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
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        post = get_object_or_404(Post, pk=pk)
        if post.author != request.user:
            return Response({"error": "You can only update your own posts"}, status=status.HTTP_403_FORBIDDEN)

        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
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
        like, created = Like.objects.get_or_create(
            user=request.user,
            post=post
        )
        if not created:
            # Unlike if already liked
            like.delete()
            return Response({'status': 'unliked'}, status=status.HTTP_200_OK)
        return Response({'status': 'liked'}, status=status.HTTP_201_CREATED)

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
    

