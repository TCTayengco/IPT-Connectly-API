import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from .models import User
from .models import Post
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Comment
from .serializers import UserSerializer, PostSerializer, CommentSerializer
# TESTING CODE
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAdminUser
from .permissions import IsPostAuthor
import logging
from singletons.logger_singleton import LoggerSingleton
from factories.post_factory import PostFactory

logger = LoggerSingleton().get_logger()

# Testing login
class LoginView(APIView):
    permission_classes = [AllowAny]  # Allow anyone to attempt login

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(username=username, password=password)

        if user is not None:
            token, created = Token.objects.get_or_create(user=user)
            logger.info(f"User {username} logged in successfully.")
            return Response({"token": token.key}, status=status.HTTP_200_OK)
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

# Testing Authenticated Views
class ProtectedView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "You are authenticated!"})

class AdminOnlyView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        return Response({"message": "You are an admin!"})

class PostDetailView(APIView):
    permission_classes = [IsAuthenticated, IsPostAuthor]

    def get(self, request, pk):
        post = Post.objects.get(pk=pk)
        self.check_object_permissions(request, post)
        return Response({"content": post.content})

# TESTING CODE

# Create your views here.
# vvvvvvvvvvvvvvvvvvvvvv

# CREATE and POST operations for Users
class UserListCreate(APIView):

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"User {serializer.data['username']} created successfully.")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        logger.error("Failed to create user: %s", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Update a user
@csrf_exempt
def update_user(request, id):
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            email = data['email']
            user = User.objects.filter(id=id).first()
            # data = UserSerializer(isinstance=user, data=request.data)
            user.email = email
            user.save()
            logger.info(f"User {user.username} updated successfully.")
            return JsonResponse({'message': 'User updated successfully'}, status=201)
        except Exception as e:
            logger.error(f"Error updating user {id}: {str(e)}")
            return JsonResponse({'error': str(e)}, status=400)
        
# Delete a user
@csrf_exempt
def delete_user(request, id):
    if request.method == 'DELETE':
        try:
            user = User.objects.filter(id=id).first()
            user.delete()
            # User.objects.delete(id=id)
            logger.info(f"User {user.username} deleted successfully.")
            return JsonResponse({'message': 'User deleted successfully'}, status=200)
        except Exception as e:
            logger.error(f"Error deleting user {id}: {str(e)}")
            return JsonResponse({'error': str(e)}, status=400)
        
# CRUD operations for Posts
class PostListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)

    def post(self, request):
        try:
            post = PostFactory.create_post(request.data)
            logger.info(f"Post created successfully by user {request.user.username}.")
            return Response(PostSerializer(post).data, status=status.HTTP_201_CREATED)
        except ValueError as e:
            logger.warning(f"Post creation failed: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request):
        try:
            data = request.data.copy()
            data["author"] = request.user.id  # Ensure the logged-in user is assigned as the author

            post = PostFactory.create_post(data)
            logger.info(f"Post created successfully by user {request.user.username}.")
            return Response(PostSerializer(post).data, status=status.HTTP_201_CREATED)
        except ValueError as e:
            logger.warning(f"Post creation failed: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, post_id):
        try:
            post = Post.objects.get(id=post_id)
        except Post.DoesNotExist:
            logger.warning(f"Attempted to update non-existent post {post_id}")
            return Response({"error": "Post not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Post {post_id} updated successfully.")
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, post_id):
        try:
            post = Post.objects.get(id=post_id)
        except Post.DoesNotExist:
            logger.warning(f"Attempted to delete non-existent post {post_id}")
            return Response({"error": "Post not found"}, status=status.HTTP_404_NOT_FOUND)

        post.delete()
        logger.info(f"Post {post_id} deleted successfully.")
        return Response({"message": "Post deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

# CRUD operations for Comments
class CommentListCreate(APIView):
    def get(self, request):
        comments = Comment.objects.all()
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)


    def post(self, request):
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Comment {serializer.data['id']} created successfully.")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        logger.error("Failed to create comment: %s", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, comment_id):
        try:
            comment = Comment.objects.get(id=comment_id)
        except Comment.DoesNotExist:
            logger.warning(f"Attempted to update non-existent comment {comment_id}")
            return Response({"error": "Comment not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = CommentSerializer(comment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Comment {comment_id} updated successfully.")
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, comment_id):
        try:
            comment = Comment.objects.get(id=comment_id)
        except Comment.DoesNotExist:
            logger.warning(f"Attempted to delete non-existent comment {comment_id}")
            return Response({"error": "Comment not found"}, status=status.HTTP_404_NOT_FOUND)

        comment.delete()
        logger.info(f"Comment {comment_id} deleted successfully.")
        return Response({"message": "Comment deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
