from rest_framework import serializers
from .models import User, Post, Comment, Like


from rest_framework import serializers
from .models import User
from django.contrib.auth.hashers import make_password

from rest_framework.pagination import PageNumberPagination

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'role', 'created_at']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])  
        return User.objects.create(**validated_data)

    def update(self, instance, validated_data):
        if 'password' in validated_data:
            instance.password = make_password(validated_data['password'])
        return super().update(instance, validated_data)

class LikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Like
        fields = ['id', 'user', 'post', 'created_at']

class PostSerializer(serializers.ModelSerializer):
    likes_count = serializers.IntegerField(source="likes.count", read_only=True)
    liked_users = serializers.PrimaryKeyRelatedField(many=True, read_only=True, source="likes")  # Debugging
    comments_count = serializers.IntegerField(source="comments.count", read_only=True)
    comments = serializers.StringRelatedField(many=True, read_only=True)


    class Meta:
        model = Post
        fields = ['id', 'content', 'author', 'created_at', 'comments', 'likes_count','liked_users', 'comments_count']
        extra_kwargs = {'author': {'read_only': True}}


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ['id', 'text', 'author', 'post', 'created_at']


    def validate_post(self, value):
        if not Post.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Post not found.")
        return value


    def validate_author(self, value):
        if not User.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Author not found.")
        return value
    
class CommentPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

class PostDetailSerializer(serializers.ModelSerializer):
    likes_count = serializers.IntegerField(source="likes.count", read_only=True)
    liked_users = serializers.PrimaryKeyRelatedField(
        many=True, read_only=True, source="likes"
    )
    comments_count = serializers.SerializerMethodField()
    comments = CommentSerializer(many=True, read_only=True)

    class Meta:
        model = Post
        fields = ['id', 'content', 'author', 'created_at', 'liked_users','likes_count', 'comments_count', 'comments']

    def get_likes_count(self, obj):
        return obj.likes.count()

    def get_comments_count(self, obj):
        return obj.comments.count()

