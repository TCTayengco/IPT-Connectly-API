from posts.models import Post
from posts.serializers import PostSerializer

class PostFactory:
    @staticmethod
    def create_post(data):
        """
        Creates a new Post instance using the provided data.
        Uses the serializer for validation before saving.
        """
        serializer = PostSerializer(data=data)
        if serializer.is_valid():
            post = serializer.save()
            return post
        else:
            raise ValueError(serializer.errors)
