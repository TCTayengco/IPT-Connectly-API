from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils.timezone import now
# Create your models here.
class User(AbstractUser):  # Use Django's built-in user system
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User'),
        ('guest', 'Guest'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

    created_at = models.DateTimeField(auto_now_add=True)
    # Resolve reverse accessor conflicts
    groups = models.ManyToManyField(
        Group,
        related_name="custom_user_set",
        blank=True
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="custom_user_permission_set",
        blank=True
    )

    def __str__(self):
        return self.username
    
class Post(models.Model):
    content = models.TextField()
    author = models.ForeignKey(User, related_name='posts', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"Post by {self.author.username} at {self.created_at}"


class Comment(models.Model):
    text = models.TextField()
    author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)
    post = models.ForeignKey(Post, related_name='comments', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"Comment by {self.author.username} on Post {self.post.id}"

class Like(models.Model):
    user = models.ForeignKey(User, related_name='likes', on_delete=models.CASCADE)
    post = models.ForeignKey(Post, related_name='likes', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'post')  # Prevent duplicate likes

    def __str__(self):
        return f"{self.user.username} likes {self.post.id}"

class Singleton(type):
    # dictionary: Stores instances of the classes.
    _instances = {}
    # method: When an instance is created, it checks if the class has already an instance. If not, it creates and stores a new instance. If yes, it returns the existing instance.    
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

# uses Singleton as its metaclass, meaning it will only ever have one instance.
class PasswordSingleton(metaclass=Singleton):
    # Initializes the instance with a password attribute.
    def __init__(self, password):
        self.password = password

# __init__ method that takes a password argument and stores it as an instance attribute.
class PasswordClass:
    def __init__(self, password):
            self.password = password

# This is the Factory class that is responsible for creating instances of classes.
# _creators dictionary: Stores the creators (constructors) of the registered classes.
# register_class method: Registers a class with the factory by associating it with a key.
# create_instance method: Creates an instance of the registered class using the provided key and arguments.
class PasswordFactory:
    def __init__(self):
        self._creators = {}

    def register_class(self, key, creator):
        self._creators[key] = creator

    def create_instance(self, key, *args, **kwargs):
        creator = self._creators.get(key)
        if not creator:
            raise ValueError(f"Class not registered for key: {key}")
        return creator(*args, **kwargs)