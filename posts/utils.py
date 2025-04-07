import bcrypt
from django.contrib.auth.hashers import make_password, check_password
from django.core.cache import cache

class PasswordFactory:
    """Factory class to handle different password hashing strategies."""
    _methods = {}

    @classmethod
    def register(cls, key, method):
        cls._methods[key] = method

    @classmethod
    def hash_password(cls, password, method="django"):
        if method not in cls._methods:
            raise ValueError(f"Hashing method '{method}' not registered.")
        return cls._methods[method](password)

    @classmethod
    def verify_password(cls, password, hashed_password):
        """Detect hash type and verify accordingly."""
        if hashed_password.startswith(("$2b$", "$2a$", "$2y$")):
            # Bcrypt hash detected
            return bcrypt.checkpw(password.encode(), hashed_password.encode())
        else:
            # Assume Django hash
            return check_password(password, hashed_password)

# Register available password hashing methods
PasswordFactory.register("django", make_password)
PasswordFactory.register("bcrypt", lambda pw: bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode())



class InvalidateCachePatterns:
    def invalidate_cache_patterns(pattern):
        if pattern.startswith("user_"):
            parts = pattern.split("_")
            if len(parts) >= 3 and parts[2] == "feed":
                user_id = parts[1]
                # Delete specific user feed caches with known variations
                variations = [
                    f"user_{user_id}_feed_desc",
                    f"user_{user_id}_feed_asc",
                    f"user_{user_id}_feed_desc_liked",
                    f"user_{user_id}_feed_asc_liked",
                ]
                # Add size variations
                for size in [10, 20, 50]:  # Common page sizes
                    variations.extend([
                        f"user_{user_id}_feed_desc_size_{size}",
                        f"user_{user_id}_feed_asc_size_{size}",
                        f"user_{user_id}_feed_desc_liked_size_{size}",
                        f"user_{user_id}_feed_asc_liked_size_{size}",
                    ])
                
                # Delete response cache variations
                for page in range(1, 5):  # First few pages
                    for size in [10, 20, 50]:
                        variations.extend([
                            f"user_{user_id}_feed_response_desc_page_{page}_size_{size}",
                            f"user_{user_id}_feed_response_asc_page_{page}_size_{size}",
                            f"user_{user_id}_feed_response_desc_liked_page_{page}_size_{size}",
                            f"user_{user_id}_feed_response_asc_liked_page_{page}_size_{size}",
                        ])
                
                # Delete all variations
                for key in variations:
                    cache.delete(key)
                    
        elif pattern == "all_posts_list*":
            # Delete main list cache
            cache.delete("all_posts_list")
            
            # Delete user-specific lists
            # This is limited but covers common cases
            from .models import User
            for user_id in User.objects.values_list('id', flat=True)[:100]:  # Limit to first 100 users
                cache.delete(f"all_posts_list_user_{user_id}")