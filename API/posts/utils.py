import bcrypt
from django.contrib.auth.hashers import make_password, check_password

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


