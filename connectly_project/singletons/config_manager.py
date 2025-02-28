class ConfigManager:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ConfigManager, cls).__new__(cls, *args, **kwargs)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize default configuration settings."""
        self.settings = {
            "DEFAULT_PAGE_SIZE": 20,
            "ENABLE_ANALYTICS": True,
            "RATE_LIMIT": 100
        }

    def get_setting(self, key):
        """Retrieve a setting value."""
        return self.settings.get(key)

    def set_setting(self, key, value):
        """Update a setting value."""
        self.settings[key] = value