import sys
import os

# test_config.py
from singletons.config_manager import ConfigManager

# Create two instances
config1 = ConfigManager()
config2 = ConfigManager()

# Ensure both instances are the same object
assert config1 is config2, "Singleton instance is not working correctly!"

# Modify a setting
config1.set_setting("DEFAULT_PAGE_SIZE", 50)

# Verify that the change is reflected in config2
assert config2.get_setting("DEFAULT_PAGE_SIZE") == 50, "Singleton does not share state correctly!"

print("Singleton ConfigManager works correctly!")
