from singletons.logger_singleton import LoggerSingleton

logger1 = LoggerSingleton().get_logger()
logger2 = LoggerSingleton().get_logger()

# Check if both loggers are the same instance
assert logger1 is logger2, "LoggerSingleton does not return the same instance!"

# Test logging messages
logger1.info("Singleton Logger is working correctly!")

print("Singleton Logger works correctly!")
