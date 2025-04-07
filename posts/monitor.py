import time
import logging
from functools import wraps
from django.core.cache import cache

# Set up logger
cache_logger = logging.getLogger('cache_logger')

class CacheMonitor:
    """Utility for monitoring cache performance"""
    
    @staticmethod
    def log_cache_stats():
        """Log current cache statistics for various cache backends"""
        try:
            cache_backend = cache.__class__.__name__
            cache_logger.info(f"Cache backend: {cache_backend}")
            
            # Handle different cache backends
            if hasattr(cache, '_cache') and hasattr(cache._cache, 'get_stats'):
                # Memcached backend
                stats = cache._cache.get_stats()
                if stats:
                    for server, stat_dict in stats:
                        cache_logger.info(f"Cache Stats for {server}:")
                        for key, value in stat_dict.items():
                            cache_logger.info(f"  {key}: {value}")
            elif hasattr(cache, 'client') and hasattr(cache.client, 'info'):
                # Redis backend
                try:
                    info = cache.client.info()
                    cache_logger.info("Redis Cache Stats:")
                    for key in ['used_memory_human', 'used_memory_peak_human', 'hit_rate', 'keyspace_hits', 'keyspace_misses']:
                        if key in info:
                            cache_logger.info(f"  {key}: {info[key]}")
                except:
                    cache_logger.error("Unable to get Redis cache stats")
            elif hasattr(cache, '_cache') and hasattr(cache._cache, 'info'):
                # Alternative Redis client
                try:
                    info = cache._cache.info()
                    cache_logger.info("Redis Cache Stats:")
                    for key, value in info.items():
                        if any(stat in key for stat in ['memory', 'hits', 'misses', 'keys']):
                            cache_logger.info(f"  {key}: {value}")
                except:
                    cache_logger.error("Unable to get Redis cache stats")
            else:
                # For other cache backends or when stats aren't available
                cache_logger.info("Cache stats not available for this cache backend")
                # Try to at least log some basic info if available
                if hasattr(cache, 'get_backend_timeout'):
                    cache_logger.info(f"Default timeout: {cache.get_backend_timeout()}")
        except Exception as e:
            cache_logger.error(f"Error getting cache stats: {e}")
    
    @staticmethod
    def cache_performance_decorator(func):
        """Decorator to log cache performance metrics"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract user info if available
            request = None
            user_id = "anonymous"
            
            for arg in args:
                if hasattr(arg, 'user'):
                    request = arg
                    if hasattr(request.user, 'id'):
                        user_id = request.user.id
                    break
            
            # Get start time
            start_time = time.time()
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Calculate execution time
            execution_time = time.time() - start_time
            
            # Extract view name
            view_name = func.__name__
            
            # Log performance
            cache_logger.info(f"Performance: {view_name} - User: {user_id} - Time: {execution_time:.4f}s")
            
            return result
        return wrapper
    
    @staticmethod
    def check_cache_hit_rate(key_pattern, sample_size=100):
        """Estimate cache hit rate for keys matching a pattern"""
        keys = cache.keys(key_pattern)
        if not keys or sample_size <= 0:
            cache_logger.info(f"No keys found matching pattern: {key_pattern}")
            return 0
        
        # Limit sample size
        keys = keys[:min(len(keys), sample_size)]
        
        hits = 0
        for key in keys:
            if cache.get(key) is not None:
                hits += 1
        
        hit_rate = hits / len(keys) * 100
        cache_logger.info(f"Cache hit rate for {key_pattern}: {hit_rate:.2f}% ({hits}/{len(keys)})")
        return hit_rate