"""
Caching Utilities
"""
import hashlib
import json
from typing import Optional, Any
from pathlib import Path
import time


class ResponseCache:
    """Cache for HTTP responses"""
    
    def __init__(self, cache_dir: str = ".cache", ttl: int = 3600):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        self.ttl = ttl  # Time to live in seconds
    
    def _get_cache_key(self, url: str, params: Optional[dict] = None) -> str:
        """Generate cache key from URL and parameters"""
        key_data = f"{url}{json.dumps(params or {}, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, url: str, params: Optional[dict] = None) -> Optional[Any]:
        """Get cached response"""
        cache_key = self._get_cache_key(url, params)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            # Check if cache is expired
            if time.time() - cache_data['timestamp'] > self.ttl:
                cache_file.unlink()
                return None
            
            return cache_data['data']
        except:
            return None
    
    def set(self, url: str, data: Any, params: Optional[dict] = None):
        """Cache response"""
        cache_key = self._get_cache_key(url, params)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        try:
            cache_data = {
                'timestamp': time.time(),
                'data': data,
            }
            
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)
        except:
            pass
    
    def clear(self):
        """Clear all cache"""
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except:
                pass
    
    def invalidate(self, url: str, params: Optional[dict] = None):
        """Invalidate specific cache entry"""
        cache_key = self._get_cache_key(url, params)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if cache_file.exists():
            try:
                cache_file.unlink()
            except:
                pass

