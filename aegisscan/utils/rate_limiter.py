"""
Rate Limiting Utilities
"""
import asyncio
import time
from typing import Optional
from collections import deque


class RateLimiter:
    """Rate limiter for controlling request frequency"""
    
    def __init__(self, max_requests: int = 10, time_window: float = 1.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire permission to make a request"""
        async with self._lock:
            now = time.time()
            
            # Remove old requests outside time window
            while self.requests and self.requests[0] < now - self.time_window:
                self.requests.popleft()
            
            # Check if we can make a request
            if len(self.requests) >= self.max_requests:
                # Wait until oldest request expires
                wait_time = self.requests[0] + self.time_window - now
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                    # Remove expired requests
                    while self.requests and self.requests[0] < time.time() - self.time_window:
                        self.requests.popleft()
            
            # Record this request
            self.requests.append(time.time())
    
    async def __aenter__(self):
        await self.acquire()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on response times"""
    
    def __init__(self, initial_rate: int = 10, min_rate: int = 1, max_rate: int = 100):
        self.current_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.response_times = deque(maxlen=10)
        self._limiter = RateLimiter(max_requests=initial_rate, time_window=1.0)
    
    async def acquire(self):
        """Acquire permission with adaptive rate"""
        await self._limiter.acquire()
    
    def record_response_time(self, response_time: float):
        """Record response time and adjust rate"""
        self.response_times.append(response_time)
        
        if len(self.response_times) >= 5:
            avg_time = sum(self.response_times) / len(self.response_times)
            
            # If responses are fast, increase rate
            if avg_time < 0.5 and self.current_rate < self.max_rate:
                self.current_rate = min(self.current_rate + 5, self.max_rate)
                self._limiter = RateLimiter(max_requests=self.current_rate, time_window=1.0)
            # If responses are slow, decrease rate
            elif avg_time > 2.0 and self.current_rate > self.min_rate:
                self.current_rate = max(self.current_rate - 5, self.min_rate)
                self._limiter = RateLimiter(max_requests=self.current_rate, time_window=1.0)

