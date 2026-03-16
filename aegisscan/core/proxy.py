"""
Proxy and TOR support for AegisScan
"""
import asyncio
import logging
from typing import Optional, List, Dict
from urllib.parse import urlparse
import aiohttp


class ProxyManager:
    """Manages proxy rotation and TOR support"""
    
    def __init__(self, proxies: Optional[List[str]] = None, use_tor: bool = False, tor_port: int = 9050):
        self.proxies = proxies or []
        self.use_tor = use_tor
        self.tor_port = tor_port
        self.current_proxy_index = 0
        self._lock = asyncio.Lock()
        self._logger = logging.getLogger(__name__)
        
        if use_tor:
            self.proxies.append(f"socks5://127.0.0.1:{tor_port}")
    
    def get_proxy(self) -> Optional[str]:
        """Get the next proxy in rotation"""
        if not self.proxies:
            return None
        
        async def _get():
            async with self._lock:
                proxy = self.proxies[self.current_proxy_index]
                self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
                return proxy
        
        # For sync access, we'll use a simple round-robin
        proxy = self.proxies[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        return proxy
    
    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Get proxy as aiohttp-compatible dict"""
        proxy_url = self.get_proxy()
        if not proxy_url:
            return None
        
        parsed = urlparse(proxy_url)
        return {
            "http": proxy_url,
            "https": proxy_url
        }
    
    async def test_proxy(self, proxy_url: str, test_url: str = "http://httpbin.org/ip") -> bool:
        """Test if a proxy is working"""
        try:
            proxy_dict = {"http": proxy_url, "https": proxy_url}
            timeout = aiohttp.ClientTimeout(total=10)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(test_url, proxy=proxy_url) as resp:
                    if resp.status == 200:
                        return True
        except Exception as e:
            self._logger.debug(f"Proxy test failed for {proxy_url}: {e}")
        
        return False
    
    async def test_all_proxies(self, test_url: str = "http://httpbin.org/ip") -> List[str]:
        """Test all proxies and return working ones"""
        working = []
        for proxy in self.proxies:
            if await self.test_proxy(proxy, test_url):
                working.append(proxy)
        return working

