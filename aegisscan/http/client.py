"""
Async HTTP client for AegisScan
"""
import aiohttp
import asyncio
import logging
from typing import Optional, Dict, List, Any, Union
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from datetime import datetime
import json
import re


@dataclass
class Response:
    """HTTP Response object"""
    url: str
    status_code: int
    headers: Dict[str, str]
    content: bytes
    text: str
    cookies: Dict[str, str] = field(default_factory=dict)
    elapsed: float = 0.0
    request_headers: Dict[str, str] = field(default_factory=dict)
    redirect_history: List[str] = field(default_factory=list)
    encoding: str = "utf-8"
    
    @property
    def json(self) -> Any:
        """Parse JSON response"""
        try:
            return json.loads(self.text)
        except:
            return None
    
    @property
    def size(self) -> int:
        """Response size in bytes"""
        return len(self.content)


class SessionManager:
    """Manages HTTP sessions and cookies"""
    
    def __init__(self):
        self.sessions: Dict[str, aiohttp.ClientSession] = {}
        self.cookies: Dict[str, Dict[str, str]] = {}
        self._lock = asyncio.Lock()
    
    async def get_session(self, base_url: str, **kwargs) -> aiohttp.ClientSession:
        """Get or create a session for a base URL"""
        parsed = urlparse(base_url)
        domain = f"{parsed.scheme}://{parsed.netloc}"
        
        async with self._lock:
            if domain not in self.sessions:
                # Create cookie jar
                jar = aiohttp.CookieJar()
                
                # Restore cookies if available
                if domain in self.cookies:
                    for name, value in self.cookies[domain].items():
                        jar.update_cookies({name: value})
                
                # Create session
                timeout = aiohttp.ClientTimeout(total=30, connect=10)
                self.sessions[domain] = aiohttp.ClientSession(
                    cookie_jar=jar,
                    timeout=timeout,
                    **kwargs
                )
            
            return self.sessions[domain]
    
    async def close_all(self):
        """Close all sessions"""
        async with self._lock:
            for session in self.sessions.values():
                await session.close()
            self.sessions.clear()
    
    def get_cookies(self, domain: str) -> Dict[str, str]:
        """Get cookies for a domain"""
        return self.cookies.get(domain, {})
    
    def set_cookie(self, domain: str, name: str, value: str):
        """Set a cookie for a domain"""
        if domain not in self.cookies:
            self.cookies[domain] = {}
        self.cookies[domain][name] = value


class CSRFDetector:
    """Detects CSRF tokens in forms and responses"""
    
    CSRF_TOKEN_PATTERNS = [
        r'name=["\']csrf_token["\']',
        r'name=["\']_token["\']',
        r'name=["\']authenticity_token["\']',
        r'name=["\']csrf["\']',
        r'name=["\']_csrf["\']',
        r'csrf-token["\']',
        r'X-CSRF-Token["\']',
        r'csrfmiddlewaretoken',
    ]
    
    @staticmethod
    def extract_tokens(html: str) -> List[Dict[str, str]]:
        """Extract CSRF tokens from HTML"""
        tokens = []
        
        for pattern in CSRFDetector.CSRF_TOKEN_PATTERNS:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                # Try to find the value attribute nearby
                context = html[max(0, match.start()-200):match.end()+200]
                value_match = re.search(r'value=["\']([^"\']+)["\']', context)
                if value_match:
                    tokens.append({
                        "name": "csrf_token",
                        "value": value_match.group(1),
                        "pattern": pattern
                    })
        
        return tokens


class AsyncHTTPClient:
    """Async HTTP client with full feature set"""
    
    def __init__(
        self,
        timeout: int = 30,
        max_redirects: int = 10,
        verify_ssl: bool = True,
        user_agent: Optional[str] = None,
        default_headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        session_manager: Optional[SessionManager] = None
    ):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "AegisScan/1.0"
        self.default_headers = default_headers or {}
        self.proxy = proxy
        self.session_manager = session_manager or SessionManager()
        self.csrf_detector = CSRFDetector()
        self._logger = logging.getLogger(__name__)
        
        # Default headers
        if "User-Agent" not in self.default_headers:
            self.default_headers["User-Agent"] = self.user_agent
    
    async def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        data: Optional[Union[str, Dict, bytes]] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        timeout: Optional[int] = None,
        proxy: Optional[str] = None,
        raw: bool = False
    ) -> Response:
        """Make an HTTP request"""
        
        # Merge headers
        request_headers = {**self.default_headers}
        if headers:
            request_headers.update(headers)
        
        # Get session
        session = await self.session_manager.get_session(url)
        
        # Prepare data
        request_data = data
        if json_data:
            request_data = json.dumps(json_data)
            request_headers["Content-Type"] = "application/json"
        
        # Use provided proxy or default
        request_proxy = proxy or self.proxy
        
        # Timeout
        request_timeout = timeout or self.timeout
        client_timeout = aiohttp.ClientTimeout(total=request_timeout, connect=10)
        
        redirect_history = []
        start_time = asyncio.get_event_loop().time()
        
        try:
            async with session.request(
                method=method,
                url=url,
                params=params,
                data=request_data,
                headers=request_headers,
                cookies=cookies,
                allow_redirects=allow_redirects,
                proxy=request_proxy,
                ssl=self.verify_ssl,
                timeout=client_timeout
            ) as resp:
                # Handle redirects manually if needed
                if not allow_redirects and resp.status in [301, 302, 303, 307, 308]:
                    redirect_history.append(str(resp.url))
                
                # Read content
                content = await resp.read()
                elapsed = asyncio.get_event_loop().time() - start_time
                
                # Detect encoding
                encoding = resp.charset or "utf-8"
                try:
                    text = content.decode(encoding)
                except:
                    text = content.decode("utf-8", errors="ignore")
                
                # Extract cookies
                response_cookies = {}
                for cookie in resp.cookies:
                    try:
                        # Handle both Cookie and string types
                        if hasattr(cookie, 'key') and hasattr(cookie, 'value'):
                            response_cookies[cookie.key] = cookie.value
                        elif isinstance(cookie, str):
                            # If cookie is a string, parse it
                            if '=' in cookie:
                                key, value = cookie.split('=', 1)
                                response_cookies[key] = value
                    except Exception as cookie_error:
                        # Skip problematic cookies
                        self._logger.debug(f"Error extracting cookie: {cookie_error}")
                        continue
                
                # Build response
                response = Response(
                    url=str(resp.url),
                    status_code=resp.status,
                    headers=dict(resp.headers),
                    content=content,
                    text=text,
                    cookies=response_cookies,
                    elapsed=elapsed,
                    request_headers=request_headers,
                    redirect_history=redirect_history,
                    encoding=encoding
                )
                
                return response
                
        except asyncio.TimeoutError:
            self._logger.debug(f"Request timeout: {url}")
            raise
        except Exception as e:
            # Log error but don't print to console - only log
            self._logger.debug(f"Request error: {url} - {str(e)[:200]}")
            raise
    
    async def get(self, url: str, **kwargs) -> Response:
        """GET request"""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Response:
        """POST request"""
        return await self.request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> Response:
        """PUT request"""
        return await self.request("PUT", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> Response:
        """DELETE request"""
        return await self.request("DELETE", url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> Response:
        """HEAD request"""
        return await self.request("HEAD", url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> Response:
        """OPTIONS request"""
        return await self.request("OPTIONS", url, **kwargs)
    
    def detect_csrf(self, response: Response) -> List[Dict[str, str]]:
        """Detect CSRF tokens in response"""
        return self.csrf_detector.extract_tokens(response.text)
    
    async def close(self):
        """Close all sessions"""
        await self.session_manager.close_all()

