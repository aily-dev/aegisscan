"""
Advanced Path and Endpoint Discovery
"""
import asyncio
import re
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import logging
from ..http.client import AsyncHTTPClient, Response
from ..utils.wordlists import WordlistManager


class PathDiscovery:
    """Advanced path and endpoint discovery"""
    
    def __init__(self, http_client: AsyncHTTPClient, wordlist_manager: Optional[WordlistManager] = None):
        self.http_client = http_client
        self.wordlist_manager = wordlist_manager or WordlistManager()
        self._logger = logging.getLogger(__name__)
        
        # Common path patterns
        self.path_patterns = [
            r'["\']([^"\']*\/[^"\']+)["\']',
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'path:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
            r'\/api\/[^"\'\s]+',
            r'\/v\d+\/[^"\'\s]+',
            r'\/rest\/[^"\'\s]+',
        ]
    
    async def discover_paths_from_response(self, response: Response, base_url: str) -> Set[str]:
        """Discover paths from HTTP response"""
        discovered = set()
        
        # Extract from HTML
        html_paths = self._extract_paths_from_html(response.text, base_url)
        discovered.update(html_paths)
        
        # Extract from JavaScript
        js_paths = self._extract_paths_from_javascript(response.text, base_url)
        discovered.update(js_paths)
        
        # Extract from headers
        header_paths = self._extract_paths_from_headers(response.headers, base_url)
        discovered.update(header_paths)
        
        return discovered
    
    def _extract_paths_from_html(self, html: str, base_url: str) -> Set[str]:
        """Extract paths from HTML"""
        paths = set()
        
        # Common HTML patterns
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'data-src=["\']([^"\']+)["\']',
            r'data-url=["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                path = match.group(1)
                if path.startswith('/') or path.startswith('http'):
                    absolute_path = urljoin(base_url, path)
                    # Remove fragments and queries for path discovery
                    parsed = urlparse(absolute_path)
                    clean_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if clean_path != base_url:
                        paths.add(clean_path)
        
        return paths
    
    def _extract_paths_from_javascript(self, js_content: str, base_url: str) -> Set[str]:
        """Extract paths from JavaScript code"""
        paths = set()
        
        # API endpoint patterns
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
            r'\.ajax\([^)]*url:\s*["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Get the URL group (might be different groups)
                for group in match.groups():
                    if group and (group.startswith('/') or group.startswith('http')):
                        absolute_path = urljoin(base_url, group)
                        parsed = urlparse(absolute_path)
                        clean_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        paths.add(clean_path)
        
        return paths
    
    def _extract_paths_from_headers(self, headers: Dict[str, str], base_url: str) -> Set[str]:
        """Extract paths from HTTP headers"""
        paths = set()
        
        # Check common headers
        header_fields = ["Location", "X-Forwarded-Path", "X-Original-URL", "X-Rewrite-URL"]
        
        for field in header_fields:
            if field in headers:
                value = headers[field]
                if value.startswith('/') or value.startswith('http'):
                    absolute_path = urljoin(base_url, value)
                    parsed = urlparse(absolute_path)
                    clean_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    paths.add(clean_path)
        
        return paths
    
    async def discover_from_sitemap(self, base_url: str) -> Set[str]:
        """Discover paths from sitemap.xml"""
        paths = set()
        
        sitemap_urls = [
            f"{base_url}/sitemap.xml",
            f"{base_url}/sitemap_index.xml",
            f"{base_url}/sitemap1.xml",
            f"{base_url}/robots.txt",
        ]
        
        for url in sitemap_urls:
            try:
                resp = await self.http_client.get(url, timeout=5)
                if resp.status_code == 200:
                    # Extract URLs from sitemap
                    url_pattern = r'<loc>(.*?)</loc>'
                    matches = re.finditer(url_pattern, resp.text, re.IGNORECASE)
                    for match in matches:
                        paths.add(match.group(1))
                    
                    # Extract from robots.txt
                    if "robots.txt" in url:
                        for line in resp.text.split('\n'):
                            if line.startswith('Sitemap:'):
                                sitemap_url = line.split('Sitemap:')[1].strip()
                                paths.add(sitemap_url)
            except:
                continue
        
        return paths
    
    async def discover_from_js_files(self, js_urls: List[str]) -> Set[str]:
        """Discover endpoints from JavaScript files"""
        endpoints = set()
        
        for js_url in js_urls[:20]:  # Limit
            try:
                resp = await self.http_client.get(js_url, timeout=5)
                if resp.status_code == 200:
                    js_paths = self._extract_paths_from_javascript(resp.text, js_url)
                    endpoints.update(js_paths)
            except:
                continue
        
        return endpoints
    
    async def discover_parameters(self, url: str) -> Dict[str, List[str]]:
        """Discover parameters from URL and response"""
        parameters = {}
        
        try:
            # Extract from URL
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for key, values in params.items():
                    parameters[key] = values
            
            # Get response and extract from forms
            resp = await self.http_client.get(url, timeout=5)
            
            # Extract from forms
            form_params = self._extract_parameters_from_forms(resp.text)
            for key, values in form_params.items():
                if key not in parameters:
                    parameters[key] = []
                parameters[key].extend(values)
            
            # Extract from JavaScript
            js_params = self._extract_parameters_from_javascript(resp.text)
            for key, values in js_params.items():
                if key not in parameters:
                    parameters[key] = []
                parameters[key].extend(values)
            
        except:
            pass
        
        return parameters
    
    def _extract_parameters_from_forms(self, html: str) -> Dict[str, List[str]]:
        """Extract parameters from HTML forms"""
        parameters = {}
        
        # Find all input fields
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\']'
        matches = re.finditer(input_pattern, html, re.IGNORECASE)
        
        for match in matches:
            param_name = match.group(1)
            if param_name not in parameters:
                parameters[param_name] = []
        
        return parameters
    
    def _extract_parameters_from_javascript(self, js_content: str) -> Dict[str, List[str]]:
        """Extract parameters from JavaScript"""
        parameters = {}
        
        # Common parameter patterns
        patterns = [
            r'["\']([a-z_][a-z0-9_]*)\s*[:=]\s*',
            r'param\[["\']([^"\']+)["\']\]',
            r'params\.([a-z_][a-z0-9_]*)',
            r'data\.([a-z_][a-z0-9_]*)',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                param_name = match.group(1)
                if param_name not in parameters:
                    parameters[param_name] = []
        
        return parameters

