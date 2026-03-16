"""
Web Crawler Engine
"""
import asyncio
import re
from typing import Set, List, Dict, Optional
from urllib.parse import urljoin, urlparse
from collections import deque
import logging
from ..http.client import AsyncHTTPClient


class Crawler:
    """Async web crawler with BFS/DFS modes"""
    
    def __init__(self, http_client: AsyncHTTPClient, max_depth: int = 3, max_pages: int = 100):
        self.http_client = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.found_urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.inputs: List[Dict] = []
        self.js_files: List[str] = []
        self.endpoints: List[str] = []
        self._logger = logging.getLogger(__name__)
    
    async def crawl(
        self,
        start_url: str,
        mode: str = "BFS",
        scope: Optional[str] = None,
        extract_forms: bool = True,
        extract_js: bool = True
    ) -> Dict:
        """Crawl website starting from start_url
        
        Args:
            start_url: Starting URL
            mode: 'BFS' or 'DFS'
            scope: Domain scope (only crawl this domain)
            extract_forms: Extract forms from pages
            extract_js: Extract and analyze JS files
        """
        # Parse scope
        if scope is None:
            parsed = urlparse(start_url)
            scope = f"{parsed.scheme}://{parsed.netloc}"
        
        # Initialize queue/stack
        if mode.upper() == "BFS":
            queue = deque([(start_url, 0)])
        else:
            queue = [(start_url, 0)]
        
        self.visited.clear()
        self.found_urls.clear()
        self.forms.clear()
        self.inputs.clear()
        self.js_files.clear()
        self.endpoints.clear()
        
        page_count = 0
        
        while queue and page_count < self.max_pages:
            if mode.upper() == "BFS":
                current_url, depth = queue.popleft()
            else:
                current_url, depth = queue.pop()
            
            # Skip if already visited or too deep
            if current_url in self.visited or depth > self.max_depth:
                continue
            
            # Check scope
            if not self._in_scope(current_url, scope):
                continue
            
            try:
                # Fetch page
                resp = await self.http_client.get(current_url, timeout=10)
                self.visited.add(current_url)
                self.found_urls.add(current_url)
                page_count += 1
                
                # Extract data
                if extract_forms:
                    forms = self._extract_forms(resp.text, current_url)
                    self.forms.extend(forms)
                
                inputs = self._extract_inputs(resp.text)
                self.inputs.extend(inputs)
                
                if extract_js:
                    js_files = self._extract_js_files(resp.text, current_url)
                    self.js_files.extend(js_files)
                
                endpoints = self._extract_endpoints(resp.text, current_url)
                self.endpoints.extend(endpoints)
                
                # Extract links for next level
                if depth < self.max_depth:
                    links = self._extract_links(resp.text, current_url)
                    for link in links:
                        if link not in self.visited and self._in_scope(link, scope):
                            if mode.upper() == "BFS":
                                queue.append((link, depth + 1))
                            else:
                                queue.append((link, depth + 1))
                
                self._logger.debug(f"Crawled: {current_url} (depth: {depth})")
                
            except Exception as e:
                # Silently skip errors - don't log every failed request
                # Only log at debug level
                self._logger.debug(f"Error crawling {current_url}: {str(e)[:100]}")
                continue
        
        return {
            "urls": sorted(list(self.found_urls)),
            "forms": self.forms,
            "inputs": self.inputs,
            "js_files": sorted(list(set(self.js_files))),
            "endpoints": sorted(list(set(self.endpoints))),
            "pages_crawled": page_count,
        }
    
    def _in_scope(self, url: str, scope: str) -> bool:
        """Check if URL is in scope"""
        try:
            parsed_url = urlparse(url)
            parsed_scope = urlparse(scope)
            
            # Same domain
            if parsed_url.netloc == parsed_scope.netloc:
                return True
            
            # Subdomain check
            if parsed_scope.netloc.startswith("."):
                domain = parsed_scope.netloc[1:]
                if parsed_url.netloc.endswith(domain):
                    return True
            
            return False
        except:
            return False
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = set()
        
        # Extract href attributes
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html):
            link = match.group(1)
            absolute_link = urljoin(base_url, link)
            # Remove fragments
            absolute_link = absolute_link.split("#")[0]
            links.add(absolute_link)
        
        # Extract src attributes (for iframes, etc.)
        src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in src_pattern.finditer(html):
            link = match.group(1)
            if link.startswith(("http://", "https://", "/")):
                absolute_link = urljoin(base_url, link)
                absolute_link = absolute_link.split("#")[0]
                links.add(absolute_link)
        
        return list(links)
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        
        for match in form_pattern.finditer(html):
            form_html = match.group(0)
            form_content = match.group(1)
            
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else ""
            if action:
                action = urljoin(base_url, action)
            
            form_data = {
                "action": action,
                "method": (method_match.group(1) if method_match else "GET").upper(),
                "inputs": []
            }
            
            # Extract inputs
            input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
            for input_match in input_pattern.finditer(form_content):
                input_html = input_match.group(0)
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                
                if name_match:
                    form_data["inputs"].append({
                        "name": name_match.group(1),
                        "type": type_match.group(1) if type_match else "text"
                    })
            
            forms.append(form_data)
        
        return forms
    
    def _extract_inputs(self, html: str) -> List[Dict]:
        """Extract all input fields"""
        inputs = []
        input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
        
        for match in input_pattern.finditer(html):
            input_html = match.group(0)
            name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            
            if name_match:
                inputs.append({
                    "name": name_match.group(1),
                    "type": type_match.group(1) if type_match else "text"
                })
        
        return inputs
    
    def _extract_js_files(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript file URLs"""
        js_files = set()
        
        # Script src
        script_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in script_pattern.finditer(html):
            js_url = match.group(1)
            absolute_url = urljoin(base_url, js_url)
            if absolute_url.endswith(".js"):
                js_files.add(absolute_url)
        
        return list(js_files)
    
    def _extract_endpoints(self, html: str, base_url: str) -> List[str]:
        """Extract API endpoints and URLs"""
        endpoints = set()
        
        # API endpoint patterns
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                endpoint = match.group(1)
                absolute_endpoint = urljoin(base_url, endpoint)
                endpoints.add(absolute_endpoint)
        
        return list(endpoints)

