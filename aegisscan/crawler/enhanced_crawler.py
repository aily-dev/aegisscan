"""
Enhanced Web Crawler with Advanced Features
"""
import asyncio
import re
from typing import Set, List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
import logging
from ..http.client import AsyncHTTPClient
from ..utils.wordlists import WordlistManager


class EnhancedCrawler:
    """Enhanced web crawler with advanced discovery"""
    
    def __init__(
        self,
        http_client: AsyncHTTPClient,
        max_depth: int = 3,
        max_pages: int = 100,
        wordlist_manager: Optional[WordlistManager] = None
    ):
        self.http_client = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.wordlist_manager = wordlist_manager or WordlistManager()
        self._logger = logging.getLogger(__name__)
        
        # Discovery storage
        self.visited: Set[str] = set()
        self.found_urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.inputs: List[Dict] = []
        self.js_files: List[str] = []
        self.endpoints: List[str] = []
        self.api_endpoints: List[str] = []
        self.parameters: Dict[str, List[str]] = {}
    
    async def crawl(
        self,
        start_url: str,
        mode: str = "BFS",
        scope: Optional[str] = None,
        extract_forms: bool = True,
        extract_js: bool = True,
        extract_api: bool = True
    ) -> Dict:
        """Enhanced crawling with API and parameter discovery"""
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
        self.api_endpoints.clear()
        
        page_count = 0
        
        while queue and page_count < self.max_pages:
            if mode.upper() == "BFS":
                current_url, depth = queue.popleft()
            else:
                current_url, depth = queue.pop()
            
            if current_url in self.visited or depth > self.max_depth:
                continue
            
            if not self._in_scope(current_url, scope):
                continue
            
            try:
                resp = await self.http_client.get(current_url, timeout=10)
                self.visited.add(current_url)
                self.found_urls.add(current_url)
                page_count += 1
                
                # Extract data
                if extract_forms:
                    forms = self._extract_forms_enhanced(resp.text, current_url)
                    self.forms.extend(forms)
                
                inputs = self._extract_inputs_enhanced(resp.text)
                self.inputs.extend(inputs)
                
                if extract_js:
                    js_files = self._extract_js_files_enhanced(resp.text, current_url)
                    self.js_files.extend(js_files)
                
                if extract_api:
                    api_endpoints = self._extract_api_endpoints_enhanced(resp.text, current_url)
                    self.api_endpoints.extend(api_endpoints)
                
                # Extract parameters
                params = self._extract_parameters_enhanced(resp.text, current_url)
                if params:
                    self.parameters[current_url] = params
                
                # Extract links
                if depth < self.max_depth:
                    links = self._extract_links_enhanced(resp.text, current_url)
                    for link in links:
                        if link not in self.visited and self._in_scope(link, scope):
                            if mode.upper() == "BFS":
                                queue.append((link, depth + 1))
                            else:
                                queue.append((link, depth + 1))
                
            except Exception as e:
                self._logger.debug(f"Error crawling {current_url}: {e}")
                continue
        
        return {
            "urls": sorted(list(self.found_urls)),
            "forms": self.forms,
            "inputs": self.inputs,
            "js_files": sorted(list(set(self.js_files))),
            "endpoints": sorted(list(set(self.endpoints))),
            "api_endpoints": sorted(list(set(self.api_endpoints))),
            "parameters": self.parameters,
            "pages_crawled": page_count,
        }
    
    def _in_scope(self, url: str, scope: str) -> bool:
        """Check if URL is in scope"""
        try:
            parsed_url = urlparse(url)
            parsed_scope = urlparse(scope)
            
            if parsed_url.netloc == parsed_scope.netloc:
                return True
            
            if parsed_scope.netloc.startswith("."):
                domain = parsed_scope.netloc[1:]
                if parsed_url.netloc.endswith(domain):
                    return True
            
            return False
        except:
            return False
    
    def _extract_links_enhanced(self, html: str, base_url: str) -> List[str]:
        """Enhanced link extraction"""
        links = set()
        
        # href attributes
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html):
            link = match.group(1)
            absolute_link = urljoin(base_url, link)
            absolute_link = absolute_link.split("#")[0]
            links.add(absolute_link)
        
        # src attributes
        src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in src_pattern.finditer(html):
            link = match.group(1)
            if link.startswith(("http://", "https://", "/")):
                absolute_link = urljoin(base_url, link)
                absolute_link = absolute_link.split("#")[0]
                links.add(absolute_link)
        
        # data attributes
        data_pattern = re.compile(r'data-[^=]*=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in data_pattern.finditer(html):
            link = match.group(1)
            if link.startswith(("http://", "https://", "/")):
                absolute_link = urljoin(base_url, link)
                links.add(absolute_link)
        
        return list(links)
    
    def _extract_forms_enhanced(self, html: str, base_url: str) -> List[Dict]:
        """Enhanced form extraction"""
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
                "inputs": [],
                "enctype": "",
            }
            
            # Extract enctype
            enctype_match = re.search(r'enctype=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            if enctype_match:
                form_data["enctype"] = enctype_match.group(1)
            
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
    
    def _extract_inputs_enhanced(self, html: str) -> List[Dict]:
        """Enhanced input extraction"""
        inputs = []
        input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
        
        for match in input_pattern.finditer(html):
            input_html = match.group(0)
            name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            id_match = re.search(r'id=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            
            if name_match:
                inputs.append({
                    "name": name_match.group(1),
                    "type": type_match.group(1) if type_match else "text",
                    "id": id_match.group(1) if id_match else None
                })
        
        return inputs
    
    def _extract_js_files_enhanced(self, html: str, base_url: str) -> List[str]:
        """Enhanced JavaScript file extraction"""
        js_files = set()
        
        # Script src
        script_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in script_pattern.finditer(html):
            js_url = match.group(1)
            absolute_url = urljoin(base_url, js_url)
            if absolute_url.endswith(".js") or "javascript" in absolute_url.lower():
                js_files.add(absolute_url)
        
        # Inline scripts with URLs
        inline_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
        for match in inline_pattern.finditer(html):
            script_content = match.group(1)
            # Look for URL patterns in JavaScript
            url_pattern = re.compile(r'["\']([^"\']*\.js[^"\']*)["\']')
            for url_match in url_pattern.finditer(script_content):
                js_url = url_match.group(1)
                absolute_url = urljoin(base_url, js_url)
                js_files.add(absolute_url)
        
        return list(js_files)
    
    def _extract_api_endpoints_enhanced(self, html: str, base_url: str) -> List[str]:
        """Enhanced API endpoint extraction"""
        endpoints = set()
        
        # API patterns
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
            r'\.ajax\([^)]*url:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                # Get URL from groups
                for group in match.groups():
                    if group and (group.startswith('/') or group.startswith('http')):
                        absolute_endpoint = urljoin(base_url, group)
                        endpoints.add(absolute_endpoint)
        
        return list(endpoints)
    
    def _extract_parameters_enhanced(self, html: str, base_url: str) -> List[str]:
        """Extract parameters from HTML"""
        parameters = set()
        
        # From forms
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in input_pattern.finditer(html):
            parameters.add(match.group(1))
        
        # From JavaScript
        js_param_patterns = [
            r'["\']([a-z_][a-z0-9_]*)\s*[:=]',
            r'param\[["\']([^"\']+)["\']\]',
            r'params\.([a-z_][a-z0-9_]*)',
        ]
        
        for pattern in js_param_patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                parameters.add(match.group(1))
        
        return list(parameters)

