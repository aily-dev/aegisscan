"""
Passive Reconnaissance Module
"""
import re
from typing import List, Set, Dict
from ..http.client import Response


class PassiveRecon:
    """Passive reconnaissance from HTML/JS sources"""
    
    def __init__(self):
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.url_pattern = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+')
        self.js_endpoint_pattern = re.compile(r'["\']([^"\']*\.js[^"\']*)["\']')
        self.api_endpoint_pattern = re.compile(r'["\'](/api/[^"\']+)["\']')
    
    def extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        emails = set(self.email_pattern.findall(text))
        return sorted(list(emails))
    
    def extract_urls(self, text: str, base_url: str = "") -> List[str]:
        """Extract URLs from text"""
        urls = set()
        
        # Find all URL patterns
        matches = self.url_pattern.findall(text)
        for match in matches:
            # Clean up URL
            url = match.rstrip('.,;:!?)')
            if url.startswith(('http://', 'https://')):
                urls.add(url)
            elif base_url and url.startswith('/'):
                from urllib.parse import urljoin
                urls.add(urljoin(base_url, url))
        
        return sorted(list(urls))
    
    def extract_js_endpoints(self, text: str, base_url: str = "") -> List[str]:
        """Extract JavaScript file endpoints"""
        endpoints = set()
        
        # Find JS file references
        matches = self.js_endpoint_pattern.findall(text)
        for match in matches:
            if match.endswith('.js'):
                if match.startswith('http'):
                    endpoints.add(match)
                elif base_url:
                    from urllib.parse import urljoin
                    endpoints.add(urljoin(base_url, match))
                else:
                    endpoints.add(match)
        
        return sorted(list(endpoints))
    
    def extract_api_endpoints(self, text: str, base_url: str = "") -> List[str]:
        """Extract API endpoints from text"""
        endpoints = set()
        
        # Find API endpoint patterns
        matches = self.api_endpoint_pattern.findall(text)
        for match in matches:
            if base_url:
                from urllib.parse import urljoin
                endpoints.add(urljoin(base_url, match))
            else:
                endpoints.add(match)
        
        # Also look for common API patterns
        api_patterns = [
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if base_url:
                    from urllib.parse import urljoin
                    endpoints.add(urljoin(base_url, match))
                else:
                    endpoints.add(match)
        
        return sorted(list(endpoints))
    
    def analyze_response(self, response: Response) -> Dict:
        """Analyze response and extract all passive recon data"""
        results = {
            "emails": [],
            "urls": [],
            "js_endpoints": [],
            "api_endpoints": [],
            "forms": [],
            "inputs": [],
        }
        
        # Extract from response text
        results["emails"] = self.extract_emails(response.text)
        results["urls"] = self.extract_urls(response.text, response.url)
        results["js_endpoints"] = self.extract_js_endpoints(response.text, response.url)
        results["api_endpoints"] = self.extract_api_endpoints(response.text, response.url)
        
        # Extract forms and inputs
        forms = self._extract_forms(response.text)
        results["forms"] = forms
        
        # Extract all input fields
        input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
        inputs = input_pattern.findall(response.text)
        results["inputs"] = inputs[:50]  # Limit
        
        return results
    
    def _extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        
        for match in form_pattern.finditer(html):
            form_html = match.group(0)
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            forms.append({
                "action": action_match.group(1) if action_match else "",
                "method": (method_match.group(1) if method_match else "GET").upper(),
                "html": form_html[:500]  # Limit size
            })
        
        return forms

