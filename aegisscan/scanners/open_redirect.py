"""
Open Redirect Scanner
"""
import re
from typing import List, Optional
from urllib.parse import urlparse, parse_qs
from .base import BaseScanner, Vulnerability, Severity


class OpenRedirectScanner(BaseScanner):
    """Open redirect vulnerability scanner"""
    
    # Redirect payloads
    REDIRECT_PAYLOADS = [
        "http://evil.com",
        "https://evil.com",
        "//evil.com",
        "///evil.com",
        "http://evil.com/",
        "https://evil.com/",
        "http://evil.com:80",
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "//evil.com@example.com",
        "http://evil.com@example.com",
        "http://example.com@evil.com",
    ]
    
    # Encoded redirect payloads
    ENCODED_PAYLOADS = [
        "%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",  # http://evil.com
        "%2f%2f%65%76%69%6c%2e%63%6f%6d",  # //evil.com
        "%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",  # https://evil.com
    ]
    
    # Common redirect parameter names
    REDIRECT_PARAMS = [
        "redirect",
        "redirect_to",
        "redirect_url",
        "url",
        "next",
        "next_url",
        "return",
        "return_to",
        "return_url",
        "goto",
        "target",
        "destination",
        "continue",
        "r",
        "u",
        "link",
        "href",
        "callback",
        "callback_url",
    ]
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for open redirect vulnerabilities"""
        vulnerabilities = []
        
        # Extract redirect parameters
        redirect_params = self._find_redirect_params(url, params)
        
        if not redirect_params:
            # Try common parameter names
            test_params = params or {}
            if not test_params:
                if "?" in url:
                    query_string = url.split("?")[1]
                    for param in query_string.split("&"):
                        if "=" in param:
                            key, value = param.split("=", 1)
                            test_params[key] = value
            
            # Test common redirect parameter names
            for param_name in self.REDIRECT_PARAMS:
                if param_name in test_params or param_name.lower() in [k.lower() for k in test_params.keys()]:
                    redirect_params.append(param_name)
        
        # Test each redirect parameter
        all_payloads = self.REDIRECT_PAYLOADS + self.ENCODED_PAYLOADS
        
        for param_name in redirect_params:
            for payload in all_payloads[:10]:  # Limit for performance
                try:
                    test_params = {param_name: payload}
                    
                    if method.upper() == "GET":
                        resp = await self.http_client.get(url, params=test_params, allow_redirects=False)
                    else:
                        resp = await self.http_client.post(url, data=test_params, allow_redirects=False)
                    
                    # Check for redirect
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get("Location", "")
                        
                        # Check if redirect goes to external domain
                        if self._is_external_redirect(location, url, payload):
                            return self._create_vulnerability(
                                name="Open Redirect",
                                severity=Severity.MEDIUM,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                description="Open redirect vulnerability detected",
                                evidence=f"Redirects to external domain: {location}",
                                recommendation="Validate redirect URLs. Whitelist allowed domains. Use relative URLs or domain validation.",
                                cwe="CWE-601"
                            )
                except:
                    continue
        
        return vulnerabilities
    
    def _find_redirect_params(self, url: str, params: Optional[dict]) -> List[str]:
        """Find parameters that might be used for redirects"""
        redirect_params = []
        
        # Check URL parameters
        if "?" in url:
            query_string = url.split("?")[1]
            parsed_params = parse_qs(query_string)
            for param_name in parsed_params.keys():
                if any(keyword in param_name.lower() for keyword in ["redirect", "url", "next", "return", "goto", "target"]):
                    redirect_params.append(param_name)
        
        # Check provided params
        if params:
            for param_name in params.keys():
                if any(keyword in param_name.lower() for keyword in ["redirect", "url", "next", "return", "goto", "target"]):
                    redirect_params.append(param_name)
        
        return redirect_params
    
    def _is_external_redirect(self, location: str, original_url: str, payload: str) -> bool:
        """Check if redirect is to external domain"""
        if not location:
            return False
        
        try:
            # Parse original URL
            original_parsed = urlparse(original_url)
            original_domain = original_parsed.netloc.lower()
            
            # Parse redirect location
            if location.startswith("//"):
                location = f"{original_parsed.scheme}:{location}"
            elif location.startswith("/"):
                # Relative URL, not external
                return False
            elif not location.startswith(("http://", "https://")):
                # Might be protocol-relative or other format
                if "://" not in location:
                    return False
            
            redirect_parsed = urlparse(location)
            redirect_domain = redirect_parsed.netloc.lower()
            
            # Remove port for comparison
            original_domain = original_domain.split(":")[0]
            redirect_domain = redirect_domain.split(":")[0]
            
            # Check if domains are different
            if redirect_domain != original_domain:
                # Check if it matches our payload
                if "evil.com" in redirect_domain or payload in location:
                    return True
            
            return False
        except:
            return False

