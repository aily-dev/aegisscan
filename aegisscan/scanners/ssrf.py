"""
SSRF (Server-Side Request Forgery) Scanner
"""
import re
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity


class SSRFScanner(BaseScanner):
    """SSRF vulnerability scanner"""
    
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/",
        "file:///etc/passwd",
        "file:///etc/hosts",
        "gopher://127.0.0.1:80",
        "dict://127.0.0.1:80",
        "ldap://127.0.0.1:80",
    ]
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for SSRF vulnerabilities"""
        vulnerabilities = []
        
        test_params = params or {}
        if not test_params:
            if "?" in url:
                query_string = url.split("?")[1]
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        test_params[key] = value
        
        for param_name, param_value in test_params.items():
            # Check if parameter name suggests URL
            if any(keyword in param_name.lower() for keyword in ["url", "link", "path", "file", "src", "dest", "redirect"]):
                for payload in self.SSRF_PAYLOADS[:10]:  # Limit
                    try:
                        test_params_dict = {param_name: payload}
                        
                        if method.upper() == "GET":
                            resp = await self.http_client.get(url, params=test_params_dict, timeout=10)
                        else:
                            resp = await self.http_client.post(url, data=test_params_dict, timeout=10)
                        
                        # Check for SSRF indicators
                        if self._check_ssrf_response(resp, payload):
                            return self._create_vulnerability(
                                name="Server-Side Request Forgery (SSRF)",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                description="SSRF vulnerability detected",
                                evidence="Response indicates server-side request was made",
                                recommendation="Validate and whitelist URLs. Use allowlists for internal resources.",
                                cwe="CWE-918"
                            )
                    except:
                        continue
        
        return vulnerabilities
    
    def _check_ssrf_response(self, response, payload: str) -> bool:
        """Check if response indicates SSRF"""
        # Check for internal IP content
        if "127.0.0.1" in payload or "localhost" in payload:
            # Look for localhost indicators in response
            localhost_indicators = [
                "localhost", "127.0.0.1", "::1",
                "internal", "private", "local",
            ]
            
            response_lower = response.text.lower()
            if any(indicator in response_lower for indicator in localhost_indicators):
                return True
        
        # Check for AWS metadata
        if "169.254.169.254" in payload:
            aws_indicators = [
                "instance-id", "ami-id", "instance-type",
                "availability-zone", "public-keys",
            ]
            
            response_lower = response.text.lower()
            if any(indicator in response_lower for indicator in aws_indicators):
                return True
        
        # Check for file:// protocol
        if "file://" in payload:
            file_indicators = [
                "root:x:", "daemon:x:", "[boot loader]",
                "for 16-bit app support",
            ]
            
            if any(indicator in response.text for indicator in file_indicators):
                return True
        
        return False

