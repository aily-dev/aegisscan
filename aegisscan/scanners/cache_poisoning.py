"""
Web Cache Poisoning Scanner
Tests for cache poisoning vulnerabilities
"""
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity


class CachePoisoningScanner(BaseScanner):
    """Web cache poisoning vulnerability scanner"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "Web Cache Poisoning Scanner"
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Scan for cache poisoning vulnerabilities"""
        vulnerabilities = []
        
        # Test unkeyed header poisoning
        vuln = await self._test_unkeyed_headers(url)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test cache key confusion
        vuln = await self._test_cache_key_confusion(url)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test HTTP header injection
        vuln = await self._test_header_injection(url)
        if vuln:
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_unkeyed_headers(self, url: str) -> Optional[Vulnerability]:
        """Test for unkeyed header cache poisoning"""
        try:
            # Test with X-Forwarded-Host header
            headers = {
                "X-Forwarded-Host": "evil.com",
            }
            
            resp = await self.http_client.get(url, headers=headers, timeout=10)
            
            # Check if header value is reflected
            if "evil.com" in resp.text or "evil.com" in str(resp.headers):
                return self._create_vulnerability(
                    name="Cache Poisoning (Unkeyed Header)",
                    severity=Severity.HIGH,
                    url=url,
                    description="Unkeyed header reflected in response, allowing cache poisoning",
                    evidence="X-Forwarded-Host header value reflected in response",
                    recommendation="Ensure all cache keys include user-controlled headers, or remove unkeyed headers from responses",
                    cwe="CWE-444"
                )
        except:
            pass
        
        return None
    
    async def _test_cache_key_confusion(self, url: str) -> Optional[Vulnerability]:
        """Test for cache key confusion"""
        try:
            # Test with different query parameter orders
            url1 = f"{url}?a=1&b=2"
            url2 = f"{url}?b=2&a=1"
            
            resp1 = await self.http_client.get(url1, timeout=10)
            resp2 = await self.http_client.get(url2, timeout=10)
            
            # Check if responses are different but cached the same
            if resp1.text != resp2.text:
                # Check cache headers
                cache1 = resp1.headers.get("Cache-Control", "")
                cache2 = resp2.headers.get("Cache-Control", "")
                
                if "public" in cache1.lower() or "public" in cache2.lower():
                    return self._create_vulnerability(
                        name="Cache Key Confusion",
                        severity=Severity.MEDIUM,
                        url=url,
                        description="Cache key confusion detected - different query parameter orders may be cached incorrectly",
                        evidence="Different query parameter orders produce different responses but may share cache key",
                        recommendation="Normalize query parameters before generating cache keys",
                        cwe="CWE-444"
                    )
        except:
            pass
        
        return None
    
    async def _test_header_injection(self, url: str) -> Optional[Vulnerability]:
        """Test for HTTP header injection in cache"""
        try:
            # Test with X-Forwarded-For header
            headers = {
                "X-Forwarded-For": "127.0.0.1\r\nX-Injected: test",
            }
            
            resp = await self.http_client.get(url, headers=headers, timeout=10)
            
            # Check if header injection occurred
            if "X-Injected" in str(resp.headers) or "X-Injected" in resp.text:
                return self._create_vulnerability(
                    name="Cache Poisoning (Header Injection)",
                    severity=Severity.HIGH,
                    url=url,
                    description="HTTP header injection detected, allowing cache poisoning",
                    evidence="Injected header appears in response",
                    recommendation="Sanitize all header values and prevent header injection",
                    cwe="CWE-113"
                )
        except:
            pass
        
        return None

