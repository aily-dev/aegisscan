"""
Clickjacking Detection Scanner
Tests for clickjacking/X-Frame-Options vulnerabilities
"""
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity


class ClickjackingScanner(BaseScanner):
    """Clickjacking vulnerability scanner"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "Clickjacking Scanner"
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Scan for clickjacking vulnerabilities"""
        vulnerabilities = []
        
        # Test X-Frame-Options header
        vuln = await self._test_x_frame_options(url)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test Content-Security-Policy frame-ancestors
        vuln = await self._test_csp_frame_ancestors(url)
        if vuln:
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_x_frame_options(self, url: str) -> Optional[Vulnerability]:
        """Test X-Frame-Options header"""
        try:
            resp = await self.http_client.get(url, timeout=10)
            
            x_frame_options = resp.headers.get("X-Frame-Options", "").lower()
            
            if not x_frame_options:
                return self._create_vulnerability(
                    name="Clickjacking: Missing X-Frame-Options",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="X-Frame-Options header is missing, allowing page to be embedded in iframes",
                    evidence="X-Frame-Options header not present in response",
                    recommendation="Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN header",
                    cwe="CWE-1021"
                )
            elif x_frame_options not in ["deny", "sameorigin"]:
                return self._create_vulnerability(
                    name="Clickjacking: Invalid X-Frame-Options",
                    severity=Severity.MEDIUM,
                    url=url,
                    description=f"X-Frame-Options header has invalid value: {x_frame_options}",
                    evidence=f"X-Frame-Options: {x_frame_options}",
                    recommendation="Set X-Frame-Options to DENY or SAMEORIGIN",
                    cwe="CWE-1021"
                )
        except:
            pass
        
        return None
    
    async def _test_csp_frame_ancestors(self, url: str) -> Optional[Vulnerability]:
        """Test Content-Security-Policy frame-ancestors directive"""
        try:
            resp = await self.http_client.get(url, timeout=10)
            
            csp = resp.headers.get("Content-Security-Policy", "")
            
            if not csp:
                # Check if X-Frame-Options is also missing
                x_frame = resp.headers.get("X-Frame-Options", "")
                if not x_frame:
                    return self._create_vulnerability(
                        name="Clickjacking: Missing Frame Protection",
                        severity=Severity.MEDIUM,
                        url=url,
                        description="Neither X-Frame-Options nor CSP frame-ancestors is set",
                        evidence="No frame protection headers found",
                        recommendation="Add Content-Security-Policy: frame-ancestors 'none' or X-Frame-Options: DENY",
                        cwe="CWE-1021"
                    )
            elif "frame-ancestors" not in csp.lower():
                return self._create_vulnerability(
                    name="Clickjacking: Missing CSP frame-ancestors",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="Content-Security-Policy header exists but frame-ancestors directive is missing",
                    evidence=f"CSP header present but no frame-ancestors: {csp[:100]}",
                    recommendation="Add frame-ancestors 'none' to Content-Security-Policy header",
                    cwe="CWE-1021"
                )
        except:
            pass
        
        return None

