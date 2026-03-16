"""
API Security Scanner
"""
import re
from typing import List, Optional, Dict
from .base import BaseScanner, Vulnerability, Severity


class APISecurityScanner(BaseScanner):
    """API security vulnerability scanner"""
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for API security vulnerabilities"""
        vulnerabilities = []
        
        # Check if URL is an API endpoint
        if not self._is_api_endpoint(url):
            return vulnerabilities
        
        # Test for various API vulnerabilities
        vulns = await self._test_rate_limiting(url, method)
        vulnerabilities.extend(vulns)
        
        vulns = await self._test_authentication_bypass(url, method)
        vulnerabilities.extend(vulns)
        
        vulns = await self._test_authorization_bypass(url, method)
        vulnerabilities.extend(vulns)
        
        vulns = await self._test_version_disclosure(url)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _is_api_endpoint(self, url: str) -> bool:
        """Check if URL is an API endpoint"""
        api_patterns = [
            r'/api/',
            r'/v\d+/',
            r'/rest/',
            r'/graphql',
            r'/rpc',
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    async def _test_rate_limiting(self, url: str, method: str) -> List[Vulnerability]:
        """Test for rate limiting"""
        vulnerabilities = []
        
        try:
            # Send multiple rapid requests
            import asyncio
            tasks = []
            for i in range(100):
                if method.upper() == "GET":
                    tasks.append(self.http_client.get(url, timeout=5))
                else:
                    tasks.append(self.http_client.post(url, data={}, timeout=5))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Check if all requests succeeded (no rate limiting)
            if responses:
                first_resp = next((r for r in responses if not isinstance(r, Exception)), None)
                if first_resp:
                    success_count = sum(1 for r in responses if not isinstance(r, Exception) and hasattr(r, 'status_code') and r.status_code == 200)
                    
                    if success_count >= 90:  # 90%+ success rate
                        vulnerabilities.append(self._create_vulnerability(
                    name="Missing Rate Limiting",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="API endpoint does not implement rate limiting",
                    evidence=f"{success_count}/100 requests succeeded without rate limiting",
                            recommendation="Implement rate limiting to prevent abuse",
                            cwe="CWE-770"
                        ))
        except:
            pass
        
        return vulnerabilities
    
    async def _test_authentication_bypass(self, url: str, method: str) -> List[Vulnerability]:
        """Test for authentication bypass"""
        vulnerabilities = []
        
        try:
            # Try accessing without authentication
            if method.upper() == "GET":
                resp = await self.http_client.get(url, timeout=5)
            else:
                resp = await self.http_client.post(url, data={}, timeout=5)
            
            # If we get 200 without auth, might be vulnerable
            if resp.status_code == 200:
                # Check if response contains sensitive data
                sensitive_indicators = ['user', 'email', 'id', 'token', 'api_key']
                if any(indicator in resp.text.lower() for indicator in sensitive_indicators):
                    vulnerabilities.append(self._create_vulnerability(
                        name="API Authentication Bypass",
                        severity=Severity.HIGH,
                        url=url,
                        description="API endpoint accessible without authentication",
                        evidence="Endpoint returned 200 without authentication",
                        recommendation="Implement proper authentication for all API endpoints",
                        cwe="CWE-306"
                    ))
        except:
            pass
        
        return vulnerabilities
    
    async def _test_authorization_bypass(self, url: str, method: str) -> List[Vulnerability]:
        """Test for authorization bypass"""
        vulnerabilities = []
        
        # This would require authenticated requests with different user contexts
        # For now, just check for IDOR patterns in URL
        idor_patterns = [
            r'/users/\d+',
            r'/user/\d+',
            r'/account/\d+',
            r'/id/\d+',
        ]
        
        for pattern in idor_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    name="Potential IDOR in API",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="API endpoint uses direct object references",
                    evidence=f"URL pattern: {pattern}",
                    recommendation="Implement proper authorization checks. Use indirect object references.",
                    cwe="CWE-639"
                ))
                break
        
        return vulnerabilities
    
    async def _test_version_disclosure(self, url: str) -> List[Vulnerability]:
        """Test for API version disclosure"""
        vulnerabilities = []
        
        try:
            resp = await self.http_client.get(url, timeout=5)
            
            # Check headers for version
            version_headers = ['X-API-Version', 'API-Version', 'Version']
            for header in version_headers:
                if header in resp.headers:
                    vulnerabilities.append(self._create_vulnerability(
                        name="API Version Disclosure",
                        severity=Severity.INFO,
                        url=url,
                        description=f"API version disclosed in {header} header",
                        evidence=f"{header}: {resp.headers[header]}",
                        recommendation="Avoid disclosing API version information",
                        cwe="CWE-200"
                    ))
                    break
            
            # Check response body
            if 'version' in resp.text.lower() or 'api-version' in resp.text.lower():
                vulnerabilities.append(self._create_vulnerability(
                    name="API Version Disclosure",
                    severity=Severity.INFO,
                    url=url,
                    description="API version information found in response",
                    evidence="Version information in response body",
                    recommendation="Avoid disclosing API version information",
                    cwe="CWE-200"
                ))
        except:
            pass
        
        return vulnerabilities

