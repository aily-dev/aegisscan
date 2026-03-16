"""
OAuth/OIDC Security Scanner
Tests for OAuth and OpenID Connect vulnerabilities
"""
import re
from typing import List, Optional, Dict
from urllib.parse import urlparse, parse_qs, urlencode
from .base import BaseScanner, Vulnerability, Severity


class OAuthOIDCScanner(BaseScanner):
    """OAuth and OIDC security scanner"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "OAuth/OIDC Security Scanner"
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Scan for OAuth/OIDC vulnerabilities"""
        vulnerabilities = []
        
        # Discover OAuth endpoints
        oauth_endpoints = await self._discover_oauth_endpoints(url)
        
        if not oauth_endpoints:
            return vulnerabilities
        
        # Test each endpoint
        for endpoint in oauth_endpoints:
            # Test redirect URI validation
            vuln = await self._test_redirect_uri_validation(endpoint)
            if vuln:
                vulnerabilities.append(vuln)
            
            # Test state parameter
            vuln = await self._test_state_parameter(endpoint)
            if vuln:
                vulnerabilities.append(vuln)
            
            # Test PKCE bypass
            vuln = await self._test_pkce_bypass(endpoint)
            if vuln:
                vulnerabilities.append(vuln)
            
            # Test authorization code reuse
            vuln = await self._test_code_reuse(endpoint)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _discover_oauth_endpoints(self, url: str) -> List[str]:
        """Discover OAuth/OIDC endpoints"""
        endpoints = []
        
        try:
            resp = await self.http_client.get(url, timeout=10)
            
            # Look for OAuth endpoints
            oauth_patterns = [
                r'["\']([^"\']*oauth[^"\']*)["\']',
                r'["\']([^"\']*authorize[^"\']*)["\']',
                r'["\']([^"\']*token[^"\']*)["\']',
                r'["\']([^"\']*callback[^"\']*)["\']',
            ]
            
            for pattern in oauth_patterns:
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                for match in matches:
                    if match.startswith('/'):
                        endpoint = url.rstrip('/') + match
                    elif match.startswith('http'):
                        endpoint = match
                    else:
                        endpoint = url.rstrip('/') + '/' + match
                    
                    if endpoint not in endpoints:
                        endpoints.append(endpoint)
            
            # Common OAuth paths
            common_paths = [
                "/oauth/authorize",
                "/oauth/token",
                "/oauth/callback",
                "/authorize",
                "/token",
                "/callback",
            ]
            
            for path in common_paths:
                test_url = url.rstrip('/') + path
                try:
                    test_resp = await self.http_client.get(test_url, timeout=5)
                    if test_resp.status_code in [200, 302, 400]:
                        endpoints.append(test_url)
                except:
                    pass
        except:
            pass
        
        return list(set(endpoints))
    
    async def _test_redirect_uri_validation(self, endpoint: str) -> Optional[Vulnerability]:
        """Test redirect URI validation"""
        try:
            # Test with open redirect
            test_redirects = [
                "http://evil.com",
                "https://evil.com",
                "//evil.com",
                "javascript:alert(1)",
            ]
            
            for redirect_uri in test_redirects:
                params = {
                    "response_type": "code",
                    "client_id": "test",
                    "redirect_uri": redirect_uri,
                    "scope": "openid",
                }
                
                test_url = f"{endpoint}?{urlencode(params)}"
                resp = await self.http_client.get(test_url, timeout=5, allow_redirects=False)
                
                # Check if redirect URI is accepted
                if resp.status_code == 302:
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location or "javascript:" in location:
                        return self._create_vulnerability(
                            name="OAuth Redirect URI Validation Bypass",
                            severity=Severity.HIGH,
                            url=test_url,
                            description="OAuth endpoint accepts arbitrary redirect URIs, allowing open redirect",
                            evidence=f"Redirect URI accepted: {redirect_uri}",
                            recommendation="Implement strict redirect URI validation using whitelist",
                            cwe="CWE-601"
                        )
        except:
            pass
        
        return None
    
    async def _test_state_parameter(self, endpoint: str) -> Optional[Vulnerability]:
        """Test state parameter implementation"""
        try:
            # Test without state parameter
            params = {
                "response_type": "code",
                "client_id": "test",
                "redirect_uri": "http://example.com/callback",
            }
            
            test_url = f"{endpoint}?{urlencode(params)}"
            resp = await self.http_client.get(test_url, timeout=5)
            
            # Check if state parameter is missing
            if resp.status_code in [200, 302]:
                if "state" not in resp.text.lower():
                    return self._create_vulnerability(
                        name="OAuth Missing State Parameter",
                        severity=Severity.MEDIUM,
                        url=test_url,
                        description="OAuth endpoint doesn't require state parameter, vulnerable to CSRF",
                        evidence="Authorization request accepted without state parameter",
                        recommendation="Always require and validate state parameter in OAuth flows",
                        cwe="CWE-352"
                    )
        except:
            pass
        
        return None
    
    async def _test_pkce_bypass(self, endpoint: str) -> Optional[Vulnerability]:
        """Test PKCE (Proof Key for Code Exchange) bypass"""
        try:
            # Test authorization without code_challenge
            params = {
                "response_type": "code",
                "client_id": "test",
                "redirect_uri": "http://example.com/callback",
            }
            
            test_url = f"{endpoint}?{urlencode(params)}"
            resp = await self.http_client.get(test_url, timeout=5)
            
            # Check if PKCE is not required
            if resp.status_code in [200, 302]:
                if "code_challenge" not in resp.text.lower():
                    return self._create_vulnerability(
                        name="OAuth PKCE Not Required",
                        severity=Severity.MEDIUM,
                        url=test_url,
                        description="OAuth endpoint doesn't require PKCE, vulnerable to authorization code interception",
                        evidence="Authorization request accepted without code_challenge",
                        recommendation="Require PKCE for all OAuth authorization code flows",
                        cwe="CWE-284"
                    )
        except:
            pass
        
        return None
    
    async def _test_code_reuse(self, endpoint: str) -> Optional[Vulnerability]:
        """Test authorization code reuse"""
        try:
            # This would require actual OAuth flow testing
            # For now, check if endpoint exists and is accessible
            resp = await self.http_client.get(endpoint, timeout=5)
            
            if resp.status_code in [200, 302, 400]:
                return self._create_vulnerability(
                    name="OAuth Authorization Code Reuse Risk",
                    severity=Severity.INFO,
                    url=endpoint,
                    description="OAuth endpoint detected - manual testing recommended for code reuse vulnerability",
                    evidence="OAuth endpoint is accessible",
                    recommendation="Ensure authorization codes are single-use and expire quickly",
                    cwe="CWE-287"
                )
        except:
            pass
        
        return None

