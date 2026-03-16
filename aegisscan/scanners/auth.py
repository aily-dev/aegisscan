"""
Authentication and Session Security Scanner
"""
import re
import base64
import json
from typing import List, Optional, Dict
from .base import BaseScanner, Vulnerability, Severity
from ..http.client import Response


class AuthScanner(BaseScanner):
    """Authentication and session security scanner"""
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for authentication and session vulnerabilities"""
        vulnerabilities = []
        
        try:
            resp = await self.http_client.get(url)
            
            # Check cookie flags
            cookie_issues = self._check_cookie_flags(resp)
            vulnerabilities.extend(cookie_issues)
            
            # Check for session fixation
            session_issues = await self._check_session_fixation(url)
            vulnerabilities.extend(session_issues)
            
            # Check for JWT tokens
            jwt_issues = self._check_jwt_tokens(resp)
            vulnerabilities.extend(jwt_issues)
            
        except:
            pass
        
        return vulnerabilities
    
    def _check_cookie_flags(self, response: Response) -> List[Vulnerability]:
        """Check cookie security flags"""
        issues = []
        
        set_cookie_headers = response.headers.get("Set-Cookie", "")
        if isinstance(set_cookie_headers, str):
            set_cookie_headers = [set_cookie_headers]
        
        for cookie_header in set_cookie_headers:
            cookie_lower = cookie_header.lower()
            
            # Check for HttpOnly flag
            if "httponly" not in cookie_lower:
                issues.append(self._create_vulnerability(
                    name="Missing HttpOnly Cookie Flag",
                    severity=Severity.MEDIUM,
                    url=response.url,
                    parameter=None,
                    payload=None,
                    description="Cookie missing HttpOnly flag",
                    evidence=f"Cookie: {cookie_header[:100]}",
                    recommendation="Set HttpOnly flag on all cookies to prevent XSS attacks from accessing them.",
                    cwe="CWE-1004"
                ))
            
            # Check for Secure flag (only if HTTPS)
            if response.url.startswith("https://") and "secure" not in cookie_lower:
                issues.append(self._create_vulnerability(
                    name="Missing Secure Cookie Flag",
                    severity=Severity.HIGH,
                    url=response.url,
                    parameter=None,
                    payload=None,
                    description="Cookie missing Secure flag on HTTPS site",
                    evidence=f"Cookie: {cookie_header[:100]}",
                    recommendation="Set Secure flag on cookies when using HTTPS to prevent transmission over unencrypted connections.",
                    cwe="CWE-614"
                ))
            
            # Check for SameSite attribute
            if "samesite" not in cookie_lower:
                issues.append(self._create_vulnerability(
                    name="Missing SameSite Cookie Attribute",
                    severity=Severity.MEDIUM,
                    url=response.url,
                    parameter=None,
                    payload=None,
                    description="Cookie missing SameSite attribute",
                    evidence=f"Cookie: {cookie_header[:100]}",
                    recommendation="Set SameSite=Strict or SameSite=Lax to prevent CSRF attacks.",
                    cwe="CWE-352"
                ))
        
        return issues
    
    async def _check_session_fixation(self, url: str) -> List[Vulnerability]:
        """Check for session fixation vulnerabilities"""
        issues = []
        
        try:
            # Make initial request
            resp1 = await self.http_client.get(url)
            cookies1 = resp1.cookies
            
            # Make another request (simulating login)
            resp2 = await self.http_client.get(url)
            cookies2 = resp2.cookies
            
            # Check if session ID changed
            session_cookies1 = {k: v for k, v in cookies1.items() if any(keyword in k.lower() for keyword in ["session", "sid", "jsessionid", "phpsessid"])}
            session_cookies2 = {k: v for k, v in cookies2.items() if any(keyword in k.lower() for keyword in ["session", "sid", "jsessionid", "phpsessid"])}
            
            # If session IDs are the same, might indicate session fixation
            for cookie_name in session_cookies1:
                if cookie_name in session_cookies2:
                    if session_cookies1[cookie_name] == session_cookies2[cookie_name]:
                        issues.append(self._create_vulnerability(
                            name="Potential Session Fixation",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=None,
                            payload=None,
                            description="Session ID may not be regenerated after authentication",
                            evidence=f"Session cookie {cookie_name} unchanged",
                            recommendation="Regenerate session ID after login. Invalidate old session tokens.",
                            cwe="CWE-384"
                        ))
        except:
            pass
        
        return issues
    
    def _check_jwt_tokens(self, response: Response) -> List[Vulnerability]:
        """Check JWT tokens for vulnerabilities"""
        issues = []
        
        # Check cookies for JWT
        for cookie_name, cookie_value in response.cookies.items():
            if self._is_jwt(cookie_value):
                jwt_issues = self._analyze_jwt(cookie_value, cookie_name, response.url)
                issues.extend(jwt_issues)
        
        # Check Authorization header (if we can access it)
        auth_header = response.request_headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if self._is_jwt(token):
                jwt_issues = self._analyze_jwt(token, "Authorization", response.url)
                issues.extend(jwt_issues)
        
        return issues
    
    def _is_jwt(self, token: str) -> bool:
        """Check if string is a JWT token"""
        try:
            parts = token.split(".")
            if len(parts) == 3:
                # Try to decode header
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                if "alg" in header:
                    return True
        except:
            pass
        return False
    
    def _analyze_jwt(self, token: str, location: str, url: str) -> List[Vulnerability]:
        """Analyze JWT for vulnerabilities"""
        issues = []
        
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return issues
            
            # Decode header
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            
            # Check for "none" algorithm
            alg = header.get("alg", "")
            if alg.lower() == "none":
                issues.append(self._create_vulnerability(
                    name="JWT 'none' Algorithm",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=location,
                    payload=None,
                    description="JWT uses 'none' algorithm which allows unsigned tokens",
                    evidence=f"Algorithm: {alg}",
                    recommendation="Reject JWT tokens with 'none' algorithm. Use strong algorithms like HS256 or RS256.",
                    cwe="CWE-345"
                ))
            
            # Check for missing algorithm
            if not alg:
                issues.append(self._create_vulnerability(
                    name="JWT Missing Algorithm",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=location,
                    payload=None,
                    description="JWT header missing algorithm specification",
                    evidence="No 'alg' field in JWT header",
                    recommendation="Always specify algorithm in JWT header. Validate algorithm on server side.",
                    cwe="CWE-345"
                ))
            
            # Decode payload (if possible)
            try:
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                
                # Check for weak secret/key indicators
                if "secret" in str(payload).lower() or "key" in str(payload).lower():
                    # This is just a heuristic
                    pass
            except:
                pass
            
        except Exception as e:
            pass
        
        return issues

