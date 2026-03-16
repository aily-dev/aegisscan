"""
JWT (JSON Web Token) Security Scanner
"""
import base64
import json
import re
from typing import List, Optional, Dict
from .base import BaseScanner, Vulnerability, Severity


class JWTScanner(BaseScanner):
    """JWT security vulnerability scanner"""
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for JWT vulnerabilities"""
        vulnerabilities = []
        
        # Extract JWT from cookies and headers
        try:
            resp = await self.http_client.get(url, timeout=5)
            
            # Check cookies
            jwt_tokens = self._extract_jwt_from_cookies(resp.cookies)
            jwt_tokens.extend(self._extract_jwt_from_headers(resp.headers))
            
            for token in jwt_tokens:
                # Analyze JWT
                vulns = self._analyze_jwt(token)
                vulnerabilities.extend(vulns)
        except:
            pass
        
        return vulnerabilities
    
    def _extract_jwt_from_cookies(self, cookies: Dict) -> List[str]:
        """Extract JWT tokens from cookies"""
        tokens = []
        jwt_pattern = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
        
        for cookie_name, cookie_value in cookies.items():
            if jwt_pattern.match(cookie_value):
                tokens.append(cookie_value)
            # Also check for JWT in cookie names
            if 'jwt' in cookie_name.lower() or 'token' in cookie_name.lower():
                if jwt_pattern.match(cookie_value):
                    tokens.append(cookie_value)
        
        return tokens
    
    def _extract_jwt_from_headers(self, headers: Dict) -> List[str]:
        """Extract JWT tokens from headers"""
        tokens = []
        jwt_pattern = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
        
        auth_header = headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            if jwt_pattern.match(token):
                tokens.append(token)
        
        return tokens
    
    def _analyze_jwt(self, token: str) -> List[Vulnerability]:
        """Analyze JWT for vulnerabilities"""
        vulnerabilities = []
        
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return vulnerabilities
            
            header_part = parts[0]
            payload_part = parts[1]
            
            # Decode header
            header = self._decode_jwt_part(header_part)
            payload = self._decode_jwt_part(payload_part)
            
            if not header or not payload:
                return vulnerabilities
            
            # Check for "none" algorithm
            if header.get('alg') == 'none':
                vulnerabilities.append(self._create_vulnerability(
                    name="JWT None Algorithm",
                    severity=Severity.HIGH,
                    url="",
                    description="JWT uses 'none' algorithm which allows signature bypass",
                    evidence=f"Header: {header}",
                    recommendation="Never use 'none' algorithm. Always use strong algorithms like RS256.",
                    cwe="CWE-345"
                ))
            
            # Check for weak algorithms
            weak_algorithms = ['HS256', 'HS384', 'HS512']
            if header.get('alg') in weak_algorithms:
                vulnerabilities.append(self._create_vulnerability(
                    name="JWT Weak Algorithm",
                    severity=Severity.MEDIUM,
                    url="",
                    description=f"JWT uses weak algorithm: {header.get('alg')}",
                    evidence=f"Header: {header}",
                    recommendation="Use RS256 or stronger algorithms",
                    cwe="CWE-327"
                ))
            
            # Check for missing expiration
            if 'exp' not in payload:
                vulnerabilities.append(self._create_vulnerability(
                    name="JWT Missing Expiration",
                    severity=Severity.MEDIUM,
                    url="",
                    description="JWT token does not have expiration claim",
                    evidence=f"Payload: {payload}",
                    recommendation="Always include 'exp' claim in JWT tokens",
                    cwe="CWE-613"
                ))
            
            # Check for sensitive data in payload
            sensitive_keys = ['password', 'secret', 'key', 'token', 'api_key']
            for key in sensitive_keys:
                if key in payload:
                    vulnerabilities.append(self._create_vulnerability(
                        name="JWT Sensitive Data Exposure",
                        severity=Severity.HIGH,
                        url="",
                        description=f"Sensitive data found in JWT payload: {key}",
                        evidence=f"Payload contains: {key}",
                        recommendation="Never store sensitive data in JWT payload",
                        cwe="CWE-200"
                    ))
                    break
        
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def _decode_jwt_part(self, part: str) -> Optional[Dict]:
        """Decode JWT part (header or payload)"""
        try:
            # Add padding if needed
            padding = 4 - len(part) % 4
            if padding != 4:
                part += '=' * padding
            
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded)
        except:
            return None

