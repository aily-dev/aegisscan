"""
LDAP Injection Scanner
Tests for LDAP injection vulnerabilities
"""
import re
from typing import List, Optional
from urllib.parse import urlencode
from .base import BaseScanner, Vulnerability, Severity


class LDAPInjectionScanner(BaseScanner):
    """LDAP injection vulnerability scanner"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "LDAP Injection Scanner"
        
        # LDAP injection payloads
        self.ldap_payloads = [
            # Boolean-based
            "*",
            "*)(&",
            "*))%00",
            "*()|&",
            "admin)(&(password=*",
            "admin)(|(password=*",
            # Error-based
            "*)(uid=*",
            "*)(|(uid=*",
            # Time-based (if supported)
            "*)(|(cn=*",
        ]
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Scan for LDAP injection vulnerabilities"""
        vulnerabilities = []
        
        # Extract parameters
        params = self._extract_params(url)
        
        if not params:
            return vulnerabilities
        
        # Test each parameter
        for param_name, param_value in params.items():
            vulns = await self._test_ldap_injection(url, param_name, param_value)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _extract_params(self, url: str) -> dict:
        """Extract parameters from URL"""
        params = {}
        
        if "?" in url:
            query_string = url.split("?")[1].split("#")[0]
            for param in query_string.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    params[key] = value
        
        return params
    
    async def _test_ldap_injection(self, url: str, param_name: str, param_value: str) -> List[Vulnerability]:
        """Test for LDAP injection in a parameter"""
        vulnerabilities = []
        
        for payload in self.ldap_payloads:
            try:
                # Test in GET parameter
                test_params = {param_name: payload}
                test_url = url.split("?")[0] + "?" + urlencode(test_params)
                
                baseline = await self.http_client.get(url, timeout=5)
                test_resp = await self.http_client.get(test_url, timeout=5)
                
                # Check for LDAP injection indicators
                if self._detect_ldap_injection(baseline, test_resp):
                    vuln = self._create_vulnerability(
                        name="LDAP Injection",
                        severity=Severity.HIGH,
                        url=test_url,
                        parameter=param_name,
                        payload=payload,
                        description="LDAP injection vulnerability detected",
                        evidence=f"LDAP injection payload caused response difference: {payload}",
                        recommendation="Use parameterized LDAP queries and input validation. Escape special LDAP characters.",
                        cwe="CWE-90"
                    )
                    vulnerabilities.append(vuln)
                    break
            except:
                continue
        
        return vulnerabilities
    
    def _detect_ldap_injection(self, baseline, test_resp) -> bool:
        """Detect LDAP injection based on response differences"""
        if baseline.status_code != test_resp.status_code:
            return True
        
        # Check for LDAP error messages
        ldap_errors = [
            "ldap",
            "ldap error",
            "invalid dn",
            "invalid filter",
            "syntax error",
            "ldap_simple_bind",
            "ldap_bind",
            "authentication failed",
            "invalid credentials",
        ]
        
        test_lower = test_resp.text.lower()
        if any(error in test_lower for error in ldap_errors):
            return True
        
        # Check for significant length difference
        length_diff = abs(len(baseline.text) - len(test_resp.text))
        if length_diff > 200:
            return True
        
        # Check for authentication bypass
        auth_indicators = [
            "welcome",
            "dashboard",
            "logged in",
            "authentication successful",
        ]
        
        baseline_lower = baseline.text.lower()
        test_lower = test_resp.text.lower()
        
        if any(indicator in test_lower for indicator in auth_indicators):
            if not any(indicator in baseline_lower for indicator in auth_indicators):
                return True
        
        return False

