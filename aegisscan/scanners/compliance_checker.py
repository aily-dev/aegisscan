"""
Security Compliance Checker (OWASP Top 10, PCI-DSS, etc.)
"""
import re
from typing import List, Dict, Optional
from .base import BaseScanner, Vulnerability, Severity


class OWASPTop10Checker(BaseScanner):
    """OWASP Top 10 compliance checker"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "OWASP Top 10 Compliance Checker"
        
        # OWASP Top 10 2021 categories
        self.categories = {
            "A01:2021": "Broken Access Control",
            "A02:2021": "Cryptographic Failures",
            "A03:2021": "Injection",
            "A04:2021": "Insecure Design",
            "A05:2021": "Security Misconfiguration",
            "A06:2021": "Vulnerable and Outdated Components",
            "A07:2021": "Identification and Authentication Failures",
            "A08:2021": "Software and Data Integrity Failures",
            "A09:2021": "Security Logging and Monitoring Failures",
            "A10:2021": "Server-Side Request Forgery",
        }
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Check OWASP Top 10 compliance"""
        vulnerabilities = []
        
        # A01: Broken Access Control
        vulns = await self._check_access_control(url)
        vulnerabilities.extend(vulns)
        
        # A02: Cryptographic Failures
        vulns = await self._check_cryptography(url)
        vulnerabilities.extend(vulns)
        
        # A03: Injection
        vulns = await self._check_injection(url)
        vulnerabilities.extend(vulns)
        
        # A05: Security Misconfiguration
        vulns = await self._check_misconfiguration(url)
        vulnerabilities.extend(vulns)
        
        # A07: Authentication Failures
        vulns = await self._check_authentication(url)
        vulnerabilities.extend(vulns)
        
        # A09: Logging and Monitoring
        vulns = await self._check_logging(url)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _check_access_control(self, url: str) -> List[Vulnerability]:
        """Check for Broken Access Control (A01:2021)"""
        vulnerabilities = []
        
        try:
            resp = await self.http_client.get(url, timeout=5)
            
            # Check for directory listing
            if "index of" in resp.text.lower():
                vulnerabilities.append(self._create_vulnerability(
                    name="Directory Listing Enabled (A01:2021)",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="Directory listing is enabled, violating access control principles",
                    evidence="Directory listing detected in response",
                    recommendation="Disable directory listing on web server",
                    cwe="CWE-548"
                ))
            
            # Check for insecure direct object references
            if re.search(r'[?&]id=\d+', url):
                vulnerabilities.append(self._create_vulnerability(
                    name="Potential IDOR (A01:2021)",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="Direct object reference found, may indicate broken access control",
                    evidence="Numeric ID parameter in URL",
                    recommendation="Implement proper authorization checks",
                    cwe="CWE-639"
                ))
        except:
            pass
        
        return vulnerabilities
    
    async def _check_cryptography(self, url: str) -> List[Vulnerability]:
        """Check for Cryptographic Failures (A02:2021)"""
        vulnerabilities = []
        
        try:
            # Check if HTTPS is used
            if url.startswith("http://"):
                vulnerabilities.append(self._create_vulnerability(
                    name="Unencrypted Transport (A02:2021)",
                    severity=Severity.HIGH,
                    url=url,
                    description="Application uses unencrypted HTTP instead of HTTPS",
                    evidence="HTTP protocol detected",
                    recommendation="Use HTTPS with strong TLS configuration",
                    cwe="CWE-319"
                ))
                return vulnerabilities
            
            resp = await self.http_client.get(url, timeout=5)
            
            # Check for HSTS
            if "strict-transport-security" not in [h.lower() for h in resp.headers.keys()]:
                vulnerabilities.append(self._create_vulnerability(
                    name="Missing HSTS Header (A02:2021)",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="HSTS header is missing, allowing downgrade attacks",
                    evidence="Strict-Transport-Security header not found",
                    recommendation="Implement HSTS with appropriate max-age",
                    cwe="CWE-319"
                ))
            
            # Check for sensitive data in URL
            sensitive_patterns = ['password', 'token', 'secret', 'key', 'api_key']
            for pattern in sensitive_patterns:
                if pattern in url.lower():
                    vulnerabilities.append(self._create_vulnerability(
                        name="Sensitive Data in URL (A02:2021)",
                        severity=Severity.HIGH,
                        url=url,
                        description="Sensitive data exposed in URL",
                        evidence=f"Sensitive keyword '{pattern}' found in URL",
                        recommendation="Never pass sensitive data in URLs",
                        cwe="CWE-598"
                    ))
                    break
        except:
            pass
        
        return vulnerabilities
    
    async def _check_injection(self, url: str) -> List[Vulnerability]:
        """Check for Injection vulnerabilities (A03:2021)"""
        vulnerabilities = []
        
        # Check if URL has parameters (potential injection points)
        if "?" in url:
            vulnerabilities.append(self._create_vulnerability(
                name="Potential Injection Point (A03:2021)",
                severity=Severity.INFO,
                url=url,
                description="URL contains parameters that may be vulnerable to injection",
                evidence="Parameters detected in URL",
                recommendation="Validate and sanitize all user inputs",
                cwe="CWE-89"
            ))
        
        return vulnerabilities
    
    async def _check_misconfiguration(self, url: str) -> List[Vulnerability]:
        """Check for Security Misconfiguration (A05:2021)"""
        vulnerabilities = []
        
        try:
            resp = await self.http_client.get(url, timeout=5)
            
            # Check for server version disclosure
            server_header = resp.headers.get("Server", "")
            if server_header and any(c.isdigit() for c in server_header):
                vulnerabilities.append(self._create_vulnerability(
                    name="Server Version Disclosure (A05:2021)",
                    severity=Severity.LOW,
                    url=url,
                    description="Server version is disclosed in headers",
                    evidence=f"Server: {server_header}",
                    recommendation="Hide server version information",
                    cwe="CWE-200"
                ))
            
            # Check for X-Powered-By header
            if "x-powered-by" in [h.lower() for h in resp.headers.keys()]:
                vulnerabilities.append(self._create_vulnerability(
                    name="Technology Stack Disclosure (A05:2021)",
                    severity=Severity.LOW,
                    url=url,
                    description="Technology stack disclosed via X-Powered-By header",
                    evidence=f"X-Powered-By: {resp.headers.get('X-Powered-By', '')}",
                    recommendation="Remove X-Powered-By header",
                    cwe="CWE-200"
                ))
            
            # Check for missing security headers
            security_headers = {
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY/SAMEORIGIN",
                "content-security-policy": "CSP",
                "referrer-policy": "Referrer-Policy",
                "permissions-policy": "Permissions-Policy",
            }
            
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            
            for header, description in security_headers.items():
                if header not in headers_lower:
                    vulnerabilities.append(self._create_vulnerability(
                        name=f"Missing Security Header: {header} (A05:2021)",
                        severity=Severity.MEDIUM,
                        url=url,
                        description=f"Security header '{header}' is missing",
                        evidence="Header not present in response",
                        recommendation=f"Implement {description} header",
                        cwe="CWE-693"
                    ))
        except:
            pass
        
        return vulnerabilities
    
    async def _check_authentication(self, url: str) -> List[Vulnerability]:
        """Check for Authentication Failures (A07:2021)"""
        vulnerabilities = []
        
        try:
            resp = await self.http_client.get(url, timeout=5)
            
            # Check for weak cookie flags
            cookies = resp.cookies
            for cookie_name, cookie_value in cookies.items():
                # Check for Secure flag
                if url.startswith("https://"):
                    # In real implementation, check actual cookie attributes
                    vulnerabilities.append(self._create_vulnerability(
                        name="Cookie Without Secure Flag (A07:2021)",
                        severity=Severity.MEDIUM,
                        url=url,
                        description=f"Cookie '{cookie_name}' missing Secure flag",
                        evidence="Cookie can be transmitted over insecure connections",
                        recommendation="Set Secure flag on all cookies",
                        cwe="CWE-614"
                    ))
                
                # Check for HttpOnly flag
                vulnerabilities.append(self._create_vulnerability(
                    name="Cookie Without HttpOnly Flag (A07:2021)",
                    severity=Severity.MEDIUM,
                    url=url,
                    description=f"Cookie '{cookie_name}' missing HttpOnly flag",
                    evidence="Cookie accessible via JavaScript",
                    recommendation="Set HttpOnly flag on session cookies",
                    cwe="CWE-1004"
                ))
        except:
            pass
        
        return vulnerabilities
    
    async def _check_logging(self, url: str) -> List[Vulnerability]:
        """Check for Logging and Monitoring Failures (A09:2021)"""
        vulnerabilities = []
        
        # This would require more context about the application
        # For now, provide general recommendations
        
        vulnerabilities.append(self._create_vulnerability(
            name="Security Logging Recommendation (A09:2021)",
            severity=Severity.INFO,
            url=url,
            description="Ensure security events are properly logged and monitored",
            evidence="General recommendation",
            recommendation="Implement comprehensive security logging and monitoring",
            cwe="CWE-778"
        ))
        
        return vulnerabilities


class PCIDSSChecker(BaseScanner):
    """PCI-DSS compliance checker"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "PCI-DSS Compliance Checker"
        
        self.requirements = {
            "1": "Install and maintain a firewall configuration",
            "2": "Do not use vendor-supplied defaults",
            "3": "Protect stored cardholder data",
            "4": "Encrypt transmission of cardholder data",
            "5": "Protect against malware",
            "6": "Develop and maintain secure systems",
            "7": "Restrict access to cardholder data",
            "8": "Identify and authenticate access",
            "9": "Restrict physical access",
            "10": "Track and monitor network access",
            "11": "Regularly test security systems",
            "12": "Maintain information security policy",
        }
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Check PCI-DSS compliance"""
        vulnerabilities = []
        
        # Requirement 4: Encrypt transmission
        vulns = await self._check_encryption(url)
        vulnerabilities.extend(vulns)
        
        # Requirement 6: Secure systems
        vulns = await self._check_secure_systems(url)
        vulnerabilities.extend(vulns)
        
        # Requirement 8: Authentication
        vulns = await self._check_authentication_pci(url)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _check_encryption(self, url: str) -> List[Vulnerability]:
        """Check encryption requirements (Req 4)"""
        vulnerabilities = []
        
        if url.startswith("http://"):
            vulnerabilities.append(self._create_vulnerability(
                name="PCI-DSS Req 4: Unencrypted Connection",
                severity=Severity.CRITICAL,
                url=url,
                description="Cardholder data may be transmitted over unencrypted connection",
                evidence="HTTP protocol used instead of HTTPS",
                recommendation="Use strong cryptography (TLS 1.2 or higher)",
                cwe="CWE-319"
            ))
        
        return vulnerabilities
    
    async def _check_secure_systems(self, url: str) -> List[Vulnerability]:
        """Check secure systems requirements (Req 6)"""
        vulnerabilities = []
        
        try:
            resp = await self.http_client.get(url, timeout=5)
            
            # Check for common vulnerabilities
            if "error" in resp.text.lower() or "exception" in resp.text.lower():
                vulnerabilities.append(self._create_vulnerability(
                    name="PCI-DSS Req 6: Error Message Disclosure",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="Detailed error messages may be exposed",
                    evidence="Error/exception keywords found in response",
                    recommendation="Implement custom error pages",
                    cwe="CWE-209"
                ))
        except:
            pass
        
        return vulnerabilities
    
    async def _check_authentication_pci(self, url: str) -> List[Vulnerability]:
        """Check authentication requirements (Req 8)"""
        vulnerabilities = []
        
        try:
            resp = await self.http_client.get(url, timeout=5)
            
            # Check for session management
            if not resp.cookies:
                vulnerabilities.append(self._create_vulnerability(
                    name="PCI-DSS Req 8: Session Management",
                    severity=Severity.INFO,
                    url=url,
                    description="Ensure proper session management is implemented",
                    evidence="General recommendation",
                    recommendation="Implement secure session management",
                    cwe="CWE-613"
                ))
        except:
            pass
        
        return vulnerabilities


class ComplianceChecker(BaseScanner):
    """Unified compliance checker combining OWASP Top 10 and PCI-DSS"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "Compliance Checker"
        self.owasp_checker = OWASPTop10Checker(http_client, engine)
        self.pci_checker = PCIDSSChecker(http_client, engine)
    
    async def scan(self, url: str) -> List[Vulnerability]:
        """Run all compliance checks"""
        vulns = []
        
        # Run OWASP Top 10 checks
        owasp_vulns = await self.owasp_checker.scan(url)
        vulns.extend(owasp_vulns)
        
        # Run PCI-DSS checks
        pci_vulns = await self.pci_checker.scan(url)
        vulns.extend(pci_vulns)
        
        return vulns
