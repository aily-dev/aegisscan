"""
Passive Security Analyzer
"""
import re
from typing import List, Dict
from ..scanners.base import BaseScanner, Vulnerability, Severity
from ..http.client import Response


class PassiveAnalyzer(BaseScanner):
    """Passive security analyzer similar to Burp"""
    
    SENSITIVE_FILES = [
        "/.git/config",
        "/.git/HEAD",
        "/.svn/entries",
        "/.env",
        "/.htaccess",
        "/.htpasswd",
        "/web.config",
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/backup.sql",
        "/database.sql",
        "/dump.sql",
        "/config.php",
        "/wp-config.php",
        "/config.inc.php",
        "/settings.py",
        "/.DS_Store",
        "/.gitignore",
        "/robots.txt",
        "/sitemap.xml",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
    ]
    
    ADMIN_PATHS = [
        "/admin",
        "/administrator",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/pma",
        "/adminer.php",
        "/cpanel",
        "/whm",
        "/manager",
        "/console",
        "/admin.php",
        "/login",
        "/signin",
    ]
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Perform passive security analysis"""
        vulnerabilities = []
        
        try:
            resp = await self.http_client.get(url)
            
            # Check security headers
            header_issues = self._check_security_headers(resp)
            vulnerabilities.extend(header_issues)
            
            # Check for sensitive files
            sensitive_issues = await self._check_sensitive_files(url)
            vulnerabilities.extend(sensitive_issues)
            
            # Check for admin panels
            admin_issues = await self._check_admin_panels(url)
            vulnerabilities.extend(admin_issues)
            
            # Check for exposed information
            info_issues = self._check_information_disclosure(resp)
            vulnerabilities.extend(info_issues)
            
        except:
            pass
        
        return vulnerabilities
    
    def _check_security_headers(self, response: Response) -> List[Vulnerability]:
        """Check for missing or weak security headers"""
        issues = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        # Content Security Policy
        if "content-security-policy" not in headers_lower:
            issues.append(self._create_vulnerability(
                name="Missing Content Security Policy",
                severity=Severity.MEDIUM,
                url=response.url,
                description="Content Security Policy header is missing",
                recommendation="Implement CSP to prevent XSS attacks",
                cwe="CWE-1021"
            ))
        
        # Strict Transport Security
        if response.url.startswith("https://"):
            if "strict-transport-security" not in headers_lower:
                issues.append(self._create_vulnerability(
                    name="Missing HSTS Header",
                    severity=Severity.MEDIUM,
                    url=response.url,
                    description="Strict-Transport-Security header is missing on HTTPS site",
                    recommendation="Implement HSTS to enforce HTTPS connections",
                    cwe="CWE-319"
                ))
            else:
                hsts = headers_lower["strict-transport-security"]
                if "max-age=0" in hsts or "max-age" not in hsts:
                    issues.append(self._create_vulnerability(
                        name="Weak HSTS Configuration",
                        severity=Severity.LOW,
                        url=response.url,
                        description="HSTS max-age is too low or missing",
                        recommendation="Set HSTS max-age to at least 31536000 (1 year)",
                        cwe="CWE-319"
                    ))
        
        # X-Frame-Options
        if "x-frame-options" not in headers_lower:
            issues.append(self._create_vulnerability(
                name="Missing X-Frame-Options",
                severity=Severity.LOW,
                url=response.url,
                description="X-Frame-Options header is missing",
                recommendation="Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking",
                cwe="CWE-1021"
            ))
        else:
            xfo = headers_lower["x-frame-options"]
            if xfo.lower() not in ["deny", "sameorigin"]:
                issues.append(self._create_vulnerability(
                    name="Weak X-Frame-Options",
                    severity=Severity.LOW,
                    url=response.url,
                    description=f"X-Frame-Options set to weak value: {xfo}",
                    recommendation="Set X-Frame-Options to DENY or SAMEORIGIN",
                    cwe="CWE-1021"
                ))
        
        # X-Content-Type-Options
        if "x-content-type-options" not in headers_lower:
            issues.append(self._create_vulnerability(
                name="Missing X-Content-Type-Options",
                severity=Severity.LOW,
                url=response.url,
                description="X-Content-Type-Options header is missing",
                recommendation="Set X-Content-Type-Options to nosniff",
                cwe="CWE-693"
            ))
        
        # X-XSS-Protection (deprecated but still checked)
        if "x-xss-protection" not in headers_lower:
            issues.append(self._create_vulnerability(
                name="Missing X-XSS-Protection",
                severity=Severity.INFO,
                url=response.url,
                description="X-XSS-Protection header is missing (note: this header is deprecated)",
                recommendation="Use Content Security Policy instead",
                cwe="CWE-79"
            ))
        
        # Referrer-Policy
        if "referrer-policy" not in headers_lower:
            issues.append(self._create_vulnerability(
                name="Missing Referrer-Policy",
                severity=Severity.LOW,
                url=response.url,
                description="Referrer-Policy header is missing",
                recommendation="Set Referrer-Policy to control referrer information leakage",
                cwe="CWE-200"
            ))
        
        return issues
    
    async def _check_sensitive_files(self, base_url: str) -> List[Vulnerability]:
        """Check for exposed sensitive files"""
        issues = []
        
        for file_path in self.SENSITIVE_FILES[:20]:  # Limit for performance
            try:
                url = f"{base_url.rstrip('/')}{file_path}"
                resp = await self.http_client.get(url, timeout=5)
                
                if resp.status_code == 200:
                    # Check if it's actually the file we're looking for
                    if self._is_sensitive_file(resp, file_path):
                        issues.append(self._create_vulnerability(
                            name="Sensitive File Exposure",
                            severity=Severity.HIGH,
                            url=url,
                            description=f"Sensitive file exposed: {file_path}",
                            evidence=f"File accessible at {url}",
                            recommendation="Remove sensitive files from web root or restrict access",
                            cwe="CWE-538"
                        ))
            except:
                continue
        
        return issues
    
    def _is_sensitive_file(self, response: Response, file_path: str) -> bool:
        """Check if response is actually the sensitive file"""
        # Check for file-specific indicators
        if ".git" in file_path:
            if "repositoryformatversion" in response.text.lower() or "[core]" in response.text:
                return True
        elif ".env" in file_path:
            if "=" in response.text and ("password" in response.text.lower() or "secret" in response.text.lower()):
                return True
        elif "phpinfo" in file_path or "info.php" in file_path:
            if "phpinfo()" in response.text or "php version" in response.text.lower():
                return True
        elif "config" in file_path:
            if "password" in response.text.lower() or "database" in response.text.lower():
                return True
        elif "robots.txt" in file_path:
            if "user-agent" in response.text.lower() or "disallow" in response.text.lower():
                return True
        
        return False
    
    async def _check_admin_panels(self, base_url: str) -> List[Vulnerability]:
        """Check for exposed admin panels"""
        issues = []
        
        for admin_path in self.ADMIN_PATHS[:10]:  # Limit for performance
            try:
                url = f"{base_url.rstrip('/')}{admin_path}"
                resp = await self.http_client.get(url, timeout=5)
                
                if resp.status_code == 200:
                    # Check if it's actually an admin panel
                    if self._is_admin_panel(resp.text, admin_path):
                        issues.append(self._create_vulnerability(
                            name="Admin Panel Exposed",
                            severity=Severity.MEDIUM,
                            url=url,
                            description=f"Admin panel accessible: {admin_path}",
                            evidence=f"Admin panel found at {url}",
                            recommendation="Restrict access to admin panels. Use strong authentication and IP whitelisting.",
                            cwe="CWE-284"
                        ))
            except:
                continue
        
        return issues
    
    def _is_admin_panel(self, html: str, path: str) -> bool:
        """Check if response is an admin panel"""
        html_lower = html.lower()
        
        admin_indicators = [
            "login",
            "password",
            "username",
            "admin",
            "dashboard",
            "control panel",
            "wp-admin",
            "phpmyadmin",
        ]
        
        indicator_count = sum(1 for indicator in admin_indicators if indicator in html_lower)
        return indicator_count >= 2
    
    def _check_information_disclosure(self, response: Response) -> List[Vulnerability]:
        """Check for information disclosure"""
        issues = []
        
        # Check for email exposure
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        emails = email_pattern.findall(response.text)
        if emails:
            issues.append(self._create_vulnerability(
                name="Email Address Exposure",
                severity=Severity.INFO,
                url=response.url,
                description=f"Email addresses found in response: {len(emails)}",
                evidence=f"Emails: {', '.join(emails[:5])}",
                recommendation="Avoid exposing email addresses in client-side code",
                cwe="CWE-200"
            ))
        
        # Check for API keys (heuristic)
        api_key_patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})',
            r'apikey["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})',
            r'secret[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})',
        ]
        
        for pattern in api_key_patterns:
            matches = re.finditer(pattern, response.text, re.IGNORECASE)
            for match in matches:
                potential_key = match.group(1)
                if len(potential_key) >= 20:
                    issues.append(self._create_vulnerability(
                        name="Potential API Key Exposure",
                        severity=Severity.HIGH,
                        url=response.url,
                        description="Potential API key found in response",
                        evidence=f"Pattern matched: {pattern}",
                        recommendation="Never expose API keys in client-side code. Use environment variables and server-side storage.",
                        cwe="CWE-798"
                    ))
                    break
        
        # Check for internal IP addresses
        ip_pattern = re.compile(r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b')
        internal_ips = ip_pattern.findall(response.text)
        if internal_ips:
            issues.append(self._create_vulnerability(
                name="Internal IP Address Exposure",
                severity=Severity.MEDIUM,
                url=response.url,
                description="Internal IP addresses found in response",
                evidence=f"IPs: {', '.join(set(internal_ips[:5]))}",
                recommendation="Avoid exposing internal IP addresses in client-side code",
                cwe="CWE-200"
            ))
        
        return issues

