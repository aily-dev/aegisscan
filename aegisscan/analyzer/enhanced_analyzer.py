"""
Enhanced Security Analyzer
"""
import re
from typing import List, Dict
from ..scanners.base import BaseScanner, Vulnerability, Severity
from ..http.client import Response


class EnhancedPassiveAnalyzer(BaseScanner):
    """Enhanced passive security analyzer"""
    
    SENSITIVE_FILES = [
        "/.git/config", "/.git/HEAD", "/.svn/entries", "/.env",
        "/.htaccess", "/.htpasswd", "/web.config", "/phpinfo.php",
        "/info.php", "/test.php", "/backup.sql", "/database.sql",
        "/dump.sql", "/config.php", "/wp-config.php", "/config.inc.php",
        "/settings.py", "/.DS_Store", "/.gitignore", "/robots.txt",
        "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/package.json", "/composer.json", "/requirements.txt",
        "/pom.xml", "/build.xml", "/Makefile", "/Dockerfile",
    ]
    
    ADMIN_PATHS = [
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/phpmyadmin", "/pma", "/adminer.php", "/cpanel", "/whm",
        "/manager", "/console", "/admin.php", "/login", "/signin",
        "/dashboard", "/control", "/panel", "/management",
    ]
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Enhanced passive security analysis"""
        vulnerabilities = []
        
        try:
            resp = await self.http_client.get(url)
            
            # Check security headers
            header_issues = self._check_security_headers_enhanced(resp)
            vulnerabilities.extend(header_issues)
            
            # Check for sensitive files
            sensitive_issues = await self._check_sensitive_files_enhanced(url)
            vulnerabilities.extend(sensitive_issues)
            
            # Check for admin panels
            admin_issues = await self._check_admin_panels_enhanced(url)
            vulnerabilities.extend(admin_issues)
            
            # Check for exposed information
            info_issues = self._check_information_disclosure_enhanced(resp)
            vulnerabilities.extend(info_issues)
            
            # Check for misconfigurations
            misconfig_issues = self._check_misconfigurations(resp)
            vulnerabilities.extend(misconfig_issues)
            
        except:
            pass
        
        return vulnerabilities
    
    def _check_security_headers_enhanced(self, response: Response) -> List[Vulnerability]:
        """Enhanced security header checking"""
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
        else:
            # Check CSP strength
            csp = headers_lower["content-security-policy"]
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                issues.append(self._create_vulnerability(
                    name="Weak Content Security Policy",
                    severity=Severity.LOW,
                    url=response.url,
                    description="CSP contains unsafe-inline or unsafe-eval",
                    recommendation="Remove unsafe-inline and unsafe-eval from CSP",
                    cwe="CWE-1021"
                ))
        
        # Strict Transport Security
        if response.url.startswith("https://"):
            if "strict-transport-security" not in headers_lower:
                issues.append(self._create_vulnerability(
                    name="Missing HSTS Header",
                    severity=Severity.MEDIUM,
                    url=response.url,
                    description="Strict-Transport-Security header is missing",
                    recommendation="Implement HSTS to enforce HTTPS",
                    cwe="CWE-319"
                ))
            else:
                hsts = headers_lower["strict-transport-security"]
                if "max-age=0" in hsts or "max-age" not in hsts:
                    issues.append(self._create_vulnerability(
                        name="Weak HSTS Configuration",
                        severity=Severity.LOW,
                        url=response.url,
                        description="HSTS max-age is too low",
                        recommendation="Set HSTS max-age to at least 31536000",
                        cwe="CWE-319"
                    ))
        
        # X-Frame-Options
        if "x-frame-options" not in headers_lower:
            issues.append(self._create_vulnerability(
                name="Missing X-Frame-Options",
                severity=Severity.LOW,
                url=response.url,
                description="X-Frame-Options header is missing",
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
        
        # Permissions-Policy / Feature-Policy
        if "permissions-policy" not in headers_lower and "feature-policy" not in headers_lower:
            issues.append(self._create_vulnerability(
                name="Missing Permissions-Policy",
                severity=Severity.INFO,
                url=response.url,
                description="Permissions-Policy header is missing",
                recommendation="Implement Permissions-Policy to restrict browser features",
                cwe="CWE-1021"
            ))
        
        return issues
    
    async def _check_sensitive_files_enhanced(self, base_url: str) -> List[Vulnerability]:
        """Enhanced sensitive file checking"""
        issues = []
        
        for file_path in self.SENSITIVE_FILES[:30]:  # Limit
            try:
                url = f"{base_url.rstrip('/')}{file_path}"
                resp = await self.http_client.get(url, timeout=5)
                
                if resp.status_code == 200:
                    if self._is_sensitive_file_enhanced(resp, file_path):
                        issues.append(self._create_vulnerability(
                            name="Sensitive File Exposure",
                            severity=Severity.HIGH,
                            url=url,
                            description=f"Sensitive file exposed: {file_path}",
                            evidence=f"File accessible at {url}",
                            recommendation="Remove sensitive files from web root",
                            cwe="CWE-538"
                        ))
            except:
                continue
        
        return issues
    
    def _is_sensitive_file_enhanced(self, response: Response, file_path: str) -> bool:
        """Enhanced sensitive file detection"""
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
        elif file_path.endswith((".json", ".xml", ".txt")):
            # Check file size - very small might indicate it's the actual file
            if len(response.content) < 10000:  # Less than 10KB
                return True
        
        return False
    
    async def _check_admin_panels_enhanced(self, base_url: str) -> List[Vulnerability]:
        """Enhanced admin panel checking"""
        issues = []
        
        for admin_path in self.ADMIN_PATHS[:20]:  # Limit
            try:
                url = f"{base_url.rstrip('/')}{admin_path}"
                resp = await self.http_client.get(url, timeout=5)
                
                if resp.status_code == 200:
                    if self._is_admin_panel_enhanced(resp.text, admin_path):
                        issues.append(self._create_vulnerability(
                            name="Admin Panel Exposed",
                            severity=Severity.MEDIUM,
                            url=url,
                            description=f"Admin panel accessible: {admin_path}",
                            evidence=f"Admin panel found at {url}",
                            recommendation="Restrict access to admin panels",
                            cwe="CWE-284"
                        ))
            except:
                continue
        
        return issues
    
    def _is_admin_panel_enhanced(self, html: str, path: str) -> bool:
        """Enhanced admin panel detection"""
        html_lower = html.lower()
        
        admin_indicators = [
            "login", "password", "username", "admin",
            "dashboard", "control panel", "wp-admin",
            "phpmyadmin", "authentication", "sign in",
        ]
        
        indicator_count = sum(1 for indicator in admin_indicators if indicator in html_lower)
        return indicator_count >= 3  # More strict
    
    def _check_information_disclosure_enhanced(self, response: Response) -> List[Vulnerability]:
        """Enhanced information disclosure checking"""
        issues = []
        
        # Email exposure
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        emails = email_pattern.findall(response.text)
        if emails:
            unique_emails = list(set(emails))[:10]  # Limit
            issues.append(self._create_vulnerability(
                name="Email Address Exposure",
                severity=Severity.INFO,
                url=response.url,
                description=f"Email addresses found in response: {len(emails)}",
                evidence=f"Emails: {', '.join(unique_emails)}",
                recommendation="Avoid exposing email addresses in client-side code",
                cwe="CWE-200"
            ))
        
        # API key exposure
        api_key_patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})',
            r'apikey["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})',
            r'secret[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})',
            r'access[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})',
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
                        recommendation="Never expose API keys in client-side code",
                        cwe="CWE-798"
                    ))
                    break
        
        # Internal IP exposure
        ip_pattern = re.compile(r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b')
        internal_ips = ip_pattern.findall(response.text)
        if internal_ips:
            unique_ips = list(set([ip[0] if isinstance(ip, tuple) else ip for ip in internal_ips]))[:5]
            issues.append(self._create_vulnerability(
                name="Internal IP Address Exposure",
                severity=Severity.MEDIUM,
                url=response.url,
                description="Internal IP addresses found in response",
                evidence=f"IPs: {', '.join(unique_ips)}",
                recommendation="Avoid exposing internal IP addresses",
                cwe="CWE-200"
            ))
        
        # Stack trace exposure
        if "stack trace" in response.text.lower() or "exception" in response.text.lower():
            if "at " in response.text and ("java" in response.text.lower() or "python" in response.text.lower()):
                issues.append(self._create_vulnerability(
                    name="Stack Trace Exposure",
                    severity=Severity.MEDIUM,
                    url=response.url,
                    description="Stack trace found in response",
                    evidence="Stack trace detected",
                    recommendation="Disable error messages in production",
                    cwe="CWE-209"
                ))
        
        return issues
    
    def _check_misconfigurations(self, response: Response) -> List[Vulnerability]:
        """Check for misconfigurations"""
        issues = []
        
        # Directory listing
        if "index of" in response.text.lower() or "directory listing" in response.text.lower():
            issues.append(self._create_vulnerability(
                name="Directory Listing Enabled",
                severity=Severity.MEDIUM,
                url=response.url,
                description="Directory listing is enabled",
                evidence="Directory listing detected",
                recommendation="Disable directory listing",
                cwe="CWE-548"
            ))
        
        # Server version disclosure
        server_header = response.headers.get("Server", "")
        if server_header and any(char.isdigit() for char in server_header):
            # Contains version number
            issues.append(self._create_vulnerability(
                name="Server Version Disclosure",
                severity=Severity.LOW,
                url=response.url,
                description=f"Server version disclosed: {server_header}",
                evidence=f"Server header: {server_header}",
                recommendation="Hide server version information",
                cwe="CWE-200"
            ))
        
        return issues

