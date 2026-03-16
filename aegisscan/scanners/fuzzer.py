"""
Advanced Fuzzing Module for Input Validation Testing
"""
import asyncio
import random
import string
from typing import List, Optional, Dict, Set
from .base import BaseScanner, Vulnerability, Severity


class AdvancedFuzzer(BaseScanner):
    """Advanced fuzzing engine for finding input validation vulnerabilities"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "Advanced Fuzzer"
        
        # Fuzzing payloads by category
        self.payloads = {
            "integers": self._generate_integer_payloads(),
            "strings": self._generate_string_payloads(),
            "special_chars": self._generate_special_char_payloads(),
            "format_strings": self._generate_format_string_payloads(),
            "buffer_overflow": self._generate_buffer_overflow_payloads(),
            "null_bytes": self._generate_null_byte_payloads(),
            "unicode": self._generate_unicode_payloads(),
            "sql": self._generate_sql_payloads(),
            "xss": self._generate_xss_payloads(),
            "path": self._generate_path_payloads(),
            "command": self._generate_command_payloads(),
        }
    
    def _generate_integer_payloads(self) -> List[str]:
        """Generate integer fuzzing payloads"""
        return [
            "0", "-1", "1", "2147483647", "-2147483648",
            "4294967295", "4294967296", "9223372036854775807",
            "-9223372036854775808", "0x0", "0xFFFFFFFF",
            "0x7FFFFFFF", "0x80000000", "999999999999999999",
            "-999999999999999999", "NaN", "Infinity", "-Infinity",
        ]
    
    def _generate_string_payloads(self) -> List[str]:
        """Generate string fuzzing payloads"""
        payloads = [
            "", " ", "  ", "   ",  # Empty and whitespace
            "A" * 100, "A" * 1000, "A" * 10000,  # Length tests
            "\n", "\r", "\r\n", "\t", "\0",  # Special characters
            "test\x00test", "test\x0Atest", "test\x0Dtest",  # Embedded chars
        ]
        
        # Random strings
        for length in [10, 50, 100, 500, 1000]:
            payloads.append(''.join(random.choices(string.ascii_letters + string.digits, k=length)))
        
        return payloads
    
    def _generate_special_char_payloads(self) -> List[str]:
        """Generate special character payloads"""
        special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', 
                        '-', '_', '=', '+', '[', ']', '{', '}', '\\', '|',
                        ';', ':', "'", '"', ',', '.', '<', '>', '/', '?', '`', '~']
        
        payloads = special_chars.copy()
        
        # Combinations
        for char1 in special_chars[:10]:
            for char2 in special_chars[:10]:
                payloads.append(char1 + char2)
        
        # Repeated characters
        for char in special_chars[:10]:
            payloads.append(char * 10)
            payloads.append(char * 100)
        
        return payloads
    
    def _generate_format_string_payloads(self) -> List[str]:
        """Generate format string attack payloads"""
        return [
            "%s", "%d", "%x", "%n", "%p",
            "%s%s%s%s%s", "%d%d%d%d%d",
            "%x%x%x%x%x", "%n%n%n%n%n",
            "%.1000d", "%.10000d", "%.100000d",
            "%08x", "%016x", "%032x",
            "%1$s", "%2$s", "%3$s", "%10$s",
            "%1$d", "%2$d", "%3$d", "%10$d",
            "%1$x", "%2$x", "%3$x", "%10$x",
            "%1$n", "%2$n", "%3$n", "%10$n",
        ]
    
    def _generate_buffer_overflow_payloads(self) -> List[str]:
        """Generate buffer overflow payloads"""
        payloads = []
        
        # Pattern-based payloads
        patterns = ['A', 'B', '\x41', '\x42', '\x90']
        sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192]
        
        for pattern in patterns:
            for size in sizes:
                payloads.append(pattern * size)
        
        # De Bruijn sequences for offset detection
        payloads.extend([
            "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9",
            "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP",
        ])
        
        return payloads
    
    def _generate_null_byte_payloads(self) -> List[str]:
        """Generate null byte injection payloads"""
        return [
            "\x00", "test\x00", "\x00test", "test\x00test",
            "test%00", "%00test", "test%00test",
            "test\x00.txt", "test%00.txt",
            "../\x00", "..%00/", "/\x00../",
            "admin\x00", "admin%00",
        ]
    
    def _generate_unicode_payloads(self) -> List[str]:
        """Generate Unicode fuzzing payloads"""
        return [
            # Unicode characters
            "\u0000", "\uFFFF", "\u2028", "\u2029",
            # Overlong UTF-8 encodings
            "%c0%af", "%e0%80%af", "%f0%80%80%af",
            # Unicode normalization issues
            "\u00C0", "\u0041\u0300",  # À vs A with combining accent
            "\u212A", "K",  # Kelvin sign vs K
            # Bidirectional override
            "\u202E", "\u202D", "\u202C",
            # Zero-width characters
            "\u200B", "\u200C", "\u200D", "\uFEFF",
            # Homoglyphs
            "\u0430",  # Cyrillic 'a' looks like Latin 'a'
            "\u043E",  # Cyrillic 'o' looks like Latin 'o'
        ]
    
    def _generate_sql_payloads(self) -> List[str]:
        """Generate SQL injection fuzzing payloads"""
        return [
            "'", "''", "' OR '1'='1", "' OR '1'='1'--",
            "'; DROP TABLE users--", "' UNION SELECT NULL--",
            "1' AND '1'='1", "1' AND '1'='2",
            "admin'--", "admin' #", "admin'/*",
            "' OR 1=1--", "' OR 'a'='a", "') OR ('1'='1",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--", "1' AND BENCHMARK(10000000,MD5('test'))--",
        ]
    
    def _generate_xss_payloads(self) -> List[str]:
        """Generate XSS fuzzing payloads"""
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src='javascript:alert(1)'>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "'-alert(1)-'", '"-alert(1)-"',
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
            "<!--<script>alert(1)</script>-->",
            "<script>alert`1`</script>",
        ]
    
    def _generate_path_payloads(self) -> List[str]:
        """Generate path traversal fuzzing payloads"""
        return [
            "../", "..\\", "..%2f", "..%5c",
            "../../", "..\\..\\", "..%2f..%2f", "..%5c..%5c",
            "../../../", "..\\..\\..\\",
            "....//", "....\\\\",
            "..;/", "..;\\",
            "/etc/passwd", "C:\\Windows\\System32\\config\\SAM",
            "%2e%2e%2f", "%2e%2e%5c",
            "..%252f", "..%255c",
            "file:///etc/passwd", "file:///C:/Windows/win.ini",
        ]
    
    def _generate_command_payloads(self) -> List[str]:
        """Generate command injection fuzzing payloads"""
        return [
            "; ls", "| ls", "|| ls", "& ls", "&& ls",
            "`ls`", "$(ls)", "${ls}",
            "; cat /etc/passwd", "| cat /etc/passwd",
            "; ping -c 1 127.0.0.1", "| ping -c 1 127.0.0.1",
            "`ping -c 1 127.0.0.1`", "$(ping -c 1 127.0.0.1)",
            "; sleep 5", "| sleep 5", "`sleep 5`",
            "\n ls", "\r\n ls",
            "; id", "| id", "`id`", "$(id)",
        ]
    
    async def fuzz_parameter(
        self,
        url: str,
        param_name: str,
        method: str = "GET",
        payload_categories: Optional[List[str]] = None
    ) -> List[Vulnerability]:
        """Fuzz a specific parameter with various payloads"""
        vulnerabilities = []
        
        if payload_categories is None:
            payload_categories = list(self.payloads.keys())
        
        # Get baseline response
        baseline = await self._get_baseline_response(url, param_name, method)
        if not baseline:
            return vulnerabilities
        
        # Test each payload category
        for category in payload_categories:
            if category not in self.payloads:
                continue
            
            category_payloads = self.payloads[category]
            
            for payload in category_payloads[:20]:  # Limit per category
                try:
                    vuln = await self._test_payload(
                        url, param_name, payload, method, baseline, category
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                except:
                    continue
        
        return vulnerabilities
    
    async def _get_baseline_response(self, url: str, param_name: str, method: str):
        """Get baseline response for comparison"""
        try:
            test_params = {param_name: "test"}
            
            if method.upper() == "GET":
                return await self.http_client.get(url, params=test_params, timeout=5)
            else:
                return await self.http_client.post(url, data=test_params, timeout=5)
        except:
            return None
    
    async def _test_payload(
        self,
        url: str,
        param_name: str,
        payload: str,
        method: str,
        baseline,
        category: str
    ) -> Optional[Vulnerability]:
        """Test a specific payload"""
        try:
            test_params = {param_name: payload}
            
            if method.upper() == "GET":
                resp = await self.http_client.get(url, params=test_params, timeout=5)
            else:
                resp = await self.http_client.post(url, data=test_params, timeout=5)
            
            # Check for anomalies
            if self._is_anomalous_response(resp, baseline, payload, category):
                return self._create_vulnerability(
                    name=f"Input Validation Issue ({category})",
                    severity=self._determine_severity(category),
                    url=url,
                    parameter=param_name,
                    payload=payload[:200],
                    description=f"Anomalous behavior detected with {category} payload",
                    evidence=f"Response differs significantly from baseline",
                    recommendation="Implement proper input validation and sanitization",
                    cwe="CWE-20"
                )
        except Exception as e:
            # Timeout or crash might indicate vulnerability
            if "timeout" in str(e).lower() or "connection" in str(e).lower():
                return self._create_vulnerability(
                    name=f"Potential DoS via Input ({category})",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter=param_name,
                    payload=payload[:200],
                    description=f"Application timeout/crash with {category} payload",
                    evidence=f"Exception: {str(e)[:200]}",
                    recommendation="Implement input validation and resource limits",
                    cwe="CWE-20"
                )
        
        return None
    
    def _is_anomalous_response(self, response, baseline, payload: str, category: str) -> bool:
        """Check if response is anomalous compared to baseline"""
        # Status code change
        if response.status_code != baseline.status_code:
            if response.status_code >= 500:  # Server error
                return True
        
        # Significant size change
        size_diff = abs(len(response.content) - len(baseline.content))
        if size_diff > 500:  # More than 500 bytes difference
            return True
        
        # Error messages
        error_indicators = [
            "error", "exception", "stack trace", "warning",
            "fatal", "critical", "syntax error", "parse error",
            "mysql", "postgresql", "oracle", "sql", "database",
        ]
        
        response_lower = response.text.lower()
        baseline_lower = baseline.text.lower()
        
        for indicator in error_indicators:
            if indicator in response_lower and indicator not in baseline_lower:
                return True
        
        # Payload reflection in unexpected places
        if payload in response.text and payload not in baseline.text:
            if category in ["xss", "sql", "command"]:
                return True
        
        return False
    
    def _determine_severity(self, category: str) -> Severity:
        """Determine severity based on payload category"""
        high_severity = ["sql", "command", "xss", "path"]
        medium_severity = ["format_strings", "buffer_overflow", "null_bytes"]
        
        if category in high_severity:
            return Severity.HIGH
        elif category in medium_severity:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Main scan method for fuzzing"""
        vulnerabilities = []
        
        test_params = params or {}
        if not test_params:
            if "?" in url:
                query_string = url.split("?")[1]
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        test_params[key] = value
        
        if not test_params:
            return vulnerabilities
        
        # Fuzz each parameter
        for param_name in test_params.keys():
            param_vulns = await self.fuzz_parameter(url, param_name, method)
            vulnerabilities.extend(param_vulns)
        
        return vulnerabilities

