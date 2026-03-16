"""
Command Injection Scanner
"""
import asyncio
import time
import re
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity


class CommandInjectionScanner(BaseScanner):
    """Command injection vulnerability scanner"""
    
    # OS command injection payloads
    OS_PAYLOADS = [
        "; ls",
        "| ls",
        "& ls",
        "&& ls",
        "|| ls",
        "; id",
        "| id",
        "& id",
        "&& id",
        "|| id",
        "; whoami",
        "| whoami",
        "& whoami",
        "`id`",
        "$(id)",
        "`whoami`",
        "$(whoami)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "& cat /etc/passwd",
        "; ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1",
        "& ping -c 5 127.0.0.1",
    ]
    
    # Time-delay payloads
    TIME_DELAY_PAYLOADS = [
        "; sleep 5",
        "| sleep 5",
        "& sleep 5",
        "&& sleep 5",
        "; ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1",
        "& ping -c 5 127.0.0.1",
        "`sleep 5`",
        "$(sleep 5)",
    ]
    
    # Windows-specific payloads
    WINDOWS_PAYLOADS = [
        "& dir",
        "| dir",
        "; dir",
        "&& dir",
        "|| dir",
        "& type C:\\Windows\\win.ini",
        "| type C:\\Windows\\win.ini",
        "; type C:\\Windows\\win.ini",
        "& ping -n 5 127.0.0.1",
        "| ping -n 5 127.0.0.1",
    ]
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for command injection vulnerabilities"""
        vulnerabilities = []
        
        test_params = params or {}
        if not test_params:
            if "?" in url:
                query_string = url.split("?")[1]
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        test_params[key] = value
        
        for param_name, param_value in test_params.items():
            # Test OS injection
            vuln = await self._test_os_injection(url, param_name, param_value, method)
            if vuln:
                vulnerabilities.append(vuln)
                continue
            
            # Test time-delay
            vuln = await self._test_time_delay(url, param_name, param_value, method)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_os_injection(
        self, url: str, param: str, value: str, method: str
    ) -> Optional[Vulnerability]:
        """Test for OS command injection"""
        all_payloads = self.OS_PAYLOADS + self.WINDOWS_PAYLOADS
        
        for payload in all_payloads[:10]:  # Limit for performance
            try:
                test_params = {param: payload}
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params)
                else:
                    resp = await self.http_client.post(url, data=test_params)
                
                # Check for command output indicators
                if self._check_command_output(resp.text, payload):
                    return self._create_vulnerability(
                        name="Command Injection",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        description="OS command injection vulnerability detected",
                        evidence="Command output found in response",
                        recommendation="Use parameterized APIs and input validation. Avoid shell execution with user input.",
                        cwe="CWE-78"
                    )
            except:
                continue
        
        return None
    
    async def _test_time_delay(
        self, url: str, param: str, value: str, method: str
    ) -> Optional[Vulnerability]:
        """Test for time-delay based command injection"""
        for payload in self.TIME_DELAY_PAYLOADS[:5]:  # Limit for performance
            try:
                test_params = {param: payload}
                start_time = time.time()
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params, timeout=10)
                else:
                    resp = await self.http_client.post(url, data=test_params, timeout=10)
                
                elapsed = time.time() - start_time
                
                # Check if response was delayed
                if elapsed > 4:
                    return self._create_vulnerability(
                        name="Command Injection (Time-based)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        description="Time-based command injection detected",
                        evidence=f"Response delayed by {elapsed:.2f} seconds",
                        recommendation="Use parameterized APIs and input validation. Avoid shell execution with user input.",
                        cwe="CWE-78"
                    )
            except asyncio.TimeoutError:
                return self._create_vulnerability(
                    name="Command Injection (Time-based)",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload=payload,
                    description="Possible time-based command injection (timeout)",
                    evidence="Request timed out, possibly due to command delay",
                    recommendation="Use parameterized APIs and input validation. Avoid shell execution with user input.",
                    cwe="CWE-78"
                )
            except:
                continue
        
        return None
    
    def _check_command_output(self, text: str, payload: str) -> bool:
        """Check if command output appears in response"""
        # Common command output patterns
        output_patterns = [
            r"uid=\d+\([^)]+\)",
            r"gid=\d+\([^)]+\)",
            r"root:x:0:0:",
            r"\[boot loader\]",
            r"for 16-bit app support",
            r"total \d+",
            r"drwx",
            r"-rw-",
            r"Directory of",
        ]
        
        # Check for common command outputs
        for pattern in output_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        # Check if payload command keywords appear in response
        command_keywords = ["ls", "id", "whoami", "dir", "type", "cat"]
        for keyword in command_keywords:
            if keyword in payload.lower() and keyword in text.lower():
                # Additional check: look for typical command output structure
                if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
                    return True
        
        return False

