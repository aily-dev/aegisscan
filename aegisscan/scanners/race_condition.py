"""
Race Condition Scanner
"""
import asyncio
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity


class RaceConditionScanner(BaseScanner):
    """Race condition vulnerability scanner"""
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "POST", **kwargs) -> List[Vulnerability]:
        """Scan for race condition vulnerabilities"""
        vulnerabilities = []
        
        # Race conditions are hard to detect automatically
        # This is a basic implementation that tests concurrent requests
        
        test_params = params or {}
        if not test_params:
            return vulnerabilities
        
        # Only test POST requests (state-changing operations)
        if method.upper() != "POST":
            return vulnerabilities
        
        try:
            # Send multiple concurrent requests
            tasks = []
            for i in range(10):
                task = self.http_client.post(url, data=test_params, timeout=10)
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Check for inconsistent responses
            status_codes = [r.status_code for r in responses if isinstance(r, type(responses[0]))]
            if len(set(status_codes)) > 1:
                # Different status codes - potential race condition
                return self._create_vulnerability(
                    name="Potential Race Condition",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="Inconsistent responses to concurrent requests detected",
                    evidence="Different status codes returned for concurrent requests",
                    recommendation="Implement proper locking mechanisms and transaction handling",
                    cwe="CWE-362"
                )
        except:
            pass
        
        return vulnerabilities

