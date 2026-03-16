"""
IDOR (Insecure Direct Object Reference) Scanner
"""
import asyncio
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity


class IDORScanner(BaseScanner):
    """IDOR vulnerability scanner"""
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for IDOR vulnerabilities"""
        vulnerabilities = []
        
        # IDOR testing requires understanding the application structure
        # This is a basic implementation
        
        test_params = params or {}
        if not test_params:
            if "?" in url:
                query_string = url.split("?")[1]
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        test_params[key] = value
        
        # Look for ID-like parameters
        id_params = {}
        for param_name, param_value in test_params.items():
            if any(keyword in param_name.lower() for keyword in ["id", "user", "account", "file", "document"]):
                id_params[param_name] = param_value
        
        if not id_params:
            return vulnerabilities
        
        # Test with different IDs
        for param_name, original_value in id_params.items():
            # Try sequential IDs
            try:
                original_id = int(original_value)
                test_ids = [original_id - 1, original_id + 1, original_id + 10]
            except:
                # Not numeric, try variations
                test_ids = [original_value + "1", original_value + "2"]
            
            for test_id in test_ids:
                try:
                    test_params_dict = {**test_params, param_name: str(test_id)}
                    
                    if method.upper() == "GET":
                        test_resp = await self.http_client.get(url, params=test_params_dict, timeout=5)
                    else:
                        test_resp = await self.http_client.post(url, data=test_params_dict, timeout=5)
                    
                    # Get original response for comparison
                    if method.upper() == "GET":
                        original_resp = await self.http_client.get(url, params=test_params, timeout=5)
                    else:
                        original_resp = await self.http_client.post(url, data=test_params, timeout=5)
                    
                    # Check if different ID returns different content (potential IDOR)
                    if test_resp.status_code == 200 and original_resp.status_code == 200:
                        if len(test_resp.content) != len(original_resp.content):
                            # Different content - might be IDOR
                            if abs(len(test_resp.content) - len(original_resp.content)) > 100:
                                return self._create_vulnerability(
                                    name="Insecure Direct Object Reference (IDOR)",
                                    severity=Severity.MEDIUM,
                                    url=url,
                                    parameter=param_name,
                                    payload=str(test_id),
                                    description="Potential IDOR vulnerability detected",
                                    evidence=f"Different content returned for different {param_name} values",
                                    recommendation="Implement proper authorization checks. Use indirect object references.",
                                    cwe="CWE-639"
                                )
                except:
                    continue
        
        return vulnerabilities

