"""
Insecure Deserialization Scanner
"""
import base64
import pickle
import json
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity
from ..http.client import Response


class DeserializationScanner(BaseScanner):
    """Insecure deserialization vulnerability scanner"""
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "POST", **kwargs) -> List[Vulnerability]:
        """Scan for insecure deserialization"""
        vulnerabilities = []
        
        # Test with various serialized payloads
        test_payloads = [
            self._create_pickle_payload(),
            self._create_java_serialized_payload(),
            self._create_php_serialized_payload(),
        ]
        
        for payload_name, payload_data in test_payloads:
            try:
                if method.upper() == "POST":
                    resp = await self.http_client.post(
                        url,
                        data=payload_data,
                        headers={"Content-Type": "application/octet-stream"}
                    )
                else:
                    resp = await self.http_client.get(url, params={"data": payload_data})
                
                # Check for deserialization indicators
                if self._check_deserialization_response(resp, payload_name):
                    return self._create_vulnerability(
                        name="Insecure Deserialization",
                        severity=Severity.HIGH,
                        url=url,
                        description=f"Insecure deserialization detected ({payload_name})",
                        evidence="Deserialization vulnerability indicators found",
                        recommendation="Avoid deserializing untrusted data. Use safe serialization formats like JSON.",
                        cwe="CWE-502"
                    )
            except:
                continue
        
        return vulnerabilities
    
    def _create_pickle_payload(self) -> tuple:
        """Create Python pickle payload"""
        try:
            # Simple pickle payload
            class TestClass:
                def __reduce__(self):
                    return (str, ("test",))
            
            payload = pickle.dumps(TestClass())
            return ("Python Pickle", base64.b64encode(payload).decode())
        except:
            return ("Python Pickle", "")
    
    def _create_java_serialized_payload(self) -> tuple:
        """Create Java serialized payload"""
        # Java serialized object signature
        java_signature = "aced0005"  # Magic number for Java serialization
        return ("Java Serialized", java_signature)
    
    def _create_php_serialized_payload(self) -> tuple:
        """Create PHP serialized payload"""
        php_serialized = 'O:8:"TestClass":0:{}'
        return ("PHP Serialized", php_serialized)
    
    def _check_deserialization_response(self, response: Response, payload_name: str) -> bool:
        """Check if response indicates deserialization"""
        # Look for error messages related to deserialization
        error_patterns = [
            "pickle", "deserialization", "unserialize",
            "objectinputstream", "readobject",
        ]
        
        response_lower = response.text.lower()
        if any(pattern in response_lower for pattern in error_patterns):
            return True
        
        return False

