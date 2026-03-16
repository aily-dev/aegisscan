"""
Business Logic Vulnerability Scanner
"""
import asyncio
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity


class BusinessLogicScanner(BaseScanner):
    """Business logic vulnerability scanner"""
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "POST", **kwargs) -> List[Vulnerability]:
        """Scan for business logic vulnerabilities"""
        vulnerabilities = []
        
        # Price manipulation
        price_vuln = await self._test_price_manipulation(url, params, method)
        if price_vuln:
            vulnerabilities.append(price_vuln)
        
        # Quantity manipulation
        quantity_vuln = await self._test_quantity_manipulation(url, params, method)
        if quantity_vuln:
            vulnerabilities.append(quantity_vuln)
        
        # Negative values
        negative_vuln = await self._test_negative_values(url, params, method)
        if negative_vuln:
            vulnerabilities.append(negative_vuln)
        
        return vulnerabilities
    
    async def _test_price_manipulation(self, url: str, params: Optional[dict], method: str) -> Optional[Vulnerability]:
        """Test for price manipulation"""
        if not params:
            return None
        
        # Look for price-related parameters
        price_params = {k: v for k, v in params.items() if "price" in k.lower() or "cost" in k.lower() or "amount" in k.lower()}
        
        if not price_params:
            return None
        
        for param_name, param_value in price_params.items():
            try:
                # Try setting price to 0 or negative
                test_params = {**params, param_name: "0"}
                
                if method.upper() == "POST":
                    resp = await self.http_client.post(url, data=test_params, timeout=5)
                else:
                    resp = await self.http_client.get(url, params=test_params, timeout=5)
                
                # Check if request succeeded with manipulated price
                if resp.status_code == 200:
                    # Check response for success indicators
                    success_indicators = ["success", "order", "payment", "complete"]
                    if any(indicator in resp.text.lower() for indicator in success_indicators):
                        return self._create_vulnerability(
                            name="Price Manipulation",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param_name,
                            payload="0",
                            description="Price manipulation vulnerability detected",
                            evidence="Request succeeded with manipulated price value",
                            recommendation="Validate prices on server side. Never trust client-side price values.",
                            cwe="CWE-840"
                        )
            except:
                continue
        
        return None
    
    async def _test_quantity_manipulation(self, url: str, params: Optional[dict], method: str) -> Optional[Vulnerability]:
        """Test for quantity manipulation"""
        if not params:
            return None
        
        quantity_params = {k: v for k, v in params.items() if "quantity" in k.lower() or "qty" in k.lower() or "amount" in k.lower()}
        
        if not quantity_params:
            return None
        
        for param_name, param_value in quantity_params.items():
            try:
                # Try negative quantity
                test_params = {**params, param_name: "-1"}
                
                if method.upper() == "POST":
                    resp = await self.http_client.post(url, data=test_params, timeout=5)
                else:
                    resp = await self.http_client.get(url, params=test_params, timeout=5)
                
                if resp.status_code == 200:
                    return self._create_vulnerability(
                        name="Quantity Manipulation",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter=param_name,
                        payload="-1",
                        description="Quantity manipulation vulnerability detected",
                        evidence="Request accepted with negative quantity",
                        recommendation="Validate quantities on server side. Reject negative values.",
                        cwe="CWE-840"
                    )
            except:
                continue
        
        return None
    
    async def _test_negative_values(self, url: str, params: Optional[dict], method: str) -> Optional[Vulnerability]:
        """Test for negative value vulnerabilities"""
        if not params:
            return None
        
        for param_name, param_value in params.items():
            try:
                # Try negative value
                test_params = {**params, param_name: "-100"}
                
                if method.upper() == "POST":
                    resp = await self.http_client.post(url, data=test_params, timeout=5)
                else:
                    resp = await self.http_client.get(url, params=test_params, timeout=5)
                
                # Check for unexpected behavior
                if resp.status_code == 200:
                    # Check if response indicates negative value was processed
                    if "negative" in resp.text.lower() or "error" not in resp.text.lower():
                        return self._create_vulnerability(
                            name="Negative Value Processing",
                            severity=Severity.LOW,
                            url=url,
                            parameter=param_name,
                            payload="-100",
                            description="Application processes negative values without validation",
                            evidence="Negative value accepted without error",
                            recommendation="Validate input ranges. Reject negative values where inappropriate.",
                            cwe="CWE-20"
                        )
            except:
                continue
        
        return None

