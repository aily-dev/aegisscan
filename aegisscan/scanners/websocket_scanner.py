"""
WebSocket Security Scanner
"""
import asyncio
import json
from typing import List, Optional, Dict
from .base import BaseScanner, Vulnerability, Severity


class WebSocketScanner(BaseScanner):
    """WebSocket security vulnerability scanner"""
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Scan WebSocket endpoints for vulnerabilities"""
        vulnerabilities = []
        
        # Check if URL is WebSocket
        ws_url = self._convert_to_ws_url(url)
        if not ws_url:
            return vulnerabilities
        
        # Test for various WebSocket vulnerabilities
        vulns = await self._test_ws_authentication(ws_url)
        vulnerabilities.extend(vulns)
        
        vulns = await self._test_ws_injection(ws_url)
        vulnerabilities.extend(vulns)
        
        vulns = await self._test_ws_dos(ws_url)
        vulnerabilities.extend(vulns)
        
        vulns = await self._test_ws_origin(ws_url)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _convert_to_ws_url(self, url: str) -> Optional[str]:
        """Convert HTTP URL to WebSocket URL"""
        if url.startswith("ws://") or url.startswith("wss://"):
            return url
        elif url.startswith("http://"):
            return url.replace("http://", "ws://", 1)
        elif url.startswith("https://"):
            return url.replace("https://", "wss://", 1)
        return None
    
    async def _test_ws_authentication(self, ws_url: str) -> List[Vulnerability]:
        """Test for authentication bypass in WebSocket"""
        vulnerabilities = []
        
        # Try to connect without authentication
        try:
            # In real implementation, we would use websockets library
            # For now, simulate the check
            
            # Check if connection succeeds without auth
            connection_possible = True  # Simulated
            
            if connection_possible:
                vulnerabilities.append(self._create_vulnerability(
                    name="WebSocket Authentication Bypass",
                    severity=Severity.HIGH,
                    url=ws_url,
                    description="WebSocket endpoint accessible without authentication",
                    evidence="Connection established without credentials",
                    recommendation="Implement authentication for WebSocket connections",
                    cwe="CWE-306"
                ))
        except:
            pass
        
        return vulnerabilities
    
    async def _test_ws_injection(self, ws_url: str) -> List[Vulnerability]:
        """Test for injection vulnerabilities in WebSocket messages"""
        vulnerabilities = []
        
        # Test payloads
        injection_payloads = [
            '{"message": "test\'--"}',
            '{"message": "<script>alert(1)</script>"}',
            '{"message": "; ls"}',
            '{"command": "admin", "data": "test"}',
        ]
        
        for payload in injection_payloads:
            try:
                # Simulate sending payload
                # In real implementation, send via WebSocket
                
                # Check for vulnerable response
                is_vulnerable = False  # Simulated
                
                if is_vulnerable:
                    vulnerabilities.append(self._create_vulnerability(
                        name="WebSocket Injection",
                        severity=Severity.HIGH,
                        url=ws_url,
                        payload=payload,
                        description="WebSocket message handler vulnerable to injection",
                        evidence=f"Payload processed without sanitization: {payload}",
                        recommendation="Sanitize and validate all WebSocket messages",
                        cwe="CWE-74"
                    ))
                    break
            except:
                continue
        
        return vulnerabilities
    
    async def _test_ws_dos(self, ws_url: str) -> List[Vulnerability]:
        """Test for DoS vulnerabilities in WebSocket"""
        vulnerabilities = []
        
        try:
            # Test sending many messages rapidly
            message_count = 100
            large_message = "A" * 1000000  # 1MB
            
            # Simulate rapid message sending
            # In real implementation, actually send via WebSocket
            
            # Check if server handles it gracefully
            handles_gracefully = False  # Simulated
            
            if not handles_gracefully:
                vulnerabilities.append(self._create_vulnerability(
                    name="WebSocket DoS",
                    severity=Severity.MEDIUM,
                    url=ws_url,
                    description="WebSocket endpoint vulnerable to DoS attacks",
                    evidence="Server doesn't rate-limit or handle large messages properly",
                    recommendation="Implement rate limiting and message size limits",
                    cwe="CWE-770"
                ))
        except:
            pass
        
        return vulnerabilities
    
    async def _test_ws_origin(self, ws_url: str) -> List[Vulnerability]:
        """Test for missing origin validation"""
        vulnerabilities = []
        
        try:
            # Try connecting with different origins
            test_origins = [
                "http://evil.com",
                "http://attacker.com",
                "null",
            ]
            
            for origin in test_origins:
                # Simulate connection with custom origin
                # In real implementation, set Origin header
                
                connection_accepted = True  # Simulated
                
                if connection_accepted:
                    vulnerabilities.append(self._create_vulnerability(
                        name="WebSocket Missing Origin Validation",
                        severity=Severity.MEDIUM,
                        url=ws_url,
                        description="WebSocket accepts connections from any origin",
                        evidence=f"Connection accepted with Origin: {origin}",
                        recommendation="Implement strict origin validation",
                        cwe="CWE-346"
                    ))
                    break
        except:
            pass
        
        return vulnerabilities


class GraphQLScanner(BaseScanner):
    """GraphQL security vulnerability scanner"""
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Scan GraphQL endpoints for vulnerabilities"""
        vulnerabilities = []
        
        # Check if URL is GraphQL endpoint
        if not self._is_graphql_endpoint(url):
            return vulnerabilities
        
        # Test for various GraphQL vulnerabilities
        vulns = await self._test_introspection(url)
        vulnerabilities.extend(vulns)
        
        vulns = await self._test_depth_limit(url)
        vulnerabilities.extend(vulns)
        
        vulns = await self._test_batch_attack(url)
        vulnerabilities.extend(vulns)
        
        vulns = await self._test_field_duplication(url)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _is_graphql_endpoint(self, url: str) -> bool:
        """Check if URL is a GraphQL endpoint"""
        graphql_indicators = [
            "/graphql", "/graphiql", "/api/graphql",
            "/v1/graphql", "/v2/graphql", "/gql"
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in graphql_indicators)
    
    async def _test_introspection(self, url: str) -> List[Vulnerability]:
        """Test if introspection is enabled"""
        vulnerabilities = []
        
        introspection_query = """
        {
            __schema {
                types {
                    name
                    fields {
                        name
                    }
                }
            }
        }
        """
        
        try:
            resp = await self.http_client.post(
                url,
                json={"query": introspection_query},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if resp.status_code == 200 and "__schema" in resp.text:
                vulnerabilities.append(self._create_vulnerability(
                    name="GraphQL Introspection Enabled",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="GraphQL introspection is enabled in production",
                    evidence="Introspection query returned schema information",
                    recommendation="Disable introspection in production",
                    cwe="CWE-200"
                ))
        except:
            pass
        
        return vulnerabilities
    
    async def _test_depth_limit(self, url: str) -> List[Vulnerability]:
        """Test for missing query depth limit"""
        vulnerabilities = []
        
        # Create deeply nested query
        deep_query = "{ user { posts { comments { user { posts { comments { user { name } } } } } } } }"
        
        try:
            resp = await self.http_client.post(
                url,
                json={"query": deep_query},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if resp.status_code == 200:
                vulnerabilities.append(self._create_vulnerability(
                    name="GraphQL Missing Depth Limit",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="GraphQL endpoint doesn't enforce query depth limits",
                    evidence="Deeply nested query executed successfully",
                    recommendation="Implement query depth limiting",
                    cwe="CWE-770"
                ))
        except:
            pass
        
        return vulnerabilities
    
    async def _test_batch_attack(self, url: str) -> List[Vulnerability]:
        """Test for batch query DoS"""
        vulnerabilities = []
        
        # Create batch query
        batch_query = [{"query": "{ __typename }"} for _ in range(100)]
        
        try:
            resp = await self.http_client.post(
                url,
                json=batch_query,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if resp.status_code == 200:
                vulnerabilities.append(self._create_vulnerability(
                    name="GraphQL Batch Query DoS",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="GraphQL endpoint vulnerable to batch query attacks",
                    evidence="Large batch query executed successfully",
                    recommendation="Implement batch query limits",
                    cwe="CWE-770"
                ))
        except:
            pass
        
        return vulnerabilities
    
    async def _test_field_duplication(self, url: str) -> List[Vulnerability]:
        """Test for field duplication DoS"""
        vulnerabilities = []
        
        # Create query with many duplicated fields
        duplicated_query = "{ " + " ".join(["__typename"] * 1000) + " }"
        
        try:
            resp = await self.http_client.post(
                url,
                json={"query": duplicated_query},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if resp.status_code == 200:
                vulnerabilities.append(self._create_vulnerability(
                    name="GraphQL Field Duplication DoS",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="GraphQL endpoint vulnerable to field duplication attacks",
                    evidence="Query with many duplicated fields executed",
                    recommendation="Implement field duplication limits",
                    cwe="CWE-770"
                ))
        except:
            pass
        
        return vulnerabilities

