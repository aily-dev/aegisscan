"""
GraphQL Security Scanner
Tests for GraphQL-specific vulnerabilities
"""
import json
import re
import time
from typing import List, Optional, Dict, Any
from .base import BaseScanner, Vulnerability, Severity


class GraphQLScanner(BaseScanner):
    """GraphQL security vulnerability scanner"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "GraphQL Security Scanner"
        
        # GraphQL introspection query
        self.introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }
        
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }
        
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Scan GraphQL endpoints for vulnerabilities"""
        vulnerabilities = []
        
        # Find GraphQL endpoints
        graphql_endpoints = await self._discover_graphql_endpoints(url)
        
        if not graphql_endpoints:
            # Try common GraphQL paths
            common_paths = [
                "/graphql",
                "/graphiql",
                "/api/graphql",
                "/v1/graphql",
                "/v2/graphql",
                "/gql",
                "/query",
                "/graphql/query"
            ]
            
            for path in common_paths:
                test_url = url.rstrip('/') + path
                if await self._is_graphql_endpoint(test_url):
                    graphql_endpoints.append(test_url)
        
        if not graphql_endpoints:
            return vulnerabilities
        
        # Test each GraphQL endpoint
        for endpoint in graphql_endpoints:
            vulns = await self._test_graphql_endpoint(endpoint)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _discover_graphql_endpoints(self, url: str) -> List[str]:
        """Discover GraphQL endpoints from the target"""
        endpoints = []
        
        try:
            resp = await self.http_client.get(url, timeout=10)
            
            # Look for GraphQL endpoints in HTML/JS
            graphql_patterns = [
                r'["\'](/graphql[^"\']*)["\']',
                r'["\'](/graphiql[^"\']*)["\']',
                r'["\'](/api/graphql[^"\']*)["\']',
                r'graphql["\']?\s*:\s*["\']([^"\']+)["\']',
                r'endpoint["\']?\s*:\s*["\']([^"\']*graphql[^"\']*)["\']',
            ]
            
            for pattern in graphql_patterns:
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                for match in matches:
                    if match.startswith('/'):
                        endpoint = url.rstrip('/') + match
                    elif match.startswith('http'):
                        endpoint = match
                    else:
                        endpoint = url.rstrip('/') + '/' + match
                    
                    if endpoint not in endpoints:
                        endpoints.append(endpoint)
        except:
            pass
        
        return endpoints
    
    async def _is_graphql_endpoint(self, url: str) -> bool:
        """Check if URL is a GraphQL endpoint"""
        try:
            # Try a simple GraphQL query
            test_query = {"query": "{ __typename }"}
            
            resp = await self.http_client.post(
                url,
                json=test_query,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data or "errors" in data:
                        return True
                except:
                    pass
            
            # Try GET request
            resp = await self.http_client.get(
                url + "?query={__typename}",
                timeout=5
            )
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data or "errors" in data:
                        return True
                except:
                    pass
        except:
            pass
        
        return False
    
    async def _test_graphql_endpoint(self, endpoint: str) -> List[Vulnerability]:
        """Test a GraphQL endpoint for vulnerabilities"""
        vulnerabilities = []
        
        # Test 1: Introspection enabled
        vuln = await self._test_introspection(endpoint)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test 2: Query depth limit
        vuln = await self._test_query_depth_limit(endpoint)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test 3: Query complexity limit
        vuln = await self._test_query_complexity(endpoint)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test 4: Field duplication DoS
        vuln = await self._test_field_duplication(endpoint)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test 5: Batch query DoS
        vuln = await self._test_batch_query(endpoint)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test 6: Authorization bypass
        vuln = await self._test_authorization_bypass(endpoint)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test 7: GraphQL injection
        vuln = await self._test_graphql_injection(endpoint)
        if vuln:
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_introspection(self, endpoint: str) -> Optional[Vulnerability]:
        """Test if GraphQL introspection is enabled"""
        try:
            query = {"query": self.introspection_query}
            
            resp = await self.http_client.post(
                endpoint,
                json=query,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        return self._create_vulnerability(
                            name="GraphQL Introspection Enabled",
                            severity=Severity.HIGH,
                            url=endpoint,
                            description="GraphQL introspection is enabled in production, exposing the entire schema",
                            evidence="Introspection query returned schema data",
                            recommendation="Disable GraphQL introspection in production environments",
                            cwe="CWE-200"
                        )
                except:
                    pass
        except:
            pass
        
        return None
    
    async def _test_query_depth_limit(self, endpoint: str) -> Optional[Vulnerability]:
        """Test for query depth limit"""
        try:
            # Create a deep nested query
            deep_query = "{"
            for i in range(20):
                deep_query += f"level{i} {{"
            deep_query += "__typename " * 20
            deep_query += "}" * 20
            deep_query += "}"
            
            query = {"query": deep_query}
            
            resp = await self.http_client.post(
                endpoint,
                json=query,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data and "errors" not in data:
                        return self._create_vulnerability(
                            name="GraphQL Missing Depth Limit",
                            severity=Severity.MEDIUM,
                            url=endpoint,
                            description="GraphQL endpoint doesn't enforce query depth limits, vulnerable to DoS",
                            evidence="Deep nested query (depth 20) executed successfully",
                            recommendation="Implement query depth limiting (max depth: 5-10)",
                            cwe="CWE-400"
                        )
                except:
                    pass
        except:
            pass
        
        return None
    
    async def _test_query_complexity(self, endpoint: str) -> Optional[Vulnerability]:
        """Test for query complexity limit"""
        try:
            # Create a complex query with many fields
            complex_query = "{"
            for i in range(100):
                complex_query += f"field{i} {{ __typename }} "
            complex_query += "}"
            
            query = {"query": complex_query}
            
            resp = await self.http_client.post(
                endpoint,
                json=query,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data and "errors" not in data:
                        return self._create_vulnerability(
                            name="GraphQL Missing Complexity Limit",
                            severity=Severity.MEDIUM,
                            url=endpoint,
                            description="GraphQL endpoint doesn't enforce query complexity limits",
                            evidence="Complex query with 100 fields executed successfully",
                            recommendation="Implement query complexity limiting",
                            cwe="CWE-400"
                        )
                except:
                    pass
        except:
            pass
        
        return None
    
    async def _test_field_duplication(self, endpoint: str) -> Optional[Vulnerability]:
        """Test for field duplication DoS"""
        try:
            # Create query with duplicated fields
            dup_query = "{"
            for i in range(50):
                dup_query += "user { id name email } " * 10
            dup_query += "}"
            
            query = {"query": dup_query}
            
            start_time = time.time()
            resp = await self.http_client.post(
                endpoint,
                json=query,
                headers={"Content-Type": "application/json"},
                timeout=15
            )
            elapsed = time.time() - start_time
            
            if resp.status_code == 200 and elapsed > 5:
                return self._create_vulnerability(
                    name="GraphQL Field Duplication DoS",
                    severity=Severity.MEDIUM,
                    url=endpoint,
                    description="GraphQL endpoint vulnerable to field duplication DoS attacks",
                    evidence=f"Field duplication query took {elapsed:.2f}s to execute",
                    recommendation="Implement field deduplication or limit field repetition",
                    cwe="CWE-400"
                )
        except:
            pass
        
        return None
    
    async def _test_batch_query(self, endpoint: str) -> Optional[Vulnerability]:
        """Test for batch query DoS"""
        try:
            # Create batch of queries
            batch = []
            for i in range(100):
                batch.append({"query": "{ __typename }"})
            
            resp = await self.http_client.post(
                endpoint,
                json=batch,
                headers={"Content-Type": "application/json"},
                timeout=15
            )
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 0:
                        return self._create_vulnerability(
                            name="GraphQL Batch Query DoS",
                            severity=Severity.MEDIUM,
                            url=endpoint,
                            description="GraphQL endpoint accepts batch queries, vulnerable to DoS",
                            evidence="Batch query with 100 queries executed successfully",
                            recommendation="Disable batch query support or implement rate limiting",
                            cwe="CWE-400"
                        )
                except:
                    pass
        except:
            pass
        
        return None
    
    async def _test_authorization_bypass(self, endpoint: str) -> Optional[Vulnerability]:
        """Test for authorization bypass"""
        try:
            # Try to access admin/user queries without authentication
            admin_queries = [
                "{ users { id email password } }",
                "{ admin { id role } }",
                "{ me { id role permissions } }",
                "{ __schema { queryType { fields { name } } } }"
            ]
            
            for query_str in admin_queries:
                query = {"query": query_str}
                
                resp = await self.http_client.post(
                    endpoint,
                    json=query,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data and data.get("data") and "errors" not in data:
                            return self._create_vulnerability(
                                name="GraphQL Authorization Bypass",
                                severity=Severity.HIGH,
                                url=endpoint,
                                description="GraphQL endpoint allows unauthorized access to sensitive queries",
                                evidence=f"Unauthorized query executed: {query_str[:50]}...",
                                recommendation="Implement proper authorization checks for all GraphQL queries",
                                cwe="CWE-284"
                            )
                    except:
                        pass
        except:
            pass
        
        return None
    
    async def _test_graphql_injection(self, endpoint: str) -> Optional[Vulnerability]:
        """Test for GraphQL injection (GQLi)"""
        try:
            # Test injection in query parameters
            injection_payloads = [
                "{ __typename } #",
                "{ __typename } /*",
                "{ __typename } union",
                "query { __typename } mutation { __typename }",
            ]
            
            for payload in injection_payloads:
                query = {"query": payload}
                
                resp = await self.http_client.post(
                    endpoint,
                    json=query,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        # Check if multiple queries executed
                        if "data" in data and isinstance(data.get("data"), dict):
                            if len(data["data"]) > 1:
                                return self._create_vulnerability(
                                    name="GraphQL Injection (GQLi)",
                                    severity=Severity.HIGH,
                                    url=endpoint,
                                    description="GraphQL endpoint vulnerable to query injection",
                                    evidence=f"Injection payload executed: {payload}",
                                    recommendation="Sanitize and validate all GraphQL query inputs",
                                    cwe="CWE-89"
                                )
                    except:
                        pass
        except:
            pass
        
        return None

