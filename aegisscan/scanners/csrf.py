"""
CSRF (Cross-Site Request Forgery) Scanner
"""
import re
from typing import List, Optional, Dict
from .base import BaseScanner, Vulnerability, Severity
from ..http.client import Response


class CSRFScanner(BaseScanner):
    """CSRF vulnerability scanner"""
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "GET", **kwargs) -> List[Vulnerability]:
        """Scan for CSRF vulnerabilities"""
        vulnerabilities = []
        
        # CSRF analysis is typically done on forms
        # First, get the page to analyze forms
        try:
            resp = await self.http_client.get(url)
            
            # Extract forms
            forms = self._extract_forms(resp.text)
            
            for form in forms:
                # Check for CSRF protection
                csrf_issues = self._analyze_form_csrf(form, resp)
                
                for issue in csrf_issues:
                    vulnerabilities.append(issue)
        except:
            pass
        
        return vulnerabilities
    
    def _extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        
        # Find all form tags
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL)
        
        for match in form_matches:
            form_html = match.group(0)
            form_content = match.group(1)
            
            # Extract form attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            form_data = {
                "html": form_html,
                "content": form_content,
                "action": action_match.group(1) if action_match else "",
                "method": (method_match.group(1) if method_match else "GET").upper(),
                "inputs": []
            }
            
            # Extract input fields
            input_pattern = r'<input[^>]*>'
            input_matches = re.finditer(input_pattern, form_content, re.IGNORECASE)
            
            for input_match in input_matches:
                input_html = input_match.group(0)
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                
                if name_match:
                    form_data["inputs"].append({
                        "name": name_match.group(1),
                        "type": type_match.group(1) if type_match else "text",
                        "value": value_match.group(1) if value_match else "",
                        "html": input_html
                    })
            
            forms.append(form_data)
        
        return forms
    
    def _analyze_form_csrf(self, form: Dict, response: Response) -> List[Vulnerability]:
        """Analyze form for CSRF protection"""
        issues = []
        
        # Check if form has CSRF token
        csrf_tokens = self._find_csrf_tokens(form["html"])
        
        # Only analyze state-changing operations (POST, PUT, DELETE)
        if form["method"] in ["POST", "PUT", "DELETE"]:
            if not csrf_tokens:
                issues.append(self._create_vulnerability(
                    name="Missing CSRF Protection",
                    severity=Severity.MEDIUM,
                    url=response.url,
                    parameter=None,
                    payload=None,
                    description=f"Form with {form['method']} method lacks CSRF protection",
                    evidence=f"Form action: {form['action']}, Method: {form['method']}",
                    recommendation="Implement CSRF tokens. Use SameSite cookie attribute. Validate Origin/Referer headers.",
                    cwe="CWE-352"
                ))
            else:
                # Check token strength
                for token in csrf_tokens:
                    if len(token.get("value", "")) < 16:
                        issues.append(self._create_vulnerability(
                            name="Weak CSRF Token",
                            severity=Severity.LOW,
                            url=response.url,
                            parameter=token.get("name"),
                            payload=None,
                            description="CSRF token is too short or weak",
                            evidence=f"Token length: {len(token.get('value', ''))}",
                            recommendation="Use cryptographically strong CSRF tokens (minimum 32 characters).",
                            cwe="CWE-352"
                        ))
        
        return issues
    
    def _find_csrf_tokens(self, html: str) -> List[Dict]:
        """Find CSRF tokens in HTML"""
        tokens = []
        
        # Common CSRF token patterns
        patterns = [
            r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']',
            r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']',
            r'name=["\']authenticity_token["\']\s+value=["\']([^"\']+)["\']',
            r'name=["\']csrf["\']\s+value=["\']([^"\']+)["\']',
            r'name=["\']_csrf["\']\s+value=["\']([^"\']+)["\']',
            r'csrf-token["\']\s+content=["\']([^"\']+)["\']',
            r'X-CSRF-Token["\']\s+content=["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                tokens.append({
                    "name": "csrf_token",
                    "value": match.group(1) if match.groups() else ""
                })
        
        return tokens

