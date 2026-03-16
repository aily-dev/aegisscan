"""
Nuclei-like Template Engine
"""
import yaml
import re
import asyncio
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging
from ..http.client import AsyncHTTPClient, Response


class TemplateEngine:
    """YAML-based template execution engine"""
    
    def __init__(self, http_client: AsyncHTTPClient):
        self.http_client = http_client
        self.templates: Dict[str, Dict] = {}
        self._logger = logging.getLogger(__name__)
    
    def load_template(self, template_path: str) -> Dict:
        """Load a YAML template"""
        with open(template_path, 'r') as f:
            template = yaml.safe_load(f)
        
        template_id = template.get('id', Path(template_path).stem)
        self.templates[template_id] = template
        return template
    
    def load_templates_from_dir(self, directory: str):
        """Load all templates from a directory"""
        template_dir = Path(directory)
        for template_file in template_dir.glob("*.yaml"):
            try:
                self.load_template(str(template_file))
            except Exception as e:
                self._logger.error(f"Error loading template {template_file}: {e}")
    
    async def execute_template(self, template_id: str, target: str, variables: Optional[Dict] = None) -> List[Dict]:
        """Execute a template against a target"""
        if template_id not in self.templates:
            raise ValueError(f"Template {template_id} not found")
        
        template = self.templates[template_id]
        variables = variables or {}
        
        results = []
        
        # Execute requests
        requests = template.get('requests', [])
        if not requests:
            # Single request format
            requests = [template]
        
        for req_template in requests:
            result = await self._execute_request(req_template, target, variables)
            if result:
                results.append(result)
        
        return results
    
    async def _execute_request(self, req_template: Dict, target: str, variables: Dict) -> Optional[Dict]:
        """Execute a single request from template"""
        # Build URL
        path = req_template.get('path', '/')
        # Replace variables
        path = self._replace_variables(path, variables)
        
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        url = f"{target.rstrip('/')}{path}"
        
        # Build method
        method = req_template.get('method', 'GET').upper()
        
        # Build headers
        headers = {}
        template_headers = req_template.get('headers', {})
        for key, value in template_headers.items():
            headers[key] = self._replace_variables(str(value), variables)
        
        # Build body
        body = req_template.get('body', '')
        if body:
            body = self._replace_variables(body, variables)
        
        # Build matchers
        matchers = req_template.get('matchers', [])
        
        try:
            # Execute request
            if method == 'GET':
                resp = await self.http_client.get(url, headers=headers, params=req_template.get('params'))
            elif method == 'POST':
                resp = await self.http_client.post(url, headers=headers, data=body)
            elif method == 'PUT':
                resp = await self.http_client.put(url, headers=headers, data=body)
            elif method == 'DELETE':
                resp = await self.http_client.delete(url, headers=headers)
            else:
                resp = await self.http_client.request(method, url, headers=headers, data=body)
            
            # Check matchers
            matched = self._check_matchers(resp, matchers)
            
            if matched:
                return {
                    "template_id": req_template.get('id', 'unknown'),
                    "matched": True,
                    "url": url,
                    "status_code": resp.status_code,
                    "matchers": matched,
                    "response": {
                        "status_code": resp.status_code,
                        "headers": dict(resp.headers),
                        "body_length": len(resp.content),
                    }
                }
        except Exception as e:
            self._logger.debug(f"Template execution error: {e}")
        
        return None
    
    def _replace_variables(self, text: str, variables: Dict) -> str:
        """Replace variables in text"""
        for key, value in variables.items():
            text = text.replace(f"{{{{{key}}}}}", str(value))
        return text
    
    def _check_matchers(self, response: Response, matchers: List[Dict]) -> List[Dict]:
        """Check if response matches any matcher"""
        matched = []
        
        for matcher in matchers:
            match_type = matcher.get('type', 'word')
            condition = matcher.get('condition', 'or')
            match_part = matcher.get('part', 'body')  # body, header, status
            
            if match_type == 'status':
                status = matcher.get('status', [])
                if isinstance(status, int):
                    status = [status]
                if response.status_code in status:
                    matched.append(matcher)
            
            elif match_type == 'word':
                words = matcher.get('words', [])
                if isinstance(words, str):
                    words = [words]
                
                text = self._get_match_part(response, match_part)
                
                for word in words:
                    if word in text:
                        matched.append(matcher)
                        break
            
            elif match_type == 'regex':
                regex = matcher.get('regex', '')
                text = self._get_match_part(response, match_part)
                
                if re.search(regex, text, re.IGNORECASE | re.MULTILINE):
                    matched.append(matcher)
            
            elif match_type == 'binary':
                binary = matcher.get('binary', [])
                if isinstance(binary, bytes):
                    binary = [binary]
                
                content = response.content
                for pattern in binary:
                    if pattern in content:
                        matched.append(matcher)
                        break
        
        return matched
    
    def _get_match_part(self, response: Response, part: str) -> str:
        """Get the part of response to match against"""
        if part == 'body':
            return response.text
        elif part == 'header':
            return str(response.headers)
        elif part == 'status':
            return str(response.status_code)
        else:
            return response.text

