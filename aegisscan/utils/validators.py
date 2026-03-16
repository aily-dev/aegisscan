"""
Input Validators and Sanitizers
"""
import re
from typing import Optional, List, Tuple
from urllib.parse import urlparse


class URLValidator:
    """URL validation utilities"""
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def is_internal_url(url: str) -> bool:
        """Check if URL is internal/localhost"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc.split(':')[0].lower()
            
            internal_hosts = [
                "localhost", "127.0.0.1", "0.0.0.0",
                "::1", "169.254.169.254",
            ]
            
            if host in internal_hosts:
                return True
            
            # Check for private IP ranges
            if host.startswith("10.") or host.startswith("192.168.") or host.startswith("172."):
                return True
            
            return False
        except:
            return False
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL"""
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        
        # Remove trailing slash
        url = url.rstrip('/')
        
        return url


class ParameterValidator:
    """Parameter validation utilities"""
    
    @staticmethod
    def extract_parameters_from_url(url: str) -> dict:
        """Extract parameters from URL"""
        params = {}
        if "?" in url:
            query_string = url.split("?")[1].split("#")[0]
            for param in query_string.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    params[key] = value
        return params
    
    @staticmethod
    def is_sql_injection_payload(payload: str) -> bool:
        """Check if payload looks like SQL injection"""
        sql_patterns = [
            r"['\"]\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"union\s+select",
            r"waitfor\s+delay",
            r"sleep\s*\(",
            r"benchmark\s*\(",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def is_xss_payload(payload: str) -> bool:
        """Check if payload looks like XSS"""
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<img[^>]*onerror",
            r"<svg[^>]*onload",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        
        return False


class ResponseValidator:
    """Response validation utilities"""
    
    @staticmethod
    def is_error_response(response) -> bool:
        """Check if response is an error"""
        return response.status_code >= 400
    
    @staticmethod
    def is_redirect_response(response) -> bool:
        """Check if response is a redirect"""
        return response.status_code in [301, 302, 303, 307, 308]
    
    @staticmethod
    def is_success_response(response) -> bool:
        """Check if response is successful"""
        return 200 <= response.status_code < 300
    
    @staticmethod
    def get_response_size(response) -> int:
        """Get response size in bytes"""
        return len(response.content)
    
    @staticmethod
    def compare_responses(resp1, resp2) -> dict:
        """Compare two responses"""
        return {
            "status_diff": resp1.status_code != resp2.status_code,
            "size_diff": abs(len(resp1.content) - len(resp2.content)),
            "header_diff": set(resp1.headers.keys()) != set(resp2.headers.keys()),
        }

