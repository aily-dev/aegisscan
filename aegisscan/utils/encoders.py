"""
Encoding and Decoding Utilities
"""
import base64
import urllib.parse
from typing import List


class URLEncoder:
    """URL encoding utilities"""
    
    @staticmethod
    def encode(text: str) -> str:
        """URL encode"""
        return urllib.parse.quote(text)
    
    @staticmethod
    def double_encode(text: str) -> str:
        """Double URL encode"""
        return urllib.parse.quote(urllib.parse.quote(text))
    
    @staticmethod
    def encode_all(text: str) -> str:
        """Encode all characters"""
        return ''.join(f'%{ord(c):02x}' for c in text)
    
    @staticmethod
    def unicode_encode(text: str) -> str:
        """Unicode encode"""
        return ''.join(f'\\u{ord(c):04x}' for c in text)


class Base64Encoder:
    """Base64 encoding utilities"""
    
    @staticmethod
    def encode(text: str) -> str:
        """Base64 encode"""
        return base64.b64encode(text.encode()).decode()
    
    @staticmethod
    def decode(encoded: str) -> str:
        """Base64 decode"""
        try:
            return base64.b64decode(encoded).decode()
        except:
            return ""
    
    @staticmethod
    def url_safe_encode(text: str) -> str:
        """URL-safe base64 encode"""
        return base64.urlsafe_b64encode(text.encode()).decode().rstrip('=')


class HexEncoder:
    """Hexadecimal encoding utilities"""
    
    @staticmethod
    def encode(text: str) -> str:
        """Hex encode"""
        return text.encode().hex()
    
    @staticmethod
    def decode(encoded: str) -> str:
        """Hex decode"""
        try:
            return bytes.fromhex(encoded).decode()
        except:
            return ""


class HTMLEncoder:
    """HTML encoding utilities"""
    
    @staticmethod
    def encode(text: str) -> str:
        """HTML encode"""
        return urllib.parse.quote(text)
    
    @staticmethod
    def entity_encode(text: str) -> str:
        """HTML entity encode"""
        entities = {
            '<': '&lt;',
            '>': '&gt;',
            '&': '&amp;',
            '"': '&quot;',
            "'": '&#x27;',
        }
        result = text
        for char, entity in entities.items():
            result = result.replace(char, entity)
        return result


class PayloadEncoder:
    """Payload encoding for bypass techniques"""
    
    @staticmethod
    def sql_bypass_payloads(payload: str) -> List[str]:
        """Generate SQL injection bypass payloads"""
        return [
            payload,
            payload.replace(" ", "/**/"),
            payload.replace(" ", "+"),
            payload.replace(" ", "%20"),
            payload.replace(" ", "%09"),
            payload.replace("'", "''"),
            payload.replace("'", "\\'"),
            payload.replace("OR", "Or"),
            payload.replace("OR", "oR"),
            payload.replace("OR", "Or"),
        ]
    
    @staticmethod
    def xss_bypass_payloads(payload: str) -> List[str]:
        """Generate XSS bypass payloads"""
        return [
            payload,
            payload.replace("<", "&lt;"),
            payload.replace("<", "%3C"),
            payload.replace(">", "%3E"),
            payload.replace(" ", "%20"),
            payload.replace("'", "\\'"),
            payload.replace('"', '\\"'),
        ]

