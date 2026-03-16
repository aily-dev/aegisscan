"""
Helper Utilities
"""
import hashlib
import time
from typing import Optional, Dict, List
from urllib.parse import urlparse, urljoin, parse_qs
import re


class URLHelper:
    """URL manipulation helpers"""
    
    @staticmethod
    def join_urls(base: str, path: str) -> str:
        """Join URLs safely"""
        return urljoin(base, path)
    
    @staticmethod
    def get_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.split(':')[0]
        except:
            return ""
    
    @staticmethod
    def get_path(url: str) -> str:
        """Extract path from URL"""
        try:
            parsed = urlparse(url)
            return parsed.path
        except:
            return ""
    
    @staticmethod
    def normalize_path(path: str) -> str:
        """Normalize URL path"""
        # Remove double slashes
        path = re.sub(r'/+', '/', path)
        # Ensure starts with /
        if not path.startswith('/'):
            path = '/' + path
        return path


class HashHelper:
    """Hashing utilities"""
    
    @staticmethod
    def md5_hash(data: str) -> str:
        """Calculate MD5 hash"""
        return hashlib.md5(data.encode()).hexdigest()
    
    @staticmethod
    def sha256_hash(data: str) -> str:
        """Calculate SHA256 hash"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def hash_response(response) -> str:
        """Hash HTTP response"""
        content = f"{response.status_code}{response.text}"
        return HashHelper.sha256_hash(content)


class TimingHelper:
    """Timing utilities"""
    
    @staticmethod
    async def measure_time(coro):
        """Measure execution time of coroutine"""
        start = time.time()
        result = await coro
        elapsed = time.time() - start
        return result, elapsed
    
    @staticmethod
    def is_delayed(elapsed: float, baseline: float, threshold: float = 2.0) -> bool:
        """Check if elapsed time is significantly delayed"""
        return elapsed > (baseline * threshold)


class PatternMatcher:
    """Pattern matching utilities"""
    
    @staticmethod
    def find_patterns(text: str, patterns: List[str]) -> List[Dict]:
        """Find all patterns in text"""
        matches = []
        for pattern in patterns:
            regex_matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in regex_matches:
                matches.append({
                    "pattern": pattern,
                    "match": match.group(0),
                    "position": match.start(),
                })
        return matches
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extract email addresses"""
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(pattern, text)))
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text"""
        pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
        return list(set(re.findall(pattern, text)))
    
    @staticmethod
    def extract_ips(text: str) -> List[str]:
        """Extract IP addresses"""
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return list(set(re.findall(pattern, text)))


class DataExtractor:
    """Data extraction utilities"""
    
    @staticmethod
    def extract_json(text: str) -> Optional[Dict]:
        """Extract JSON from text"""
        import json
        try:
            # Try to find JSON object
            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text)
            if json_match:
                return json.loads(json_match.group(0))
        except:
            pass
        return None
    
    @staticmethod
    def extract_base64(text: str) -> List[str]:
        """Extract base64 encoded strings"""
        pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(pattern, text)
        # Filter by length (base64 strings are typically longer)
        return [m for m in matches if len(m) >= 20]
    
    @staticmethod
    def extract_hex(text: str) -> List[str]:
        """Extract hexadecimal strings"""
        pattern = r'\b[0-9a-fA-F]{16,}\b'
        return list(set(re.findall(pattern, text)))

