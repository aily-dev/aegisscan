"""
Directory Bruteforce Module
"""
import asyncio
from typing import List, Dict, Optional
import logging
from ..http.client import Response


class DirectoryBruteforcer:
    """Directory and file bruteforcer"""
    
    def __init__(self, http_client):
        self.http_client = http_client
        self._logger = logging.getLogger(__name__)
        
        # Common directory wordlist
        self.wordlist = [
            "admin", "administrator", "api", "app", "assets", "backup", "backups",
            "bin", "blog", "cache", "config", "css", "data", "database", "db",
            "dev", "development", "doc", "docs", "download", "downloads", "etc",
            "files", "forum", "ftp", "git", "help", "home", "images", "img",
            "include", "includes", "index", "install", "js", "lib", "libs",
            "log", "logs", "mail", "media", "mobile", "old", "panel", "php",
            "private", "public", "readme", "remote", "rest", "root", "scripts",
            "secure", "server", "site", "sites", "src", "static", "stats",
            "store", "test", "tmp", "tools", "upload", "uploads", "user",
            "users", "var", "vendor", "web", "webapp", "www", "xml",
            ".git", ".svn", ".env", ".htaccess", ".htpasswd", "robots.txt",
            "sitemap.xml", "crossdomain.xml", "phpinfo.php", "info.php",
            "test.php", "admin.php", "config.php", "wp-config.php",
        ]
    
    async def bruteforce(
        self,
        base_url: str,
        wordlist: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
        status_codes: List[int] = [200, 201, 204, 301, 302, 307, 401, 403],
        max_workers: int = 10
    ) -> List[Dict]:
        """Bruteforce directories and files"""
        found = []
        wordlist = wordlist or self.wordlist
        extensions = extensions or []
        
        # Normalize base URL
        if not base_url.endswith("/"):
            base_url += "/"
        
        # Create tasks
        tasks = []
        for word in wordlist:
            # Test directory
            tasks.append(self._test_path(f"{base_url}{word}/", status_codes))
            
            # Test file with extensions
            for ext in extensions:
                tasks.append(self._test_path(f"{base_url}{word}.{ext}", status_codes))
            
            # Test file without extension
            tasks.append(self._test_path(f"{base_url}{word}", status_codes))
        
        # Execute with concurrency limit
        semaphore = asyncio.Semaphore(max_workers)
        
        async def bounded_test(path, codes):
            async with semaphore:
                return await self._test_path(path, codes)
        
        bounded_tasks = [bounded_test(path, status_codes) for path in [t[0] for t in [(f"{base_url}{w}/", status_codes) for w in wordlist]]]
        
        # Simplified execution
        results = []
        for word in wordlist:
            # Test directory
            result = await self._test_path(f"{base_url}{word}/", status_codes)
            if result:
                found.append(result)
            
            # Test file
            result = await self._test_path(f"{base_url}{word}", status_codes)
            if result:
                found.append(result)
            
            # Test with extensions
            for ext in extensions:
                result = await self._test_path(f"{base_url}{word}.{ext}", status_codes)
                if result:
                    found.append(result)
        
        return found
    
    async def _test_path(self, url: str, status_codes: List[int]) -> Optional[Dict]:
        """Test if a path exists"""
        try:
            resp = await self.http_client.get(url, timeout=5)
            
            if resp.status_code in status_codes:
                return {
                    "url": url,
                    "status_code": resp.status_code,
                    "size": len(resp.content),
                    "title": self._extract_title(resp.text),
                }
        except:
            pass
        
        return None
    
    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        import re
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]
        return ""
    
    async def test_403_bypass(self, url: str) -> List[str]:
        """Test 403 bypass techniques"""
        bypasses = []
        
        bypass_payloads = [
            f"{url}/..",
            f"{url}/..;/",
            f"{url}/%2e%2e/",
            f"{url}/%2e%2e%2f",
            f"{url}/..%2f",
            f"{url}/%252e%252e/",
            f"{url}?",
            f"{url}??",
            f"{url}#",
            f"{url}/*",
            f"{url}/%20",
            f"{url}/%09",
            f"{url}/%00",
            f"{url}/%0d%0a",
            f"{url}/%0d",
            f"{url}/%0a",
        ]
        
        for payload in bypass_payloads:
            try:
                resp = await self.http_client.get(payload, timeout=5)
                if resp.status_code == 200:
                    bypasses.append(payload)
            except:
                continue
        
        return bypasses

