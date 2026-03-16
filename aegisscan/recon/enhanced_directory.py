"""
Enhanced Directory Bruteforcer with Multiple Wordlists
"""
import asyncio
from typing import List, Dict, Optional, Set
import logging
from ..http.client import Response
from ..utils.wordlists import WordlistManager
from ..native_dirbruteforce_interface import generate_candidate_urls


class EnhancedDirectoryBruteforcer:
    """Enhanced directory and file bruteforcer with wordlist support"""
    
    def __init__(self, http_client, wordlist_manager: Optional[WordlistManager] = None):
        self.http_client = http_client
        self.wordlist_manager = wordlist_manager or WordlistManager()
        self._logger = logging.getLogger(__name__)
        
        # Status codes that indicate success
        self.success_codes = [200, 201, 204, 301, 302, 307, 401, 403]
        
        # Status codes that indicate redirect
        self.redirect_codes = [301, 302, 303, 307, 308]
    
    async def bruteforce(
        self,
        base_url: str,
        wordlist: Optional[List[str]] = None,
        wordlist_categories: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
        status_codes: List[int] = None,
        max_workers: int = 20,
        follow_redirects: bool = False
    ) -> List[Dict]:
        """Bruteforce directories and files with wordlists
        
        Args:
            base_url: Base URL to bruteforce
            wordlist: Custom wordlist (overrides categories)
            wordlist_categories: Categories to use (directories, sensitive_files, etc.)
            extensions: File extensions to try
            status_codes: Status codes to consider as success
            max_workers: Maximum concurrent workers
            follow_redirects: Follow redirects
        
        Returns:
            List of found directories/files
        """
        found = []
        status_codes = status_codes or self.success_codes
        
        # Get wordlist
        if wordlist:
            words = wordlist
        elif wordlist_categories:
            words = self.wordlist_manager.get_combined_wordlist(wordlist_categories)
        else:
            # Default: use directories and sensitive_files
            words = self.wordlist_manager.get_combined_wordlist(["directories", "sensitive_files"])
        
        # Get extensions
        if extensions is None:
            extensions = self.wordlist_manager.get_wordlist("file_extensions")
        
        # Create semaphore for rate limiting
        semaphore = asyncio.Semaphore(max_workers)
        
        # Generate candidate URLs (optionally using C++ helper)
        candidate_urls = generate_candidate_urls(
            base_url=base_url,
            words=words,
            extensions=extensions,
            max_exts_per_word=10,
        )
        
        # Test all candidate URLs
        tasks = [
            self._test_path_with_semaphore(
                semaphore, url, status_codes, follow_redirects
            )
            for url in candidate_urls
        ]
        
        # Execute all tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect results
        for result in results:
            if isinstance(result, dict) and result:
                found.append(result)
            elif isinstance(result, Exception):
                self._logger.debug(f"Bruteforce error: {result}")
        
        # Remove duplicates
        seen = set()
        unique_found = []
        for item in found:
            url_key = item["url"]
            if url_key not in seen:
                seen.add(url_key)
                unique_found.append(item)
        
        return unique_found
    
    async def _test_path_with_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        url: str,
        status_codes: List[int],
        follow_redirects: bool
    ) -> Optional[Dict]:
        """Test path with semaphore for concurrency control"""
        async with semaphore:
            return await self._test_path(url, status_codes, follow_redirects)
    
    async def _test_path(
        self,
        url: str,
        status_codes: List[int],
        follow_redirects: bool
    ) -> Optional[Dict]:
        """Test if a path exists"""
        try:
            resp = await self.http_client.get(
                url,
                timeout=5,
                allow_redirects=follow_redirects
            )
            
            if resp.status_code in status_codes:
                result = {
                    "url": url,
                    "status_code": resp.status_code,
                    "size": len(resp.content),
                    "title": self._extract_title(resp.text),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "server": resp.headers.get("Server", ""),
                }
                
                # Check for interesting content
                if self._is_interesting(resp):
                    result["interesting"] = True
                    result["indicators"] = self._find_indicators(resp)
                
                return result
        except Exception as e:
            # Silently skip errors - don't log every failed request
            # Only log at debug level with truncated message
            self._logger.debug(f"Request error: {url[:100]} - {str(e)[:100]}")
            return None
        
        return None
    
    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        import re
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]
        return ""
    
    def _is_interesting(self, response: Response) -> bool:
        """Check if response is interesting (contains sensitive info)"""
        text_lower = response.text.lower()
        
        interesting_indicators = [
            "password", "secret", "key", "token", "api",
            "database", "config", "admin", "login",
            "error", "exception", "stack trace",
        ]
        
        return any(indicator in text_lower for indicator in interesting_indicators)
    
    def _find_indicators(self, response: Response) -> List[str]:
        """Find security indicators in response"""
        indicators = []
        text_lower = response.text.lower()
        
        indicator_patterns = {
            "password": ["password", "pwd", "passwd"],
            "api_key": ["api[_-]?key", "apikey", "api_key"],
            "database": ["database", "db", "mysql", "postgresql"],
            "config": ["config", "configuration", "settings"],
            "error": ["error", "exception", "stack trace", "fatal"],
        }
        
        for category, patterns in indicator_patterns.items():
            for pattern in patterns:
                import re
                if re.search(pattern, text_lower, re.IGNORECASE):
                    indicators.append(category)
                    break
        
        return indicators
    
    async def test_403_bypass(self, url: str) -> List[Dict]:
        """
        Test 403 bypass techniques and return detailed info for each successful bypass.

        Each entry in the returned list has keys:
            - payload:    URL that was requested
            - technique:  short name of the technique
            - description:human‑readable explanation of how the bypass worked
            - status_code:HTTP status code received
        """
        bypasses: List[Dict] = []
        
        techniques = [
            {
                "template": "{url}/..",
                "technique": "path_traversal_simple",
                "description": "اضافه کردن '/..' برای دور زدن بررسی ثابت روی مسیر اصلی (path traversal ساده).",
            },
            {
                "template": "{url}/..;/",
                "technique": "semicolon_path_confusion",
                "description": "استفاده از ';/..' برای گیج کردن WAF/وب‌سرور در پارس مسیر و دور زدن محدودیت 403.",
            },
            {
                "template": "{url}/%2e%2e/",
                "technique": "url_encoded_dotdot",
                "description": "کد کردن '..' به '%2e%2e' تا فایروال بررسی رشته‌ی خام را دور بزند.",
            },
            {
                "template": "{url}/%2e%2e%2f",
                "technique": "double_url_encoded_dotdot_slash",
                "description": "کد کردن '../' به '%2e%2e%2f' برای دور زدن فیلترهایی که فقط روی '../' ساده چک می‌کنند.",
            },
            {
                "template": "{url}/..%2f",
                "technique": "mixed_encoded_traversal",
                "description": "ترکیب '..' با '%2f' برای ایجاد مسیر ترکیبی که بعضی سرورها اشتباه نرمالایز می‌کنند.",
            },
            {
                "template": "{url}/%252e%252e/",
                "technique": "double_encoded_traversal",
                "description": "دو بار کد کردن '..' ( '%252e%252e/' ) برای بای‌پس لایه اول فیلتر و decode شدن در لایه بعدی.",
            },
            {
                "template": "{url}?",
                "technique": "query_confusion",
                "description": "اضافه کردن '?' خالی برای تغییر نحوه‌ی match شدن مسیر در برخی WAFها/وب‌سرورها.",
            },
            {
                "template": "{url}??",
                "technique": "double_query_confusion",
                "description": "استفاده از '??' برای ایجاد edge-case در پارس URL و دور زدن قوانین 403.",
            },
            {
                "template": "{url}#",
                "technique": "fragment_truncation",
                "description": "اضافه کردن '#' باعث می‌شود بخش بعد از آن سمت سرور دیده نشود و بعضی فیلترها را دور بزند.",
            },
            {
                "template": "{url}/*",
                "technique": "wildcard_suffix",
                "description": "اضافه کردن '/*' برای match شدن روی ruleهای متفاوت یا rewrite ruleهای خاص.",
            },
            {
                "template": "{url}/%20",
                "technique": "space_suffix",
                "description": "اضافه کردن space کد شده '%20' که ممکن است توسط بعضی سرورها trim شود و 403 را دور بزند.",
            },
            {
                "template": "{url}/%09",
                "technique": "tab_suffix",
                "description": "استفاده از tab کد شده '%09' برای trigger کردن رفتار متفاوت پارس مسیر.",
            },
            {
                "template": "{url}/%00",
                "technique": "null_byte_injection",
                "description": "تزریق null byte '%00' که در بعضی زبان‌ها پایان رشته محسوب می‌شود و چک‌های بعدی را حذف می‌کند.",
            },
            {
                "template": "{url}/%0d%0a",
                "technique": "crlf_injection",
                "description": "تزریق CRLF برای تست باگ‌های پارس هدر/مسیر که می‌تواند به بای‌پس 403 منجر شود.",
            },
            {
                "template": "{url}/%0d",
                "technique": "cr_injection",
                "description": "تزریق CR تنها برای پیدا کردن رفتارهای عجیب در وب‌سرور یا WAF.",
            },
            {
                "template": "{url}/%0a",
                "technique": "lf_injection",
                "description": "تزریق LF تنها (line feed) برای تست پیاده‌سازی‌های حساس به newline.",
            },
            {
                "template": "{url}/%2f%2f",
                "technique": "double_slash_encoded",
                "description": "کد کردن '//' به '%2f%2f' برای دور زدن نرمالایزکننده‌هایی که فقط روی '//' ساده کار می‌کنند.",
            },
            {
                "template": "{url}/..%252f",
                "technique": "mixed_double_encoded_traversal",
                "description": "ترکیب '..' با '%252f' (slash دوبار کد شده) برای بای‌پس چند لایه decode و فیلتر.",
            },
            {
                "template": "{url}/....//....//",
                "technique": "deep_traversal_confusion",
                "description": "استفاده از چندین '....//\" برای گیج کردن نرمالایز مسیر و پرش به دایرکتوری‌های بالاتر.",
            },
        ]
        
        for entry in techniques:
            payload = entry["template"].format(url=url)
            try:
                resp = await self.http_client.get(payload, timeout=5)
                if resp.status_code == 200:
                    bypasses.append(
                        {
                            "payload": payload,
                            "technique": entry["technique"],
                            "description": entry["description"],
                            "status_code": resp.status_code,
                        }
                    )
            except Exception:
                continue
        
        return bypasses
    
    async def bruteforce_api_endpoints(
        self,
        base_url: str,
        max_workers: int = 20
    ) -> List[Dict]:
        """Bruteforce API endpoints"""
        api_wordlist = self.wordlist_manager.get_wordlist("api_endpoints")
        return await self.bruteforce(
            base_url,
            wordlist=api_wordlist,
            status_codes=[200, 201, 204, 401, 403, 405],
            max_workers=max_workers
        )
    
    async def bruteforce_admin_panels(
        self,
        base_url: str,
        max_workers: int = 20
    ) -> List[Dict]:
        """Bruteforce admin panels"""
        admin_wordlist = self.wordlist_manager.get_wordlist("admin_panels")
        return await self.bruteforce(
            base_url,
            wordlist=admin_wordlist,
            status_codes=[200, 301, 302, 401, 403],
            max_workers=max_workers
        )

