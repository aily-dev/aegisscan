"""
Subdomain Enumeration Module
"""
import asyncio
import aiohttp
import dns.asyncresolver
from typing import List, Set, Optional
import logging


class SubdomainEnumerator:
    """Subdomain enumeration using multiple techniques"""
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self._logger = logging.getLogger(__name__)
        
        # Common subdomain wordlist
        self.wordlist = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
            "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
            "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
            "wiki", "web", "media", "email", "images", "img", "www1", "intranet",
            "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4",
            "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my",
            "svn", "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup",
            "mx2", "static2", "blog2", "ns5", "vpn2", "api2", "www4", "secure2",
            "shop2", "ftp2", "mail3", "web2", "dev2", "test2", "m2", "ns6", "www5",
        ]
    
    async def enumerate(self, domain: str, wordlist: Optional[List[str]] = None, use_dns: bool = True, use_http: bool = True) -> List[str]:
        """Enumerate subdomains"""
        found_subdomains: Set[str] = set()
        
        wordlist = wordlist or self.wordlist
        
        # DNS-based enumeration
        if use_dns:
            dns_results = await self._dns_enumeration(domain, wordlist)
            found_subdomains.update(dns_results)
        
        # HTTP-based enumeration
        if use_http and self.http_client:
            http_results = await self._http_enumeration(domain, wordlist)
            found_subdomains.update(http_results)
        
        # Check for wildcard DNS
        if found_subdomains:
            wildcard = await self._check_wildcard(domain)
            if wildcard:
                self._logger.warning(f"Wildcard DNS detected for {domain}, results may be inaccurate")
        
        return sorted(list(found_subdomains))
    
    async def _dns_enumeration(self, domain: str, wordlist: List[str]) -> List[str]:
        """DNS-based subdomain enumeration"""
        found = []
        
        tasks = []
        for subdomain in wordlist:
            full_domain = f"{subdomain}.{domain}"
            tasks.append(self._resolve_dns(full_domain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, list) and result:
                found.append(f"{wordlist[i]}.{domain}")
        
        return found
    
    async def _resolve_dns(self, domain: str) -> List[str]:
        """Resolve DNS for a domain"""
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            answers = await resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except:
            return []
    
    async def _http_enumeration(self, domain: str, wordlist: List[str]) -> List[str]:
        """HTTP-based subdomain enumeration"""
        found = []
        
        if not self.http_client:
            return found
        
        tasks = []
        for subdomain in wordlist[:50]:  # Limit for performance
            full_domain = f"{subdomain}.{domain}"
            for protocol in ["https", "http"]:
                url = f"{protocol}://{full_domain}"
                tasks.append(self._check_http(url, full_domain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, str):
                found.append(result)
        
        return found
    
    async def _check_http(self, url: str, domain: str) -> Optional[str]:
        """Check if subdomain responds to HTTP"""
        try:
            resp = await self.http_client.get(url, timeout=5)
            if resp.status_code < 500:
                return domain
        except:
            pass
        return None
    
    async def _check_wildcard(self, domain: str) -> bool:
        """Check if domain has wildcard DNS"""
        try:
            random_subdomain = f"nonexistent-{asyncio.get_event_loop().time()}.{domain}"
            results = await self._resolve_dns(random_subdomain)
            return len(results) > 0
        except:
            return False
    
    async def check_takeover(self, subdomain: str) -> bool:
        """Check if subdomain is vulnerable to subdomain takeover"""
        # This is a simplified check
        # Real implementation would check for specific services (GitHub Pages, Heroku, etc.)
        try:
            resp = await self.http_client.get(f"https://{subdomain}", timeout=5)
            
            # Check for common takeover indicators
            takeover_indicators = [
                "github.io",
                "herokuapp.com",
                "tumblr.com",
                "wordpress.com",
                "shopify.com",
                "squarespace.com",
            ]
            
            for indicator in takeover_indicators:
                if indicator in resp.text.lower():
                    return True
        except:
            pass
        
        return False

