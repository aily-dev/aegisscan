"""
Advanced Subdomain Enumeration with Multiple Techniques
"""
import asyncio
import re
from typing import List, Set, Optional
import logging
from ..http.client import AsyncHTTPClient
from ..utils.wordlists import WordlistManager


class AdvancedSubdomainEnumerator:
    """Advanced subdomain enumeration with multiple techniques"""
    
    def __init__(self, http_client: AsyncHTTPClient, wordlist_manager: Optional[WordlistManager] = None):
        self.http_client = http_client
        self.wordlist_manager = wordlist_manager or WordlistManager()
        self._logger = logging.getLogger(__name__)
        
        # Common subdomain wordlist
        self.common_subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
            "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
            "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin",
            "exchange", "owa", "www1", "mx", "cdn", "api", "static", "images",
            "img", "media", "video", "videos", "music", "audio", "files",
            "file", "download", "downloads", "upload", "uploads", "secure",
            "ssl", "vpn", "remote", "ssh", "db", "database", "sql", "mysql",
            "postgres", "mongodb", "redis", "cache", "memcache", "elasticsearch",
            "solr", "kibana", "grafana", "jenkins", "git", "svn", "hg",
            "staging", "stage", "test", "testing", "qa", "prod", "production",
            "live", "demo", "dev", "development", "staging", "preprod",
            "pre-prod", "preprod", "beta", "alpha", "internal", "private",
            "public", "external", "partner", "partners", "client", "clients",
            "customer", "customers", "support", "help", "docs", "documentation",
            "wiki", "kb", "knowledge", "forum", "forums", "community",
            "shop", "store", "ecommerce", "cart", "checkout", "payment",
            "payments", "billing", "invoice", "invoices", "account", "accounts",
            "login", "signin", "signup", "register", "registration", "auth",
            "authentication", "oauth", "sso", "ldap", "ad", "active-directory",
            "portal", "dashboard", "panel", "control", "admin", "administrator",
            "manager", "management", "console", "monitor", "monitoring",
            "logs", "log", "logging", "analytics", "stats", "statistics",
            "metrics", "reports", "reporting", "backup", "backups", "archive",
            "archives", "old", "legacy", "v1", "v2", "v3", "api-v1", "api-v2",
            "rest", "restapi", "graphql", "soap", "xmlrpc", "rpc", "ws",
            "websocket", "socket", "stream", "streaming", "live", "broadcast",
            "tv", "radio", "podcast", "video", "audio", "image", "images",
            "photo", "photos", "gallery", "albums", "media", "assets",
            "static", "cdn", "cache", "proxy", "gateway", "router",
            "firewall", "waf", "ddos", "protection", "security", "secure",
            "ssl", "tls", "https", "cert", "certificate", "ca", "issuer",
            "monitor", "monitoring", "alert", "alerts", "notification",
            "notifications", "email", "smtp", "pop3", "imap", "mail",
            "webmail", "outlook", "exchange", "owa", "activesync",
            "calendar", "cal", "contacts", "addressbook", "tasks",
            "notes", "files", "sharepoint", "onedrive", "dropbox",
            "google", "gmail", "drive", "docs", "sheets", "slides",
            "facebook", "twitter", "instagram", "linkedin", "youtube",
            "github", "gitlab", "bitbucket", "jira", "confluence",
            "slack", "teams", "zoom", "webex", "gotomeeting",
            "salesforce", "hubspot", "zendesk", "freshdesk", "intercom",
            "stripe", "paypal", "square", "braintree", "adyen",
            "aws", "azure", "gcp", "cloud", "s3", "ec2", "lambda",
            "docker", "kubernetes", "k8s", "helm", "terraform",
            "ansible", "puppet", "chef", "salt", "jenkins", "bamboo",
            "teamcity", "circleci", "travis", "gitlab-ci", "github-actions",
            "prometheus", "grafana", "kibana", "elasticsearch", "splunk",
            "datadog", "newrelic", "appdynamics", "dynatrace", "sentry",
            "loggly", "papertrail", "sumologic", "logz", "logstash",
            "fluentd", "fluentbit", "filebeat", "metricbeat", "packetbeat",
            "heartbeat", "auditbeat", "functionbeat", "winlogbeat",
            "apm", "apm-server", "apm-server-", "apm-server-",
        ]
    
    async def enumerate(self, domain: str, techniques: Optional[List[str]] = None) -> Set[str]:
        """Enumerate subdomains using multiple techniques"""
        if techniques is None:
            techniques = ["dns", "bruteforce", "certificate", "dns_brute"]
        
        all_subdomains = set()
        
        # DNS enumeration
        if "dns" in techniques:
            dns_subdomains = await self._dns_enumeration(domain)
            all_subdomains.update(dns_subdomains)
        
        # Certificate transparency
        if "certificate" in techniques:
            cert_subdomains = await self._certificate_transparency(domain)
            all_subdomains.update(cert_subdomains)
        
        # DNS bruteforce
        if "dns_brute" in techniques or "bruteforce" in techniques:
            brute_subdomains = await self._dns_bruteforce(domain)
            all_subdomains.update(brute_subdomains)
        
        # Passive DNS
        if "passive" in techniques:
            passive_subdomains = await self._passive_dns(domain)
            all_subdomains.update(passive_subdomains)
        
        return all_subdomains
    
    async def _dns_enumeration(self, domain: str) -> Set[str]:
        """DNS-based subdomain enumeration"""
        subdomains = set()
        
        # Try common DNS record types
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV"]
        
        for record_type in record_types:
            try:
                # This would require a DNS library like dnspython
                # For now, we'll use a simplified approach
                pass
            except:
                continue
        
        return subdomains
    
    async def _certificate_transparency(self, domain: str) -> Set[str]:
        """Certificate Transparency enumeration"""
        subdomains = set()
        
        # Certificate Transparency logs would be queried here
        # Using services like crt.sh, censys, etc.
        
        try:
            # Simulate CT log query
            ct_url = f"https://crt.sh/?q={domain}&output=json"
            # In real implementation, we would query this
            pass
        except:
            pass
        
        return subdomains
    
    async def _dns_bruteforce(self, domain: str) -> Set[str]:
        """DNS bruteforce enumeration"""
        subdomains = set()
        
        # Combine common subdomains with wordlist
        wordlist = self.common_subdomains + self.wordlist_manager.get_wordlist("directories")[:100]
        
        tasks = []
        for subdomain in wordlist[:200]:  # Limit
            full_domain = f"{subdomain}.{domain}"
            tasks.append(self._check_subdomain(full_domain, subdomains))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return subdomains
    
    async def _check_subdomain(self, full_domain: str, subdomains: Set[str]):
        """Check if subdomain exists"""
        try:
            # Try DNS resolution
            import socket
            try:
                socket.gethostbyname(full_domain)
                subdomains.add(full_domain)
            except:
                pass
            
            # Try HTTP request
            try:
                resp = await self.http_client.get(f"http://{full_domain}", timeout=3)
                if resp.status_code in [200, 301, 302, 403, 401]:
                    subdomains.add(full_domain)
            except:
                pass
        except:
            pass
    
    async def _passive_dns(self, domain: str) -> Set[str]:
        """Passive DNS enumeration"""
        subdomains = set()
        
        # Passive DNS sources would be queried here
        # Services like SecurityTrails, PassiveTotal, etc.
        
        return subdomains
    
    async def check_takeover(self, subdomain: str) -> bool:
        """Check for subdomain takeover vulnerability"""
        try:
            resp = await self.http_client.get(f"http://{subdomain}", timeout=5)
            
            # Check for common takeover indicators
            takeover_indicators = [
                "github.io", "herokuapp.com", "azurewebsites.net",
                "s3.amazonaws.com", "cloudfront.net", "fastly.com",
                "shopify.com", "squarespace.com", "tumblr.com",
                "wordpress.com", "ghost.io", "helpjuice.com",
            ]
            
            for indicator in takeover_indicators:
                if indicator in resp.text.lower():
                    return True
            
            # Check for 404 or error pages from service providers
            if resp.status_code == 404:
                if "github" in resp.text.lower() or "heroku" in resp.text.lower():
                    return True
        
        except:
            pass
        
        return False

