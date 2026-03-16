"""
Subdomain Takeover Detection
Detects vulnerable subdomains that can be taken over
"""
import re
import dns.resolver
from typing import List, Optional, Dict
import logging
from ..scanners.base import Vulnerability, Severity
from ..http.client import AsyncHTTPClient


class SubdomainTakeoverDetector:
    """Detect subdomain takeover vulnerabilities"""
    
    def __init__(self, http_client: AsyncHTTPClient):
        self.http_client = http_client
        self._logger = logging.getLogger(__name__)
        
        # Service fingerprints for takeover detection
        self.service_fingerprints = {
            "GitHub Pages": {
                "cname": ["github.io", "githubusercontent.com"],
                "response": ["There isn't a GitHub Pages site here", "404: Not Found"],
            },
            "Heroku": {
                "cname": ["herokuapp.com", "herokussl.com"],
                "response": ["No such app", "herokucdn.com"],
            },
            "AWS S3": {
                "cname": ["s3.amazonaws.com", "s3-website"],
                "response": ["NoSuchBucket", "The specified bucket does not exist"],
            },
            "AWS CloudFront": {
                "cname": ["cloudfront.net"],
                "response": ["ERROR: The request could not be satisfied"],
            },
            "Shopify": {
                "cname": ["myshopify.com"],
                "response": ["Sorry, this shop is currently unavailable"],
            },
            "Tumblr": {
                "cname": ["tumblr.com"],
                "response": ["Whatever you were looking for doesn't currently exist"],
            },
            "WordPress": {
                "cname": ["wordpress.com"],
                "response": ["Do you want to register"],
            },
            "Fastly": {
                "cname": ["fastly.net"],
                "response": ["Fastly error: unknown domain"],
            },
            "Pantheon": {
                "cname": ["pantheonsite.io"],
                "response": ["404 error unknown site"],
            },
            "Zendesk": {
                "cname": ["zendesk.com"],
                "response": ["Help Center Closed"],
            },
        }
    
    async def check_subdomain(self, subdomain: str) -> Optional[Vulnerability]:
        """Check if a subdomain is vulnerable to takeover"""
        try:
            # Resolve CNAME
            cname = await self._resolve_cname(subdomain)
            if not cname:
                return None
            
            # Check if CNAME points to a known service
            service = self._identify_service(cname)
            if not service:
                return None
            
            # Check if service is vulnerable
            is_vulnerable = await self._check_service_vulnerability(subdomain, service)
            
            if is_vulnerable:
                return Vulnerability(
                    name=f"Subdomain Takeover: {service}",
                    severity=Severity.HIGH,
                    url=f"http://{subdomain}",
                    description=f"Subdomain {subdomain} is vulnerable to takeover via {service}",
                    evidence=f"CNAME points to {cname} which is a {service} service that can be claimed",
                    recommendation=f"Remove the CNAME record or claim the {service} service to prevent takeover",
                    cwe="CWE-922"
                )
        except Exception as e:
            self._logger.debug(f"Error checking subdomain {subdomain}: {e}")
        
        return None
    
    async def _resolve_cname(self, subdomain: str) -> Optional[str]:
        """Resolve CNAME record for subdomain"""
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except:
            pass
        
        return None
    
    def _identify_service(self, cname: str) -> Optional[str]:
        """Identify service from CNAME"""
        cname_lower = cname.lower()
        
        for service, config in self.service_fingerprints.items():
            for pattern in config["cname"]:
                if pattern in cname_lower:
                    return service
        
        return None
    
    async def _check_service_vulnerability(self, subdomain: str, service: str) -> bool:
        """Check if service is actually vulnerable"""
        try:
            url = f"http://{subdomain}"
            resp = await self.http_client.get(url, timeout=10)
            
            # Check for service-specific error messages
            if service in self.service_fingerprints:
                patterns = self.service_fingerprints[service]["response"]
                for pattern in patterns:
                    if pattern.lower() in resp.text.lower():
                        return True
        except:
            pass
        
        return False

