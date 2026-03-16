"""
Technology Fingerprinting Engine
"""
import re
from typing import Dict, List, Optional
from ..http.client import Response


class FingerprintEngine:
    """Technology fingerprinting similar to Wappalyzer"""
    
    def __init__(self):
        self.signatures = self._load_signatures()
    
    def fingerprint(self, response: Response) -> Dict[str, List[str]]:
        """Fingerprint technologies from response"""
        technologies = {
            "cms": [],
            "framework": [],
            "frontend": [],
            "server": [],
            "waf": [],
            "cdn": [],
            "language": [],
            "database": [],
            "other": [],
        }
        
        # Check headers
        header_tech = self._check_headers(response.headers)
        for category, items in header_tech.items():
            technologies[category].extend(items)
        
        # Check HTML content
        html_tech = self._check_html(response.text)
        for category, items in html_tech.items():
            technologies[category].extend(items)
        
        # Check cookies
        cookie_tech = self._check_cookies(response.cookies)
        for category, items in cookie_tech.items():
            technologies[category].extend(items)
        
        # Deduplicate
        for category in technologies:
            technologies[category] = list(set(technologies[category]))
        
        return technologies
    
    def _check_headers(self, headers: Dict[str, str]) -> Dict[str, List[str]]:
        """Check HTTP headers for technology signatures"""
        tech = {k: [] for k in ["cms", "framework", "server", "waf", "cdn", "language"]}
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Server header
        if "server" in headers_lower:
            server = headers_lower["server"]
            tech["server"].append(server)
            
            # Specific server detection
            if "nginx" in server:
                tech["server"].append("Nginx")
            elif "apache" in server:
                tech["server"].append("Apache")
            elif "iis" in server:
                tech["server"].append("IIS")
            elif "cloudflare" in server:
                tech["cdn"].append("Cloudflare")
        
        # X-Powered-By header
        if "x-powered-by" in headers_lower:
            powered_by = headers_lower["x-powered-by"]
            if "php" in powered_by:
                tech["language"].append("PHP")
            elif "asp.net" in powered_by:
                tech["framework"].append("ASP.NET")
                tech["language"].append("C#")
        
        # WAF detection
        waf_headers = {
            "x-waf": ["Generic WAF"],
            "x-sucuri-id": ["Sucuri"],
            "x-sucuri-cache": ["Sucuri"],
            "x-cache": ["Cloudflare", "Fastly"],
            "cf-ray": ["Cloudflare"],
            "x-akamai-transformed": ["Akamai"],
            "x-aws-cf-id": ["AWS CloudFront"],
        }
        
        for header, wafs in waf_headers.items():
            if header in headers_lower:
                tech["waf"].extend(wafs)
        
        # CDN detection
        cdn_headers = {
            "cf-ray": ["Cloudflare"],
            "x-cache": ["Cloudflare", "Fastly"],
            "x-amz-cf-id": ["AWS CloudFront"],
            "x-akamai-transformed": ["Akamai"],
            "server": ["Cloudflare", "Fastly"],
        }
        
        for header, cdns in cdn_headers.items():
            if header in headers_lower:
                value = headers_lower[header]
                for cdn in cdns:
                    if cdn.lower() in value:
                        tech["cdn"].append(cdn)
        
        return tech
    
    def _check_html(self, html: str) -> Dict[str, List[str]]:
        """Check HTML content for technology signatures"""
        tech = {k: [] for k in ["cms", "framework", "frontend", "server", "language"]}
        html_lower = html.lower()
        
        # CMS detection
        cms_patterns = {
            "WordPress": [
                r'wp-content',
                r'wp-includes',
                r'/wp-json/',
                r'wordpress',
            ],
            "Drupal": [
                r'drupal',
                r'sites/all',
                r'/sites/default/',
            ],
            "Joomla": [
                r'joomla',
                r'/media/jui/',
            ],
            "Magento": [
                r'magento',
                r'/skin/frontend/',
            ],
            "Shopify": [
                r'shopify',
                r'shopify\.com',
            ],
        }
        
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    tech["cms"].append(cms)
                    break
        
        # Framework detection
        framework_patterns = {
            "React": [
                r'react',
                r'__REACT_DEVTOOLS',
            ],
            "Vue.js": [
                r'vue\.js',
                r'__vue__',
            ],
            "Angular": [
                r'angular',
                r'ng-',
            ],
            "Django": [
                r'csrfmiddlewaretoken',
                r'django',
            ],
            "Laravel": [
                r'laravel_session',
                r'laravel',
            ],
            "Rails": [
                r'rails',
                r'csrf-token',
            ],
        }
        
        for framework, patterns in framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    tech["framework"].append(framework)
                    break
        
        # Frontend library detection
        frontend_patterns = {
            "jQuery": [
                r'jquery',
                r'\$\.',
            ],
            "Bootstrap": [
                r'bootstrap',
                r'btn btn-',
            ],
            "Font Awesome": [
                r'font-awesome',
                r'fa fa-',
            ],
        }
        
        for library, patterns in frontend_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    tech["frontend"].append(library)
                    break
        
        # Language detection from meta tags
        meta_patterns = {
            "PHP": r'<meta[^>]*generator[^>]*php',
            "ASP.NET": r'<meta[^>]*generator[^>]*asp\.net',
        }
        
        for lang, pattern in meta_patterns.items():
            if re.search(pattern, html_lower, re.IGNORECASE):
                tech["language"].append(lang)
        
        return tech
    
    def _check_cookies(self, cookies: Dict[str, str]) -> Dict[str, List[str]]:
        """Check cookies for technology signatures"""
        tech = {k: [] for k in ["cms", "framework", "language"]}
        
        cookie_names_lower = [k.lower() for k in cookies.keys()]
        
        # Framework detection from cookies
        framework_cookies = {
            "Django": ["csrftoken", "sessionid"],
            "Laravel": ["laravel_session"],
            "Rails": ["_rails_session"],
            "ASP.NET": ["aspnet_sessionid"],
            "PHP": ["phpsessid"],
        }
        
        for framework, cookie_patterns in framework_cookies.items():
            for pattern in cookie_patterns:
                if any(pattern.lower() in name for name in cookie_names_lower):
                    tech["framework"].append(framework)
                    break
        
        return tech
    
    def _load_signatures(self) -> Dict:
        """Load technology signatures"""
        # This would typically load from a JSON file
        # For now, we use inline patterns
        return {}

