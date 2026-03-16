"""
Enhanced Technology Fingerprinting
"""
import re
from typing import Dict, List, Optional
from ..http.client import Response


class EnhancedFingerprintEngine:
    """Enhanced technology fingerprinting with more patterns"""
    
    def __init__(self):
        self.signatures = self._load_enhanced_signatures()
    
    def fingerprint(self, response: Response) -> Dict[str, List[str]]:
        """Enhanced fingerprinting"""
        technologies = {
            "cms": [],
            "framework": [],
            "frontend": [],
            "server": [],
            "waf": [],
            "cdn": [],
            "language": [],
            "database": [],
            "cache": [],
            "analytics": [],
            "other": [],
        }
        
        # Check headers
        header_tech = self._check_headers_enhanced(response.headers)
        for category, items in header_tech.items():
            if category in technologies:
                technologies[category].extend(items)
        
        # Check HTML content
        html_tech = self._check_html_enhanced(response.text)
        for category, items in html_tech.items():
            if category in technologies:
                technologies[category].extend(items)
        
        # Check cookies
        cookie_tech = self._check_cookies_enhanced(response.cookies)
        for category, items in cookie_tech.items():
            if category in technologies:
                technologies[category].extend(items)
        
        # Check URL patterns
        url_tech = self._check_url_patterns(response.url)
        for category, items in url_tech.items():
            if category in technologies:
                technologies[category].extend(items)
        
        # Deduplicate
        for category in technologies:
            technologies[category] = list(set(technologies[category]))
        
        return technologies
    
    def _load_enhanced_signatures(self) -> Dict:
        """Load enhanced technology signatures"""
        return {
            "cms": {
                "WordPress": {
                    "headers": ["x-powered-by"],
                    "html": [r"wp-content", r"wp-includes", r"/wp-json/"],
                    "cookies": ["wordpress_", "wp-settings"],
                },
                "Drupal": {
                    "headers": ["x-drupal-cache"],
                    "html": [r"drupal", r"sites/all"],
                    "cookies": ["SESS", "SSESS"],
                },
                "Joomla": {
                    "html": [r"joomla", r"/media/jui/"],
                    "cookies": ["joomla_user_state"],
                },
            },
            "waf": {
                "Cloudflare": {
                    "headers": ["cf-ray", "cf-request-id"],
                },
                "Sucuri": {
                    "headers": ["x-sucuri-id"],
                },
                "Incapsula": {
                    "headers": ["x-iinfo"],
                },
            },
        }
    
    def _check_headers_enhanced(self, headers: Dict[str, str]) -> Dict[str, List[str]]:
        """Enhanced header checking"""
        tech = {k: [] for k in ["cms", "framework", "server", "waf", "cdn", "language", "cache"]}
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Server detection
        if "server" in headers_lower:
            server = headers_lower["server"]
            tech["server"].append(server)
            
            # Specific servers
            if "nginx" in server:
                tech["server"].append("Nginx")
            elif "apache" in server:
                tech["server"].append("Apache")
            elif "iis" in server:
                tech["server"].append("IIS")
            elif "cloudflare" in server:
                tech["cdn"].append("Cloudflare")
        
        # WAF detection
        waf_headers = {
            "x-waf": ["Generic WAF"],
            "x-sucuri-id": ["Sucuri"],
            "x-sucuri-cache": ["Sucuri"],
            "x-cache": ["Cloudflare", "Fastly"],
            "cf-ray": ["Cloudflare"],
            "x-akamai-transformed": ["Akamai"],
            "x-aws-cf-id": ["AWS CloudFront"],
            "x-iinfo": ["Incapsula"],
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
        }
        
        for header, cdns in cdn_headers.items():
            if header in headers_lower:
                value = headers_lower[header]
                for cdn in cdns:
                    if cdn.lower() in value:
                        tech["cdn"].append(cdn)
        
        # Cache detection
        cache_headers = {
            "x-cache": ["Varnish", "Cloudflare"],
            "x-varnish": ["Varnish"],
            "x-cache-status": ["Varnish", "Nginx"],
        }
        
        for header, caches in cache_headers.items():
            if header in headers_lower:
                tech["cache"].extend(caches)
        
        return tech
    
    def _check_html_enhanced(self, html: str) -> Dict[str, List[str]]:
        """Enhanced HTML checking"""
        tech = {k: [] for k in ["cms", "framework", "frontend", "server", "language", "analytics"]}
        html_lower = html.lower()
        
        # CMS detection
        cms_patterns = {
            "WordPress": [
                r'wp-content', r'wp-includes', r'/wp-json/', r'wordpress',
                r'wp-embed', r'wp-block',
            ],
            "Drupal": [
                r'drupal', r'sites/all', r'/sites/default/', r'drupal\.js',
            ],
            "Joomla": [
                r'joomla', r'/media/jui/', r'joomla\.js',
            ],
            "Magento": [
                r'magento', r'/skin/frontend/', r'mage/',
            ],
            "Shopify": [
                r'shopify', r'shopify\.com', r'cdn\.shopify',
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
                r'react', r'__REACT_DEVTOOLS', r'react-dom',
            ],
            "Vue.js": [
                r'vue\.js', r'__vue__', r'vue-router',
            ],
            "Angular": [
                r'angular', r'ng-', r'@angular',
            ],
            "Django": [
                r'csrfmiddlewaretoken', r'django', r'Django',
            ],
            "Laravel": [
                r'laravel_session', r'laravel', r'Laravel',
            ],
            "Rails": [
                r'rails', r'csrf-token', r'Rails',
            ],
        }
        
        for framework, patterns in framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    tech["framework"].append(framework)
                    break
        
        # Analytics detection
        analytics_patterns = {
            "Google Analytics": [
                r'google-analytics', r'ga\(', r'gtag',
            ],
            "Google Tag Manager": [
                r'googletagmanager', r'GTM-',
            ],
            "Facebook Pixel": [
                r'facebook\.net', r'fbq\(',
            ],
        }
        
        for analytics, patterns in analytics_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    tech["analytics"].append(analytics)
                    break
        
        return tech
    
    def _check_cookies_enhanced(self, cookies: Dict[str, str]) -> Dict[str, List[str]]:
        """Enhanced cookie checking"""
        tech = {k: [] for k in ["cms", "framework", "language"]}
        
        cookie_names_lower = [k.lower() for k in cookies.keys()]
        
        # Framework detection from cookies
        framework_cookies = {
            "Django": ["csrftoken", "sessionid"],
            "Laravel": ["laravel_session"],
            "Rails": ["_rails_session"],
            "ASP.NET": ["aspnet_sessionid"],
            "PHP": ["phpsessid"],
            "WordPress": ["wordpress_", "wp-settings"],
        }
        
        for framework, cookie_patterns in framework_cookies.items():
            for pattern in cookie_patterns:
                if any(pattern.lower() in name for name in cookie_names_lower):
                    tech["framework"].append(framework)
                    break
        
        return tech
    
    def _check_url_patterns(self, url: str) -> Dict[str, List[str]]:
        """Check URL patterns for technology hints"""
        tech = {k: [] for k in ["cms", "framework"]}
        url_lower = url.lower()
        
        # URL-based detection
        if "wp-" in url_lower or "wordpress" in url_lower:
            tech["cms"].append("WordPress")
        
        if "drupal" in url_lower:
            tech["cms"].append("Drupal")
        
        if "joomla" in url_lower:
            tech["cms"].append("Joomla")
        
        return tech

