"""
Statistics and Analytics Utilities
"""
from typing import Dict, List
from collections import Counter
from datetime import datetime, timedelta


class ScanStatistics:
    """Statistics collector for scans"""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.requests_made = 0
        self.responses_received = 0
        self.errors = 0
        self.vulnerabilities_found = 0
        self.urls_discovered = 0
        self.forms_discovered = 0
        self.endpoints_discovered = 0
    
    def start_scan(self):
        """Mark scan start"""
        self.start_time = datetime.now()
    
    def end_scan(self):
        """Mark scan end"""
        self.end_time = datetime.now()
    
    def record_request(self):
        """Record a request"""
        self.requests_made += 1
    
    def record_response(self):
        """Record a response"""
        self.responses_received += 1
    
    def record_error(self):
        """Record an error"""
        self.errors += 1
    
    def record_vulnerability(self):
        """Record a vulnerability"""
        self.vulnerabilities_found += 1
    
    def get_duration(self) -> timedelta:
        """Get scan duration"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return timedelta(0)
    
    def get_summary(self) -> Dict:
        """Get statistics summary"""
        duration = self.get_duration()
        
        return {
            "duration_seconds": duration.total_seconds(),
            "requests_made": self.requests_made,
            "responses_received": self.responses_received,
            "errors": self.errors,
            "vulnerabilities_found": self.vulnerabilities_found,
            "urls_discovered": self.urls_discovered,
            "forms_discovered": self.forms_discovered,
            "endpoints_discovered": self.endpoints_discovered,
            "success_rate": (self.responses_received / self.requests_made * 100) if self.requests_made > 0 else 0,
        }


class VulnerabilityStatistics:
    """Statistics for vulnerabilities"""
    
    @staticmethod
    def analyze_vulnerabilities(vulnerabilities: List) -> Dict:
        """Analyze vulnerability statistics"""
        if not vulnerabilities:
            return {
                "total": 0,
                "by_severity": {},
                "by_type": {},
                "by_url": {},
            }
        
        # Count by severity
        severity_counter = Counter()
        for vuln in vulnerabilities:
            severity = str(vuln.severity) if hasattr(vuln, 'severity') else 'UNKNOWN'
            severity_counter[severity] += 1
        
        # Count by type
        type_counter = Counter()
        for vuln in vulnerabilities:
            vuln_type = vuln.name if hasattr(vuln, 'name') else 'UNKNOWN'
            type_counter[vuln_type] += 1
        
        # Count by URL
        url_counter = Counter()
        for vuln in vulnerabilities:
            url = vuln.url if hasattr(vuln, 'url') else 'UNKNOWN'
            url_counter[url] += 1
        
        return {
            "total": len(vulnerabilities),
            "by_severity": dict(severity_counter),
            "by_type": dict(type_counter),
            "by_url": dict(url_counter),
            "most_common_type": type_counter.most_common(1)[0] if type_counter else None,
            "most_vulnerable_url": url_counter.most_common(1)[0] if url_counter else None,
        }


class PerformanceMetrics:
    """Performance metrics collector"""
    
    def __init__(self):
        self.response_times = []
        self.request_times = []
    
    def record_response_time(self, time_ms: float):
        """Record response time"""
        self.response_times.append(time_ms)
    
    def record_request_time(self, time_ms: float):
        """Record request time"""
        self.request_times.append(time_ms)
    
    def get_average_response_time(self) -> float:
        """Get average response time"""
        if not self.response_times:
            return 0.0
        return sum(self.response_times) / len(self.response_times)
    
    def get_average_request_time(self) -> float:
        """Get average request time"""
        if not self.request_times:
            return 0.0
        return sum(self.request_times) / len(self.request_times)
    
    def get_max_response_time(self) -> float:
        """Get maximum response time"""
        return max(self.response_times) if self.response_times else 0.0
    
    def get_min_response_time(self) -> float:
        """Get minimum response time"""
        return min(self.response_times) if self.response_times else 0.0
    
    def get_summary(self) -> Dict:
        """Get performance summary"""
        return {
            "average_response_time_ms": self.get_average_response_time(),
            "average_request_time_ms": self.get_average_request_time(),
            "max_response_time_ms": self.get_max_response_time(),
            "min_response_time_ms": self.get_min_response_time(),
            "total_requests": len(self.request_times),
            "total_responses": len(self.response_times),
        }

