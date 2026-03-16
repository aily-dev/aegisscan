"""
AegisScan - Advanced Web Security Testing Framework
"""

__version__ = "1.0.0"
__author__ = "AegisScan Team"

# Export main classes
from .core.automation import DeepScanner
from .http.client import AsyncHTTPClient
from .scanners.sqli import SQLiScanner
from .scanners.xss import XSSScanner
from .crawler.engine import Crawler
from .reports.generator import ReportGenerator

__all__ = [
    "DeepScanner",
    "AsyncHTTPClient",
    "SQLiScanner",
    "XSSScanner",
    "Crawler",
    "ReportGenerator",
]
