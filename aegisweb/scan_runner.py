from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Dict, Any
from urllib.parse import urlparse

from aegisscan import DeepScanner, AsyncHTTPClient
from aegisscan.scanners import (
    SQLiScanner,
    XSSScanner,
    CommandInjectionScanner,
    PathTraversalScanner,
    LFIRFIScanner,
    SSTIScanner,
    CSRFScanner,
    OpenRedirectScanner,
    AuthScanner,
    APISecurityScanner,
    JWTScanner,
    FileUploadScanner,
    WebSocketScanner,
    SSRFScanner,
    XXEScanner,
    IDORScanner,
    ComplianceChecker,
)
from aegisscan.recon import (
    EnhancedPortScanner,
    EnhancedDirectoryBruteforcer,
)
from aegisscan.analyzer import PassiveAnalyzer
from aegisscan.crawler import Crawler


logger = logging.getLogger(__name__)


@dataclass
class ScanJobResult:
    ok: bool
    message: str
    summary: Dict[str, Any] | None = None


def _normalize_domain(url: str) -> str:
    parsed = urlparse(url)
    if parsed.netloc:
        return parsed.netloc.lower()
    return url.lower()


async def _run_deep_scan(target_url: str, output_dir: str) -> ScanJobResult:
    http_client = AsyncHTTPClient()
    try:
        scanner = DeepScanner(
            http_client,
            output_dir=output_dir,
            use_external_tools=True,
            auto_install_tools=False,
        )
        summary = await scanner.deep_scan(target_url)
        return ScanJobResult(True, "Deep scan completed", summary=summary)
    finally:
        await http_client.close()


async def _run_normal_scan(target_url: str, output_dir: str) -> ScanJobResult:
    """
    A lighter scan: crawl + passive + core vulnerability scanners, بدون همه ابزارهای خارجی.
    """
    http_client = AsyncHTTPClient()
    try:
        crawler = Crawler(http_client)
        passive = PassiveAnalyzer(http_client)
        sqli = SQLiScanner(http_client)
        xss = XSSScanner(http_client)
        ssti = SSTIScanner(http_client)
        open_redirect = OpenRedirectScanner(http_client)

        pages = await crawler.crawl(target_url, max_depth=2, max_pages=50)

        vulns: list[dict[str, Any]] = []
        for page in pages[:50]:
            url = page["url"]
            for scanner in (sqli, xss, ssti, open_redirect):
                try:
                    res = await scanner.scan(url)
                    vulns.extend([v.to_dict() for v in res])
                except Exception as e:  # noqa: BLE001
                    logger.debug(f"Scanner error on {url}: {e}")

        summary: Dict[str, Any] = {
            "target": target_url,
            "pages_crawled": len(pages),
            "vulnerabilities": {
                "total": len(vulns),
                "items": vulns,
            },
        }
        return ScanJobResult(True, "Normal scan completed", summary=summary)
    finally:
        await http_client.close()


async def _run_single_scanner(target_url: str, scanner_name: str) -> ScanJobResult:
    http_client = AsyncHTTPClient()
    try:
        scanner_map = {
            "sqli": SQLiScanner,
            "xss": XSSScanner,
            "cmdi": CommandInjectionScanner,
            "path_traversal": PathTraversalScanner,
            "lfi_rfi": LFIRFIScanner,
            "ssti": SSTIScanner,
            "csrf": CSRFScanner,
            "open_redirect": OpenRedirectScanner,
            "auth": AuthScanner,
            "api": APISecurityScanner,
            "jwt": JWTScanner,
            "file_upload": FileUploadScanner,
            "websocket": WebSocketScanner,
            "ssrf": SSRFScanner,
            "xxe": XXEScanner,
            "idor": IDORScanner,
            "compliance": ComplianceChecker,
        }

        if scanner_name not in scanner_map:
            return ScanJobResult(False, f"Scanner '{scanner_name}' not supported")

        scanner_cls = scanner_map[scanner_name]
        scanner = scanner_cls(http_client)
        results = await scanner.scan(target_url)

        items = [v.to_dict() for v in results]
        summary: Dict[str, Any] = {
            "target": target_url,
            "scanner": scanner_name,
            "count": len(items),
            "items": items,
        }
        return ScanJobResult(True, f"{scanner_name} scan completed", summary=summary)
    finally:
        await http_client.close()


async def _run_port_scan(target_url: str) -> ScanJobResult:
    parsed = urlparse(target_url)
    host = parsed.hostname or parsed.netloc or target_url
    scanner = EnhancedPortScanner(timeout=2.0)
    ports = [21, 22, 25, 80, 110, 143, 443, 445, 3306, 5432, 6379, 27017, 8080, 8443]
    res = await scanner.scan(host, ports)
    return ScanJobResult(
        True,
        "Port scan completed",
        summary={"target": host, "ports": res},
    )


async def _run_dir_bruteforce(target_url: str) -> ScanJobResult:
    http_client = AsyncHTTPClient()
    try:
        brute = EnhancedDirectoryBruteforcer(http_client)
        res = await brute.bruteforce(
            target_url,
            wordlist_categories=["directories", "sensitive_files", "admin_panels"],
            max_workers=30,
        )
        return ScanJobResult(
            True,
            "Directory bruteforce completed",
            summary={"target": target_url, "results": res},
        )
    finally:
        await http_client.close()


def run_scan_job(scan_type: str, target_url: str, output_dir: str) -> ScanJobResult:
    """
    Synchronous wrapper so Flask routes can call scans safely.
    Internally این تابع از asyncio.run استفاده می‌کند.
    """

    async def _runner() -> ScanJobResult:
        if scan_type == "deep":
            return await _run_deep_scan(target_url, output_dir)
        if scan_type == "normal":
            return await _run_normal_scan(target_url, output_dir)
        if scan_type == "port":
            return await _run_port_scan(target_url)
        if scan_type == "dir_bruteforce":
            return await _run_dir_bruteforce(target_url)

        # Single-scanner modes
        return await _run_single_scanner(target_url, scan_type)

    return asyncio.run(_runner())


