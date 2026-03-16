#!/usr/bin/env python3
"""
AegisScan - Simple CLI for Deep Scanning
Usage: python3 aegis_deepscan.py <url>
"""

import asyncio
import sys
import os
import json
import argparse
from datetime import datetime
from pathlib import Path
import signal

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aegisscan import DeepScanner
from aegisscan.http.client import AsyncHTTPClient
from aegisscan.scanners.base import Severity


# رنگ‌ها برای ترمینال
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'


# Global variable for graceful shutdown
shutdown_requested = False


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global shutdown_requested
    print(f"\n\n{Colors.YELLOW}⚠️ Shutdown requested... Saving results...{Colors.NC}")
    shutdown_requested = True


def print_banner():
    """نمایش بنر"""
    print(f"""
{Colors.RED}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║     █████╗ ███████╗  ██████╗ ██╗███████╗                    ║
    ║    ██╔══██╗██╔════╝ ██╔════╝ ██║██╔════╝                    ║
    ║    ███████║█████╗   ██║  ███╗██║███████╗                    ║
    ║    ██╔══██║██╔══╝   ██║   ██║██║╚════██║                    ║
    ║    ██║  ██║███████╗ ╚██████╔╝██║███████║                    ║
    ║    ╚═╝  ╚═╝╚══════╝  ╚═════╝ ╚═╝╚══════╝                    ║
    ║                                                              ║
    ║              Deep Scan - Security Testing                   ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
{Colors.NC}
""")


def print_section(title):
    """نمایش بخش"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 70}{Colors.NC}")
    print(f"{Colors.CYAN}{Colors.BOLD}{title}{Colors.NC}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'=' * 70}{Colors.NC}\n")


def print_vulnerability(vuln, index):
    """نمایش آسیب‌پذیری"""
    # رنگ بر اساس شدت
    severity = vuln.severity
    if hasattr(severity, 'value'):
        severity_str = severity.value
    else:
        severity_str = str(severity)
    
    if severity_str == 'CRITICAL':
        color = Colors.RED
    elif severity_str == 'HIGH':
        color = Colors.MAGENTA
    elif severity_str == 'MEDIUM':
        color = Colors.YELLOW
    elif severity_str == 'LOW':
        color = Colors.BLUE
    else:
        color = Colors.GREEN
    
    print(f"{color}{Colors.BOLD}[{index}] {vuln.name}{Colors.NC}")
    print(f"    {Colors.CYAN}URL:{Colors.NC} {vuln.url}")
    
    if vuln.parameter:
        print(f"    {Colors.CYAN}Parameter:{Colors.NC} {vuln.parameter}")
    
    if vuln.payload:
        print(f"    {Colors.CYAN}Payload:{Colors.NC} {vuln.payload[:100]}...")
    
    if vuln.evidence:
        print(f"    {Colors.CYAN}Evidence:{Colors.NC} {vuln.evidence[:200]}...")
    
    if vuln.description:
        print(f"    {Colors.CYAN}Description:{Colors.NC} {vuln.description[:300]}")
    
    if vuln.recommendation:
        print(f"    {Colors.CYAN}Recommendation:{Colors.NC} {vuln.recommendation[:200]}")
    
    if vuln.cwe:
        print(f"    {Colors.CYAN}CWE:{Colors.NC} {vuln.cwe}")
    
    print(f"    {Colors.CYAN}Severity:{Colors.NC} {color}{severity_str}{Colors.NC}")
    print()


async def deep_scan(url: str, output_dir: str = None, proxy: str = None):
    """اجرای دیپ اسکن"""
    
    if output_dir is None:
        output_dir = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print_banner()
    print(f"{Colors.YELLOW}🎯 Target: {Colors.WHITE}{url}{Colors.NC}")
    print(f"{Colors.YELLOW}📁 Output: {Colors.WHITE}{output_dir}{Colors.NC}")
    print(f"{Colors.YELLOW}⏰ Start: {Colors.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.NC}\n")
    
    if proxy:
        print(f"{Colors.YELLOW}🔒 Proxy: {Colors.WHITE}{proxy}{Colors.NC}\n")

    # ایجاد HTTP Client
    http_client = AsyncHTTPClient(
        timeout=60,
        max_redirects=10,
        verify_ssl=True,
        user_agent="AegisScan-DeepScan/1.0",
        proxy=proxy
    )
    
    try:
        # ایجاد DeepScanner
        scanner = DeepScanner(
            http_client,
            output_dir=output_dir,
            use_external_tools=True,
            auto_install_tools=True
        )
        
        # اجرای دیپ اسکن
        summary = await scanner.deep_scan(
            url,
            max_depth=3,
            max_pages=100
        )
        
        # نمایش نتایج
        print_section("📊 SCAN SUMMARY")
        
        # Discovery Results
        discovery = summary.get('discovery', {})
        print(f"{Colors.CYAN}Discovery Results:{Colors.NC}")
        print(f"  • URLs Discovered: {Colors.GREEN}{discovery.get('urls', 0)}{Colors.NC}")
        print(f"  • Forms Discovered: {Colors.GREEN}{discovery.get('forms', 0)}{Colors.NC}")
        print(f"  • Endpoints: {Colors.GREEN}{discovery.get('endpoints', 0)}{Colors.NC}")
        print(f"  • JavaScript Files: {Colors.GREEN}{discovery.get('js_files', 0)}{Colors.NC}")
        print(f"  • Input Fields: {Colors.GREEN}{discovery.get('inputs', 0)}{Colors.NC}")
        print(f"  • Open Ports: {Colors.GREEN}{discovery.get('ports', 0)}{Colors.NC}")
        print(f"  • Directories Found: {Colors.GREEN}{discovery.get('directories', 0)}{Colors.NC}")
        
        # Vulnerabilities by Severity
        vulns_by_severity = summary.get('vulnerabilities', {}).get('by_severity', {})
        print(f"\n{Colors.CYAN}Vulnerabilities by Severity:{Colors.NC}")
        
        severity_colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.MAGENTA,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.BLUE,
            'INFO': Colors.GREEN
        }
        
        total_vulns = 0
        for severity, count in vulns_by_severity.items():
            color = severity_colors.get(severity.upper(), Colors.WHITE)
            print(f"  • {color}{severity}: {count}{Colors.NC}")
            total_vulns += count
        
        # Vulnerabilities by Type
        vulns_by_type = summary.get('vulnerabilities', {}).get('by_type', {})
        if vulns_by_type:
            print(f"\n{Colors.CYAN}Vulnerabilities by Type:{Colors.NC}")
            for vuln_type, count in sorted(vulns_by_type.items(), key=lambda x: x[1], reverse=True):
                print(f"  • {vuln_type}: {count}")
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}Total Vulnerabilities Found: {total_vulns}{Colors.NC}")
        
        # نمایش جزئیات آسیب‌پذیری‌ها
        if scanner.all_vulnerabilities:
            print_section("🔓 VULNERABILITIES DETAILS")
            
            # مرتب‌سازی بر اساس شدت
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
            sorted_vulns = sorted(
                scanner.all_vulnerabilities,
                key=lambda v: severity_order.get(
                    v.severity.value if hasattr(v.severity, 'value') else str(v.severity), 
                    5
                )
            )
            
            for i, vuln in enumerate(sorted_vulns, 1):
                print_vulnerability(vuln, i)
        
        # نمایش پورت‌های باز
        if scanner.discovered_ports:
            print_section("🔌 OPEN PORTS")
            for port_info in scanner.discovered_ports[:20]:
                print(f"  • Port {port_info.get('port', 'N/A')}: {port_info.get('service', 'unknown')} ({port_info.get('status', 'open')})")
        
        # نمایش دایرکتوری‌های پیدا شده
        if scanner.discovered_directories:
            print_section("📂 DIRECTORIES FOUND")
            for dir_info in scanner.discovered_directories[:20]:
                status = dir_info.get('status_code', 'N/A')
                url = dir_info.get('url', 'N/A')
                print(f"  [{status}] {url}")
        
        # External Tools Results
        external = summary.get('external_tools', {})
        if external.get('used'):
            print_section("🔧 EXTERNAL TOOLS USED")
            for tool in external.get('used', []):
                print(f"  • {tool}")
        
        # ذخیره نتایج به JSON
        results_file = Path(output_dir) / "scan_summary.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ Scan completed!{Colors.NC}")
        print(f"{Colors.CYAN}📁 Results saved to: {output_dir}/{Colors.NC}")
        print(f"{Colors.CYAN}📄 Summary saved to: {results_file}{Colors.NC}")
        
        return summary
        
    except Exception as e:
        print(f"\n{Colors.RED}{Colors.BOLD}Error: {e}{Colors.NC}")
        import traceback
        traceback.print_exc()
        return None
        
    finally:
        await http_client.close()


def main():
    parser = argparse.ArgumentParser(
        description='AegisScan - Deep Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 aegis_deepscan.py https://example.com
  python3 aegis_deepscan.py https://example.com -o my_scan
  python3 aegis_deepscan.py http://localhost:8080
        """
    )
    
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output directory name', default=None)
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., socks5://127.0.0.1:9050, http://127.0.0.1:8080)', default=None)
    parser.add_argument('-t', '--tor', action='store_true', help='Use TOR proxy (socks5://127.0.0.1:9050)', default=False)
    
    args = parser.parse_args()
    
    # Determine proxy
    proxy = None
    if args.tor:
        proxy = "socks5://127.0.0.1:9050"
        print(f"{Colors.CYAN}Using TOR proxy: {proxy}{Colors.NC}")
    elif args.proxy:
        proxy = args.proxy
        print(f"{Colors.CYAN}Using proxy: {proxy}{Colors.NC}")
    
    # اعتبارسنجی URL
    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        print(f"{Colors.YELLOW}Warning: URL changed to {url}{Colors.NC}")
    
    # اجرای اسکن
    asyncio.run(deep_scan(url, args.output, proxy))


if __name__ == "__main__":
    main()

