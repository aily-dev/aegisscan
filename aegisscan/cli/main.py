"""
AegisScan CLI
"""
import asyncio
import argparse
import sys
from typing import List, Optional
import logging
from ..core.engine import AsyncEngine
from ..core.logger import setup_logger
from ..core.proxy import ProxyManager
from ..http.client import AsyncHTTPClient
from ..scanners.sqli import SQLiScanner
from ..scanners.xss import XSSScanner
from ..scanners.command_injection import CommandInjectionScanner
from ..scanners.path_traversal import PathTraversalScanner
from ..scanners.ssti import SSTIScanner
from ..scanners.lfi_rfi import LFIRFIScanner
from ..scanners.open_redirect import OpenRedirectScanner
from ..scanners.csrf import CSRFScanner
from ..scanners.auth import AuthScanner
from ..recon.subdomain import SubdomainEnumerator
from ..recon.port_scan import PortScanner
from ..recon.directory import DirectoryBruteforcer
from ..recon.passive import PassiveRecon
from ..crawler.engine import Crawler
from ..fingerprint.engine import FingerprintEngine
from ..analyzer.passive import PassiveAnalyzer
from ..templates.engine import TemplateEngine
from ..reports.generator import ReportGenerator
from ..scanners.base import Vulnerability


class AegisScanCLI:
    """Main CLI interface"""
    
    def __init__(self):
        self.engine = None
        self.http_client = None
        self.logger = None
    
    async def initialize(self, proxy: Optional[str] = None, use_tor: bool = False):
        """Initialize components"""
        # Setup logger
        self.logger = setup_logger("aegisscan", logging.INFO)
        
        # Setup proxy
        proxy_manager = ProxyManager(proxies=[proxy] if proxy else None, use_tor=use_tor)
        proxy_dict = proxy_manager.get_proxy_dict()
        
        # Initialize HTTP client
        self.http_client = AsyncHTTPClient(proxy=proxy_dict.get("http") if proxy_dict else None)
        
        # Initialize engine
        self.engine = AsyncEngine(max_workers=10, rate_limit=10)
        await self.engine.start()
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.http_client:
            await self.http_client.close()
        if self.engine:
            await self.engine.stop()
    
    async def scan(self, url: str, scanners: Optional[List[str]] = None, full: bool = False) -> List[Vulnerability]:
        """Run vulnerability scan"""
        all_vulnerabilities = []
        
        scanners_to_run = scanners or []
        
        if full or not scanners_to_run:
            scanners_to_run = [
                "sqli", "xss", "command_injection", "path_traversal",
                "ssti", "lfi_rfi", "open_redirect", "csrf", "auth"
            ]
        
        scanner_map = {
            "sqli": SQLiScanner,
            "xss": XSSScanner,
            "command_injection": CommandInjectionScanner,
            "path_traversal": PathTraversalScanner,
            "ssti": SSTIScanner,
            "lfi_rfi": LFIRFIScanner,
            "open_redirect": OpenRedirectScanner,
            "csrf": CSRFScanner,
            "auth": AuthScanner,
        }
        
        self.logger.info(f"Starting scan of {url}")
        
        for scanner_name in scanners_to_run:
            if scanner_name in scanner_map:
                self.logger.info(f"Running {scanner_name} scanner...")
                scanner = scanner_map[scanner_name](self.http_client, self.engine)
                try:
                    vulns = await scanner.scan(url)
                    all_vulnerabilities.extend(vulns)
                    self.logger.info(f"Found {len(vulns)} vulnerabilities with {scanner_name}")
                except Exception as e:
                    self.logger.error(f"Error in {scanner_name}: {e}")
        
        # Also run passive analyzer
        self.logger.info("Running passive analyzer...")
        passive = PassiveAnalyzer(self.http_client, self.engine)
        try:
            vulns = await passive.scan(url)
            all_vulnerabilities.extend(vulns)
        except Exception as e:
            self.logger.error(f"Error in passive analyzer: {e}")
        
        return all_vulnerabilities
    
    async def recon(self, domain: str) -> dict:
        """Run reconnaissance"""
        results = {}
        
        self.logger.info(f"Starting reconnaissance of {domain}")
        
        # Subdomain enumeration
        self.logger.info("Enumerating subdomains...")
        subdomain_enum = SubdomainEnumerator(self.http_client)
        subdomains = await subdomain_enum.enumerate(domain)
        results["subdomains"] = subdomains
        self.logger.info(f"Found {len(subdomains)} subdomains")
        
        # Port scan
        self.logger.info("Scanning ports...")
        port_scanner = PortScanner()
        ports = await port_scanner.scan(domain)
        results["ports"] = ports
        self.logger.info(f"Found {len(ports)} open ports")
        
        # Directory bruteforce
        self.logger.info("Bruteforcing directories...")
        dir_brute = DirectoryBruteforcer(self.http_client)
        url = f"https://{domain}" if not domain.startswith("http") else domain
        dirs = await dir_brute.bruteforce(url)
        results["directories"] = dirs
        self.logger.info(f"Found {len(dirs)} directories/files")
        
        # Passive recon
        self.logger.info("Performing passive reconnaissance...")
        try:
            resp = await self.http_client.get(url)
            passive_recon = PassiveRecon()
            passive_data = passive_recon.analyze_response(resp)
            results["passive"] = passive_data
        except:
            pass
        
        return results
    
    async def subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains"""
        self.logger.info(f"Enumerating subdomains for {domain}")
        subdomain_enum = SubdomainEnumerator(self.http_client)
        subdomains = await subdomain_enum.enumerate(domain)
        return subdomains
    
    async def dirs(self, url: str) -> List[dict]:
        """Bruteforce directories"""
        self.logger.info(f"Bruteforcing directories for {url}")
        dir_brute = DirectoryBruteforcer(self.http_client)
        dirs = await dir_brute.bruteforce(url)
        return dirs
    
    async def fingerprint(self, url: str) -> dict:
        """Fingerprint technologies"""
        self.logger.info(f"Fingerprinting {url}")
        try:
            resp = await self.http_client.get(url)
            fp_engine = FingerprintEngine()
            tech = fp_engine.fingerprint(resp)
            return tech
        except Exception as e:
            self.logger.error(f"Error fingerprinting: {e}")
            return {}
    
    async def crawl(self, url: str) -> dict:
        """Crawl website"""
        self.logger.info(f"Crawling {url}")
        crawler = Crawler(self.http_client)
        results = await crawler.crawl(url)
        return results
    
    def generate_report(self, vulnerabilities: List[Vulnerability], output_path: str, format: str = "html"):
        """Generate report"""
        report_gen = ReportGenerator()
        report_gen.add_vulnerabilities(vulnerabilities)
        report_gen.set_metadata({
            "tool": "AegisScan",
            "version": "1.0.0"
        })
        
        if format == "json":
            report_gen.generate_json(output_path)
        elif format == "html":
            report_gen.generate_html(output_path)
        elif format == "markdown":
            report_gen.generate_markdown(output_path)
        elif format == "text":
            report_gen.generate_text(output_path)
        
        self.logger.info(f"Report generated: {output_path}")


def main():
    """Main entry point"""
    asyncio.run(_main())


async def _main():
    """Async main entry point"""
    parser = argparse.ArgumentParser(description="AegisScan - Advanced Web Security Testing Framework")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scan")
    scan_parser.add_argument("url", help="Target URL")
    scan_parser.add_argument("--full", action="store_true", help="Run all scanners")
    scan_parser.add_argument("--sqli", action="store_true", help="SQL injection scan")
    scan_parser.add_argument("--xss", action="store_true", help="XSS scan")
    scan_parser.add_argument("--output", "-o", help="Output file for report")
    scan_parser.add_argument("--format", choices=["json", "html", "markdown", "text"], default="html", help="Report format")
    scan_parser.add_argument("--proxy", help="Proxy URL")
    scan_parser.add_argument("--tor", action="store_true", help="Use TOR")
    
    # Recon command
    recon_parser = subparsers.add_parser("recon", help="Run reconnaissance")
    recon_parser.add_argument("domain", help="Target domain")
    recon_parser.add_argument("--proxy", help="Proxy URL")
    
    # Subdomains command
    subdomain_parser = subparsers.add_parser("subdomains", help="Enumerate subdomains")
    subdomain_parser.add_argument("domain", help="Target domain")
    subdomain_parser.add_argument("--proxy", help="Proxy URL")
    
    # Dirs command
    dirs_parser = subparsers.add_parser("dirs", help="Bruteforce directories")
    dirs_parser.add_argument("url", help="Target URL")
    dirs_parser.add_argument("--proxy", help="Proxy URL")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate report from JSON")
    report_parser.add_argument("input", help="Input JSON file")
    report_parser.add_argument("output", help="Output file")
    report_parser.add_argument("--format", choices=["html", "markdown", "text"], default="html", help="Report format")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    cli = AegisScanCLI()
    
    try:
        # Initialize
        proxy = getattr(args, "proxy", None)
        use_tor = getattr(args, "tor", False)
        await cli.initialize(proxy=proxy, use_tor=use_tor)
        
        if args.command == "scan":
            scanners = []
            if args.sqli:
                scanners.append("sqli")
            if args.xss:
                scanners.append("xss")
            
            vulnerabilities = await cli.scan(args.url, scanners=scanners if scanners else None, full=args.full)
            
            print(f"\nScan complete. Found {len(vulnerabilities)} vulnerabilities.")
            
            if args.output:
                cli.generate_report(vulnerabilities, args.output, args.format)
            else:
                # Print summary
                for vuln in vulnerabilities:
                    print(f"[{vuln.severity.value.upper()}] {vuln.name} - {vuln.url}")
        
        elif args.command == "recon":
            results = await cli.recon(args.domain)
            print(f"\nReconnaissance complete:")
            print(f"Subdomains: {len(results.get('subdomains', []))}")
            print(f"Open ports: {len(results.get('ports', []))}")
            print(f"Directories: {len(results.get('directories', []))}")
        
        elif args.command == "subdomains":
            subdomains = await cli.subdomains(args.domain)
            print(f"\nFound {len(subdomains)} subdomains:")
            for subdomain in subdomains:
                print(f"  - {subdomain}")
        
        elif args.command == "dirs":
            dirs = await cli.dirs(args.url)
            print(f"\nFound {len(dirs)} directories/files:")
            for dir_info in dirs[:20]:  # Limit output
                print(f"  [{dir_info['status_code']}] {dir_info['url']}")
        
        elif args.command == "report":
            import json
            with open(args.input, 'r') as f:
                data = json.load(f)
            
            # Convert dicts back to Vulnerability objects
            vulns = []
            for v_dict in data.get("vulnerabilities", []):
                from ..scanners.base import Severity
                vuln = Vulnerability(
                    name=v_dict["name"],
                    severity=Severity(v_dict["severity"]),
                    url=v_dict["url"],
                    parameter=v_dict.get("parameter"),
                    payload=v_dict.get("payload"),
                    description=v_dict.get("description", ""),
                    evidence=v_dict.get("evidence", ""),
                    recommendation=v_dict.get("recommendation", ""),
                    cwe=v_dict.get("cwe"),
                    references=v_dict.get("references", [])
                )
                vulns.append(vuln)
            
            cli.generate_report(vulns, args.output, args.format)
            print(f"Report generated: {args.output}")
    
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
    finally:
        await cli.cleanup()


if __name__ == "__main__":
    main()

