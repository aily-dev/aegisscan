"""
Automated Deep Scanning System
"""
import asyncio
import subprocess
import json
import os
from typing import List, Dict, Optional, Set, Any
from pathlib import Path
import logging
from ..http.client import AsyncHTTPClient
from ..crawler.engine import Crawler
from ..scanners.base import Vulnerability, BaseScanner, Severity
from ..scanners.sqli import SQLiScanner
from ..scanners.sqli_advanced import AdvancedSQLiScanner as EnhancedSQLiScanner
from ..scanners.xss import XSSScanner
from ..scanners.command_injection import CommandInjectionScanner
from ..scanners.path_traversal import PathTraversalScanner
from ..scanners.ssti import SSTIScanner
from ..scanners.lfi_rfi import LFIRFIScanner
from ..scanners.open_redirect import OpenRedirectScanner
from ..scanners.csrf import CSRFScanner
from ..scanners.auth import AuthScanner
from ..analyzer.passive import PassiveAnalyzer
from ..recon.passive import PassiveRecon
from ..recon.enhanced_port_scan import EnhancedPortScanner
from ..recon.enhanced_directory import EnhancedDirectoryBruteforcer
from ..recon.path_discovery import PathDiscovery
from ..recon.service_tester import ServiceTester
from ..integrations.external_tools import ExternalToolManager
from ..utils.wordlists import WordlistManager
from ..utils.wordlist_downloader import WordlistDownloader


class DeepScanner:
    """Automated Deep Scanning System"""
    
    def __init__(self, http_client: AsyncHTTPClient, output_dir: str = "scan_results", use_external_tools: bool = True, auto_install_tools: bool = True):
        self.http_client = http_client
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self._logger = logging.getLogger(__name__)
        self.use_external_tools = use_external_tools
        self.auto_install_tools = auto_install_tools
        
        # Wordlist manager
        self.wordlist_manager = WordlistManager()
        
        # Wordlist downloader
        self.wordlist_downloader = WordlistDownloader(
            wordlists_dir=str(self.output_dir / "wordlists")
        )
        
        # Service tester
        self.service_tester = ServiceTester(wordlist_manager=self.wordlist_manager)
        
        # External tools manager with auto-install
        self.tool_manager = ExternalToolManager(
            output_dir=str(self.output_dir / "external_tools"),
            auto_install=auto_install_tools
        ) if use_external_tools else None
        
        # Store discovered information
        self.discovered_urls: Set[str] = set()
        self.discovered_forms: List[Dict] = []
        self.discovered_endpoints: List[str] = []
        self.discovered_inputs: List[Dict] = []
        self.discovered_js_files: List[str] = []
        self.discovered_paths: Set[str] = set()
        self.discovered_ports: List[Dict] = []
        self.discovered_directories: List[Dict] = []
        self.discovered_parameters: Dict[str, List[str]] = {}
        
        # Scan results
        self.all_vulnerabilities: List[Vulnerability] = []
        self.external_tool_results: Dict[str, Any] = {}
    
    async def deep_scan(self, start_url: str, max_depth: int = 3, max_pages: int = 100) -> Dict:
        """Deep comprehensive scan"""
        self._logger.info(f"Starting deep scan of {start_url}")
        
        # Phase 1: Crawling and Discovery
        print("\n" + "=" * 70)
        print("Phase 1: Discovering forms, endpoints and site structure")
        print("=" * 70)
        
        discovery_results = await self._discover_all(start_url, max_depth, max_pages)
        
        # Phase 2: Port Scanning
        print("\n" + "=" * 70)
        print("Phase 2: Port scanning and service detection")
        print("=" * 70)
        
        await self._port_scanning(start_url)
        
        # Phase 2.5: Service Authentication Testing
        print("\n" + "=" * 70)
        print("Phase 2.5: Service authentication testing and brute forcing")
        print("=" * 70)
        
        await self._service_authentication_testing(start_url)
        
        # Phase 3: Enhanced Directory Bruteforce
        print("\n" + "=" * 70)
        print("Phase 3: Enhanced directory and path discovery")
        print("=" * 70)
        
        await self._enhanced_directory_bruteforce(start_url)
        
        # Phase 4: Path Discovery
        print("\n" + "=" * 70)
        print("Phase 4: Advanced path and endpoint discovery")
        print("=" * 70)
        
        await self._advanced_path_discovery(start_url)
        
        # Phase 5: Passive Analysis
        print("\n" + "=" * 70)
        print("Phase 5: Passive security analysis")
        print("=" * 70)
        
        await self._passive_analysis(start_url)
        
        # Phase 6: Active Scanning
        print("\n" + "=" * 70)
        print("Phase 6: Active vulnerability scanning")
        print("=" * 70)
        
        await self._active_scanning()
        
        # Phase 7: Deep Testing with external tools
        print("\n" + "=" * 70)
        print("Phase 7: Deep testing with specialized tools")
        print("=" * 70)
        
        await self._deep_testing_with_tools()
        
        # Generate summary
        return self._generate_summary()
    
    async def _discover_all(self, start_url: str, max_depth: int, max_pages: int) -> Dict:
        """Complete site discovery"""
        crawler = Crawler(self.http_client, max_depth=max_depth, max_pages=max_pages)
        
        print(f"Crawling {start_url}...")
        
        try:
            crawl_results = await crawler.crawl(
                start_url,
                mode="BFS",
                extract_forms=True,
                extract_js=True
            )
        except Exception as e:
            self._logger.debug(f"Error in crawling: {e}")
            crawl_results = {
                "urls": [],
                "forms": [],
                "endpoints": [],
                "js_files": [],
                "inputs": [],
                "pages_crawled": 0
            }
        
        # Store results
        self.discovered_urls.update(crawl_results["urls"])
        self.discovered_forms.extend(crawl_results["forms"])
        self.discovered_endpoints.extend(crawl_results["endpoints"])
        self.discovered_js_files.extend(crawl_results["js_files"])
        
        # Extract inputs from pages
        for url in list(self.discovered_urls)[:50]:  # Limit for performance
            try:
                resp = await self.http_client.get(url, timeout=10)
                passive_recon = PassiveRecon()
                data = passive_recon.analyze_response(resp)
                self.discovered_inputs.extend(data.get("inputs", []))
            except Exception as e:
                self._logger.debug(f"Error extracting inputs from {url}: {e}")
                continue
        
        print(f"\nDiscovered:")
        print(f"   - {len(self.discovered_urls)} URLs")
        print(f"   - {len(self.discovered_forms)} forms")
        print(f"   - {len(self.discovered_endpoints)} endpoints")
        print(f"   - {len(self.discovered_js_files)} JavaScript files")
        print(f"   - {len(self.discovered_inputs)} input fields")
        
        # Save to file
        discovery_file = self.output_dir / "discovery.json"
        with open(discovery_file, 'w', encoding='utf-8') as f:
            json.dump({
                "urls": list(self.discovered_urls),
                "forms": self.discovered_forms,
                "endpoints": self.discovered_endpoints,
                "js_files": self.discovered_js_files,
                "inputs": self.discovered_inputs[:100],  # Limit
                "paths": list(self.discovered_paths),
                "ports": self.discovered_ports,
                "directories": self.discovered_directories,
                "parameters": self.discovered_parameters,
            }, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"   Saved: {discovery_file}")
        
        return crawl_results
    
    async def _port_scanning(self, start_url: str):
        """Port scanning on discovered hosts"""
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(start_url)
            host = parsed.netloc.split(':')[0]  # Remove port if present
            
            print(f"Scanning ports on {host}...")
            
            port_scanner = EnhancedPortScanner(wordlist_manager=self.wordlist_manager)
            
            # Scan common ports
            open_ports = await port_scanner.scan_top_ports(host, top_n=100)
            
            self.discovered_ports = open_ports
            
            if open_ports:
                print(f"Found {len(open_ports)} open ports:")
                for port_info in open_ports[:10]:  # Show first 10
                    print(f"   - Port {port_info['port']}: {port_info.get('service', 'unknown')} ({port_info.get('status', 'open')})")
            else:
                print("No open ports found")
            
            # Save port scan results
            ports_file = self.output_dir / "port_scan.json"
            try:
                with open(ports_file, 'w') as f:
                    json.dump(open_ports, f, indent=2, default=str)
                print(f"   Saved: {ports_file}")
            except Exception as e:
                self._logger.debug(f"Error saving port scan results: {e}")
        except Exception as e:
            self._logger.debug(f"Error in port scanning: {e}")
            self.discovered_ports = []
    
    async def _service_authentication_testing(self, start_url: str):
        """Test services for authentication and perform brute force"""
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(start_url)
            host = parsed.netloc.split(':')[0]
            
            if not self.discovered_ports:
                print("No open ports found, skipping service testing")
                return
            
            print(f"Testing {len(self.discovered_ports)} services on {host}...")
            
            # Download wordlists if needed
            print("\nDownloading wordlists for brute forcing...")
            try:
                wordlist_results = await self.wordlist_downloader.download_popular_wordlists(force=False)
                downloaded = [name for name, path in wordlist_results.items() if path]
                if downloaded:
                    print(f"   Downloaded wordlists: {', '.join(downloaded)}")
            except Exception as e:
                self._logger.debug(f"Error downloading wordlists: {e}")
            
            service_results = []
            credentials_found = []
            
            # Test each open port
            for port_info in self.discovered_ports:
                port = port_info.get("port")
                service = port_info.get("service", "unknown")
                
                if service == "unknown":
                    continue
                
                print(f"\nTesting {service} on port {port}...")
                
                # Test service authentication
                test_result = await self.service_tester.test_service(host, port, service)
                service_results.append(test_result)
                
                # Report results
                if test_result.get("error"):
                    print(f"   Error: {test_result['error']}")
                    continue
                
                if not test_result.get("requires_auth"):
                    print(f"   ✓ No authentication required (anonymous access allowed)")
                    if test_result.get("credentials"):
                        for cred in test_result["credentials"]:
                            credentials_found.append({
                                "host": host,
                                "port": port,
                                "service": service,
                                **cred
                            })
                            print(f"   ✓ Valid credentials: {cred.get('username', 'N/A')}:{cred.get('password', 'N/A')}")
                elif test_result.get("anonymous_allowed"):
                    print(f"   ✓ Anonymous access allowed")
                else:
                    print(f"   ⚠ Authentication required - starting brute force...")
                    
                    # Load wordlists
                    usernames = []
                    passwords = []
                    
                    # Try to load from downloaded wordlists
                    try:
                        usernames_list = self.wordlist_downloader.load_wordlist("usernames", max_lines=1000)
                        if usernames_list:
                            usernames = usernames_list
                        else:
                            usernames = self.service_tester.default_credentials["usernames"]
                    except:
                        usernames = self.service_tester.default_credentials["usernames"]
                    
                    try:
                        passwords_list = self.wordlist_downloader.load_wordlist("common_passwords", max_lines=5000)
                        if passwords_list:
                            passwords = passwords_list
                        else:
                            passwords = self.service_tester.default_credentials["passwords"]
                    except:
                        passwords = self.service_tester.default_credentials["passwords"]
                    
                    # Perform brute force
                    brute_result = await self.service_tester.brute_force_service(
                        host, port, service,
                        usernames=usernames,
                        passwords=passwords,
                        max_attempts=5000  # Limit attempts
                    )
                    
                    if brute_result.get("found_credentials"):
                        print(f"   ✓ Found {len(brute_result['found_credentials'])} valid credential(s):")
                        for cred in brute_result["found_credentials"]:
                            credentials_found.append({
                                "host": host,
                                "port": port,
                                "service": service,
                                **cred
                            })
                            username = cred.get("username", "N/A")
                            password = cred.get("password", "N/A")
                            print(f"      - {username}:{password}")
                    else:
                        print(f"   ✗ No valid credentials found (attempted {brute_result.get('attempted', 0)} combinations)")
            
            # Save results
            if service_results:
                service_file = self.output_dir / "service_testing.json"
                try:
                    with open(service_file, 'w') as f:
                        json.dump({
                            "service_tests": service_results,
                            "credentials_found": credentials_found
                        }, f, indent=2, default=str)
                    print(f"\n   Saved service testing results: {service_file}")
                except Exception as e:
                    self._logger.debug(f"Error saving service testing results: {e}")
            
            if credentials_found:
                print(f"\n⚠️  Found {len(credentials_found)} valid credential(s) across services!")
            else:
                print("\n✓ No valid credentials found")
                
        except Exception as e:
            self._logger.debug(f"Error in service authentication testing: {e}")
    
    async def _enhanced_directory_bruteforce(self, start_url: str):
        """Enhanced directory bruteforce with wordlists"""
        print(f"Bruteforcing directories on {start_url}...")
        
        try:
            dir_brute = EnhancedDirectoryBruteforcer(
                self.http_client,
                wordlist_manager=self.wordlist_manager
            )
            
            # Bruteforce with multiple wordlist categories
            # Use smaller max_workers to avoid overwhelming the server
            directories = await dir_brute.bruteforce(
                start_url,
                wordlist_categories=["directories", "sensitive_files", "admin_panels"],
                max_workers=10  # Reduced from 30 to 10
            )
            
            self.discovered_directories = directories
            
            if directories:
                print(f"Found {len(directories)} directories/files:")
                for dir_info in directories[:20]:  # Show first 20
                    status = dir_info['status_code']
                    url = dir_info['url']
                    size = dir_info.get('size', 0)
                    print(f"   [{status}] {url} ({size} bytes)")
            else:
                print("No directories found")
            
            # Test 403 bypass on found directories
            if directories:
                print("\nTesting 403 bypass techniques...")
                for dir_info in directories[:5]:  # Limit
                    if dir_info['status_code'] == 403:
                        try:
                            bypasses = await dir_brute.test_403_bypass(dir_info['url'])
                            if bypasses:
                                # Attach detailed bypass info so it appears in JSON reports
                                dir_info["403_bypass"] = bypasses
                                print(f"   Bypass found for {dir_info['url']}:")
                                for bp in bypasses:
                                    tech = bp.get("technique", "unknown_technique")
                                    payload = bp.get("payload", "")
                                    desc = bp.get("description", "")
                                    print(
                                        f"      - Technique: {tech}\n"
                                        f"        Payload:   {payload}\n"
                                        f"        Detail:    {desc[:200]}"
                                    )
                        except Exception as e:
                            self._logger.debug(f"Error testing 403 bypass: {e}")
            
            # Bruteforce API endpoints
            print("\nBruteforcing API endpoints...")
            try:
                api_endpoints = await dir_brute.bruteforce_api_endpoints(start_url)
                self.discovered_endpoints.extend([ep['url'] for ep in api_endpoints])
            except Exception as e:
                self._logger.debug(f"Error in API endpoint bruteforce: {e}")
                api_endpoints = []
            
            # Bruteforce admin panels
            print("\nBruteforcing admin panels...")
            try:
                admin_panels = await dir_brute.bruteforce_admin_panels(start_url)
                if admin_panels:
                    print(f"   Found {len(admin_panels)} admin panels")
            except Exception as e:
                self._logger.debug(f"Error in admin panel bruteforce: {e}")
                admin_panels = []
            
            # Save directory bruteforce results
            dirs_file = self.output_dir / "directory_bruteforce.json"
            try:
                with open(dirs_file, 'w') as f:
                    json.dump(directories + api_endpoints + admin_panels, f, indent=2, default=str)
                print(f"   Saved: {dirs_file}")
            except Exception as e:
                self._logger.debug(f"Error saving directory bruteforce results: {e}")
        except Exception as e:
            self._logger.debug(f"Error in directory bruteforce: {e}")
            self.discovered_directories = []
    
    async def _advanced_path_discovery(self, start_url: str):
        """Advanced path and endpoint discovery"""
        print(f"Discovering paths and endpoints on {start_url}...")
        
        try:
            path_discovery = PathDiscovery(
                self.http_client,
                wordlist_manager=self.wordlist_manager
            )
            
            # Discover from sitemap
            print("Checking sitemap.xml and robots.txt...")
            try:
                sitemap_paths = await path_discovery.discover_from_sitemap(start_url)
                self.discovered_paths.update(sitemap_paths)
            except Exception as e:
                self._logger.debug(f"Error discovering from sitemap: {e}")
            
            # Discover from main page
            try:
                resp = await self.http_client.get(start_url, timeout=10)
                page_paths = await path_discovery.discover_paths_from_response(resp, start_url)
                self.discovered_paths.update(page_paths)
            except Exception as e:
                self._logger.debug(f"Error discovering paths from main page: {e}")
            
            # Discover from JavaScript files
            if self.discovered_js_files:
                print(f"Analyzing {len(self.discovered_js_files)} JavaScript files...")
                try:
                    js_paths = await path_discovery.discover_from_js_files(list(self.discovered_js_files))
                    self.discovered_paths.update(js_paths)
                except Exception as e:
                    self._logger.debug(f"Error discovering from JS files: {e}")
            
            # Discover parameters
            print("Discovering parameters...")
            for url in list(self.discovered_urls)[:20]:  # Limit
                try:
                    params = await path_discovery.discover_parameters(url)
                    if params:
                        self.discovered_parameters[url] = list(params.keys())
                except Exception as e:
                    self._logger.debug(f"Error discovering parameters from {url}: {e}")
                    continue
            
            if self.discovered_paths:
                print(f"Discovered {len(self.discovered_paths)} paths/endpoints")
            
            # Save path discovery results
            paths_file = self.output_dir / "path_discovery.json"
            try:
                with open(paths_file, 'w') as f:
                    json.dump({
                        "paths": list(self.discovered_paths),
                        "parameters": self.discovered_parameters
                    }, f, indent=2, default=str)
                print(f"   Saved: {paths_file}")
            except Exception as e:
                self._logger.debug(f"Error saving path discovery results: {e}")
        except Exception as e:
            self._logger.debug(f"Error in path discovery: {e}")
    
    async def _passive_analysis(self, start_url: str):
        """Passive security analysis"""
        print(f"Running passive analysis on {start_url}...")
        
        passive_analyzer = PassiveAnalyzer(self.http_client)
        vulns = await passive_analyzer.scan(start_url)
        
        self.all_vulnerabilities.extend(vulns)
        
        # Analyze discovered URLs
        for url in list(self.discovered_urls)[:20]:  # Limit
            try:
                vulns = await passive_analyzer.scan(url)
                self.all_vulnerabilities.extend(vulns)
            except:
                continue
        
        print(f"Found {len(vulns)} passive security issues")
    
    async def _active_scanning(self):
        """Active scanning on all discovered targets"""
        scanners = {
            "SQL Injection": SQLiScanner,
            "Advanced SQL Injection": EnhancedSQLiScanner,
            "XSS": XSSScanner,
            "Command Injection": CommandInjectionScanner,
            "Path Traversal": PathTraversalScanner,
            "SSTI": SSTIScanner,
            "LFI/RFI": LFIRFIScanner,
            "Open Redirect": OpenRedirectScanner,
            "CSRF": CSRFScanner,
            "Auth": AuthScanner,
        }
        
        # Scan main URLs
        urls_to_scan = list(self.discovered_urls)[:30]  # Limit for performance
        
        for scanner_name, scanner_class in scanners.items():
            print(f"\nScanning {scanner_name}...")
            scanner = scanner_class(self.http_client)
            
            for url in urls_to_scan:
                try:
                    # Extract parameters from URL
                    params = self._extract_params_from_url(url)
                    
                    # Only scan if there are parameters
                    if not params:
                        continue
                    
                    # Scan
                    vulns = await scanner.scan(url, params=params, method="GET")
                    self.all_vulnerabilities.extend(vulns)
                    
                    if vulns:
                        print(f"   Found {len(vulns)} vulnerabilities in {url}")
                except Exception as e:
                    self._logger.debug(f"Error scanning {url}: {e}")
                    continue
            
            # Scan forms
            for form in self.discovered_forms[:20]:  # Limit
                try:
                    if form["method"] == "POST" and form.get("inputs"):
                        # Extract parameters from form
                        form_params = {inp["name"]: "test" for inp in form.get("inputs", [])}
                        
                        form_url = form.get("action") or list(self.discovered_urls)[0] if self.discovered_urls else ""
                        if form_url:
                            vulns = await scanner.scan(
                                form_url,
                                params=form_params,
                                method="POST"
                            )
                            self.all_vulnerabilities.extend(vulns)
                except:
                    continue
        
        print(f"\nActive scanning completed. Found {len(self.all_vulnerabilities)} vulnerabilities")
        
        # If no vulnerabilities found, use external tools
        if len(self.all_vulnerabilities) == 0 and self.use_external_tools:
            print("\nInternal scanners found nothing. Using external tools for deeper analysis...")
    
    async def _deep_testing_with_tools(self):
        """Deep testing with external tools - only if internal scanners found nothing"""
        if not self.use_external_tools or not self.tool_manager:
            return
        
        # If vulnerabilities found, use external tools for confirmation
        # If nothing found, use deeper scanning
        use_deep_scan = len(self.all_vulnerabilities) == 0
        
        # Check tool availability
        print("\nChecking external tools...")
        tools_to_check = ["sqlmap", "xsstrike", "dalfox", "commix", "nikto", "nuclei", "wfuzz"]
        for tool in tools_to_check:
            available = await self.tool_manager.check_tool_available(tool)
            if available:
                print(f"   ✓ {tool} available")
            else:
                print(f"   ✗ {tool} not available")
        
        # SQLMap for SQL Injection - only if SQL Injection not found
        if use_deep_scan or not any("SQL Injection" in v.name for v in self.all_vulnerabilities):
            print("\nDeep testing SQL Injection with SQLMap...")
            sqlmap_results = await self._run_sqlmap_deep()
            if sqlmap_results:
                self.external_tool_results["sqlmap"] = sqlmap_results
        
        # XSS Tools - only if XSS not found
        if use_deep_scan or not any("XSS" in v.name or "Cross-Site Scripting" in v.name for v in self.all_vulnerabilities):
            print("\nDeep testing XSS with specialized tools...")
            xss_results = await self._run_xss_tools_deep()
            if xss_results:
                self.external_tool_results["xss"] = xss_results
        
        # Command Injection - only if not found
        if use_deep_scan or not any("Command Injection" in v.name for v in self.all_vulnerabilities):
            print("\nDeep testing Command Injection with Commix...")
            commix_results = await self._run_commix_deep()
            if commix_results:
                self.external_tool_results["commix"] = commix_results
        
        # Nikto for general scanning
        print("\nTesting with Nikto...")
        nikto_results = await self._run_nikto_deep()
        if nikto_results:
            self.external_tool_results["nikto"] = nikto_results
        
        # Nuclei for template-based scanning
        print("\nTesting with Nuclei...")
        nuclei_results = await self._run_nuclei_deep()
        if nuclei_results:
            self.external_tool_results["nuclei"] = nuclei_results
        
        # WFuzz for directory bruteforce
        print("\nTesting with WFuzz...")
        wfuzz_results = await self._run_wfuzz_deep()
        if wfuzz_results:
            self.external_tool_results["wfuzz"] = wfuzz_results
    
    async def _run_sqlmap_deep(self) -> List[Dict]:
        """Run SQLMap for deep SQL Injection testing"""
        if not self.tool_manager:
            return []
        
        sqlmap_results = []
        
        # Test URLs with parameters
        for url in list(self.discovered_urls)[:10]:  # Limit
            if "?" in url:
                try:
                    params = self._extract_params_from_url(url)
                    if not params:
                        continue
                    
                    result = await self.tool_manager.run_sqlmap(url, params=params, level=3, risk=2)
                    if result:
                        sqlmap_results.append(result)
                        
                        # Check results more carefully
                        if result.get("vulnerable"):
                            # Convert to Vulnerability
                            # Severity already imported at top of file
                            
                            # Extract more information
                            vuln_type = result.get("type", "Unknown")
                            dbms = result.get("dbms", "Unknown")
                            param = result.get("parameter", "Unknown")
                            payload = result.get("payload", "")
                            
                            evidence_parts = []
                            if vuln_type and vuln_type != "Unknown":
                                evidence_parts.append(f"Type: {vuln_type}")
                            if dbms and dbms != "Unknown":
                                evidence_parts.append(f"DBMS: {dbms}")
                            if param and param != "Unknown":
                                evidence_parts.append(f"Parameter: {param}")
                            if payload:
                                evidence_parts.append(f"Payload: {payload[:100]}")
                            
                            evidence = " | ".join(evidence_parts) if evidence_parts else result.get("output", "")[:500]
                            
                            vuln = Vulnerability(
                                name=f"SQL Injection (SQLMap Confirmed - {vuln_type})",
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter=param if param != "Unknown" else None,
                                payload=payload[:200] if payload else None,
                                description=f"SQL Injection vulnerability confirmed by SQLMap. Type: {vuln_type}, DBMS: {dbms}",
                                evidence=evidence,
                                recommendation="Use parameterized queries and input validation. Disable error messages in production.",
                                cwe="CWE-89"
                            )
                            self.all_vulnerabilities.append(vuln)
                            self._logger.info(f"SQL Injection found in {url} ({vuln_type}, {dbms})")
                        else:
                            # Even if not vulnerable, check output
                            output = result.get("output", "")
                            if output and ("testing" in output.lower() or "scanning" in output.lower()):
                                # SQLMap is testing, may need more time
                                self._logger.debug(f"SQLMap testing {url}, may need more time")
                except Exception as e:
                    self._logger.debug(f"SQLMap error for {url}: {e}")
                    continue
        
        # Test forms
        for form in self.discovered_forms[:5]:
            if form.get("action") and form.get("inputs"):
                try:
                    form_url = form["action"]
                    if not form_url or form_url == "#":
                        continue
                    
                    form_params = {inp["name"]: "test" for inp in form["inputs"][:5]}
                    result = await self.tool_manager.run_sqlmap(form_url, params=form_params, level=3, risk=2)
                    if result and result.get("vulnerable"):
                        sqlmap_results.append(result)
                except Exception as e:
                    self._logger.debug(f"SQLMap error for form: {e}")
                    continue
        
        if sqlmap_results:
            print(f"   ✓ SQLMap: Found {len(sqlmap_results)} vulnerabilities")
        else:
            print("   ℹ SQLMap: No vulnerabilities found")
        
        return sqlmap_results
    
    async def _run_xss_tools_deep(self) -> Dict:
        """Run XSS tools"""
        if not self.tool_manager:
            return {}
        
        results = {}
        
        # XSStrike
        for url in list(self.discovered_urls)[:10]:
            if "?" in url:
                try:
                    params = self._extract_params_from_url(url)
                    result = await self.tool_manager.run_xsstrike(url, params=params)
                    if result and result.get("vulnerable"):
                        results["xsstrike"] = results.get("xsstrike", []) + [result]
                except:
                    continue
        
        # Dalfox
        for url in list(self.discovered_urls)[:10]:
            if "?" in url:
                try:
                    params = self._extract_params_from_url(url)
                    result = await self.tool_manager.run_dalfox(url, params=params)
                    if result and result.get("vulnerable"):
                        results["dalfox"] = results.get("dalfox", []) + [result]
                except:
                    continue
        
        if results:
            total = sum(len(v) for v in results.values())
            print(f"   ✓ XSS Tools: Found {total} vulnerabilities")
        else:
            print("   ℹ XSS Tools: No vulnerabilities found")
        
        return results
    
    async def _run_commix_deep(self) -> List[Dict]:
        """Run Commix for Command Injection"""
        if not self.tool_manager:
            return []
        
        commix_results = []
        
        for url in list(self.discovered_urls)[:10]:
            if "?" in url:
                try:
                    params = self._extract_params_from_url(url)
                    result = await self.tool_manager.run_commix(url, params=params)
                    if result and result.get("vulnerable"):
                        commix_results.append(result)
                except:
                    continue
        
        if commix_results:
            print(f"   ✓ Commix: Found {len(commix_results)} vulnerabilities")
        else:
            print("   ℹ Commix: No vulnerabilities found")
        
        return commix_results
    
    async def _run_nikto_deep(self) -> Optional[Dict]:
        """Run Nikto"""
        if not self.tool_manager or not self.discovered_urls:
            return None
        
        try:
            from urllib.parse import urlparse
            url = list(self.discovered_urls)[0]
            parsed = urlparse(url)
            host = parsed.netloc
            
            result = await self.tool_manager.run_nikto(host)
            if result:
                print(f"   ✓ Nikto: Results saved")
            return result
        except Exception as e:
            self._logger.debug(f"Nikto error: {e}")
            return None
    
    async def _run_nuclei_deep(self) -> Optional[Dict]:
        """Run Nuclei"""
        if not self.tool_manager or not self.discovered_urls:
            return None
        
        try:
            urls = list(self.discovered_urls)[:50]
            result = await self.tool_manager.run_nuclei(urls)
            if result and result.get("findings"):
                print(f"   ✓ Nuclei: Found {len(result['findings'])} findings")
            elif result:
                print(f"   ✓ Nuclei: Results saved")
            return result
        except Exception as e:
            self._logger.debug(f"Nuclei error: {e}")
            return None
    
    async def _run_wfuzz_deep(self) -> Optional[Dict]:
        """Run WFuzz"""
        if not self.tool_manager or not self.discovered_urls:
            return None
        
        try:
            # Test on first URL
            url = list(self.discovered_urls)[0]
            # Convert to base URL for directory bruteforce
            from urllib.parse import urlparse, urlunparse
            parsed = list(urlparse(url))
            parsed[2] = "/FUZZ"  # Path
            parsed[3] = ""  # Query
            parsed[4] = ""  # Fragment
            base_url = urlunparse(parsed)
            
            result = await self.tool_manager.run_wfuzz(base_url)
            if result and result.get("findings"):
                print(f"   ✓ WFuzz: Found {len(result['findings'])} findings")
            return result
        except Exception as e:
            self._logger.debug(f"WFuzz error: {e}")
            return None
    
    def _extract_params_from_url(self, url: str) -> Dict[str, str]:
        """Extract parameters from URL"""
        params = {}
        if "?" in url:
            query_string = url.split("?")[1].split("#")[0]
            for param in query_string.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    params[key] = value
        return params
    
    def _generate_summary(self) -> Dict:
        """Generate results summary"""
        summary = {
            "discovery": {
                "urls": len(self.discovered_urls),
                "forms": len(self.discovered_forms),
                "endpoints": len(self.discovered_endpoints),
                "js_files": len(self.discovered_js_files),
                "inputs": len(self.discovered_inputs),
                "paths": len(self.discovered_paths),
                "ports": len(self.discovered_ports),
                "directories": len(self.discovered_directories),
                "parameters": sum(len(v) for v in self.discovered_parameters.values()),
            },
            "vulnerabilities": {
                "total": len(self.all_vulnerabilities),
                "by_severity": {},
                "by_type": {}
            },
            "external_tools": {
                "used": list(self.external_tool_results.keys()),
                "status": self.tool_manager.get_tools_status() if self.tool_manager else {}
            }
        }
        
        # Categorize by severity
        for vuln in self.all_vulnerabilities:
            # Handle both enum and string severity
            if hasattr(vuln.severity, 'value'):
                sev = vuln.severity.value
            else:
                sev = str(vuln.severity)
            
            summary["vulnerabilities"]["by_severity"][sev] = \
                summary["vulnerabilities"]["by_severity"].get(sev, 0) + 1
            
            vuln_type = vuln.name.split("(")[0].strip()
            summary["vulnerabilities"]["by_type"][vuln_type] = \
                summary["vulnerabilities"]["by_type"].get(vuln_type, 0) + 1
        
        # Save external tools results
        if self.external_tool_results:
            tools_file = self.output_dir / "external_tools_results.json"
            with open(tools_file, 'w', encoding='utf-8') as f:
                json.dump(self.external_tool_results, f, indent=2, ensure_ascii=False, default=str)
        
        return summary

