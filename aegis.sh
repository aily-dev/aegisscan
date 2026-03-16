 #!/bin/bash

# AegisScan - Advanced Web Security Testing Framework
# Interactive CLI with Hacker Theme

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ASCII Art Banner
show_banner() {
    clear
    echo -e "${RED}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║     █████╗ ███████╗  ██████╗ ██╗███████╗                    ║
    ║    ██╔══██╗██╔════╝ ██╔════╝ ██║██╔════╝                    ║
    ║    ███████║█████╗   ██║  ███╗██║███████╗                    ║
    ║    ██╔══██║██╔══╝   ██║   ██║██║╚════██║                    ║
    ║    ██║  ██║███████╗ ╚██████╔╝██║███████║                    ║
    ║    ╚═╝  ╚═╝╚══════╝  ╚═════╝ ╚═╝╚══════╝                    ║
    ║                                                              ║
    ║           ╔═╗╔═╗╔═╗╦╔═╗╔═╗  ╔═╗╔═╗╔═╗╔═╗╦                   ║
    ║           ╠═╝╠═╣║ ╦║║╣ ╚═╗  ╠═╝╠═╣║ ╦║  ╠╩╗                  ║
    ║           ╩  ╩ ╩╚═╝╩╚═╝╚═╝  ╩  ╩ ╩╚═╝╚═╝╩ ╩                  ║
    ║                                                              ║
    ║        Advanced Web Security Testing Framework v1.0          ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}${BOLD}⚠️  WARNING: Use only on systems you have permission to test!${NC}\n"
}

# Show main menu
show_menu() {
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║                    ${WHITE}MAIN MENU${CYAN}${BOLD}                              ║${NC}"
    echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}1.${NC} ${WHITE}Deep Scan${NC} ${YELLOW}(Complete comprehensive scan)${NC}              ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}2.${NC} ${WHITE}Normal Scan${NC} ${YELLOW}(Standard vulnerability scan)${NC}          ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}3.${NC} ${WHITE}SQL Injection Scan${NC} ${YELLOW}(SQLi testing)${NC}                ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}4.${NC} ${WHITE}XSS Scan${NC} ${YELLOW}(Cross-Site Scripting testing)${NC}            ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}5.${NC} ${WHITE}Port Scanning${NC} ${YELLOW}(Service detection)${NC}                ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}6.${NC} ${WHITE}Directory Bruteforce${NC} ${YELLOW}(Path discovery)${NC}              ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}7.${NC} ${WHITE}Subdomain Enumeration${NC} ${YELLOW}(DNS discovery)${NC}              ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}8.${NC} ${WHITE}Service Testing${NC} ${YELLOW}(Auth & Brute Force)${NC}              ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}9.${NC} ${WHITE}Passive Analysis${NC} ${YELLOW}(Security headers, etc.)${NC}          ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}10.${NC} ${WHITE}Command Injection Scan${NC} ${YELLOW}(OS command testing)${NC}         ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}11.${NC} ${WHITE}Path Traversal Scan${NC} ${YELLOW}(Directory traversal)${NC}          ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}12.${NC} ${WHITE}LFI/RFI Scan${NC} ${YELLOW}(File inclusion testing)${NC}              ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}13.${NC} ${WHITE}SSTI Scan${NC} ${YELLOW}(Server-Side Template Injection)${NC}        ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}14.${NC} ${WHITE}CSRF Analysis${NC} ${YELLOW}(Cross-Site Request Forgery)${NC}        ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}15.${NC} ${WHITE}Open Redirect Scan${NC} ${YELLOW}(Redirect vulnerability)${NC}         ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}16.${NC} ${WHITE}Auth & Session Scan${NC} ${YELLOW}(Authentication testing)${NC}        ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}17.${NC} ${WHITE}API Security Scan${NC} ${YELLOW}(API vulnerability testing)${NC}        ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}18.${NC} ${WHITE}JWT Security Scan${NC} ${YELLOW}(JWT token testing)${NC}              ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}19.${NC} ${WHITE}File Upload Scan${NC} ${YELLOW}(Upload vulnerability)${NC}            ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}20.${NC} ${WHITE}WebSocket Scan${NC} ${YELLOW}(WebSocket security)${NC}                ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}21.${NC} ${WHITE}SSRF Scan${NC} ${YELLOW}(Server-Side Request Forgery)${NC}           ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}22.${NC} ${WHITE}XXE Scan${NC} ${YELLOW}(XML External Entity)${NC}                    ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}23.${NC} ${WHITE}IDOR Scan${NC} ${YELLOW}(Insecure Direct Object Reference)${NC}       ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}24.${NC} ${WHITE}Compliance Check${NC} ${YELLOW}(OWASP Top 10, PCI-DSS)${NC}           ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}25.${NC} ${WHITE}GraphQL Security Scan${NC} ${YELLOW}(GraphQL vulnerabilities)${NC}      ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}26.${NC} ${WHITE}NoSQL Injection Scan${NC} ${YELLOW}(MongoDB, Redis, etc.)${NC}         ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}27.${NC} ${WHITE}HTTP Request Smuggling${NC} ${YELLOW}(CL.TE, TE.CL attacks)${NC}         ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}28.${NC} ${WHITE}WAF Detection & Bypass${NC} ${YELLOW}(WAF identification)${NC}           ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}29.${NC} ${WHITE}Cache Poisoning Scan${NC} ${YELLOW}(Web cache attacks)${NC}            ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}30.${NC} ${WHITE}OAuth/OIDC Security${NC} ${YELLOW}(OAuth vulnerabilities)${NC}          ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}31.${NC} ${WHITE}Clickjacking Detection${NC} ${YELLOW}(X-Frame-Options)${NC}            ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}32.${NC} ${WHITE}LDAP Injection Scan${NC} ${YELLOW}(LDAP vulnerabilities)${NC}          ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}33.${NC} ${WHITE}Subdomain Takeover${NC} ${YELLOW}(Takeover detection)${NC}             ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}0.${NC} ${RED}Exit${NC}                                                    ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}\n"
}

# Get URL from user
get_url() {
    echo -e "${YELLOW}${BOLD}Enter target URL:${NC}"
    echo -e "${CYAN}Example: https://example.com or http://example.com/path${NC}"
    read -p "> " target_url
    
    if [ -z "$target_url" ]; then
        echo -e "${RED}Error: URL cannot be empty!${NC}"
        return 1
    fi
    
    # Basic URL validation
    if [[ ! $target_url =~ ^https?:// ]]; then
        echo -e "${YELLOW}Warning: URL should start with http:// or https://${NC}"
        echo -e "${YELLOW}Adding http:// prefix...${NC}"
        target_url="http://$target_url"
    fi
    
    echo -e "${GREEN}✓ Target: ${WHITE}${BOLD}$target_url${NC}\n"
    return 0
}

# Create Python script for scanning
create_scan_script() {
    local scan_type=$1
    local url=$2
    local output_dir="scan_results_$(date +%Y%m%d_%H%M%S)"
    
    # Get the directory where aegis.sh is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    sudo bash -c 'cat > /tmp/aegis_scan.py << EOF'
#!/usr/bin/env python3
import asyncio
import sys
import os
import logging

# Add project directory to Python path
project_dir = "$SCRIPT_DIR"
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

from aegisscan import DeepScanner, AsyncHTTPClient
from aegisscan.scanners import (
    SQLiScanner, XSSScanner, CommandInjectionScanner,
    PathTraversalScanner, LFIRFIScanner, SSTIScanner,
    CSRFScanner, OpenRedirectScanner, AuthScanner,
    APISecurityScanner, JWTScanner, FileUploadScanner,
    WebSocketScanner, SSRFScanner, XXEScanner, IDORScanner,
    ComplianceChecker, GraphQLScanner, NoSQLInjectionScanner,
    HTTPSmugglingScanner, WAFBypassScanner, CachePoisoningScanner,
    OAuthOIDCScanner, ClickjackingScanner, LDAPInjectionScanner
)
from aegisscan.recon import (
    EnhancedPortScanner, EnhancedDirectoryBruteforcer,
    SubdomainEnumerator, ServiceTester
)
from aegisscan.analyzer import PassiveAnalyzer
from aegisscan.crawler import Crawler

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')

async def main():
    target_url = "$url"
    output_dir = "$output_dir"
    
    print("\\n" + "=" * 70)
    print("🔒 AegisScan - Security Testing")
    print("=" * 70)
    print(f"🎯 Target: {target_url}")
    print(f"📁 Output: {output_dir}")
    print("=" * 70 + "\\n")
    
    http_client = AsyncHTTPClient(
        timeout=60,
        max_redirects=10,
        verify_ssl=True,
        user_agent="AegisScan/1.0"
    )
    
    try:
EOF

    case $scan_type in
        "deep")
            sudo bash -c 'cat >> /tmp/aegis_scan.py << EOF'
        scanner = DeepScanner(
            http_client,
            output_dir=output_dir,
            use_external_tools=True,
            auto_install_tools=True
        )
        
        summary = await scanner.deep_scan(
            target_url,
            max_depth=3,
            max_pages=100
        )
        
        print("\\n" + "=" * 70)
        print("📊 Scan Summary")
        print("=" * 70)
        print(f"URLs Discovered: {summary['discovery']['urls']}")
        print(f"Forms Discovered: {summary['discovery']['forms']}")
        print(f"Open Ports: {summary['discovery']['ports']}")
        print(f"Directories Found: {summary['discovery']['directories']}")
        print(f"Total Vulnerabilities: {summary['vulnerabilities']['total']}")
        print(f"\\nDetailed reports saved to: {output_dir}/")
EOF
            ;;
        "normal")
            cat >> /tmp/aegis_scan.py << EOF
        scanner = DeepScanner(
            http_client,
            output_dir=output_dir,
            use_external_tools=False
        )
        
        # Normal scan without external tools
        summary = await scanner.deep_scan(
            target_url,
            max_depth=2,
            max_pages=50
        )
        
        print(f"\\n✓ Scan completed. Found {summary['vulnerabilities']['total']} vulnerabilities.")
EOF
            ;;
        "sqli")
            cat >> /tmp/aegis_scan.py << EOF
        sqli_scanner = SQLiScanner(http_client)
        vulns = await sqli_scanner.scan(target_url)
        
        print(f"\\n✓ SQL Injection scan completed.")
        print(f"Found {len(vulns)} SQL Injection vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "xss")
            cat >> /tmp/aegis_scan.py << EOF
        xss_scanner = XSSScanner(http_client)
        vulns = await xss_scanner.scan(target_url)
        
        print(f"\\n✓ XSS scan completed.")
        print(f"Found {len(vulns)} XSS vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "port")
            cat >> /tmp/aegis_scan.py << EOF
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.netloc.split(':')[0]
        
        port_scanner = EnhancedPortScanner()
        ports = await port_scanner.scan_top_ports(host, top_n=100)
        
        print(f"\\n✓ Port scan completed.")
        print(f"Found {len(ports)} open ports:")
        for p in ports:
            print(f"  - Port {p['port']}: {p.get('service', 'unknown')}")
EOF
            ;;
        "directory")
            cat >> /tmp/aegis_scan.py << EOF
        from aegisscan.utils import WordlistManager
        
        wordlist_manager = WordlistManager()
        dir_brute = EnhancedDirectoryBruteforcer(http_client, wordlist_manager=wordlist_manager)
        dirs = await dir_brute.bruteforce(target_url, max_workers=30)
        
        print(f"\\n✓ Directory bruteforce completed.")
        print(f"Found {len(dirs)} directories/files:")
        for d in dirs[:20]:
            print(f"  - [{d['status_code']}] {d['url']}")
EOF
            ;;
        "subdomain")
            cat >> /tmp/aegis_scan.py << EOF
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(':')[0]
        
        subdomain_enum = SubdomainEnumerator()
        subdomains = await subdomain_enum.enumerate(domain)
        
        print(f"\\n✓ Subdomain enumeration completed.")
        print(f"Found {len(subdomains)} subdomains:")
        for s in subdomains:
            print(f"  - {s}")
EOF
            ;;
        "service")
            cat >> /tmp/aegis_scan.py << EOF
        from urllib.parse import urlparse
        from aegisscan.recon import EnhancedPortScanner
        from aegisscan.utils import WordlistManager
        
        parsed = urlparse(target_url)
        host = parsed.netloc.split(':')[0]
        
        # First scan ports
        port_scanner = EnhancedPortScanner()
        ports = await port_scanner.scan_top_ports(host, top_n=50)
        
        # Test services
        wordlist_manager = WordlistManager()
        service_tester = ServiceTester(wordlist_manager=wordlist_manager)
        
        print(f"Testing {len(ports)} services...")
        for port_info in ports:
            service = port_info.get('service', 'unknown')
            if service != 'unknown':
                result = await service_tester.test_service(host, port_info['port'], service)
                if result.get('anonymous_allowed') or result.get('credentials'):
                    print(f"  ✓ {service} on port {port_info['port']}: Accessible")
EOF
            ;;
        "passive")
            cat >> /tmp/aegis_scan.py << EOF
        passive_analyzer = PassiveAnalyzer(http_client)
        vulns = await passive_analyzer.scan(target_url)
        
        print(f"\\n✓ Passive analysis completed.")
        print(f"Found {len(vulns)} security issues:")
        for v in vulns:
            print(f"  - {v.name}: {v.description}")
EOF
            ;;
        "command")
            cat >> /tmp/aegis_scan.py << EOF
        cmd_scanner = CommandInjectionScanner(http_client)
        vulns = await cmd_scanner.scan(target_url)
        
        print(f"\\n✓ Command Injection scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "path")
            cat >> /tmp/aegis_scan.py << EOF
        path_scanner = PathTraversalScanner(http_client)
        vulns = await path_scanner.scan(target_url)
        
        print(f"\\n✓ Path Traversal scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "lfi")
            cat >> /tmp/aegis_scan.py << EOF
        lfi_scanner = LFIRFIScanner(http_client)
        vulns = await lfi_scanner.scan(target_url)
        
        print(f"\\n✓ LFI/RFI scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "ssti")
            cat >> /tmp/aegis_scan.py << EOF
        ssti_scanner = SSTIScanner(http_client)
        vulns = await ssti_scanner.scan(target_url)
        
        print(f"\\n✓ SSTI scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "csrf")
            cat >> /tmp/aegis_scan.py << EOF
        csrf_scanner = CSRFScanner(http_client)
        vulns = await csrf_scanner.scan(target_url)
        
        print(f"\\n✓ CSRF analysis completed.")
        print(f"Found {len(vulns)} issues:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "redirect")
            cat >> /tmp/aegis_scan.py << EOF
        redirect_scanner = OpenRedirectScanner(http_client)
        vulns = await redirect_scanner.scan(target_url)
        
        print(f"\\n✓ Open Redirect scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "auth")
            cat >> /tmp/aegis_scan.py << EOF
        auth_scanner = AuthScanner(http_client)
        vulns = await auth_scanner.scan(target_url)
        
        print(f"\\n✓ Auth & Session scan completed.")
        print(f"Found {len(vulns)} issues:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "api")
            cat >> /tmp/aegis_scan.py << EOF
        api_scanner = APISecurityScanner(http_client)
        vulns = await api_scanner.scan(target_url)
        
        print(f"\\n✓ API Security scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "jwt")
            cat >> /tmp/aegis_scan.py << EOF
        jwt_scanner = JWTScanner(http_client)
        vulns = await jwt_scanner.scan(target_url)
        
        print(f"\\n✓ JWT Security scan completed.")
        print(f"Found {len(vulns)} issues:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "upload")
            cat >> /tmp/aegis_scan.py << EOF
        upload_scanner = FileUploadScanner(http_client)
        vulns = await upload_scanner.scan(target_url)
        
        print(f"\\n✓ File Upload scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "websocket")
            cat >> /tmp/aegis_scan.py << EOF
        ws_scanner = WebSocketScanner(http_client)
        vulns = await ws_scanner.scan(target_url)
        
        print(f"\\n✓ WebSocket scan completed.")
        print(f"Found {len(vulns)} issues:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "ssrf")
            cat >> /tmp/aegis_scan.py << EOF
        ssrf_scanner = SSRFScanner(http_client)
        vulns = await ssrf_scanner.scan(target_url)
        
        print(f"\\n✓ SSRF scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "xxe")
            cat >> /tmp/aegis_scan.py << EOF
        xxe_scanner = XXEScanner(http_client)
        vulns = await xxe_scanner.scan(target_url)
        
        print(f"\\n✓ XXE scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "idor")
            cat >> /tmp/aegis_scan.py << EOF
        idor_scanner = IDORScanner(http_client)
        vulns = await idor_scanner.scan(target_url)
        
        print(f"\\n✓ IDOR scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "compliance")
            cat >> /tmp/aegis_scan.py << EOF
        compliance_checker = ComplianceChecker(http_client)
        vulns = await compliance_checker.scan(target_url)
        
        print(f"\\n✓ Compliance check completed.")
        print(f"Found {len(vulns)} compliance issues:")
        for v in vulns:
            print(f"  - {v.name}: {v.description}")
EOF
            ;;
        "graphql")
            cat >> /tmp/aegis_scan.py << EOF
        graphql_scanner = GraphQLScanner(http_client)
        vulns = await graphql_scanner.scan(target_url)
        
        print(f"\\n✓ GraphQL Security scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "nosql")
            cat >> /tmp/aegis_scan.py << EOF
        nosql_scanner = NoSQLInjectionScanner(http_client)
        vulns = await nosql_scanner.scan(target_url)
        
        print(f"\\n✓ NoSQL Injection scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "smuggling")
            cat >> /tmp/aegis_scan.py << EOF
        smuggling_scanner = HTTPSmugglingScanner(http_client)
        vulns = await smuggling_scanner.scan(target_url)
        
        print(f"\\n✓ HTTP Request Smuggling scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "waf")
            cat >> /tmp/aegis_scan.py << EOF
        waf_scanner = WAFBypassScanner(http_client)
        vulns = await waf_scanner.scan(target_url)
        
        print(f"\\n✓ WAF Detection & Bypass scan completed.")
        print(f"Found {len(vulns)} issues:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "cache")
            cat >> /tmp/aegis_scan.py << EOF
        cache_scanner = CachePoisoningScanner(http_client)
        vulns = await cache_scanner.scan(target_url)
        
        print(f"\\n✓ Cache Poisoning scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "oauth")
            cat >> /tmp/aegis_scan.py << EOF
        oauth_scanner = OAuthOIDCScanner(http_client)
        vulns = await oauth_scanner.scan(target_url)
        
        print(f"\\n✓ OAuth/OIDC Security scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "clickjacking")
            cat >> /tmp/aegis_scan.py << EOF
        clickjacking_scanner = ClickjackingScanner(http_client)
        vulns = await clickjacking_scanner.scan(target_url)
        
        print(f"\\n✓ Clickjacking scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "ldap")
            cat >> /tmp/aegis_scan.py << EOF
        ldap_scanner = LDAPInjectionScanner(http_client)
        vulns = await ldap_scanner.scan(target_url)
        
        print(f"\\n✓ LDAP Injection scan completed.")
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
        "takeover")
            cat >> /tmp/aegis_scan.py << EOF
        from urllib.parse import urlparse
        from aegisscan.recon import SubdomainEnumerator, SubdomainTakeoverDetector
        
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(':')[0]
        
        # First enumerate subdomains
        subdomain_enum = SubdomainEnumerator()
        subdomains = await subdomain_enum.enumerate(domain)
        
        # Check for takeover
        takeover_detector = SubdomainTakeoverDetector(http_client)
        vulnerable = []
        
        for subdomain in subdomains[:20]:  # Limit
            vuln = await takeover_detector.check_subdomain(subdomain)
            if vuln:
                vulnerable.append(vuln)
        
        print(f"\\n✓ Subdomain Takeover scan completed.")
        print(f"Checked {len(subdomains)} subdomains, found {len(vulnerable)} vulnerable:")
        for v in vulnerable:
            print(f"  - {v.name} at {v.url}")
EOF
            ;;
    esac
    
    sudo bash -c 'cat >> /tmp/aegis_scan.py << EOF'
    
    except Exception as e:
        print(f"\\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await http_client.close()

if __name__ == "__main__":
    asyncio.run(main())
EOF
}

# Execute scan
execute_scan() {
    local scan_type=$1
    local url=$2
    
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║                    ${WHITE}STARTING SCAN${CYAN}${BOLD}                            ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    
    create_scan_script "$scan_type" "$url"
    
    echo -e "${YELLOW}Running scan...${NC}\n"
    
    # Run Python script
    python3 /tmp/aegis_scan.py
    
    echo -e "\n${GREEN}${BOLD}✓ Scan completed!${NC}\n"
    read -p "Press Enter to continue..."
}

# Main loop
main() {
    while true; do
        show_banner
        show_menu
        
        read -p "$(echo -e ${CYAN}${BOLD}Select option: ${NC})" choice
        
        case $choice in
            1)
                if get_url; then
                    execute_scan "deep" "$target_url"
                fi
                ;;
            2)
                if get_url; then
                    execute_scan "normal" "$target_url"
                fi
                ;;
            3)
                if get_url; then
                    execute_scan "sqli" "$target_url"
                fi
                ;;
            4)
                if get_url; then
                    execute_scan "xss" "$target_url"
                fi
                ;;
            5)
                if get_url; then
                    execute_scan "port" "$target_url"
                fi
                ;;
            6)
                if get_url; then
                    execute_scan "directory" "$target_url"
                fi
                ;;
            7)
                if get_url; then
                    execute_scan "subdomain" "$target_url"
                fi
                ;;
            8)
                if get_url; then
                    execute_scan "service" "$target_url"
                fi
                ;;
            9)
                if get_url; then
                    execute_scan "passive" "$target_url"
                fi
                ;;
            10)
                if get_url; then
                    execute_scan "command" "$target_url"
                fi
                ;;
            11)
                if get_url; then
                    execute_scan "path" "$target_url"
                fi
                ;;
            12)
                if get_url; then
                    execute_scan "lfi" "$target_url"
                fi
                ;;
            13)
                if get_url; then
                    execute_scan "ssti" "$target_url"
                fi
                ;;
            14)
                if get_url; then
                    execute_scan "csrf" "$target_url"
                fi
                ;;
            15)
                if get_url; then
                    execute_scan "redirect" "$target_url"
                fi
                ;;
            16)
                if get_url; then
                    execute_scan "auth" "$target_url"
                fi
                ;;
            17)
                if get_url; then
                    execute_scan "api" "$target_url"
                fi
                ;;
            18)
                if get_url; then
                    execute_scan "jwt" "$target_url"
                fi
                ;;
            19)
                if get_url; then
                    execute_scan "upload" "$target_url"
                fi
                ;;
            20)
                if get_url; then
                    execute_scan "websocket" "$target_url"
                fi
                ;;
            21)
                if get_url; then
                    execute_scan "ssrf" "$target_url"
                fi
                ;;
            22)
                if get_url; then
                    execute_scan "xxe" "$target_url"
                fi
                ;;
            23)
                if get_url; then
                    execute_scan "idor" "$target_url"
                fi
                ;;
            24)
                if get_url; then
                    execute_scan "compliance" "$target_url"
                fi
                ;;
            25)
                if get_url; then
                    execute_scan "graphql" "$target_url"
                fi
                ;;
            26)
                if get_url; then
                    execute_scan "nosql" "$target_url"
                fi
                ;;
            27)
                if get_url; then
                    execute_scan "smuggling" "$target_url"
                fi
                ;;
            28)
                if get_url; then
                    execute_scan "waf" "$target_url"
                fi
                ;;
            29)
                if get_url; then
                    execute_scan "cache" "$target_url"
                fi
                ;;
            30)
                if get_url; then
                    execute_scan "oauth" "$target_url"
                fi
                ;;
            31)
                if get_url; then
                    execute_scan "clickjacking" "$target_url"
                fi
                ;;
            32)
                if get_url; then
                    execute_scan "ldap" "$target_url"
                fi
                ;;
            33)
                if get_url; then
                    execute_scan "takeover" "$target_url"
                fi
                ;;
            0)
                echo -e "\n${YELLOW}Goodbye! Stay secure! 🔒${NC}\n"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option! Please try again.${NC}"
                sleep 2
                ;;
        esac
    done
}

# Run main function
main

