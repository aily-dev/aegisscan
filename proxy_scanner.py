#!/usr/bin/env python3
"""
Proxy Scanner - Germany IP Range
Scans for proxy ports, tests them, and saves working proxies by protocol
"""

import asyncio
import aiohttp
import socket
import re
import os
import json
import subprocess
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse

# Configuration
GERMANY_IP_RANGES_URL = "https://raw.githubusercontent.com/hero444/proxy-list/main/germany.txt"
PROXY_PORTS = {
    'http': [80, 8080, 3128, 8888, 8000, 7001],
    'socks4': [1080, 2011, 2012],
    'socks5': [1080, 2011, 2012, 9050, 9051, 10808]
}
TEST_URL = "http://httpbin.org/ip"
TIMEOUT = 15
MAX_CONCURRENT = 100

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    NC = '\033[0m'

def log_info(msg):
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")

def log_success(msg):
    print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {msg}")

def log_warning(msg):
    print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {msg}")

def log_error(msg):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")

async def download_germany_ips() -> List[str]:
    """Download Germany IP ranges from various sources"""
    log_info("Downloading Germany IP ranges...")
    
    ips = []
    
    # Try multiple sources for Germany IPs
    sources = [
        "https://raw.githubusercontent.com/hero444/proxy-list/main/germany.txt",
        "https://raw.githubusercontent.com/herrbischoff/awesome-ipgeo/master/docs/subnets/de.md",
    ]
    
    for url in sources:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        # Extract IP ranges
                        for line in text.splitlines():
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Handle CIDR notation
                                if '/' in line:
                                    ips.append(line)
                                elif re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                                    ips.append(line)
                        if ips:
                            log_success(f"Downloaded {len(ips)} IP ranges from {url}")
                            break
        except Exception as e:
            log_warning(f"Failed to download from {url}: {e}")
            continue
    
    # If no IPs from sources, use common Germany IP ranges
    if not ips:
        log_warning("Using default Germany IP ranges...")
        # Common Germany IP ranges (sample)
        ips = [
            "88.198.0.0/16",
            "88.199.0.0/16",
            "91.107.0.0/16",
            "93.104.0.0/16",
            "136.243.0.0/16",
            "144.76.0.0/16",
            "148.251.0.0/16",
            "159.69.0.0/16",
            "178.63.0.0/16",
            "195.154.0.0/16",
        ]
    
    # Expand to individual IPs for scanning
    expanded_ips = []
    for ip_range in ips[:20]:  # Limit to first 20 ranges
        if '/' in ip_range:
            # Convert CIDR to list of IPs (limit to /24 for performance)
            try:
                network = ip_range.split('/')[0]
                for i in range(1, 256):
                    expanded_ips.append(f"{network.rsplit('.', 1)[0]}.{i}")
            except:
                pass
        else:
            expanded_ips.append(ip_range)
    
    log_success(f"Generated {len(expanded_ips)} IPs for scanning")
    return expanded_ips

def cidr_to_ips(cidr: str, limit: int = 256) -> List[str]:
    """Convert CIDR to list of IPs with limit"""
    import ipaddress
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in list(network.hosts())[:limit]]
    except:
        return []

async def scan_port(ip: str, port: int) -> bool:
    """Scan a single port on an IP"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=3
        )
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

async def scan_proxy_ports(ips: List[str]) -> Dict[Tuple[str, int], List[str]]:
    """Scan IPs for proxy ports and identify protocol"""
    log_info(f"Scanning {len(ips)} IPs for proxy ports...")
    
    all_ports = []
    for protocol, ports in PROXY_PORTS.items():
        for ip in ips:
            for port in ports:
                all_ports.append((ip, port, protocol))
    
    log_info(f"Total scan targets: {len(all_ports)}")
    
    found_proxies = {}
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    
    async def check_port(ip_port_proto):
        ip, port, protocol = ip_port_proto
        async with semaphore:
            if await scan_port(ip, port):
                return (ip, port, protocol)
            return None
    
    # Process in batches
    batch_size = 500
    for i in range(0, len(all_ports), batch_size):
        batch = all_ports[i:i+batch_size]
        results = await asyncio.gather(*[check_port(item) for item in batch])
        
        for result in results:
            if result:
                ip, port, protocol = result
                key = (ip, port)
                if key not in found_proxies:
                    found_proxies[key] = []
                found_proxies[key].append(protocol)
        
        log_info(f"Progress: {min(i+batch_size, len(all_ports))}/{len(all_ports)} - Found: {len(found_proxies)}")
    
    log_success(f"Found {len(found_proxies)} potential proxy endpoints")
    return found_proxies

def format_proxy_url(ip: str, port: int, protocol: str = "http") -> str:
    """Format proxy URL"""
    return f"{protocol}://{ip}:{port}"

async def test_proxy(proxy_url: str, protocol: str) -> bool:
    """Test if a proxy is working"""
    try:
        timeout = aiohttp.ClientTimeout(total=TIMEOUT)
        
        # Determine proxy type for aiohttp
        if protocol in ['socks4', 'socks5']:
            # Use aiohttp socks support
            proxy_type = aiohttp.socks.PROXY_SOCKS4 if protocol == 'socks4' else aiohttp.socks.PROXY_SOCKS5
            connector = aiohttp.socks.SocksConnector(
                proxy_type=proxy_type,
                proxy_url=proxy_url,
                rdns=True
            )
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(TEST_URL) as resp:
                    return resp.status == 200
        else:
            # HTTP proxy
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(TEST_URL, proxy=proxy_url) as resp:
                    return resp.status == 200
    except Exception as e:
        return False

async def test_all_proxies(found_proxies: Dict[Tuple[str, int], List[str]]) -> Dict[str, List[str]]:
    """Test all found proxies and categorize by protocol"""
    log_info("Testing proxies...")
    
    working = {
        'http': [],
        'socks4': [],
        'socks5': []
    }
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    
    async def test_one(ip: int, port: int, protocols: List[str]):
        async with semaphore:
            for protocol in protocols:
                proxy_url = format_proxy_url(ip, port, protocol)
                if await test_proxy(proxy_url, protocol):
                    return (protocol, proxy_url)
            return None
    
    tasks = []
    for (ip, port), protocols in found_proxies.items():
        tasks.append(test_one(ip, port, protocols))
    
    results = await asyncio.gather(*tasks)
    
    for result in results:
        if result:
            protocol, proxy_url = result
            working[protocol].append(proxy_url)
            log_success(f"Working {protocol}: {proxy_url}")
    
    return working

def save_results(working: Dict[str, List[str]], output_dir: str):
    """Save results to files"""
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save all proxies in combined format
    combined_file = os.path.join(output_dir, f"all_proxies_{timestamp}.txt")
    with open(combined_file, 'w') as f:
        for protocol, proxies in working.items():
            for proxy in proxies:
                f.write(f"{proxy}\n")
    log_success(f"Saved combined proxies to {combined_file}")
    
    # Save by protocol
    for protocol, proxies in working.items():
        if proxies:
            protocol_file = os.path.join(output_dir, f"working_{protocol}_proxies.txt")
            with open(protocol_file, 'w') as f:
                for proxy in proxies:
                    f.write(f"{proxy}\n")
            log_success(f"Saved {len(proxies)} {protocol} proxies to {protocol_file}")
    
    # Create summary
    summary = {
        "timestamp": timestamp,
        "http": len(working['http']),
        "socks4": len(working['socks4']),
        "socks5": len(working['socks5']),
        "total": sum(len(v) for v in working.values())
    }
    
    summary_file = os.path.join(output_dir, f"summary_{timestamp}.json")
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    return summary

def format_scan_output(found_proxies: Dict[Tuple[str, int], List[str]], output_file: str):
    """Format and save scan results in the requested format"""
    log_info(f"Formatting output to {output_file}...")
    
    with open(output_file, 'w') as f:
        for (ip, port), protocols in sorted(found_proxies.items()):
            # Write each protocol on separate line
            for protocol in protocols:
                proxy_url = format_proxy_url(ip, port, protocol)
                f.write(f"{proxy_url}\n")
    
    log_success(f"Saved formatted output to {output_file}")

async def main():
    print(f"""
{Colors.CYAN}╔═══════════════════════════════════════════════╗
║       Germany Proxy Scanner v1.0             ║
║    Scan, Test & Filter Working Proxies        ║
╚═══════════════════════════════════════════════╝{Colors.NC}
    """)
    
    output_dir = "proxy_results"
    os.makedirs(output_dir, exist_ok=True)
    
    # Step 1: Download Germany IPs
    ips = await download_germany_ips()
    
    if not ips:
        log_error("No IPs to scan. Exiting.")
        return
    
    # Step 2: Scan for proxy ports
    found_proxies = await scan_proxy_ports(ips)
    
    if not found_proxies:
        log_warning("No proxies found during scanning")
        return
    
    # Step 3: Save raw scan results in requested format
    raw_output = os.path.join(output_dir, "scan_results.txt")
    format_scan_output(found_proxies, raw_output)
    
    # Step 4: Test all proxies
    working = await test_all_proxies(found_proxies)
    
    # Step 5: Save results
    summary = save_results(working, output_dir)
    
    print(f"""
{Colors.GREEN}╔═══════════════════════════════════════════════╗
║              SCAN COMPLETE                     ║
╚═══════════════════════════════════════════════╝{Colors.NC}

Results:
  {Colors.GREEN}HTTP:{Colors.NC}   {summary['http']}
  {Colors.YELLOW}SOCKS4:{Colors.NC} {summary['socks4']}
  {Colors.BLUE}SOCKS5:{Colors.NC} {summary['socks5']}
  {Colors.CYAN}TOTAL:{Colors.NC} {summary['total']}

Output files saved to: {output_dir}/
""")

if __name__ == "__main__":
    asyncio.run(main())

