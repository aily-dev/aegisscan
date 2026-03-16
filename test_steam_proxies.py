#!/usr/bin/env python3
"""
Steam Proxy Tester - Tries multiple proxy types and configurations
"""

import asyncio
import httpx
import ssl
import socket
import random
from pathlib import Path

PROXY_FILE = "/home/iliya/Documents/Tools/proxy_results/working_http_proxies.txt"
SCAN_RESULTS_FILE = "/home/iliya/Documents/Tools/proxy_results/scan_results.txt"
OUTPUT_FILE = "/home/iliya/Documents/Tools/proxy_results/working_steam_proxies.txt"
TEST_URL = "https://store.steampowered.com/"
TIMEOUT = 15

# Steam endpoints to test (some may be less protected)
STEAM_ENDPOINTS = [
    "https://store.steampowered.com/",
    "https://steamcommunity.com/",
    "https://help.steampowered.com/",
]


def load_proxies():
    """Load all proxies from files"""
    proxies = []
    
    try:
        with open(SCAN_RESULTS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and (line.startswith('http://') or line.startswith('socks4://') or line.startswith('socks5://')):
                    proxies.append(line)
    except FileNotFoundError:
        pass
    
    try:
        with open(PROXY_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and line.startswith('http://'):
                    if line not in proxies:
                        proxies.append(line)
    except FileNotFoundError:
        pass
    
    return proxies


async def test_single_proxy(proxy, test_url, semaphore):
    """Test a single proxy against a single URL"""
    async with semaphore:
        try:
            # Try different SSL configurations
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            async with httpx.AsyncClient(
                proxy=proxy,
                ssl=ssl_context,
                timeout=TIMEOUT,
                follow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                }
            ) as client:
                response = await client.get(test_url)
                
                if response.status_code == 200:
                    text_lower = response.text.lower()
                    if any(x in text_lower for x in ["steam", "store", "valve", "community"]):
                        return True, response.status_code
                elif response.status_code in [301, 302]:
                    return True, response.status_code
                    
        except Exception as e:
            pass
            
        return False, 0


async def test_proxy_all_endpoints(proxy, semaphore):
    """Test a proxy against all Steam endpoints"""
    for endpoint in STEAM_ENDPOINTS:
        success, status = await test_single_proxy(proxy, endpoint, semaphore)
        if success:
            return proxy, True
    return proxy, False


async def main():
    print("=" * 60)
    print("Steam Proxy Tester - Multi-Endpoint")
    print("=" * 60)
    
    proxies = load_proxies()
    print(f"Loaded {len(proxies)} proxies")
    print("=" * 60)
    
    if not proxies:
        print("No proxies found!")
        return []
    
    semaphore = asyncio.Semaphore(3)
    
    tasks = [test_proxy_all_endpoints(proxy, semaphore) for proxy in proxies]
    results = await asyncio.gather(*tasks)
    
    working_proxies = [proxy for proxy, success in results if success]
    
    print("=" * 60)
    print(f"RESULTS: {len(working_proxies)}/{len(proxies)} proxies working")
    print("=" * 60)
    
    if working_proxies:
        with open(OUTPUT_FILE, 'w') as f:
            for proxy in working_proxies:
                f.write(proxy + '\n')
        print(f"Saved to: {OUTPUT_FILE}")
    else:
        print("No working proxies found!")
        print("\nNOTE: German datacenter IPs (Hetzner, etc.) are blocked by Steam.")
        print("To get working Steam proxies, you need:")
        print("  - Residential proxies (from ISPs)")
        print("  - Premium proxy services")
        print("  - Specialized Steam proxy providers")
        
    return working_proxies


if __name__ == "__main__":
    asyncio.run(main())

