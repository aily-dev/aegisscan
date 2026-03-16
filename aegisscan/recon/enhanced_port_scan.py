"""
Enhanced Port Scanner with Service Detection
"""
import asyncio
import socket
from typing import List, Tuple, Optional, Dict
import logging
from ..utils.wordlists import WordlistManager


class EnhancedPortScanner:
    """Enhanced port scanner with service detection and banner grabbing"""
    
    def __init__(self, timeout: float = 2.0, wordlist_manager: Optional[WordlistManager] = None):
        self.timeout = timeout
        self._logger = logging.getLogger(__name__)
        self.wordlist_manager = wordlist_manager or WordlistManager()
        
        # Extended service detection patterns
        self.service_patterns = {
            21: {"name": "FTP", "patterns": [b"220", b"FTP", b"FileZilla", b"vsftpd", b"ProFTPD"]},
            22: {"name": "SSH", "patterns": [b"SSH-", b"OpenSSH", b"dropbear"]},
            23: {"name": "Telnet", "patterns": [b"login:", b"Password:", b"Welcome"]},
            25: {"name": "SMTP", "patterns": [b"220", b"ESMTP", b"mail", b"Postfix", b"Sendmail"]},
            53: {"name": "DNS", "patterns": []},
            80: {"name": "HTTP", "patterns": [b"HTTP/", b"Server:", b"Apache", b"nginx", b"IIS", b"lighttpd"]},
            110: {"name": "POP3", "patterns": [b"+OK", b"POP3", b"Dovecot"]},
            143: {"name": "IMAP", "patterns": [b"* OK", b"IMAP", b"Dovecot"]},
            443: {"name": "HTTPS", "patterns": [b"HTTP/", b"Server:"]},
            445: {"name": "SMB", "patterns": [b"SMB", b"Microsoft"]},
            993: {"name": "IMAPS", "patterns": [b"* OK", b"IMAP"]},
            995: {"name": "POP3S", "patterns": [b"+OK", b"POP3"]},
            1433: {"name": "MSSQL", "patterns": [b"SQL Server", b"Microsoft SQL"]},
            1521: {"name": "Oracle", "patterns": [b"Oracle", b"TNS"]},
            3306: {"name": "MySQL", "patterns": [b"mysql", b"MariaDB", b"MySQL"]},
            3389: {"name": "RDP", "patterns": [b"rdp", b"RDP", b"Microsoft Terminal Services"]},
            5432: {"name": "PostgreSQL", "patterns": [b"PostgreSQL", b"postgres"]},
            5900: {"name": "VNC", "patterns": [b"RFB", b"VNC"]},
            5984: {"name": "CouchDB", "patterns": [b"CouchDB", b"couchdb"]},
            6379: {"name": "Redis", "patterns": [b"REDIS", b"redis"]},
            8080: {"name": "HTTP-Proxy", "patterns": [b"HTTP/", b"Server:", b"Proxy"]},
            8443: {"name": "HTTPS-Alt", "patterns": [b"HTTP/"]},
            9200: {"name": "Elasticsearch", "patterns": [b"\"cluster_name\"", b"elasticsearch"]},
            11211: {"name": "Memcached", "patterns": [b"memcached"]},
            27017: {"name": "MongoDB", "patterns": [b"MongoDB", b"mongod"]},
            5000: {"name": "HTTP-Alt", "patterns": [b"HTTP/"]},
            8000: {"name": "HTTP-Alt2", "patterns": [b"HTTP/"]},
            8888: {"name": "HTTP-Alt3", "patterns": [b"HTTP/"]},
            9000: {"name": "SonarQube", "patterns": [b"SonarQube"]},
        }
    
    async def scan(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        scan_type: str = "connect",
    ) -> List[Dict]:
        """
        Scan ports on a host.

        NOTE:
            This class is now considered the *pure Python* backend. New code
            that wants a stable API should use `aegisscan.native_portscan_interface`
            instead of instantiating this directly, so we can later swap the
            heavy lifting to a C++ implementation without touching callers.

        Args:
            host: Target hostname or IP
            ports: List of ports to scan (None = use common ports)
            scan_type: "connect" or "syn" (syn requires root)

        Returns:
            List of dicts with port, status, service, banner
        """
        if ports is None:
            ports = self.wordlist_manager.get_wordlist("common_ports")
        
        tasks = [self._scan_port(host, port, scan_type) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = []
        for i, result in enumerate(results):
            if isinstance(result, dict) and result.get("status") == "open":
                open_ports.append(result)
            elif isinstance(result, Exception):
                self._logger.debug(f"Port {ports[i]} scan error: {result}")
        
        return sorted(open_ports, key=lambda x: x["port"])
    
    async def _scan_port(self, host: str, port: int, scan_type: str) -> Dict:
        """Scan a single port"""
        result = {
            "port": port,
            "status": "closed",
            "service": "unknown",
            "banner": None,
            "version": None
        }
        
        try:
            if scan_type == "connect":
                # TCP connect scan
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                connect_result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: sock.connect_ex((host, port))
                )
                
                if connect_result == 0:
                    result["status"] = "open"
                    
                    # Grab banner and detect service
                    service_info = await self._grab_banner_and_detect(host, port)
                    result.update(service_info)
                    
                    sock.close()
            else:
                # SYN scan (requires root)
                # For now, fallback to connect
                return await self._scan_port(host, port, "connect")
                
        except Exception as e:
            self._logger.debug(f"Port {port} scan error: {e}")
        
        return result
    
    async def _grab_banner_and_detect(self, host: str, port: int) -> Dict:
        """Grab banner and detect service"""
        service_info = {
            "service": "unknown",
            "banner": None,
            "version": None
        }
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # Try to read banner
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner_str = banner.decode('utf-8', errors='ignore').strip()
                service_info["banner"] = banner_str[:500]
                
                # Detect service from banner
                service_info.update(self._detect_service(port, banner))
                
                writer.close()
                await writer.wait_closed()
            except:
                writer.close()
                await writer.wait_closed()
                
        except:
            # Try to detect service from port number
            if port in self.service_patterns:
                service_info["service"] = self.service_patterns[port]["name"]
        
        return service_info
    
    def _detect_service(self, port: int, banner: bytes) -> Dict:
        """Detect service from banner"""
        service_info = {
            "service": "unknown",
            "version": None
        }
        
        # Check port-specific patterns
        if port in self.service_patterns:
            patterns = self.service_patterns[port]["patterns"]
            for pattern in patterns:
                if pattern in banner:
                    service_info["service"] = self.service_patterns[port]["name"]
                    break
        
        # Try to extract version
        import re
        version_patterns = [
            rb'(\d+\.\d+\.\d+)',
            rb'v(\d+\.\d+)',
            rb'version[:\s]+(\d+\.\d+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                service_info["version"] = match.group(1).decode('utf-8', errors='ignore')
                break
        
        return service_info
    
    async def scan_range(self, host: str, start_port: int, end_port: int) -> List[Dict]:
        """Scan a range of ports"""
        ports = list(range(start_port, end_port + 1))
        return await self.scan(host, ports)
    
    async def scan_top_ports(self, host: str, top_n: int = 100) -> List[Dict]:
        """Scan top N most common ports"""
        # Top ports based on frequency
        top_ports = [
            80, 443, 22, 21, 25, 110, 143, 53, 993, 995,
            3306, 3389, 5432, 8080, 8443, 5900, 1723,
            27017, 6379, 11211, 9200, 5000, 3000, 8000,
        ]
        
        return await self.scan(host, top_ports[:top_n])

