"""
Port Scanner Module
"""
import asyncio
import socket
from typing import List, Tuple, Optional
import logging


class PortScanner:
    """Async port scanner"""
    
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000
    ]
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self._logger = logging.getLogger(__name__)
    
    async def scan(self, host: str, ports: Optional[List[int]] = None) -> List[Tuple[int, str, Optional[str]]]:
        """Scan ports on a host
        
        Returns: List of (port, status, banner) tuples
        """
        ports = ports or self.COMMON_PORTS
        
        tasks = [self._scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = []
        for i, result in enumerate(results):
            if isinstance(result, tuple):
                port, status, banner = result
                if status == "open":
                    open_ports.append((port, status, banner))
            elif isinstance(result, Exception):
                self._logger.debug(f"Port {ports[i]} scan error: {result}")
        
        return open_ports
    
    async def _scan_port(self, host: str, port: int) -> Tuple[int, str, Optional[str]]:
        """Scan a single port"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Try to connect
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sock.connect_ex((host, port))
            )
            
            if result == 0:
                # Port is open, try to grab banner
                banner = await self._grab_banner(host, port)
                sock.close()
                return (port, "open", banner)
            else:
                sock.close()
                return (port, "closed", None)
        except Exception as e:
            return (port, "error", None)
    
    async def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Grab banner from open port"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # Try to read banner
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner_str = banner.decode('utf-8', errors='ignore').strip()
                writer.close()
                await writer.wait_closed()
                return banner_str[:200]  # Limit banner length
            except:
                writer.close()
                await writer.wait_closed()
                return None
        except:
            return None

