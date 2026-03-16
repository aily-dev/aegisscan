"""
Network and Connection Utilities
"""
import socket
import struct
import asyncio
from typing import Optional, Tuple, List
import logging


class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Check if IP address is valid"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def is_valid_port(port: int) -> bool:
        """Check if port is valid"""
        return 0 < port <= 65535
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is private"""
        try:
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            
            # 10.0.0.0/8
            if (ip_int & 0xFF000000) == 0x0A000000:
                return True
            
            # 172.16.0.0/12
            if (ip_int & 0xFFF00000) == 0xAC100000:
                return True
            
            # 192.168.0.0/16
            if (ip_int & 0xFFFF0000) == 0xC0A80000:
                return True
            
            # 127.0.0.0/8
            if (ip_int & 0xFF000000) == 0x7F000000:
                return True
            
            return False
        except:
            return False
    
    @staticmethod
    async def resolve_hostname(hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            loop = asyncio.get_event_loop()
            addrs = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            if addrs:
                return addrs[0][4][0]
        except:
            pass
        return None
    
    @staticmethod
    async def reverse_dns(ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            loop = asyncio.get_event_loop()
            hostname, _, _ = await loop.getnameinfo((ip, 0), 0)
            return hostname
        except:
            return None
    
    @staticmethod
    def get_subnet_hosts(network: str) -> List[str]:
        """Get all hosts in a subnet (CIDR notation)"""
        hosts = []
        
        try:
            if '/' not in network:
                return [network]
            
            ip, prefix = network.split('/')
            prefix_int = int(prefix)
            
            if prefix_int < 24 or prefix_int > 32:
                return []
            
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            mask = (0xFFFFFFFF << (32 - prefix_int)) & 0xFFFFFFFF
            network_int = ip_int & mask
            
            num_hosts = 2 ** (32 - prefix_int)
            
            # Limit to reasonable size
            if num_hosts > 256:
                num_hosts = 256
            
            for i in range(1, num_hosts - 1):  # Skip network and broadcast
                host_int = network_int + i
                host_ip = socket.inet_ntoa(struct.pack('!I', host_int))
                hosts.append(host_ip)
        
        except:
            pass
        
        return hosts


class TCPConnection:
    """TCP connection utilities"""
    
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._logger = logging.getLogger(__name__)
    
    async def connect(self) -> bool:
        """Test if connection can be established"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def send_receive(self, data: bytes) -> Optional[bytes]:
        """Send data and receive response"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout
            )
            
            writer.write(data)
            await writer.drain()
            
            response = await asyncio.wait_for(
                reader.read(4096),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            return response
        except:
            return None


class UDPConnection:
    """UDP connection utilities"""
    
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._logger = logging.getLogger(__name__)
    
    async def send_receive(self, data: bytes) -> Optional[bytes]:
        """Send UDP packet and receive response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: sock.sendto(data, (self.host, self.port))
            )
            
            response, _ = await loop.run_in_executor(
                None,
                lambda: sock.recvfrom(4096)
            )
            
            sock.close()
            return response
        except:
            return None

