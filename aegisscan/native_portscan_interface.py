"""
Bridge / abstraction layer for port scanning that can later be backed by a C++ extension.

For now this simply forwards to the existing Python implementation in
`aegisscan.recon.enhanced_port_scan.EnhancedPortScanner`, but all callers
should use this module so we can swap in a native (C++/pybind11) backend
without touching the rest of the codebase.
"""

from typing import List, Dict, Optional

import logging

from .recon.enhanced_port_scan import EnhancedPortScanner

logger = logging.getLogger(__name__)

try:
    # Native C++ backend (pybind11 extension)
    from aegis_native import port_scan as native_port_scan

    HAS_NATIVE = True
except Exception:  # pragma: no cover - purely optional optimization
    native_port_scan = None
    HAS_NATIVE = False


class PortScanBackend:
    """
    Thin wrapper around the current Python EnhancedPortScanner.

    In the future this class can detect and use a native backend, e.g.:

        try:
            from aegis_native import port_scan as native_port_scan
            HAS_NATIVE = True
        except ImportError:
            HAS_NATIVE = False

    and then delegate heavy work to C++ when available.
    """

    def __init__(self, timeout: float = 2.0):
        self._py_scanner = EnhancedPortScanner(timeout=timeout)
        self._timeout = timeout

    async def scan(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        scan_type: str = "connect",
    ) -> List[Dict]:
        """
        Scan ports on a host and return a list of open ports with service info.

        The signature intentionally matches EnhancedPortScanner.scan so that the
        rest of the codebase does not care whether the implementation is Python
        or C++.
        """
        # If native backend is available and we're doing a simple connect scan,
        # use the fast C++ implementation to find open ports, then enrich them
        # with banner/service detection in Python.
        if HAS_NATIVE and scan_type == "connect" and ports is not None:
            try:
                raw_results = native_port_scan.scan(
                    host=host,
                    ports=list(ports),
                    timeout=self._timeout,
                )
                # raw_results: [{"port": int, "status": "open"/"closed"}]
                open_ports = [
                    item["port"]
                    for item in raw_results
                    if isinstance(item, dict) and item.get("status") == "open"
                ]
                enriched: List[Dict] = []
                for port in open_ports:
                    # Reuse Python banner + service detection for accuracy
                    info = await self._py_scanner._grab_banner_and_detect(host, port)  # type: ignore[attr-defined]  # noqa: SLF001,E501
                    if info is None:
                        info = {}
                    enriched.append(
                        {
                            "port": port,
                            "status": "open",
                            "service": info.get("service", "unknown"),
                            "banner": info.get("banner"),
                            "version": info.get("version"),
                        }
                    )
                return sorted(enriched, key=lambda x: x["port"])
            except Exception as e:  # pragma: no cover - defensive fallback
                logger.debug(f"Native port scan failed, falling back to Python: {e}")

        # Fallback: pure Python implementation
        return await self._py_scanner.scan(host, ports=ports, scan_type=scan_type)


async def scan_ports(
    host: str,
    ports: Optional[List[int]] = None,
    scan_type: str = "connect",
    timeout: float = 2.0,
) -> List[Dict]:
    """
    Convenience function used by other modules.

    Example:

        from aegisscan.native_portscan_interface import scan_ports
        results = await scan_ports("example.com", [21, 22, 80])
    """
    backend = PortScanBackend(timeout=timeout)
    return await backend.scan(host, ports=ports, scan_type=scan_type)


