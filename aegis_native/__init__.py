"""
Native (C++ accelerated) backends for AegisScan.

This package is intended to host performance‑critical pieces of the framework
implemented in C++ and exposed to Python via pybind11.

Current modules:

    - aegis_native.port_scan    → high‑performance TCP connect port scanner
    - aegis_native.dir_wordgen  → fast directory bruteforce URL generator

To build the native extensions you typically need:

    - a C++17 compatible compiler
    - pybind11 (as a build dependency)

See comments in `port_scan.cpp` for a minimal example of how to compile.
"""

__all__ = [
    "port_scan",
    "dir_wordgen",
]


