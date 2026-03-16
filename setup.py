"""
Setup script for AegisScan
"""
from setuptools import setup, find_packages, Extension
from pybind11.setup_helpers import Pybind11Extension, build_ext
from pybind11 import get_cmake_dir
import pybind11

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# C++ extensions for performance-critical operations
ext_modules = [
    Pybind11Extension(
        "aegis_native.port_scan",
        [
            "aegis_native/port_scan.cpp",
        ],
        cxx_std=17,
        include_dirs=[
            # pybind11 includes are automatically added
        ],
    ),
    Pybind11Extension(
        "aegis_native.dir_wordgen",
        [
            "aegis_native/dir_wordgen.cpp",
        ],
        cxx_std=17,
        include_dirs=[
            # pybind11 includes are automatically added
        ],
    ),
]

setup(
    name="aegisscan",
    version="1.0.0",
    author="AegisScan Team",
    description="Advanced Web Security Testing Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: C++",
    ],
    python_requires=">=3.8",
    install_requires=[
        "aiohttp>=3.8.0",
        "httpx>=0.24.0",
        "dnspython>=2.3.0",
        "pyyaml>=6.0",
        "pybind11>=2.10.0",
    ],
    setup_requires=[
        "pybind11>=2.10.0",
    ],
    entry_points={
        "console_scripts": [
            "aegis=aegisscan.cli.main:main",
        ],
    },
    include_package_data=True,
)

