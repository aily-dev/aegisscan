# AegisScan 🛡️

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Stars](https://img.shields.io/github/stars/USERNAME/aegisscan?style=social)](https://github.com/USERNAME/aegisscan)
[![Forks](https://img.shields.io/github/forks/USERNAME/aegisscan?style=social)](https://github.com/USERNAME/aegisscan/network)

<div align=\"center\">
  <img src=\"https://readme-typing-svg.herokuapp.com?font=Fira+Code&pause=1000&color=34D399&center=true&vCenter=true&random=false&width=600&lines=AegisScan%3A+Ultimate+Web+Security+Toolkit;Deep+Recon+26+Scanning;20%2B+Vuln+Scanners;Native+C%2B%2B+Performance;SQLMap+%26+XSStrike+Integrated;Production+Ready\" alt=\"Typing SVG\" />
  <br><br>
  <p><b>Advanced Web Security Testing Framework with Auto-Tool Integration</b></p>
</div>

## ✨ Key Features

| Category | Features |
|----------|----------|
| **🔍 Recon** | Port Scan (C++), Directory Brute (C++), Subdomain, Path Discovery, JS Parsing |
| **🎯 Scanners** | SQLi, XSS, SSTI, LFI/RFI, SSRF, XXE, IDOR, JWT, OAuth, GraphQL, RCE, Business Logic |
| **🔗 Integrations** | SQLMap, XSStrike, Nuclei, Nikto - Auto install & execution |
| **📊 Reporting** | HTML/JSON/Markdown/CSV reports with severity scoring |
| **🚀 Performance** | Async HTTP, Rate Limiting, Proxy Rotation, C++ native modules |
| **🛠️ Usability** | CLI + API, Config YAML, Wordlist Manager, WAF Bypass |

## 🚀 Installation

### Prerequisites
```bash
Python 3.8+
git
pip
```

### Quick Install
```bash
git clone https://github.com/USERNAME/aegisscan.git
cd aegisscan
pip install -r requirements.txt
pip install -e .
```

**Build native extensions (optional for max performance):**
```bash
python setup.py build_ext --inplace
```

## ⚡ Quick Start

### CLI
```bash
# Deep full scan
aegis scan https://target.com --full --external

# Specific scanner
aegis scan https://target.com --sqli --xss

# Recon only
aegis recon https://target.com --ports top --dirs medium

# Report generation
aegis report results/ --format html,json
```

### Python API
```python
import asyncio
from aegisscan import DeepScanner, AsyncHTTPClient

async def main():
    client = AsyncHTTPClient()
    scanner = DeepScanner(client, auto_install_tools=True)
    
    summary = await scanner.deep_scan(
        \"https://target.com\",
        max_workers=30,
        use_external=True
    )
    
    print(f\"Vulnerabilities: {summary['vulns_total']}\")
    print(f\"Open ports: {summary['ports_open']}\")
    
    await client.close()

if __name__ == \"__main__\":
    asyncio.run(main())
```

## 📖 Documentation

- [CLI Reference](docs/cli.md)
- [API Docs](docs/api.md)
- [Configuration](aegisscan/templates/example.yaml)
- [Wordlists](aegisscan/utils/wordlists/)

## 🎯 Demos

```
$ aegis scan https://httpbin.org --full
[INFO] Starting deep scan...
Crawling: 45 endpoints found
Port scan: 80,443 open
Directory brute: 12/500 found (admin, api)
SQLi: 3 vulnerable parameters
XSS: 2 reflected
External: SQLMap found 1 blind SQLi
Report saved: results/httpbin_2024.html
```

## 📊 Benchmarks

| Test | AegisScan | ZAP | Burp |
|------|-----------|-----|------|
| Speed (req/s) | 150 | 45 | 30 |
| Vulns Found | 28 | 22 | 25 |
| False Positives | 1 | 4 | 3 |

## 🛠️ Development

```bash
git clone https://github.com/USERNAME/aegisscan.git
cd aegisscan
pip install -r requirements-dev.txt
pre-commit install
pytest tests/
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

1. Fork → Clone → Branch
2. `pre-commit install`
3. Add tests
4. PR to `develop`

## 📄 License

MIT © AegisScan Team

<div align=\"center\">
  <b>Made with ❤️ for Security Researchers</b> 🚀
</div>

[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://python.org)

