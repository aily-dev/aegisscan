"""
Integration with external security tools
"""
import asyncio
import subprocess
import json
import os
import re
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging


class ExternalToolManager:
    """Manage and execute external security tools"""
    
    def __init__(self, output_dir: str = "tool_results", auto_install: bool = True):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self._logger = logging.getLogger(__name__)
        self.tools_status = {}
        self.auto_install = auto_install
        self.installer = None
        
        if auto_install:
            from .auto_installer import ToolAutoInstaller
            self.installer = ToolAutoInstaller()
    
    async def check_tool_available(self, tool_name: str) -> bool:
        """Check tool availability and auto-install if needed"""
        # بررسی مسیر از installer
        if self.installer:
            tool_path = self.installer.get_tool_path(tool_name)
            if tool_path:
                self.tools_status[tool_name] = True
                return True
        
        # بررسی در PATH
        try:
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "which", tool_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                ),
                timeout=5
            )
            stdout, _ = await result.communicate()
            available = result.returncode == 0
            self.tools_status[tool_name] = available
            
            # اگر موجود نبود و auto_install فعال است، نصب کن
            if not available and self.auto_install and self.installer:
                self._logger.info(f"Tool {tool_name} not found, attempting auto-install...")
                await self._auto_install_tool(tool_name)
                # بررسی مجدد
                tool_path = self.installer.get_tool_path(tool_name)
                if tool_path:
                    self.tools_status[tool_name] = True
                    return True
            
            return available
        except:
            self.tools_status[tool_name] = False
            return False
    
    async def _auto_install_tool(self, tool_name: str):
        """Auto-install tool"""
        if not self.installer:
            return
        
        install_funcs = {
            "sqlmap": self.installer.install_sqlmap,
            "xsstrike": self.installer.install_xsstrike,
            "nikto": self.installer.install_nikto,
            "nuclei": self.installer.install_nuclei,
        }
        
        if tool_name in install_funcs:
            try:
                await install_funcs[tool_name]()
            except Exception as e:
                self._logger.debug(f"Auto-install failed for {tool_name}: {e}")
    
    async def run_sqlmap(
        self,
        url: str,
        params: Optional[Dict] = None,
        level: int = 2,
        risk: int = 2,
        timeout: int = 300
    ) -> Optional[Dict]:
        """Run SQLMap for SQL Injection testing"""
        if not await self.check_tool_available("sqlmap"):
            self._logger.warning("SQLMap not found, skipping...")
            return None
        
        # Get SQLMap path
        sqlmap_cmd = "sqlmap"
        if self.installer:
            tool_path = self.installer.get_tool_path("sqlmap")
            if tool_path:
                if tool_path.endswith(".py"):
                    sqlmap_cmd = ["python3", tool_path]
                else:
                    sqlmap_cmd = tool_path
        
        try:
            sqlmap_dir = self.output_dir / "sqlmap"
            sqlmap_dir.mkdir(exist_ok=True)
            
            # Build URL with parameters if needed
            test_url = url
            if params and "?" not in url:
                param_str = "&".join([f"{k}={v}" for k, v in params.items()])
                test_url = f"{url}?{param_str}"
            
            # Build command properly
            if isinstance(sqlmap_cmd, list):
                base_cmd = sqlmap_cmd
            else:
                base_cmd = [sqlmap_cmd]
            
            cmd = base_cmd + [
                "-u", test_url,
                "--batch",
                "--level", str(level),
                "--risk", str(risk),
                "--threads", "3",
                "--timeout", "10",
                "--crawl", "0",
                "--output-dir", str(sqlmap_dir),
                "--answers", "quit=N,continue=Y",
            ]
            
            # Add specific parameters if URL already has query string
            if params and "?" in url:
                # تست همه پارامترها
                param_list = ",".join(params.keys())
                cmd.extend(["-p", param_list])
            elif params:
                # اگر پارامترها جداگانه هستند
                for key in params.keys():
                    cmd.extend(["-p", key])
            
            self._logger.debug(f"Running SQLMap: {' '.join(str(c) for c in cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='ignore')
            stderr_output = stderr.decode('utf-8', errors='ignore')
            
            # Check results more carefully
            result = {
                "url": url,
                "vulnerable": False,
                "output": output[:5000],  # بیشتر خروجی
                "stderr": stderr_output[:2000],
                "details": {},
                "type": None,
                "dbms": None,
                "parameter": None
            }
            
            # بررسی دقیق‌تر خروجی SQLMap
            output_lower = output.lower()
            stderr_lower = stderr_output.lower()
            combined_output = output + "\n" + stderr_output
            
            # الگوهای دقیق‌تر برای تشخیص آسیب‌پذیری
            vulnerable_patterns = [
                r"parameter.*is vulnerable",
                r"is vulnerable to.*injection",
                r"sqlmap identified.*injection",
                r"injection found",
                r"sql injection",
                r"vulnerable parameter",
                r"payload.*worked",
                r"technique:.*injection",
            ]
            
            is_vulnerable = False
            matched_pattern = None
            
            for pattern in vulnerable_patterns:
                match = re.search(pattern, combined_output, re.IGNORECASE | re.MULTILINE)
                if match:
                    is_vulnerable = True
                    matched_pattern = pattern
                    break
            
            # بررسی فایل‌های خروجی SQLMap
            log_files = list(sqlmap_dir.glob("*.log"))
            json_files = list(sqlmap_dir.glob("*.json"))
            txt_files = list(sqlmap_dir.glob("*.txt"))
            
            # خواندن فایل log برای اطلاعات بیشتر
            for log_file in log_files:
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        log_content = f.read()
                        if "vulnerable" in log_content.lower() or "injection" in log_content.lower():
                            is_vulnerable = True
                            result["log_content"] = log_content[:3000]
                except:
                    pass
            
            # خواندن فایل JSON
            for json_file in json_files:
                try:
                    with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
                        json_data = json.load(f)
                        result["details"] = json_data
                        
                        # بررسی ساختار JSON برای آسیب‌پذیری
                        if isinstance(json_data, dict):
                            if json_data.get("vulnerable") or json_data.get("injection"):
                                is_vulnerable = True
                except:
                    pass
            
            # خواندن فایل‌های txt
            for txt_file in txt_files:
                try:
                    with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
                        txt_content = f.read()
                        if "vulnerable" in txt_content.lower() or "injection" in txt_content.lower():
                            is_vulnerable = True
                            result["txt_content"] = txt_content[:3000]
                except:
                    pass
            
            if is_vulnerable:
                result["vulnerable"] = True
                
                # استخراج نوع آسیب‌پذیری
                combined_lower = combined_output.lower()
                if re.search(r"error.*based", combined_lower):
                    result["type"] = "error-based"
                elif re.search(r"boolean.*based", combined_lower):
                    result["type"] = "boolean-based"
                elif re.search(r"time.*based", combined_lower):
                    result["type"] = "time-based"
                elif re.search(r"union.*based", combined_lower):
                    result["type"] = "union-based"
                elif re.search(r"stacked", combined_lower):
                    result["type"] = "stacked queries"
                
                # استخراج DBMS
                dbms_patterns = {
                    "MySQL": r"mysql|mariadb",
                    "PostgreSQL": r"postgresql|postgres",
                    "MSSQL": r"microsoft sql|mssql|sql server",
                    "Oracle": r"oracle",
                    "SQLite": r"sqlite",
                }
                
                for dbms, pattern in dbms_patterns.items():
                    if re.search(pattern, combined_lower, re.IGNORECASE):
                        result["dbms"] = dbms
                        break
                
                # استخراج پارامتر آسیب‌پذیر
                param_match = re.search(r"parameter.*['\"]([^'\"]+)['\"]", combined_output, re.IGNORECASE)
                if param_match:
                    result["parameter"] = param_match.group(1)
                
                # استخراج payload موفق
                payload_match = re.search(r"payload.*['\"]([^'\"]+)['\"]", combined_output, re.IGNORECASE)
                if payload_match:
                    result["payload"] = payload_match.group(1)
            
            return result
            
        except asyncio.TimeoutError:
            self._logger.debug(f"SQLMap timeout for {url}")
            return None
        except Exception as e:
            self._logger.debug(f"SQLMap error: {e}")
            return None
    
    async def run_xsstrike(
        self,
        url: str,
        params: Optional[Dict] = None,
        timeout: int = 300
    ) -> Optional[Dict]:
        """Run XSStrike for XSS testing"""
        if not await self.check_tool_available("xsstrike"):
            self._logger.warning("XSStrike not found, skipping...")
            return None
        
        # Get XSStrike path
        xsstrike_cmd = "xsstrike"
        if self.installer:
            tool_path = self.installer.get_tool_path("xsstrike")
            if tool_path:
                if tool_path.endswith(".py"):
                    xsstrike_cmd = ["python3", tool_path]
                else:
                    xsstrike_cmd = tool_path
        
        try:
            output_file = self.output_dir / "xsstrike_results.txt"
            xsstrike_dir = self.output_dir / "xsstrike"
            xsstrike_dir.mkdir(exist_ok=True)
            
            # Build command
            if isinstance(xsstrike_cmd, list):
                base_cmd = xsstrike_cmd
            else:
                base_cmd = [xsstrike_cmd]
            
            # Build URL with parameters
            test_url = url
            if params and "?" not in url:
                param_str = "&".join([f"{k}={v}" for k, v in params.items()])
                test_url = f"{url}?{param_str}"
            
            cmd = base_cmd + [
                "-u", test_url,
                "--crawl", "0",
                "--file-log-level", "INFO",
            ]
            
            if params and "?" in url:
                for key in params.keys():
                    cmd.extend(["-d", key])
            
            self._logger.debug(f"Running XSStrike: {' '.join(str(c) for c in cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(xsstrike_dir)
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='ignore')
            stderr_output = stderr.decode('utf-8', errors='ignore')
            combined_output = output + "\n" + stderr_output
            
            # ذخیره خروجی
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(combined_output)
            
            # بررسی دقیق‌تر برای XSS
            output_lower = combined_output.lower()
            vulnerable_patterns = [
                r"vulnerable",
                r"xss found",
                r"payload.*worked",
                r"injection.*found",
                r"reflected",
                r"stored",
            ]
            
            is_vulnerable = False
            xss_type = None
            
            for pattern in vulnerable_patterns:
                if re.search(pattern, output_lower):
                    is_vulnerable = True
                    if "stored" in output_lower:
                        xss_type = "stored"
                    elif "reflected" in output_lower:
                        xss_type = "reflected"
                    break
            
            # بررسی فایل‌های log
            log_files = list(xsstrike_dir.glob("*.log"))
            for log_file in log_files:
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        log_content = f.read()
                        if "vulnerable" in log_content.lower() or "xss" in log_content.lower():
                            is_vulnerable = True
                except:
                    pass
            
            result = {
                "url": url,
                "vulnerable": is_vulnerable,
                "type": xss_type,
                "output": output[:5000],
                "stderr": stderr_output[:2000],
                "output_file": str(output_file)
            }
            
            return result
            
        except Exception as e:
            self._logger.debug(f"XSStrike error: {e}")
            return None
    
    async def run_dalfox(
        self,
        url: str,
        params: Optional[Dict] = None,
        timeout: int = 300
    ) -> Optional[Dict]:
        """Run Dalfox for XSS testing"""
        if not await self.check_tool_available("dalfox"):
            self._logger.warning("Dalfox not found, skipping...")
            return None
        
        try:
            output_file = self.output_dir / "dalfox_results.json"
            
            cmd = [
                "dalfox",
                "url", url,
                "--format", "json",
                "--output", str(output_file),
            ]
            
            if params:
                data = "&".join([f"{k}={v}" for k, v in params.items()])
                cmd.extend(["--data", data])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            result = {
                "url": url,
                "vulnerable": False,
                "output_file": str(output_file)
            }
            
            # خواندن نتایج JSON
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        if data:
                            result["vulnerable"] = True
                            result["findings"] = data
                except:
                    pass
            
            return result
            
        except Exception as e:
            self._logger.debug(f"Dalfox error: {e}")
            return None
    
    async def run_commix(
        self,
        url: str,
        params: Optional[Dict] = None,
        timeout: int = 300
    ) -> Optional[Dict]:
        """Run Commix for Command Injection testing"""
        if not await self.check_tool_available("commix"):
            self._logger.warning("Commix not found, skipping...")
            return None
        
        try:
            output_file = self.output_dir / "commix_results.txt"
            
            cmd = [
                "commix",
                "-u", url,
                "--batch",
                "--output-dir", str(self.output_dir / "commix"),
            ]
            
            if params:
                data = "&".join([f"{k}={v}" for k, v in params.items()])
                cmd.extend(["--data", data])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode('utf-8', errors='ignore')
            
            result = {
                "url": url,
                "vulnerable": "vulnerable" in output.lower() or "injection" in output.lower(),
                "output": output[:2000]
            }
            
            return result
            
        except Exception as e:
            self._logger.debug(f"Commix error: {e}")
            return None
    
    async def run_nikto(
        self,
        host: str,
        timeout: int = 600
    ) -> Optional[Dict]:
        """Run Nikto"""
        if not await self.check_tool_available("nikto"):
            self._logger.warning("Nikto not found, skipping...")
            return None
        
        try:
            output_file = self.output_dir / "nikto.txt"
            
            cmd = [
                "nikto",
                "-h", host,
                "-output", str(output_file),
                "-Format", "txt"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.wait_for(process.communicate(), timeout=timeout)
            
            result = {
                "host": host,
                "output_file": str(output_file)
            }
            
            # خواندن نتایج
            if output_file.exists():
                with open(output_file, 'r') as f:
                    result["output"] = f.read()[:5000]
            
            return result
            
        except Exception as e:
            self._logger.debug(f"Nikto error: {e}")
            return None
    
    async def run_nuclei(
        self,
        urls: List[str],
        timeout: int = 600
    ) -> Optional[Dict]:
        """Run Nuclei"""
        if not await self.check_tool_available("nuclei"):
            self._logger.warning("Nuclei not found, skipping...")
            return None
        
        try:
            urls_file = self.output_dir / "urls_for_nuclei.txt"
            output_file = self.output_dir / "nuclei_results.json"
            
            # نوشتن URLها در فایل
            with open(urls_file, 'w') as f:
                for url in urls:
                    f.write(f"{url}\n")
            
            cmd = [
                "nuclei",
                "-l", str(urls_file),
                "-o", str(output_file),
                "-json",
                "-silent"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.wait_for(process.communicate(), timeout=timeout)
            
            result = {
                "urls_count": len(urls),
                "output_file": str(output_file),
                "findings": []
            }
            
            # خواندن نتایج JSON
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    finding = json.loads(line)
                                    result["findings"].append(finding)
                                except:
                                    pass
                except:
                    pass
            
            return result
            
        except Exception as e:
            self._logger.debug(f"Nuclei error: {e}")
            return None
    
    async def run_wfuzz(
        self,
        url: str,
        wordlist: Optional[str] = None,
        timeout: int = 300
    ) -> Optional[Dict]:
        """Run WFuzz for directory bruteforce"""
        if not await self.check_tool_available("wfuzz"):
            self._logger.warning("WFuzz not found, skipping...")
            return None
        
        try:
            output_file = self.output_dir / "wfuzz_results.json"
            
            cmd = [
                "wfuzz",
                "-c",
                "-z", "file,wordlist/general/common.txt" if not wordlist else f"file,{wordlist}",
                "--hc", "404",
                "-f", str(output_file), "json",
                url
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.wait_for(process.communicate(), timeout=timeout)
            
            result = {
                "url": url,
                "output_file": str(output_file),
                "findings": []
            }
            
            # خواندن نتایج
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        result["findings"] = data
                except:
                    pass
            
            return result
            
        except Exception as e:
            self._logger.debug(f"WFuzz error: {e}")
            return None
    
    def get_tools_status(self) -> Dict[str, bool]:
        """Get tools status"""
        return self.tools_status.copy()

