"""
Auto-installer for penetration testing tools
نصب خودکار ابزارهای پنتست
"""
import asyncio
import subprocess
import os
import sys
import shutil
from pathlib import Path
from typing import Dict, List, Optional
import logging
import platform


class ToolAutoInstaller:
    """نصب خودکار ابزارهای پنتست"""
    
    def __init__(self, tools_dir: str = "aegisscan_tools"):
        self.tools_dir = Path(tools_dir)
        self.tools_dir.mkdir(exist_ok=True, parents=True)
        self._logger = logging.getLogger(__name__)
        self.system = platform.system().lower()
        
        # مسیرهای ابزارها
        self.tool_paths: Dict[str, Path] = {}
    
    async def install_sqlmap(self) -> Optional[str]:
        """نصب خودکار SQLMap"""
        try:
            # بررسی وجود pip
            if not shutil.which("pip") and not shutil.which("pip3"):
                self._logger.warning("pip not found, trying to install SQLMap from git...")
                return await self._install_sqlmap_from_git()
            
            # نصب از pip
            pip_cmd = "pip3" if shutil.which("pip3") else "pip"
            cmd = [pip_cmd, "install", "sqlmap"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.wait_for(process.communicate(), timeout=300)
            
            # بررسی نصب
            if shutil.which("sqlmap"):
                self.tool_paths["sqlmap"] = Path(shutil.which("sqlmap"))
                return "sqlmap"
            
            return await self._install_sqlmap_from_git()
            
        except Exception as e:
            self._logger.error(f"Error installing SQLMap: {e}")
            return await self._install_sqlmap_from_git()
    
    async def _install_sqlmap_from_git(self) -> Optional[str]:
        """نصب SQLMap از Git"""
        try:
            sqlmap_dir = self.tools_dir / "sqlmap"
            
            if sqlmap_dir.exists():
                # به‌روزرسانی
                cmd = ["git", "pull"]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=str(sqlmap_dir),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=60)
            else:
                # کلون
                cmd = ["git", "clone", "https://github.com/sqlmapproject/sqlmap.git", str(sqlmap_dir)]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=300)
            
            sqlmap_path = sqlmap_dir / "sqlmap.py"
            if sqlmap_path.exists():
                self.tool_paths["sqlmap"] = sqlmap_path
                return str(sqlmap_path)
            
        except Exception as e:
            self._logger.error(f"Error installing SQLMap from git: {e}")
        
        return None
    
    async def install_xsstrike(self) -> Optional[str]:
        """نصب خودکار XSStrike"""
        try:
            xsstrike_dir = self.tools_dir / "XSStrike"
            
            if xsstrike_dir.exists():
                # به‌روزرسانی
                cmd = ["git", "pull"]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=str(xsstrike_dir),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=60)
            else:
                # کلون
                cmd = ["git", "clone", "https://github.com/s0md3v/XSStrike.git", str(xsstrike_dir)]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=300)
                
                # نصب requirements
                if (xsstrike_dir / "requirements.txt").exists():
                    pip_cmd = "pip3" if shutil.which("pip3") else "pip"
                    cmd = [pip_cmd, "install", "-r", str(xsstrike_dir / "requirements.txt")]
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await asyncio.wait_for(process.communicate(), timeout=300)
            
            xsstrike_path = xsstrike_dir / "xsstrike.py"
            if xsstrike_path.exists():
                self.tool_paths["xsstrike"] = xsstrike_path
                return str(xsstrike_path)
            
        except Exception as e:
            self._logger.error(f"Error installing XSStrike: {e}")
        
        return None
    
    async def install_nikto(self) -> Optional[str]:
        """نصب خودکار Nikto"""
        try:
            # برای Linux
            if self.system == "linux":
                # بررسی apt
                if shutil.which("apt-get"):
                    cmd = ["sudo", "apt-get", "update"]
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await asyncio.wait_for(process.communicate(), timeout=120)
                    
                    cmd = ["sudo", "apt-get", "install", "-y", "nikto"]
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await asyncio.wait_for(process.communicate(), timeout=300)
                    
                    if shutil.which("nikto"):
                        self.tool_paths["nikto"] = Path(shutil.which("nikto"))
                        return "nikto"
            
            # نصب از Git
            return await self._install_nikto_from_git()
            
        except Exception as e:
            self._logger.error(f"Error installing Nikto: {e}")
            return await self._install_nikto_from_git()
    
    async def _install_nikto_from_git(self) -> Optional[str]:
        """نصب Nikto از Git"""
        try:
            nikto_dir = self.tools_dir / "nikto"
            
            if not nikto_dir.exists():
                cmd = ["git", "clone", "https://github.com/sullo/nikto.git", str(nikto_dir)]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=300)
            
            nikto_path = nikto_dir / "program" / "nikto.pl"
            if nikto_path.exists():
                self.tool_paths["nikto"] = nikto_path
                return str(nikto_path)
            
        except Exception as e:
            self._logger.error(f"Error installing Nikto from git: {e}")
        
        return None
    
    async def install_nuclei(self) -> Optional[str]:
        """نصب خودکار Nuclei"""
        try:
            # بررسی Go
            if not shutil.which("go"):
                self._logger.warning("Go not found, downloading Nuclei binary...")
                return await self._install_nuclei_binary()
            
            # نصب از Go
            cmd = ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "GOPATH": str(self.tools_dir / "go")}
            )
            await asyncio.wait_for(process.communicate(), timeout=600)
            
            # بررسی مسیر Go bin
            go_bin = Path.home() / "go" / "bin" / "nuclei"
            if go_bin.exists():
                self.tool_paths["nuclei"] = go_bin
                return str(go_bin)
            
            return await self._install_nuclei_binary()
            
        except Exception as e:
            self._logger.error(f"Error installing Nuclei: {e}")
            return await self._install_nuclei_binary()
    
    async def _install_nuclei_binary(self) -> Optional[str]:
        """دانلود باینری Nuclei"""
        try:
            import urllib.request
            import zipfile
            
            # تعیین architecture
            arch = platform.machine().lower()
            if "x86_64" in arch or "amd64" in arch:
                arch = "amd64"
            elif "arm" in arch:
                arch = "arm64"
            else:
                arch = "386"
            
            # تعیین OS
            os_name = "linux" if self.system == "linux" else "windows" if self.system == "windows" else "darwin"
            
            # URL دانلود
            version = "v3.1.0"  # آخرین نسخه پایدار
            url = f"https://github.com/projectdiscovery/nuclei/releases/download/{version}/nuclei_{version}_{os_name}_{arch}.zip"
            
            zip_path = self.tools_dir / "nuclei.zip"
            
            # دانلود
            self._logger.info(f"Downloading Nuclei from {url}...")
            urllib.request.urlretrieve(url, zip_path)
            
            # Extract
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.tools_dir)
            
            # پیدا کردن باینری
            nuclei_bin = self.tools_dir / "nuclei"
            if not nuclei_bin.exists():
                nuclei_bin = self.tools_dir / f"nuclei_{os_name}_{arch}" / "nuclei"
            
            if nuclei_bin.exists():
                # قابل اجرا کردن
                os.chmod(nuclei_bin, 0o755)
                self.tool_paths["nuclei"] = nuclei_bin
                return str(nuclei_bin)
            
        except Exception as e:
            self._logger.error(f"Error downloading Nuclei binary: {e}")
        
        return None
    
    async def install_all_tools(self) -> Dict[str, bool]:
        """نصب همه ابزارها"""
        results = {}
        
        tools = {
            "sqlmap": self.install_sqlmap,
            "xsstrike": self.install_xsstrike,
            "nikto": self.install_nikto,
            "nuclei": self.install_nuclei,
        }
        
        for tool_name, install_func in tools.items():
            try:
                self._logger.info(f"Installing {tool_name}...")
                result = await install_func()
                results[tool_name] = result is not None
                if result:
                    self._logger.info(f"✅ {tool_name} installed: {result}")
                else:
                    self._logger.warning(f"❌ {tool_name} installation failed")
            except Exception as e:
                self._logger.error(f"Error installing {tool_name}: {e}")
                results[tool_name] = False
        
        return results
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """دریافت مسیر ابزار"""
        if tool_name in self.tool_paths:
            return str(self.tool_paths[tool_name])
        
        # بررسی PATH
        path = shutil.which(tool_name)
        if path:
            return path
        
        return None

