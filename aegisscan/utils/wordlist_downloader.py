"""
Wordlist Downloader from Internet
Downloads popular wordlists from various sources
"""
import asyncio
import aiohttp
from typing import List, Optional, Dict
from pathlib import Path
import logging
import gzip
import zipfile
import tarfile
import io


class WordlistDownloader:
    """Download wordlists from internet sources"""
    
    def __init__(self, wordlists_dir: Optional[str] = None):
        self.wordlists_dir = Path(wordlists_dir) if wordlists_dir else Path(__file__).parent / "wordlists" / "downloaded"
        self.wordlists_dir.mkdir(exist_ok=True, parents=True)
        self._logger = logging.getLogger(__name__)
        
        # Popular wordlist sources
        self.wordlist_sources = {
            "rockyou": {
                "url": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
                "filename": "rockyou.txt",
                "description": "RockYou password list (14M passwords)"
            },
            "common_passwords": {
                "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
                "filename": "common_passwords.txt",
                "description": "Common passwords list (1M passwords)"
            },
            "usernames": {
                "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/xato-net-10-million-usernames.txt",
                "filename": "usernames.txt",
                "description": "Xato usernames list (10M usernames)"
            },
            "directory_list": {
                "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
                "filename": "directory_list.txt",
                "description": "Directory list for web content discovery"
            },
            "api_endpoints": {
                "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
                "filename": "api_endpoints.txt",
                "description": "API endpoints wordlist"
            },
            "subdomains": {
                "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
                "filename": "subdomains.txt",
                "description": "Top subdomains list"
            }
        }
    
    async def download_wordlist(self, wordlist_name: str, force: bool = False) -> Optional[Path]:
        """Download a wordlist by name"""
        if wordlist_name not in self.wordlist_sources:
            self._logger.error(f"Unknown wordlist: {wordlist_name}")
            return None
        
        source = self.wordlist_sources[wordlist_name]
        filepath = self.wordlists_dir / source["filename"]
        
        # Check if already downloaded
        if filepath.exists() and not force:
            self._logger.info(f"Wordlist {wordlist_name} already exists: {filepath}")
            return filepath
        
        try:
            self._logger.info(f"Downloading {wordlist_name} from {source['url']}...")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(source["url"], timeout=aiohttp.ClientTimeout(total=300)) as resp:
                    if resp.status == 200:
                        content = await resp.read()
                        
                        # Save file
                        with open(filepath, 'wb') as f:
                            f.write(content)
                        
                        self._logger.info(f"Downloaded {wordlist_name} to {filepath} ({len(content)} bytes)")
                        return filepath
                    else:
                        self._logger.error(f"Failed to download {wordlist_name}: HTTP {resp.status}")
                        return None
        except Exception as e:
            self._logger.debug(f"Error downloading {wordlist_name}: {e}")
            return None
    
    async def download_all_wordlists(self, force: bool = False) -> Dict[str, Optional[Path]]:
        """Download all available wordlists"""
        results = {}
        
        for wordlist_name in self.wordlist_sources.keys():
            filepath = await self.download_wordlist(wordlist_name, force=force)
            results[wordlist_name] = filepath
        
        return results
    
    async def download_popular_wordlists(self, force: bool = False) -> Dict[str, Optional[Path]]:
        """Download most popular wordlists for brute forcing"""
        popular = ["rockyou", "common_passwords", "usernames"]
        results = {}
        
        for wordlist_name in popular:
            filepath = await self.download_wordlist(wordlist_name, force=force)
            results[wordlist_name] = filepath
        
        return results
    
    def get_wordlist_path(self, wordlist_name: str) -> Optional[Path]:
        """Get path to downloaded wordlist"""
        if wordlist_name not in self.wordlist_sources:
            return None
        
        filepath = self.wordlists_dir / self.wordlist_sources[wordlist_name]["filename"]
        if filepath.exists():
            return filepath
        return None
    
    def load_wordlist(self, wordlist_name: str, max_lines: Optional[int] = None) -> List[str]:
        """Load wordlist into memory"""
        filepath = self.get_wordlist_path(wordlist_name)
        if not filepath:
            return []
        
        words = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if max_lines and i >= max_lines:
                        break
                    word = line.strip()
                    if word:
                        words.append(word)
        except Exception as e:
            self._logger.debug(f"Error loading wordlist {wordlist_name}: {e}")
        
        return words
    
    def list_available_wordlists(self) -> Dict[str, str]:
        """List all available wordlists with descriptions"""
        return {name: source["description"] for name, source in self.wordlist_sources.items()}

