"""
Wordlist Manager for Directory Bruteforce and Path Discovery
"""
from typing import List, Dict, Optional
from pathlib import Path
import json


class WordlistManager:
    """Manage wordlists for various scanning purposes"""
    
    def __init__(self, wordlists_dir: Optional[str] = None):
        self.wordlists_dir = Path(wordlists_dir) if wordlists_dir else Path(__file__).parent / "wordlists"
        self.wordlists_dir.mkdir(exist_ok=True, parents=True)
        self._wordlists: Dict[str, List[str]] = {}
        self._load_default_wordlists()
    
    def _load_default_wordlists(self):
        """Load default wordlists"""
        # Directory wordlist
        self._wordlists["directories"] = [
            "admin", "administrator", "api", "app", "assets", "backup", "backups",
            "bin", "blog", "cache", "config", "css", "data", "database", "db",
            "dev", "development", "doc", "docs", "download", "downloads", "etc",
            "files", "forum", "ftp", "git", "help", "home", "images", "img",
            "include", "includes", "index", "install", "js", "lib", "libs",
            "log", "logs", "mail", "media", "mobile", "old", "panel", "php",
            "private", "public", "readme", "remote", "rest", "root", "scripts",
            "secure", "server", "site", "sites", "src", "static", "stats",
            "store", "test", "tmp", "tools", "upload", "uploads", "user",
            "users", "var", "vendor", "web", "webapp", "www", "xml",
            ".git", ".svn", ".env", ".htaccess", ".htpasswd", "robots.txt",
            "sitemap.xml", "crossdomain.xml", "phpinfo.php", "info.php",
            "test.php", "admin.php", "config.php", "wp-config.php",
            "wp-admin", "wp-content", "wp-includes", "wp-login.php",
            "administrator", "cpanel", "whm", "phpmyadmin", "pma",
            "adminer.php", "manager", "console", "admin.php", "login",
            "signin", "dashboard", "control", "panel", "management",
        ]
        
        # API endpoints wordlist
        self._wordlists["api_endpoints"] = [
            "api", "v1", "v2", "v3", "api/v1", "api/v2", "api/v3",
            "rest", "restapi", "graphql", "graphiql", "swagger",
            "swagger-ui", "swagger.json", "openapi.json", "api-docs",
            "api/docs", "api/status", "api/health", "api/info",
            "api/version", "api/test", "api/debug", "api/admin",
            "endpoint", "endpoints", "routes", "rpc", "soap",
            "wsdl", "xmlrpc", "jsonrpc", "api/users", "api/auth",
            "api/login", "api/logout", "api/register", "api/token",
        ]
        
        # File extensions wordlist
        self._wordlists["file_extensions"] = [
            "php", "asp", "aspx", "jsp", "html", "htm", "xml", "json",
            "txt", "log", "bak", "old", "backup", "sql", "db", "sqlite",
            "zip", "tar", "gz", "rar", "7z", "pdf", "doc", "docx",
            "xls", "xlsx", "ppt", "pptx", "csv", "ini", "conf", "config",
            "env", "properties", "yaml", "yml", "toml", "sh", "bat",
            "exe", "dll", "so", "dylib", "jar", "war", "ear",
        ]
        
        # Sensitive files wordlist
        self._wordlists["sensitive_files"] = [
            ".git/config", ".git/HEAD", ".git/index", ".git/logs",
            ".svn/entries", ".svn/wc.db", ".hg/requires",
            ".env", ".env.local", ".env.production", ".env.development",
            ".htaccess", ".htpasswd", ".htgroup", ".htdigest",
            "web.config", "config.php", "config.inc.php", "config.json",
            "wp-config.php", "settings.py", "settings.json",
            "application.properties", "application.yml", "application.yaml",
            "database.yml", "secrets.yml", "credentials.json",
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
            "known_hosts", "authorized_keys", "ssh_config",
            "passwd", "shadow", "group", "hosts", "hosts.allow",
            "hosts.deny", "sudoers", "fstab", "crontab",
            "backup.sql", "dump.sql", "database.sql", "db.sql",
            "backup.tar", "backup.tar.gz", "backup.zip",
            "phpinfo.php", "info.php", "test.php", "debug.php",
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            "clientaccesspolicy.xml", ".DS_Store", ".gitignore",
            "package.json", "composer.json", "requirements.txt",
            "pom.xml", "build.xml", "Makefile", "Dockerfile",
        ]
        
        # Admin panels wordlist
        self._wordlists["admin_panels"] = [
            "admin", "administrator", "admin.php", "admin.html",
            "admin/index.php", "admin/login.php", "admin/dashboard",
            "wp-admin", "wp-login.php", "wp-admin/admin.php",
            "administrator", "administrator/index.php",
            "cpanel", "cpanel/", "whm", "whm/",
            "phpmyadmin", "phpmyadmin/", "pma", "pma/",
            "adminer.php", "adminer", "adminer.php?server=",
            "manager", "manager/html", "manager/status",
            "console", "console/", "jboss/console",
            "weblogic", "weblogic/console", "tomcat/manager",
            "jenkins", "jenkins/", "jenkins/login",
            "grafana", "grafana/", "grafana/login",
            "kibana", "kibana/", "kibana/app/kibana",
            "elasticsearch", "elasticsearch/_plugin/head",
            "solr", "solr/admin", "solr/admin/cores",
            "zabbix", "zabbix/", "zabbix/index.php",
            "nagios", "nagios/", "nagios/cgi-bin",
        ]
        
        # Common ports wordlist
        self._wordlists["common_ports"] = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888,
            9000, 9200, 27017, 6379, 11211, 5000, 3000, 8000, 8888,
        ]
    
    def get_wordlist(self, category: str) -> List[str]:
        """Get wordlist by category"""
        return self._wordlists.get(category, [])
    
    def load_wordlist_from_file(self, filepath: str, category: str = "custom") -> bool:
        """Load wordlist from file"""
        try:
            wordlist_file = Path(filepath)
            if not wordlist_file.exists():
                return False
            
            words = []
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith('#'):
                        words.append(word)
            
            self._wordlists[category] = words
            return True
        except Exception:
            return False
    
    def save_wordlist(self, category: str, filepath: str) -> bool:
        """Save wordlist to file"""
        try:
            if category not in self._wordlists:
                return False
            
            wordlist_file = Path(filepath)
            wordlist_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(wordlist_file, 'w', encoding='utf-8') as f:
                for word in self._wordlists[category]:
                    f.write(f"{word}\n")
            
            return True
        except Exception:
            return False
    
    def add_word(self, category: str, word: str):
        """Add word to wordlist"""
        if category not in self._wordlists:
            self._wordlists[category] = []
        if word not in self._wordlists[category]:
            self._wordlists[category].append(word)
    
    def get_combined_wordlist(self, categories: List[str]) -> List[str]:
        """Get combined wordlist from multiple categories"""
        combined = []
        for category in categories:
            combined.extend(self.get_wordlist(category))
        return list(set(combined))  # Remove duplicates

