"""
Configuration Management
"""
import json
import os
from pathlib import Path
from typing import Dict, Optional, Any


class Config:
    """Configuration manager for AegisScan"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = Path(config_file) if config_file else Path.home() / ".aegisscan" / "config.json"
        self.config_file.parent.mkdir(exist_ok=True, parents=True)
        self._config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            "http": {
                "timeout": 10,
                "max_retries": 3,
                "user_agent": "AegisScan/1.0",
                "follow_redirects": True,
                "max_redirects": 10,
            },
            "scanning": {
                "max_workers": 20,
                "rate_limit": 10,
                "rate_window": 1.0,
                "max_depth": 3,
                "max_pages": 100,
            },
            "external_tools": {
                "auto_install": False,
                "timeout": 300,
            },
            "reporting": {
                "formats": ["json", "html", "markdown"],
                "output_dir": "scan_results",
            },
            "proxy": {
                "enabled": False,
                "http": None,
                "https": None,
            },
            "tor": {
                "enabled": False,
                "socks_port": 9050,
            },
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    # Merge with defaults
                    return self._merge_config(default_config, user_config)
            except:
                pass
        
        return default_config
    
    def _merge_config(self, default: Dict, user: Dict) -> Dict:
        """Merge user config with defaults"""
        result = default.copy()
        
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self.save()
    
    def save(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self._config, f, indent=2)
    
    def get_http_config(self) -> Dict:
        """Get HTTP configuration"""
        return self.get("http", {})
    
    def get_scanning_config(self) -> Dict:
        """Get scanning configuration"""
        return self.get("scanning", {})
    
    def get_external_tools_config(self) -> Dict:
        """Get external tools configuration"""
        return self.get("external_tools", {})
    
    def get_reporting_config(self) -> Dict:
        """Get reporting configuration"""
        return self.get("reporting", {})
    
    def get_proxy_config(self) -> Dict:
        """Get proxy configuration"""
        return self.get("proxy", {})
    
    def get_tor_config(self) -> Dict:
        """Get TOR configuration"""
        return self.get("tor", {})

