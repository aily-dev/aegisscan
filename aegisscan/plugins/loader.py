"""
Plugin Loader and Manager
"""
import importlib
import importlib.util
import inspect
from typing import Dict, List, Type, Optional
from pathlib import Path
import logging
from ..scanners.base import BaseScanner


class PluginManager:
    """Manages plugins for AegisScan"""
    
    def __init__(self):
        self.plugins: Dict[str, Type] = {}
        self.scanner_plugins: List[Type[BaseScanner]] = []
        self._logger = logging.getLogger(__name__)
    
    def load_plugin(self, plugin_path: str):
        """Load a plugin from a file path"""
        try:
            spec = importlib.util.spec_from_file_location("plugin", plugin_path)
            if spec is None or spec.loader is None:
                raise ValueError(f"Cannot load plugin from {plugin_path}")
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find scanner classes
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, BaseScanner) and 
                    obj != BaseScanner):
                    self.scanner_plugins.append(obj)
                    self.plugins[name] = obj
                    self._logger.info(f"Loaded scanner plugin: {name}")
        except Exception as e:
            self._logger.error(f"Error loading plugin {plugin_path}: {e}")
    
    def load_plugins_from_dir(self, directory: str):
        """Load all plugins from a directory"""
        plugin_dir = Path(directory)
        for plugin_file in plugin_dir.glob("*.py"):
            if plugin_file.name != "__init__.py":
                self.load_plugin(str(plugin_file))
    
    def get_scanner_plugins(self) -> List[Type[BaseScanner]]:
        """Get all loaded scanner plugins"""
        return self.scanner_plugins
    
    def create_scanner(self, plugin_name: str, http_client, engine=None) -> Optional[BaseScanner]:
        """Create an instance of a scanner plugin"""
        if plugin_name in self.plugins:
            plugin_class = self.plugins[plugin_name]
            return plugin_class(http_client, engine)
        return None

