#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration management for KittySploit Framework
Supports TOML configuration files
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
from core.version import VERSION

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # Fallback for older Python versions
    except ImportError:
        tomllib = None


class Config:
    """Configuration manager for KittySploit Framework"""
    
    # Default configuration values (class attributes for backward compatibility)
    DEFAULT_WORKSPACES_DIR = "database"
    DEFAULT_WORKSPACE = "default"
    VERSION = VERSION
    
    DEFAULT_PROXY_CONFIG = {
        'enabled': False,
        'host': '127.0.0.1',
        'port': 8080,
        'protocol': 'http',
        'username': '',
        'password': '',
        'http_proxy': None,
        'https_proxy': None,
        'socks_proxy': None,
        'no_proxy': ''
    }
    
    PROXY_CONFIG = DEFAULT_PROXY_CONFIG.copy()
    
    # Valid module types
    VALID_MODULE_TYPES = [
        'exploit', 'payload', 'encoder', 'nop', 'auxiliary',
        'post', 'listener', 'browser_exploit', 'browser_auxiliary',
        'workflow', 'backdoor'
    ]
    
    # Global instance
    _instance = None
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration"""
        if config_file is None:
            # Try to find config file
            current_dir = Path.cwd()
            config_file = self._find_config_file(current_dir)
        
        self.config_file = config_file
        self.config: Dict[str, Any] = {}
        self.load_config()
    
    def _find_config_file(self, start_dir: Path) -> str:
        """Find config file in current or parent directories"""
        for directory in [start_dir] + list(start_dir.parents):
            for candidate in ["config.toml", "config/kittysploit.toml", "kittysploit.toml"]:
                config_path = directory / candidate
                if config_path.exists():
                    return str(config_path)
        # Return default path
        return str(start_dir / "config.toml")
    
    def load_config(self):
        """Load configuration from file"""
        if tomllib is None:
            # Use defaults if TOML not available
            self.config = self._get_default_config()
            return
        
        try:
            config_path = Path(self.config_file)
            if not config_path.exists():
                self._create_default_config_file(config_path)
            with open(config_path, 'rb') as f:
                self.config = tomllib.load(f)
        except Exception as e:
            print(f"Warning: Failed to load configuration from {self.config_file}: {e}")
            self.config = self._get_default_config()
        
        # Update class attributes from loaded config
        self._update_class_attributes()

    def _create_default_config_file(self, config_path: Path) -> None:
        """Create default config.toml if it does not exist"""
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write("[FRAMEWORK]\n")
                f.write('prompt = "kittysploit"\n')
                f.write('api_key = ""\n')
        except Exception as e:
            print(f"Warning: Could not create default configuration at {config_path}: {e}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'framework': {
                'version': self.VERSION,
                'workspaces_dir': self.DEFAULT_WORKSPACES_DIR,
                'default_workspace': self.DEFAULT_WORKSPACE,
            },
            'proxy': self.DEFAULT_PROXY_CONFIG.copy()
        }
    
    def _update_class_attributes(self):
        """Update class attributes from loaded config"""
        # Update proxy config
        proxy_config = self.config.get('proxy', {})
        if proxy_config:
            # Merge with defaults to ensure all keys exist
            Config.PROXY_CONFIG = self.DEFAULT_PROXY_CONFIG.copy()
            # Convert empty strings to None for proxy URLs
            for key in ['http_proxy', 'https_proxy', 'socks_proxy']:
                if proxy_config.get(key) == '':
                    proxy_config[key] = None
            Config.PROXY_CONFIG.update(proxy_config)
        
        # Update framework settings
        framework = self.config.get('framework') or self.config.get('FRAMEWORK', {})
        if 'workspaces_dir' in framework:
            Config.DEFAULT_WORKSPACES_DIR = framework['workspaces_dir']
        if 'default_workspace' in framework:
            Config.DEFAULT_WORKSPACE = framework['default_workspace']
    
    def get_config(self) -> Dict[str, Any]:
        """Get full configuration"""
        return self.config
    
    def get_config_value(self, key: str) -> Any:
        """Get configuration value by key"""
        return self.config.get(key)
    
    def get_config_value_by_path(self, path: str) -> Any:
        """Get configuration value by dot-separated path (e.g., 'framework.version')"""
        keys = path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value
    
    @staticmethod
    def validate_module_type(module_type: str) -> bool:
        """Validate if module type is valid"""
        return module_type.lower() in Config.VALID_MODULE_TYPES
    
    @classmethod
    def get_instance(cls) -> 'Config':
        """Get or create global config instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


# Create global instance on import
Config._instance = Config()
    