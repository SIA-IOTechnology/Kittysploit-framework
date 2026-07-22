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
    
    DEFAULT_TOR_CONFIG = {
        'enabled': False,
        'socks_host': '127.0.0.1',
        'socks_port': 9050,
        'control_host': '127.0.0.1',
        'control_port': 9051
    }

    DEFAULT_OBSERVABILITY_CONFIG = {
        'enabled': True,
        'structured_logs': True,
        'metrics_jsonl': True,
        'logs_jsonl': True,
        'dir': '~/.kittysploit/observability',
        'log_level': 'INFO',
        'include_console': False,
    }
    
    PROXY_CONFIG = DEFAULT_PROXY_CONFIG.copy()
    TOR_CONFIG = DEFAULT_TOR_CONFIG.copy()
    
    # Valid module types (canonical DB/search forms; aliases normalized at validation)
    VALID_MODULE_TYPES = [
        'exploit', 'payload', 'encoder', 'nop', 'auxiliary',
        'post', 'listener', 'browser_exploits', 'browser_auxiliary',
        'workflow', 'backdoor'
    ]
    
    # Global instance
    _instance = None
    
    def __init__(self, config_file: Optional[str] = None):
        if config_file is None:
            config_file = self._find_config_file(Path.cwd())

        self.config_file = config_file
        self.config: Dict[str, Any] = {}
        self.load_config()

    @staticmethod
    def default_config_path() -> Path:
        """Preferred user-level config path when none exists yet."""
        return Path.home() / ".kittysploit" / "config.toml"

    def _find_config_file(self, start_dir: Path) -> Optional[str]:
        """Find an existing config file; return None when none is present."""
        env_path = os.environ.get("KITTYSPLOIT_CONFIG")
        if env_path:
            return os.path.expanduser(env_path)

        for directory in [start_dir] + list(start_dir.parents):
            for candidate in ["config.toml", "config/kittysploit.toml", "kittysploit.toml"]:
                config_path = directory / candidate
                try:
                    if config_path.exists():
                        return str(config_path)
                except (PermissionError, OSError):
                    continue

        user_config = self.default_config_path()
        try:
            if user_config.exists():
                return str(user_config)
        except (PermissionError, OSError):
            pass

        return None
    
    def load_config(self):
        if tomllib is None:
            self.config = self._get_default_config()
            self._update_class_attributes()
            return

        if not self.config_file:
            self.config = self._get_default_config()
            self._update_class_attributes()
            return

        try:
            config_path = Path(self.config_file)
            try:
                exists = config_path.exists()
            except (PermissionError, OSError):
                exists = False
            if not exists:
                self.config = self._get_default_config()
                self._update_class_attributes()
                return
            with open(config_path, 'rb') as f:
                self.config = tomllib.load(f)
        except Exception as e:
            print(f"Warning: Failed to load configuration from {self.config_file}: {e}")
            self.config = self._get_default_config()

        self._update_class_attributes()

    def ensure_config_file(self, path: Optional[str] = None) -> str:
        """Create a default config file on disk when explicitly requested."""
        target = Path(path) if path else Path(self.config_file or self.default_config_path())
        if not target.exists():
            self._create_default_config_file(target)
        self.config_file = str(target)
        self.load_config()
        return str(target)

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
        return {
            'framework': {
                'version': self.VERSION,
                'workspaces_dir': self.DEFAULT_WORKSPACES_DIR,
                'default_workspace': self.DEFAULT_WORKSPACE,
            },
            'proxy': self.DEFAULT_PROXY_CONFIG.copy(),
            'tor': self.DEFAULT_TOR_CONFIG.copy(),
            'observability': self.DEFAULT_OBSERVABILITY_CONFIG.copy(),
        }
    
    def _update_class_attributes(self):
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
        return self.config
    
    def get_config_value(self, key: str) -> Any:
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
        """Validate if module type is valid (accepts canonical and legacy aliases)."""
        from core.utils.module_static_metadata import normalize_module_type
        if not module_type:
            return False
        canonical = normalize_module_type(module_type)
        allowed = {normalize_module_type(t) for t in Config.VALID_MODULE_TYPES}
        return canonical in allowed
    
    @classmethod
    def get_instance(cls) -> 'Config':
        """Get or create global config instance (lazy, not on import)."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    