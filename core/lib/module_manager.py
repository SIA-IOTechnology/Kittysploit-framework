#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Manager for KittySploit Library Interface
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from core.module_loader import ModuleLoader

class ModuleManager:
    
    def __init__(self, modules_path: str = None):
        """
        Initialize the module manager
        
        Args:
            modules_path: Path to modules directory. If None, uses default.
        """
        if modules_path is None:
            # Get the path relative to this file
            current_dir = Path(__file__).parent.parent
            modules_path = str(current_dir / "modules")
        
        self.modules_path = modules_path
        self.module_loader = ModuleLoader(modules_path)
        self._modules_cache = {}
        self._discovered_modules = None
    
    def discover_modules(self) -> Dict[str, str]:
        if self._discovered_modules is None:
            self._discovered_modules = self.module_loader.discover_modules()
        return self._discovered_modules
    
    def get_modules_by_type(self, module_type: str) -> Dict[str, Any]:
        return self.module_loader.get_modules_by_type(module_type)
    
    def get_exploits(self) -> Dict[str, Any]:
        return self.get_modules_by_type("exploit")
    
    def get_auxiliary(self) -> Dict[str, Any]:
        return self.get_modules_by_type("auxiliary")
    
    def get_payloads(self) -> Dict[str, Any]:
        return self.get_modules_by_type("payload")
    
    def get_listeners(self) -> Dict[str, Any]:
        return self.get_modules_by_type("listener")

    def get_transforms(self) -> Dict[str, Any]:
        return self.get_modules_by_type("transform")

    def get_obfuscators(self) -> Dict[str, Any]:
        """Deprecated alias for get_transforms()."""
        return self.get_transforms()
    
    def get_environments(self) -> Dict[str, Any]:
        return self.get_modules_by_type("environment")
    
    def get_browser_auxiliary(self) -> Dict[str, Any]:
        return self.get_modules_by_type("browser_auxiliary")
    
    def get_browser_exploits(self) -> Dict[str, Any]:
        return self.get_modules_by_type("browser_exploit")
    
    def load_module(self, module_path: str) -> Optional[Any]:
        if module_path not in self._modules_cache:
            module = self.module_loader.load_module(module_path, load_only=True)
            if module:
                self._modules_cache[module_path] = module
        return self._modules_cache.get(module_path)
    
    def get_module_info(self, module_path: str) -> Optional[Dict[str, Any]]:
        return self.module_loader.get_module_info(module_path)
    
    def search_modules(self, query: str = "", module_type: str = "", 
                      author: str = "", cve: str = "", limit: int = 100) -> List[Dict]:
        return self.module_loader.search_modules_db(
            query, module_type, author, cve, tags="", limit=limit
        )
    
    def get_all_modules(self) -> Dict[str, Any]:
        all_modules = {}
        
        # Get modules by type
        module_types = [
            "exploit", "auxiliary", "payload", "listener", 
            "transform", "environment", "browser_auxiliary", "browser_exploit"
        ]
        
        for module_type in module_types:
            modules = self.get_modules_by_type(module_type)
            if modules:
                all_modules[module_type] = modules
        
        return all_modules
    
    def get_module_stats(self) -> Dict[str, int]:
        stats = {}
        all_modules = self.get_all_modules()
        
        for module_type, modules in all_modules.items():
            stats[module_type] = len(modules)
        
        stats['total'] = sum(stats.values())
        return stats
    
    def list_module_paths(self) -> List[str]:
        discovered = self.discover_modules()
        return list(discovered.keys())
    
    def __repr__(self) -> str:
        """String representation of the module manager"""
        stats = self.get_module_stats()
        return f"ModuleManager(modules={stats['total']}, types={list(stats.keys())})"
    
    def __str__(self) -> str:
        stats = self.get_module_stats()
        output = ["ModuleManager Statistics:"]
        for module_type, count in stats.items():
            if module_type != 'total':
                output.append(f"  {module_type}: {count}")
        output.append(f"  Total: {stats['total']}")
        return "\n".join(output)
