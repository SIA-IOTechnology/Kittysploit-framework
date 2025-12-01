#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Dict, Optional
import importlib
import subprocess
import sys
import warnings

class DependencyManager:
    """Manage module dependencies"""
    
    def __init__(self):
        self.installed_packages = set()
        self._check_installed_packages()
    
    def _check_installed_packages(self):
        """Check installed packages"""
        try:
            # Try to use importlib.metadata (Python 3.8+) first
            try:
                from importlib import metadata
            except ImportError:
                # Fallback for Python < 3.8
                try:
                    import importlib_metadata as metadata
                except ImportError:
                    metadata = None
            
            if metadata:
                try:
                    self.installed_packages = {
                        dist.metadata.get('Name', '').lower() 
                        for dist in metadata.distributions()
                        if dist.metadata.get('Name')
                    }
                    return
                except (AttributeError, KeyError):
                    pass
        except (ImportError, AttributeError):
            pass
        
        # Fallback to pkg_resources if importlib.metadata is not available
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings('ignore', category=UserWarning, message='.*pkg_resources.*')
                import pkg_resources
                self.installed_packages = {pkg.project_name.lower() for pkg in pkg_resources.working_set}
        except ImportError:
            pass
    
    def check_dependencies(self, dependencies: List[str], optional: bool = False) -> Dict[str, bool]:
        """Check if dependencies are installed"""
        results = {}
        for dep in dependencies:
            # Parse dependency (e.g., "requests>=2.28.0" or "requests")
            package_name = dep.split(">=")[0].split("==")[0].strip()
            results[dep] = self._is_installed(package_name)
        
        missing = [dep for dep, installed in results.items() if not installed]
        if missing and not optional:
            raise ImportError(f"Missing required dependencies: {', '.join(missing)}")
        
        return results
    
    def _is_installed(self, package_name: str) -> bool:
        """Check if package is installed"""
        # Skip internal framework modules - these are not external dependencies
        internal_modules = ['lib.', 'core.', 'kittysploit.', 'modules.']
        if any(package_name.startswith(prefix) for prefix in internal_modules):
            # Try to import it - if it works, it's available (internal module)
            try:
                __import__(package_name.replace("-", "_"))
                return True
            except ImportError:
                # Internal module not found - this is an error in the framework
                return False
        
        # For external packages, check if they can be imported
        try:
            __import__(package_name.replace("-", "_"))
            return True
        except ImportError:
            return package_name.lower() in self.installed_packages
    
    def install_dependency(self, dependency: str) -> bool:
        """Install a dependency"""
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dependency])
            return True
        except subprocess.CalledProcessError:
            return False