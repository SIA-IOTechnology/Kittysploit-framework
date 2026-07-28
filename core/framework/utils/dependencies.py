#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Dict, Optional, Set
import subprocess
import sys
import threading
import warnings


class DependencyManager:
    """Manage module dependencies.

    Installed-package discovery is cached process-wide: scanning
    ``metadata.distributions()`` on every module instantiation was ~0.8s+
    and dominated bulk ``scanner -u`` runtime.
    """

    _packages_lock = threading.Lock()
    _cached_packages: Optional[Set[str]] = None

    def __init__(self, *, refresh: bool = False):
        self.installed_packages = self._get_installed_packages(refresh=refresh)

    @classmethod
    def _get_installed_packages(cls, *, refresh: bool = False) -> Set[str]:
        if not refresh and cls._cached_packages is not None:
            return cls._cached_packages
        with cls._packages_lock:
            if not refresh and cls._cached_packages is not None:
                return cls._cached_packages
            packages = cls._discover_installed_packages()
            cls._cached_packages = packages
            return packages

    @classmethod
    def _discover_installed_packages(cls) -> Set[str]:
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
                    return {
                        dist.metadata.get("Name", "").lower()
                        for dist in metadata.distributions()
                        if dist.metadata.get("Name")
                    }
                except (AttributeError, KeyError):
                    pass
        except (ImportError, AttributeError):
            pass

        # Fallback to pkg_resources if importlib.metadata is not available
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore", category=UserWarning, message=".*pkg_resources.*"
                )
                import pkg_resources

                return {pkg.project_name.lower() for pkg in pkg_resources.working_set}
        except ImportError:
            return set()

    @classmethod
    def clear_package_cache(cls) -> None:
        with cls._packages_lock:
            cls._cached_packages = None

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
        internal_modules = ["lib.", "core.", "kittysploit.", "modules."]
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
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dependency])
            self.clear_package_cache()
            self.installed_packages = self._get_installed_packages(refresh=True)
            return True
        except subprocess.CalledProcessError:
            return False
