#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Packaging tool for creating extension bundles (.kext)
"""

import os
import zipfile
import shutil
import tempfile
from typing import List, Optional
from pathlib import Path

from core.registry.manifest import ManifestParser, ExtensionManifest
from core.registry.signature import RegistrySignatureManager
from core.output_handler import print_error, print_warning, print_success, print_info


class ExtensionPackager:
    """Tool to extract and verify extension bundles (read-only)"""
    
    def __init__(self, signature_manager: Optional[RegistrySignatureManager] = None):
        """
        Initialize the packager
        
        Args:
            signature_manager: Signature manager for verification
        """
        self.signature_manager = signature_manager or RegistrySignatureManager()
    
    def extract_bundle(self, bundle_path: str, extract_dir: str) -> bool:
        """
        Extract a bundle
        
        Args:
            bundle_path: Path to bundle
            extract_dir: Destination directory
            
        Returns:
            True if extraction succeeded
        """
        try:
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(bundle_path, 'r') as zipf:
                zipf.extractall(extract_dir)
            
            print_success(f"Bundle extracted to {extract_dir}")
            return True
        except Exception as e:
            print_error(f"Error extracting bundle: {e}")
            return False
    
    def verify_bundle(self, bundle_path: str) -> tuple[bool, Optional[ExtensionManifest]]:
        """
        Verify bundle integrity
        
        Args:
            bundle_path: Path to bundle
            
        Returns:
            (is_valid, manifest)
        """
        try:
            # Extract temporarily
            with tempfile.TemporaryDirectory() as tmpdir:
                with zipfile.ZipFile(bundle_path, 'r') as zipf:
                    zipf.extractall(tmpdir)
                
                # Look for manifest
                manifest_path = os.path.join(tmpdir, "extension.toml")
                if not os.path.exists(manifest_path):
                    print_error("Manifest not found in bundle")
                    return False, None
                
                # Parse manifest
                manifest = ManifestParser.parse(manifest_path)
                if not manifest:
                    print_error("Error parsing manifest")
                    return False, None
                
                # Validate manifest
                is_valid, errors = ManifestParser.validate(manifest)
                if not is_valid:
                    print_error(f"Invalid manifest: {', '.join(errors)}")
                    return False, None
                
                # Verify file hashes
                for rel_path, expected_hash in manifest.payload_hashes.items():
                    file_path = os.path.join(tmpdir, rel_path)
                    if not os.path.exists(file_path):
                        print_warning(f"File missing in bundle: {rel_path}")
                        continue
                    
                    actual_hash = ManifestParser.compute_file_hash(file_path)
                    if actual_hash != expected_hash:
                        print_error(f"Invalid hash for {rel_path}")
                        return False, None
                
                # Verify signature if present
                if manifest.signature and manifest.public_key:
                    manifest_content = open(manifest_path, 'r', encoding='utf-8').read()
                    if not self.signature_manager.verify_signature(
                        manifest_content,
                        manifest.signature,
                        manifest.public_key
                    ):
                        print_error("Invalid signature")
                        return False, None
                
                return True, manifest
                
        except Exception as e:
            print_error(f"Error verifying bundle: {e}")
            return False, None


def generate_python_stub_module(
    *,
    extension_id: str,
    entry_rel_path: str,
    export_symbol: str = "Module",
    version_dir: str = "latest",
    marketplace_id: Optional[str] = None,
) -> str:
    """
    Generate a small "stub" module that dynamically loads the real module code
    from the installed extension directory.
    
    This is useful on Windows where symlinks/junctions can be problematic:
    you keep the real code in `extensions/<id>/<version_dir>/...` and place the stub
    in `modules/...` so the framework can `use auxiliary/test` normally.
    
    Args:
        extension_id: Extension id (folder name under extensions/)
        entry_rel_path: Path inside the extension install dir to the real python file
                        (e.g. "src/modules/auxiliary/test_impl.py")
        export_symbol: Name of the symbol/class to re-export (default: "Module")
        version_dir: "latest" or a concrete version directory
        marketplace_id: Optional marketplace ID for new structure: extensions/{marketplace_id}/{extension_id}/...
    """
    # Normalize to forward slashes for embedding in python source.
    entry_rel_path = (entry_rel_path or "").replace("\\", "/").lstrip("/")
    version_dir = (version_dir or "latest").replace("\\", "/").strip().strip("/")
    if not version_dir:
        version_dir = "latest"
    
    # Generate marketplace ID code for path resolution
    if marketplace_id:
        marketplace_id_str = str(marketplace_id).strip()
        marketplace_code = f'''    # Try new structure first: extensions/{marketplace_id_str}/{extension_id}/{version_dir}/
    for parent in (here.parent, *here.parents):
        candidate = parent / "extensions" / {marketplace_id_str!r} / __extension_id__ / __extension_version_dir__
        if candidate.exists() and candidate.is_dir():
            return candidate
    # Also try from current working directory
    candidate = Path.cwd() / "extensions" / {marketplace_id_str!r} / __extension_id__ / __extension_version_dir__
    if candidate.exists() and candidate.is_dir():
        return candidate
    
    # Fallback to old structure: extensions/{extension_id}/{version_dir}/'''
    else:
        marketplace_code = f'''    # Try old structure: extensions/{extension_id}/{version_dir}/'''
    
    # Keep this code dependency-free (std lib only).
    return f'''# Auto-generated stub module (marketplace extension)
# Extension: {extension_id}
# Entry: {entry_rel_path}
#
# This file is safe to keep in the framework tree. It loads the real code from:
#   extensions/{extension_id}/{version_dir}/{entry_rel_path}
#
# NOTE: Do not edit this file manually; edit the extension source instead.

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


__extension_id__ = {extension_id!r}
__extension_version_dir__ = {version_dir!r}
__extension_entry_rel_path__ = {entry_rel_path!r}


def _find_extension_base() -> Path:
    here = Path(__file__).resolve()
{marketplace_code}
    # Walk upward until we find an `extensions/<id>/<version_dir>/` directory.
    for parent in (here.parent, *here.parents):
        candidate = parent / "extensions" / __extension_id__ / __extension_version_dir__
        if candidate.exists() and candidate.is_dir():
            return candidate
    # Fallback: assume cwd is repo root
    candidate = Path.cwd() / "extensions" / __extension_id__ / __extension_version_dir__
    return candidate


def _load_impl():
    base = _find_extension_base()
    entry = base / __extension_entry_rel_path__
    if not entry.exists():
        raise FileNotFoundError(f"Extension entry file not found: {{entry}}")

    # Make extension importable (helps if the extension uses packages).
    # Add the version directory and its `src` to sys.path (idempotent)
    for p in (base, base / "src"):
        p_str = str(p)
        if p.exists() and p_str not in sys.path:
            sys.path.insert(0, p_str)

    mod_name = f"kittyext_{{__extension_id__}}_{{entry.stem}}"
    spec = importlib.util.spec_from_file_location(mod_name, str(entry))
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load extension module from: {{entry}}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module, entry


_impl, _impl_path = _load_impl()

# Expose source path for tooling (e.g. edit command can follow this).
__source_path__ = str(_impl_path)

# Get the original Module class from the loaded implementation
_OriginalModule = getattr(_impl, {export_symbol!r})

# Define a wrapper class that inherits from the original Module
# This is required for AST validation which checks for class definitions
class {export_symbol}(_OriginalModule):
    """
    Wrapper class for marketplace extension module.
    This class inherits from the extension's Module class to satisfy
    AST validation while maintaining full functionality.
    """
    def run(self):
        """Delegate to parent class run() method"""
        return super().run()
'''
