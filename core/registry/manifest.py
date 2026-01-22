#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Parser and manager for extension manifests (extension.toml)
"""

import os
import toml
import hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum


class ExtensionType(Enum):
    """Extension types"""
    MODULE = "module"
    PLUGIN = "plugin"
    UI = "UI"
    MIDDLEWARE = "middleware"


@dataclass
class Compatibility:
    """Compatibility with KittySploit"""
    kittysploit_min: str
    kittysploit_max: Optional[str] = None


@dataclass
class Permissions:
    """Permissions required by the extension"""
    network_access: bool = False
    database_access: bool = False
    sandbox_level: str = "standard"  # permissive, standard, strict, paranoid
    hooks: List[str] = field(default_factory=list)
    events: List[str] = field(default_factory=list)
    middlewares: List[str] = field(default_factory=list)
    allowed_imports: List[str] = field(default_factory=list)
    blocked_imports: List[str] = field(default_factory=list)


@dataclass
class ExtensionManifest:
    """Extension manifest"""
    # Identity
    id: str
    name: str
    version: str
    description: Optional[str] = None
    author: str = ""
    
    # Type and compatibility
    extension_type: ExtensionType = ExtensionType.MODULE
    compatibility: Optional[Compatibility] = None
    
    # Permissions
    permissions: Permissions = field(default_factory=Permissions)
    
    # Security
    payload_hashes: Dict[str, str] = field(default_factory=dict)  # SHA256 of files
    signature: Optional[str] = None  # Manifest signature
    public_key: Optional[str] = None  # Signer's public key
    
    # Metadata
    price: float = 0.0
    currency: str = "USD"
    license: str = "MIT"
    
    # Assets and files
    entry_point: Optional[str] = None  # Main entry point
    assets: List[str] = field(default_factory=list)  # Included files/assets
    install_path: Optional[str] = None  # Installation path relative to framework root (e.g: modules/auxiliary/test_module)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert manifest to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "extension_type": self.extension_type.value,
            "compatibility": {
                "kittysploit_min": self.compatibility.kittysploit_min if self.compatibility else None,
                "kittysploit_max": self.compatibility.kittysploit_max if self.compatibility else None,
            } if self.compatibility else None,
            "permissions": {
                "network_access": self.permissions.network_access,
                "database_access": self.permissions.database_access,
                "sandbox_level": self.permissions.sandbox_level,
                "hooks": self.permissions.hooks,
                "events": self.permissions.events,
                "middlewares": self.permissions.middlewares,
                "allowed_imports": self.permissions.allowed_imports,
                "blocked_imports": self.permissions.blocked_imports,
            },
            "payload_hashes": self.payload_hashes,
            "signature": self.signature,
            "public_key": self.public_key,
            "price": self.price,
            "currency": self.currency,
            "license": self.license,
            "entry_point": self.entry_point,
            "assets": self.assets,
            "install_path": self.install_path,
        }
    
    def to_toml(self) -> str:
        """Convert manifest to TOML"""
        data = self.to_dict()
        # Nettoyer les valeurs None
        cleaned = {}
        for key, value in data.items():
            if value is not None:
                if isinstance(value, dict):
                    cleaned[key] = {k: v for k, v in value.items() if v is not None}
                else:
                    cleaned[key] = value
        
        return toml.dumps(cleaned)


class ManifestParser:
    """TOML manifest parser"""
    
    @staticmethod
    def parse(manifest_path: str) -> Optional[ExtensionManifest]:
        """
        Parse a TOML manifest file
        
        Args:
            manifest_path: Path to extension.toml
            
        Returns:
            ExtensionManifest or None on error
        """
        try:
            if not os.path.exists(manifest_path):
                return None
            
            with open(manifest_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
            
            return ManifestParser._parse_dict(data)
        except Exception as e:
            print(f"Error parsing manifest: {e}")
            return None
    
    @staticmethod
    def parse_string(manifest_content: str) -> Optional[ExtensionManifest]:
        """
        Parse a manifest from a TOML string
        
        Args:
            manifest_content: TOML content of the manifest
            
        Returns:
            ExtensionManifest or None on error
        """
        try:
            data = toml.loads(manifest_content)
            return ManifestParser._parse_dict(data)
        except Exception as e:
            print(f"Error parsing manifest: {e}")
            return None
    
    @staticmethod
    def _parse_dict(data: Dict[str, Any]) -> ExtensionManifest:
        """Parse a dictionary into ExtensionManifest"""
        # Compatibility
        compatibility = None
        if "compatibility" in data:
            comp_data = data["compatibility"]
            compatibility = Compatibility(
                kittysploit_min=comp_data.get("kittysploit_min", "0.0.0"),
                kittysploit_max=comp_data.get("kittysploit_max")
            )
        
        # Permissions
        permissions_data = data.get("permissions", {})
        permissions = Permissions(
            network_access=permissions_data.get("network_access", False),
            database_access=permissions_data.get("database_access", False),
            sandbox_level=permissions_data.get("sandbox_level", "standard"),
            hooks=permissions_data.get("hooks", []),
            events=permissions_data.get("events", []),
            middlewares=permissions_data.get("middlewares", []),
            allowed_imports=permissions_data.get("allowed_imports", []),
            blocked_imports=permissions_data.get("blocked_imports", []),
        )
        
        # Extension type
        ext_type_str = data.get("extension_type", "module")
        try:
            ext_type = ExtensionType(ext_type_str)
        except ValueError:
            ext_type = ExtensionType.MODULE
        
        # Metadata section (can be nested or at root level)
        metadata = data.get("metadata", {})
        
        # Get fields from metadata section or root level (for backward compatibility)
        price = float(metadata.get("price", data.get("price", 0.0)))
        currency = metadata.get("currency", data.get("currency", "USD"))
        license = metadata.get("license", data.get("license", "MIT"))
        entry_point = metadata.get("entry_point", data.get("entry_point"))
        assets = metadata.get("assets", data.get("assets", []))
        install_path = metadata.get("install_path", data.get("install_path"))
        
        return ExtensionManifest(
            id=data["id"],
            name=data["name"],
            version=data["version"],
            description=data.get("description"),
            author=data.get("author", ""),
            extension_type=ext_type,
            compatibility=compatibility,
            permissions=permissions,
            payload_hashes=data.get("payload_hashes", {}),
            signature=data.get("signature"),
            public_key=data.get("public_key"),
            price=price,
            currency=currency,
            license=license,
            entry_point=entry_point,
            assets=assets,
            install_path=install_path,
        )
    
    @staticmethod
    def validate(manifest: ExtensionManifest) -> tuple[bool, List[str]]:
        """
        Validate a manifest
        
        Returns:
            (is_valid, list_of_errors)
        """
        errors = []
        
        # Check required fields
        if not manifest.id:
            errors.append("Field 'id' is required")
        if not manifest.name:
            errors.append("Field 'name' is required")
        if not manifest.version:
            errors.append("Field 'version' is required")
        
        # Validate version format (semver)
        if manifest.version and not ManifestParser._is_semver(manifest.version):
            errors.append(f"Invalid version (semver format expected): {manifest.version}")
        
        # Validate compatibility
        if manifest.compatibility:
            if not manifest.compatibility.kittysploit_min:
                errors.append("kittysploit_min is required in compatibility")
        
        # Validate sandbox level
        valid_sandbox_levels = ["permissive", "standard", "strict", "paranoid"]
        if manifest.permissions.sandbox_level not in valid_sandbox_levels:
            errors.append(f"Invalid sandbox_level: {manifest.permissions.sandbox_level}")
        
        # Validate install_path according to extension type
        if manifest.extension_type.value.lower() in ['ui', 'interface']:
            # UI interfaces must NOT have install_path
            if manifest.install_path:
                errors.append(f"install_path must not be defined for UI interfaces (received: {manifest.install_path})")
        elif manifest.install_path:
            # For modules/plugins, install_path is required and must be valid
            # Normalize path (use slashes)
            normalized_path = manifest.install_path.replace("\\", "/").strip()
            
            # Check that path starts with modules/ or plugins/
            if not (normalized_path.startswith("modules/") or normalized_path.startswith("plugins/")):
                errors.append(f"Invalid install_path: must start with 'modules/' or 'plugins/' (received: {manifest.install_path})")
            
            # Check for path traversal attempts
            if ".." in normalized_path:
                errors.append(f"Invalid install_path: cannot contain '..' (received: {manifest.install_path})")
            
            # Check for absolute paths
            if os.path.isabs(normalized_path):
                errors.append(f"Invalid install_path: must be a relative path (received: {manifest.install_path})")
        elif manifest.extension_type.value.lower() in ['module', 'plugin']:
            # Modules and plugins MUST have an install_path
            errors.append("install_path is required for modules and plugins")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def _is_semver(version: str) -> bool:
        """Check if a version follows semver format"""
        import re
        semver_pattern = r'^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?(\+[a-zA-Z0-9]+)?$'
        return bool(re.match(semver_pattern, version))
    
    @staticmethod
    def compute_bundle_hash(bundle_path: str) -> str:
        """
        Calculate SHA256 hash of a bundle
        
        Args:
            bundle_path: Path to bundle (.kext or .zip)
            
        Returns:
            SHA256 hash in hexadecimal
        """
        sha256 = hashlib.sha256()
        with open(bundle_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def compute_file_hash(file_path: str) -> str:
        """
        Calculate SHA256 hash of a file
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA256 hash in hexadecimal
        """
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            sha256.update(f.read())
        return sha256.hexdigest()

