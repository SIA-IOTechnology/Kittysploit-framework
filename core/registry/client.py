#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Marketplace Client - Client to interact with the registry
"""

import os
import shutil
import zipfile
import tempfile
from typing import Optional, Dict, List, Any
import requests

try:
    from core.registry.manifest import ManifestParser, ExtensionManifest
    from core.registry.signature import RegistrySignatureManager
    REGISTRY_AVAILABLE = True
except ImportError as e:
    REGISTRY_AVAILABLE = False
    REGISTRY_IMPORT_ERROR = str(e)

from core.output_handler import print_error, print_warning, print_success, print_info


class ExtensionClient:
    """Client for the extensions marketplace"""
    
    def __init__(
        self,
        registry_url: Optional[str] = None,
        extensions_dir: str = "extensions",
        signature_manager: Optional[RegistrySignatureManager] = None
    ):
        """
        Initialize the marketplace client
        
        Args:
            registry_url: Remote registry server URL (default: from config or registry.kittysploit.com)
            extensions_dir: Local directory to install extensions
            signature_manager: Signature manager
        """
        if not REGISTRY_AVAILABLE:
            raise ImportError(f"Registry marketplace not available: {REGISTRY_IMPORT_ERROR}")
        
        # Remote registry URL (centralized KittySploit service)
        if registry_url is None:
            # Try to load from config
            try:
                from core.config import Config
                config = Config.get_instance()
                registry_url = config.get_config_value_by_path('registry.url')
            except:
                pass
            
            # Default: centralized KittySploit service
            if not registry_url:
                registry_url = "https://registry.kittysploit.com"
        
        self.registry_url = registry_url.rstrip('/')
        
        # Ensure extensions_dir is absolute and at framework root
        if not os.path.isabs(extensions_dir):
            # Try to find framework root (where core/ directory is)
            import sys
            framework_root = None
            for path in sys.path:
                if os.path.exists(os.path.join(path, 'core', '__init__.py' if os.path.exists(os.path.join(path, 'core', '__init__.py')) else 'config.py')):
                    framework_root = path
                    break
            
            if framework_root:
                self.extensions_dir = os.path.join(framework_root, extensions_dir)
            else:
                # Fallback: use current working directory
                self.extensions_dir = os.path.abspath(extensions_dir)
        else:
            self.extensions_dir = extensions_dir
        
        try:
            self.signature_manager = signature_manager or RegistrySignatureManager()
        except Exception as e:
            print_warning(f"Could not initialize signature manager: {e}")
            self.signature_manager = None
        
        # Create extensions directory if it doesn't exist
        os.makedirs(self.extensions_dir, exist_ok=True)
        print_info(f"Extensions directory: {self.extensions_dir}")
    
    def list_extensions(
        self,
        extension_type: Optional[str] = None,
        is_free: Optional[bool] = None,
        search: Optional[str] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Dict[str, Any]:
        """
        List available extensions
        
        Returns:
            Dict with extensions and pagination metadata
        """
        try:
            params = {
                "page": page,
                "per_page": per_page
            }
            if extension_type:
                params["type"] = extension_type
            if is_free is not None:
                params["is_free"] = is_free
            if search:
                params["search"] = search
            
            response = requests.get(
                f"{self.registry_url}/api/registry/extensions",
                params=params,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError:
            print_error(f"Could not connect to registry server at {self.registry_url}")
            print_warning("Make sure the API server is running (kittyapi.py)")
            return {"extensions": [], "total": 0, "page": 1, "per_page": per_page}
        except requests.exceptions.Timeout:
            print_error("Request to registry server timed out")
            return {"extensions": [], "total": 0, "page": 1, "per_page": per_page}
        except Exception as e:
            print_error(f"Error retrieving extension list: {e}")
            return {"extensions": [], "total": 0, "page": 1, "per_page": per_page}
    
    def get_extension(self, extension_id: str) -> Optional[Dict[str, Any]]:
        """Get extension details"""
        try:
            response = requests.get(
                f"{self.registry_url}/api/registry/extensions/{extension_id}",
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print_error(f"Error retrieving extension: {e}")
            return None
    
    def install_extension(
        self,
        extension_id: str,
        version: Optional[str] = None,
        user_id: Optional[str] = None,
        verify_signature: bool = True
    ) -> bool:
        """
        Install an extension
        
        Args:
            extension_id: Extension ID
            version: Specific version (None for latest)
            user_id: User ID (to verify license)
            verify_signature: Verify signature before installation
            
        Returns:
            True if installation succeeded
        """
        try:
            print_info(f"Installing extension {extension_id}...")
            
            # Download bundle - try new API endpoint first, fallback to old
            params = {}
            if version:
                params["version"] = version
            
            # Try new API endpoint first: /api/cli/market/download/{id}
            url = f"{self.registry_url}/api/cli/market/download/{extension_id}"
            headers = {}
            
            # Add authentication if available (for paid modules)
            # Try Bearer token first (new API), then API key (old API)
            token = None
            api_key = None
            
            try:
                # Try to load token from registry config (same as market command)
                config_dir = os.path.join(os.path.expanduser("~"), ".kittysploit")
                config_file = os.path.join(config_dir, "registry_config.json")
                if os.path.exists(config_file):
                    import json
                    with open(config_file, 'r') as f:
                        registry_config = json.load(f)
                        token = registry_config.get('token')
                        api_key = registry_config.get('api_key')  # Fallback
            except:
                pass
            
            # Also try from environment/config
            if not token and not api_key:
                try:
                    from core.config import Config
                    config = Config.get_instance()
                    api_key = config.get_config_value_by_path('framework.api_key') or os.environ.get('KITTYSPLOIT_API_KEY')
                except:
                    pass
            
            # Set authentication header (prefer Bearer token for new API)
            if token:
                headers['Authorization'] = f'Bearer {token}'
            elif api_key:
                headers['X-API-Key'] = api_key
            
            try:
                response = requests.get(url, headers=headers, params=params, stream=True, timeout=30)
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    # Fallback to old endpoint
                    url = f"{self.registry_url}/api/registry/extensions/{extension_id}/download"
                    response = requests.get(url, headers=headers, params=params, stream=True, timeout=30)
                    response.raise_for_status()
                else:
                    raise
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.kext') as tmp_file:
                tmp_path = tmp_file.name
                for chunk in response.iter_content(chunk_size=8192):
                    tmp_file.write(chunk)
            
            # Extract to temporary directory first to read manifest
            temp_extract_dir = tempfile.mkdtemp()
            
            # Extract bundle to temporary directory
            if tmp_path.endswith('.zip') or tmp_path.endswith('.kext'):
                with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_extract_dir)
            
            # Look for manifest in temporary directory
            manifest_path = os.path.join(temp_extract_dir, "extension.toml")
            if not os.path.exists(manifest_path):
                print_error("Manifest extension.toml not found in bundle")
                shutil.rmtree(temp_extract_dir, ignore_errors=True)
                os.remove(tmp_path)
                return False
            
            # Parse manifest
            manifest = ManifestParser.parse(manifest_path)
            if not manifest:
                print_error("Error parsing manifest")
                shutil.rmtree(temp_extract_dir, ignore_errors=True)
                os.remove(tmp_path)
                return False
            
            # Validate manifest
            is_valid, errors = ManifestParser.validate(manifest)
            if not is_valid:
                print_error(f"Invalid manifest: {', '.join(errors)}")
                shutil.rmtree(temp_extract_dir, ignore_errors=True)
                os.remove(tmp_path)
                return False
            
            # Use marketplace ID as first level, manifest ID as second level
            # Structure: extensions/{marketplace_id}/{manifest_id}/latest/
            # This allows multiple installations of same manifest from different marketplaces
            manifest_id = manifest.id
            marketplace_id = extension_id  # The ID used to download (marketplace ID)
            
            if manifest_id != marketplace_id:
                print_info(f"Installing extension: marketplace ID '{marketplace_id}', manifest ID '{manifest_id}'")
            
            # Determine final extract directory: extensions/{marketplace_id}/{manifest_id}/latest/
            extract_dir = os.path.join(self.extensions_dir, marketplace_id, manifest_id)
            if version:
                extract_dir = os.path.join(extract_dir, version)
            else:
                extract_dir = os.path.join(extract_dir, "latest")
            
            # Move from temp directory to final location
            os.makedirs(extract_dir, exist_ok=True)
            
            # If target directory already exists, remove it first
            if os.path.exists(extract_dir) and os.listdir(extract_dir):
                print_warning(f"Extension directory already exists: {extract_dir}")
                print_info("Removing existing installation...")
                shutil.rmtree(extract_dir)
                os.makedirs(extract_dir, exist_ok=True)
            
            # Move all files from temp to final location
            for item in os.listdir(temp_extract_dir):
                src = os.path.join(temp_extract_dir, item)
                dst = os.path.join(extract_dir, item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(src, dst)
            
            # Clean up temp directory
            shutil.rmtree(temp_extract_dir, ignore_errors=True)
            
            # Update manifest_path to final location
            manifest_path = os.path.join(extract_dir, "extension.toml")
            
            # Verify signature if requested
            if verify_signature and manifest.signature and manifest.public_key:
                manifest_content = open(manifest_path, 'r', encoding='utf-8').read()
                if not self.signature_manager.verify_signature(
                    manifest_content,
                    manifest.signature,
                    manifest.public_key
                ):
                    print_error("Invalid signature - installation refused")
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
            
            # Check compatibility with KittySploit
            from core.config import Config
            try:
                kittysploit_version = Config.VERSION
                if manifest.compatibility:
                    from packaging import version as pkg_version
                    min_version = manifest.compatibility.kittysploit_min
                    max_version = manifest.compatibility.kittysploit_max
                    
                    if pkg_version.parse(kittysploit_version) < pkg_version.parse(min_version):
                        print_error(f"KittySploit version {kittysploit_version} < {min_version} required")
                        shutil.rmtree(extract_dir, ignore_errors=True)
                        os.remove(tmp_path)
                        return False
                    
                    # "*" means no maximum version limit
                    if max_version and max_version != "*":
                        if pkg_version.parse(kittysploit_version) > pkg_version.parse(max_version):
                            print_warning(f"KittySploit version {kittysploit_version} > {max_version} supported")
            except Exception as e:
                print_warning(f"Unable to verify compatibility: {e}")
            
            # Generate sandbox profile from manifest permissions
            sandbox_config = self._generate_sandbox_config(manifest)
            
            # Validate with PolicyEngine if available (skip for UI/INTERFACE types)
            extension_type = manifest.extension_type.value.lower() if hasattr(manifest.extension_type, 'value') else str(manifest.extension_type).lower()
            
            # Skip PolicyEngine validation for UI/INTERFACE types (they don't have Module class)
            if extension_type not in ['ui', 'interface']:
                try:
                    from core.framework.utils.policy_engine import PolicyEngine, PolicyLevel
                    
                    # Determine policy level
                    policy_level_map = {
                        "permissive": PolicyLevel.PERMISSIVE,
                        "standard": PolicyLevel.STANDARD,
                        "strict": PolicyLevel.STRICT,
                        "paranoid": PolicyLevel.PARANOID
                    }
                    policy_level = policy_level_map.get(
                        manifest.permissions.sandbox_level,
                        PolicyLevel.STANDARD
                    )
                    
                    # Create PolicyEngine
                    policy_engine = PolicyEngine(policy_level=policy_level)
                    
                    # Read main code if entry_point is defined
                    if manifest.entry_point:
                        entry_file = os.path.join(extract_dir, manifest.entry_point)
                        if os.path.exists(entry_file):
                            with open(entry_file, 'r', encoding='utf-8') as f:
                                entry_code = f.read()
                            
                            # Validate with PolicyEngine
                            validation_result = policy_engine.validate_module(
                                module_path=f"extensions/{extension_id}/{manifest.entry_point}",
                                module_code=entry_code,
                                require_approval=False,  # Auto-approval for signed extensions
                                enable_sandbox=(policy_level in [PolicyLevel.STRICT, PolicyLevel.PARANOID])
                            )
                            
                            if not validation_result.get("valid", True):
                                print_warning("PolicyEngine validation warnings:")
                                for warning in validation_result.get("warnings", []):
                                    print_warning(f"  - {warning}")
                                
                                if validation_result.get("errors"):
                                    print_error("PolicyEngine validation errors:")
                                    for error in validation_result.get("errors", []):
                                        print_error(f"  - {error}")
                                    # Don't block, but warn
                except ImportError:
                    print_warning("PolicyEngine not available - sandbox validation ignored")
                except Exception as e:
                    print_warning(f"Error during PolicyEngine validation: {e}")
            else:
                # For UI/INTERFACE types, just log that validation is skipped
                print_info("UI interface detected - PolicyEngine validation ignored (no Module class required)")
            
            # Save sandbox configuration
            sandbox_config_path = os.path.join(extract_dir, ".sandbox_config.json")
            try:
                import json
                with open(sandbox_config_path, 'w') as f:
                    json.dump(sandbox_config, f, indent=2)
            except Exception as e:
                print_warning(f"Unable to save sandbox config: {e}")
            
            # Register hooks/events/middlewares if declared
            self._register_extension_components(manifest, extract_dir)
            
            # Create stubs/links according to extension type
            # Pass marketplace_id so launcher can find extension in new structure
            stub_created = self._create_stub_files(manifest, extract_dir, version or "latest", marketplace_id=marketplace_id)
            if not stub_created:
                print_warning("Unable to create stubs - extension may not be accessible")
            
            # Installation successful
            os.remove(tmp_path)
            print_success(f"Extension {manifest_id} v{manifest.version} installed successfully")
            return True
            
        except Exception as e:
            print_error(f"Error during installation: {e}")
            return False
    
    def update_extension(self, extension_id: str, version: Optional[str] = None) -> bool:
        """Update an extension to a newer version"""
        # Uninstall old version
        old_dir = os.path.join(self.extensions_dir, extension_id)
        if os.path.exists(old_dir):
            shutil.rmtree(old_dir, ignore_errors=True)
        
        # Install new version
        return self.install_extension(extension_id, version=version)
    
    def remove_extension(self, extension_id: str) -> bool:
        """Remove an installed extension (can use marketplace ID or manifest ID)"""
        try:
            # New structure: extensions/{marketplace_id}/{manifest_id}/latest/
            # Old structure: extensions/{manifest_id}/latest/ (for backward compatibility)
            
            # First, try direct lookup by extension_id as marketplace ID (new structure)
            marketplace_dir = os.path.join(self.extensions_dir, extension_id)
            ext_dir = None
            manifest = None
            
            if os.path.exists(marketplace_dir):
                # New structure: extensions/{marketplace_id}/{manifest_id}/latest/
                # Find manifest_id subdirectory
                for item in os.listdir(marketplace_dir):
                    item_path = os.path.join(marketplace_dir, item)
                    if not os.path.isdir(item_path):
                        continue
                    
                    # Check for latest/ or version directory
                    latest_path = os.path.join(item_path, "latest")
                    if os.path.exists(latest_path):
                        item_path = latest_path
                    
                    manifest_path = os.path.join(item_path, "extension.toml")
                    if os.path.exists(manifest_path):
                        try:
                            manifest = ManifestParser.parse(manifest_path)
                            if manifest:
                                ext_dir = item_path
                                break
                        except:
                            continue
            
            # If not found, try as manifest ID (old structure or search in new structure)
            if not ext_dir and os.path.exists(self.extensions_dir):
                # Search through all installed extensions
                for marketplace_id in os.listdir(self.extensions_dir):
                    marketplace_path = os.path.join(self.extensions_dir, marketplace_id)
                    if not os.path.isdir(marketplace_path):
                        continue
                    
                    # Check if old structure (marketplace_id == manifest_id)
                    if marketplace_id == extension_id:
                        # Old structure: extensions/{manifest_id}/latest/
                        ext_dir = marketplace_path
                        manifest_path = None
                        for root, dirs, files in os.walk(marketplace_path):
                            if "extension.toml" in files:
                                manifest_path = os.path.join(root, "extension.toml")
                                break
                        if manifest_path:
                            manifest = ManifestParser.parse(manifest_path)
                        break
                    else:
                        # New structure: search for manifest_id
                        for item in os.listdir(marketplace_path):
                            item_path = os.path.join(marketplace_path, item)
                            if not os.path.isdir(item_path):
                                continue
                            
                            latest_path = os.path.join(item_path, "latest")
                            if os.path.exists(latest_path):
                                item_path = latest_path
                            
                            manifest_path = os.path.join(item_path, "extension.toml")
                            if os.path.exists(manifest_path):
                                try:
                                    test_manifest = ManifestParser.parse(manifest_path)
                                    if test_manifest and test_manifest.id == extension_id:
                                        ext_dir = item_path
                                        manifest = test_manifest
                                        break
                                except:
                                    continue
                        if ext_dir:
                            break
            
            if not ext_dir or not os.path.exists(ext_dir):
                print_warning(f"Extension {extension_id} not found")
                return False
            
            if manifest:
                # Remove stubs according to type
                self._remove_stub_files(manifest)
                display_id = manifest.id
            else:
                display_id = extension_id
            
            # Remove extension directory
            # For new structure, remove the entire marketplace_id/manifest_id/ directory
            # For old structure, remove the manifest_id/ directory
            if os.path.basename(os.path.dirname(ext_dir)) == extension_id:
                # New structure: remove extensions/{marketplace_id}/{manifest_id}/
                shutil.rmtree(os.path.dirname(ext_dir), ignore_errors=True)
                # Also remove marketplace_id directory if empty
                marketplace_parent = os.path.dirname(os.path.dirname(ext_dir))
                if os.path.exists(marketplace_parent) and not os.listdir(marketplace_parent):
                    os.rmdir(marketplace_parent)
            else:
                # Old structure or direct removal
                shutil.rmtree(ext_dir, ignore_errors=True)
            
            print_success(f"Extension {display_id} removed")
            return True
        except Exception as e:
            print_error(f"Error during removal: {e}")
            return False
    
    def list_installed_extensions(self) -> List[Dict[str, Any]]:
        """List locally installed extensions"""
        installed = []
        
        if not os.path.exists(self.extensions_dir):
            return installed
        
        # New structure: extensions/{marketplace_id}/{manifest_id}/latest/
        # Also support old structure: extensions/{manifest_id}/latest/ for backward compatibility
        for marketplace_id in os.listdir(self.extensions_dir):
            marketplace_path = os.path.join(self.extensions_dir, marketplace_id)
            if not os.path.isdir(marketplace_path):
                continue
            
            # Check if this is new structure (marketplace_id/manifest_id/latest/) or old (manifest_id/latest/)
            for item in os.listdir(marketplace_path):
                item_path = os.path.join(marketplace_path, item)
                if not os.path.isdir(item_path):
                    continue
                
                # Look for latest/ or version directory
                version_dirs = ['latest']
                if os.path.isdir(item_path):
                    # Check if item is a version directory or if it contains latest/
                    if item not in version_dirs:
                        latest_path = os.path.join(item_path, "latest")
                        if os.path.exists(latest_path):
                            item_path = latest_path
                        else:
                            # Might be a version directory directly
                            version_dirs.append(item)
                
                # Look for manifest
                manifest_path = os.path.join(item_path, "extension.toml")
                if not os.path.exists(manifest_path):
                    # Try searching in subdirectories
                    for root, dirs, files in os.walk(item_path):
                        if "extension.toml" in files:
                            manifest_path = os.path.join(root, "extension.toml")
                            break
                
                if os.path.exists(manifest_path):
                    manifest = ManifestParser.parse(manifest_path)
                    if manifest:
                        # Determine if this is new structure or old
                        # If marketplace_id == manifest.id, it's old structure
                        if marketplace_id == manifest.id:
                            # Old structure: extensions/{manifest_id}/latest/
                            installed.append({
                                "id": manifest.id,
                                "name": manifest.name,
                                "version": manifest.version,
                                "type": manifest.extension_type.value,
                                "path": marketplace_path,  # extensions/{manifest_id}
                                "marketplace_id": None,  # Unknown in old structure
                                "directory_id": marketplace_id
                            })
                        else:
                            # New structure: extensions/{marketplace_id}/{manifest_id}/latest/
                            installed.append({
                                "id": manifest.id,  # Manifest ID (canonical)
                                "name": manifest.name,
                                "version": manifest.version,
                                "type": manifest.extension_type.value,
                                "path": item_path,  # extensions/{marketplace_id}/{manifest_id}/latest/
                                "marketplace_id": marketplace_id,  # Marketplace ID
                                "directory_id": marketplace_id  # For backward compatibility
                            })
        
        return installed
    
    def purchase_extension(self, extension_id: str, user_id: str, version: Optional[str] = None) -> bool:
        """Purchase a paid extension"""
        try:
            data = {}
            if version:
                data["version"] = version
            
            response = requests.post(
                f"{self.registry_url}/api/registry/extensions/{extension_id}/purchase",
                json={"user_id": user_id, **data},
                timeout=10
            )
            response.raise_for_status()
            
            result = response.json()
            if result.get("success"):
                print_success(f"Extension {extension_id} purchased successfully")
                return True
            else:
                print_error(result.get("error", "Unknown error"))
                return False
        except Exception as e:
            print_error(f"Error during purchase: {e}")
            return False
    
    def _generate_sandbox_config(self, manifest) -> Dict[str, Any]:
        """
        Generate a sandbox configuration from the manifest
        
        Args:
            manifest: ExtensionManifest
            
        Returns:
            Dict of sandbox configuration
        """
        config = {
            "allowed_imports": manifest.permissions.allowed_imports,
            "blocked_imports": manifest.permissions.blocked_imports,
            "sandbox_level": manifest.permissions.sandbox_level,
            "network_access": manifest.permissions.network_access,
            "database_access": manifest.permissions.database_access,
        }
        
        # Add restrictions according to level
        if manifest.permissions.sandbox_level == "strict":
            config["max_cpu_percent"] = 80.0
            config["max_memory_mb"] = 512
            config["max_execution_time"] = 300
        elif manifest.permissions.sandbox_level == "paranoid":
            config["max_cpu_percent"] = 50.0
            config["max_memory_mb"] = 256
            config["max_execution_time"] = 180
        
        return config
    
    def _register_extension_components(self, manifest, extract_dir: str):
        """
        Register hooks/events/middlewares declared in the manifest
        
        Args:
            manifest: ExtensionManifest
            extract_dir: Extension extraction directory
        """
        try:
            # This function will be called during framework loading
            # to automatically register declared components
            
            # Create a metadata file for automatic loading
            metadata_path = os.path.join(extract_dir, ".extension_metadata.json")
            import json
            
            metadata = {
                "id": manifest.id,
                "version": manifest.version,
                "type": manifest.extension_type.value,
                "entry_point": manifest.entry_point,
                "hooks": manifest.permissions.hooks,
                "events": manifest.permissions.events,
                "middlewares": manifest.permissions.middlewares,
                "sandbox_config": self._generate_sandbox_config(manifest)
            }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print_info(f"Components registered: {len(manifest.permissions.hooks)} hooks, "
                      f"{len(manifest.permissions.events)} events, "
                      f"{len(manifest.permissions.middlewares)} middlewares")
        except Exception as e:
            print_warning(f"Error during component registration: {e}")
    
    def _create_stub_files(self, manifest, extract_dir: str, version_dir: str, marketplace_id: Optional[str] = None) -> bool:
        """
        Create stub files according to extension type
        
        Args:
            manifest: ExtensionManifest
            extract_dir: Extension extraction directory
            version_dir: Version directory name (e.g. "latest" or "1.0.0")
            marketplace_id: Marketplace ID (for new structure: extensions/{marketplace_id}/{manifest_id}/latest/)
            
        Returns:
            True if stubs were created successfully
        """
        try:
            from core.registry.packaging import generate_python_stub_module
            
            extension_type = manifest.extension_type.value.lower()
            
            # MODULE or PLUGIN type
            if extension_type in ['module', 'plugin']:
                # Check that install_path and entry_point are defined
                if not manifest.install_path:
                    print_warning(f"install_path not defined in manifest - module not installed")
                    return False
                
                if not manifest.entry_point:
                    print_warning(f"entry_point not defined in manifest - module not installed")
                    return False
                
                # Normalize install_path (modules/exploits/test_module.py or modules/exploits/test_module/)
                install_path = manifest.install_path.replace("\\", "/").strip()
                
                # Determine target path
                # If install_path ends with .py, it's the complete target path
                # Otherwise, it's a folder and we create __init__.py inside
                if install_path.endswith('.py'):
                    target_path = install_path
                else:
                    # Create folder and put __init__.py inside
                    target_path = os.path.join(install_path, '__init__.py')
                
                # Absolute target path
                abs_target_path = os.path.join(os.getcwd(), target_path)
                
                # Create parent directories if necessary
                os.makedirs(os.path.dirname(abs_target_path), exist_ok=True)
                
                # For simple modules, copy the file directly instead of creating a stub
                # This is simpler and avoids AST validation issues
                source_file = os.path.join(extract_dir, manifest.entry_point)
                
                if os.path.exists(source_file) and os.path.isfile(source_file):
                    # Simple case: single file module - just copy it
                    import shutil
                    shutil.copy2(source_file, abs_target_path)
                    print_success(f"Module copied: {target_path}")
                    return True
                else:
                    # Complex case: package or file not found - fall back to stub
                    print_warning(f"Source file not found or is a package, creating stub instead: {source_file}")
                    stub_content = generate_python_stub_module(
                        extension_id=manifest.id,
                        entry_rel_path=manifest.entry_point,
                        export_symbol="Module",  # Framework expects "Module"
                        version_dir=version_dir,
                        marketplace_id=marketplace_id
                    )
                    
                    # Write stub
                    with open(abs_target_path, 'w', encoding='utf-8') as f:
                        f.write(stub_content)
                    
                    print_success(f"Stub created: {target_path}")
                    return True
            
            # UI/INTERFACE type
            elif extension_type in ['ui', 'interface']:
                # For interfaces, create a launcher at project root
                if not manifest.entry_point:
                    print_warning(f"entry_point not defined in manifest - launcher not created")
                    return False
                
                # Ensure UI interfaces don't have install_path (should be None)
                if manifest.install_path:
                    print_error(f"UI interfaces cannot have install_path (found: {manifest.install_path}). Remove it from extension.toml")
                    return False
                
                # Launcher name based on extension ID
                launcher_name = f"launch_{manifest.id.replace('-', '_')}.py"
                
                # Find framework root (where extensions/ directory is)
                framework_root = os.path.dirname(self.extensions_dir) if os.path.dirname(self.extensions_dir) else os.getcwd()
                launcher_path = os.path.join(framework_root, launcher_name)
                
                # Generate launcher content
                launcher_content = self._generate_interface_launcher(
                    extension_id=manifest.id,
                    entry_rel_path=manifest.entry_point,
                    version_dir=version_dir,
                    extension_name=manifest.name,
                    marketplace_id=marketplace_id
                )
                
                # Write launcher
                with open(launcher_path, 'w', encoding='utf-8') as f:
                    f.write(launcher_content)
                
                # Make launcher executable on Unix
                try:
                    os.chmod(launcher_path, 0o755)
                except:
                    pass  # Ignore on Windows
                
                print_success(f"Launcher created: {launcher_name}")
                print_info(f"To launch the interface: python {launcher_name}")
                return True
            
            # MIDDLEWARE type
            elif extension_type == 'middleware':
                # Middlewares are loaded dynamically, no stub needed
                print_info("Middleware registered - no stub needed")
                return True
            
            else:
                print_warning(f"Unknown extension type: {extension_type}")
                return False
                
        except Exception as e:
            print_error(f"Error creating stubs: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _remove_stub_files(self, manifest) -> bool:
        """
        Remove stub files according to extension type
        
        Args:
            manifest: ExtensionManifest
            
        Returns:
            True if stubs were removed successfully
        """
        try:
            extension_type = manifest.extension_type.value.lower()
            
            # MODULE or PLUGIN type
            if extension_type in ['module', 'plugin']:
                if not manifest.install_path:
                    return True
                
                # Normalize install_path
                install_path = manifest.install_path.replace("\\", "/").strip()
                
                # Determine stub path
                if install_path.endswith('.py'):
                    stub_path = install_path
                else:
                    stub_path = os.path.join(install_path, '__init__.py')
                
                # Absolute stub/module path
                abs_stub_path = os.path.join(os.getcwd(), stub_path)
                
                # Remove stub or copied module file
                if os.path.exists(abs_stub_path):
                    # Detect if it's a stub or a directly copied file
                    is_stub = False
                    try:
                        with open(abs_stub_path, 'r', encoding='utf-8') as f:
                            first_line = f.readline()
                            if first_line and "# Auto-generated stub module" in first_line:
                                is_stub = True
                    except Exception:
                        pass  # If we can't read it, just remove it
                    
                    os.remove(abs_stub_path)
                    if is_stub:
                        print_info(f"Stub removed: {stub_path}")
                    else:
                        print_info(f"Module file removed: {stub_path}")
                
                # Remove parent directory if empty
                parent_dir = os.path.dirname(abs_stub_path)
                if os.path.exists(parent_dir) and not os.listdir(parent_dir):
                    os.rmdir(parent_dir)
                
                return True
            
            # UI/INTERFACE type
            elif extension_type in ['ui', 'interface']:
                # Remove launcher
                launcher_name = f"launch_{manifest.id.replace('-', '_')}.py"
                # Find framework root (where extensions/ directory is)
                framework_root = os.path.dirname(self.extensions_dir) if os.path.dirname(self.extensions_dir) else os.getcwd()
                launcher_path = os.path.join(framework_root, launcher_name)
                
                if os.path.exists(launcher_path):
                    os.remove(launcher_path)
                    print_info(f"Launcher removed: {launcher_name}")
                
                return True
            
            return True
            
        except Exception as e:
            print_warning(f"Error removing stubs: {e}")
            return False
    
    def _generate_interface_launcher(self, extension_id: str, entry_rel_path: str, 
                                     version_dir: str, extension_name: str, marketplace_id: Optional[str] = None) -> str:
        """
        Generate a Python launcher for an interface
        
        Args:
            extension_id: Extension ID (manifest ID)
            entry_rel_path: Relative path to entry point
            version_dir: Version directory (e.g. "latest")
            extension_name: Extension name
            marketplace_id: Marketplace ID (for new structure)
            
        Returns:
            Launcher file content
        """
        entry_rel_path = (entry_rel_path or "").replace("\\", "/").lstrip("/")
        version_dir = (version_dir or "latest").replace("\\", "/").strip().strip("/")
        if not version_dir:
            version_dir = "latest"
        
        # Build search paths: new structure first, then old structure
        search_paths = []
        marketplace_id_str = marketplace_id if marketplace_id and marketplace_id != extension_id else None
        if marketplace_id_str:
            # New structure: extensions/{marketplace_id}/{manifest_id}/latest/
            search_paths.append(f'extensions/{marketplace_id_str}/{extension_id}/{version_dir}')
        # Old structure: extensions/{manifest_id}/latest/
        search_paths.append(f'extensions/{extension_id}/{version_dir}')
        
        search_paths_str = '", "'.join(search_paths)
        
        # Build the launcher code with proper marketplace_id handling
        if marketplace_id_str:
            marketplace_code = f'''    # Try new structure first: extensions/{marketplace_id_str}/{extension_id}/{version_dir}/
    candidate = here / "extensions" / "{marketplace_id_str}" / "{extension_id}" / "{version_dir}"
    if candidate.exists() and candidate.is_dir():
        return candidate
    # Also try from current working directory
    candidate = Path.cwd() / "extensions" / "{marketplace_id_str}" / "{extension_id}" / "{version_dir}"
    if candidate.exists() and candidate.is_dir():
        return candidate
    
    # Fallback to old structure: extensions/{extension_id}/{version_dir}/'''
        else:
            marketplace_code = f'''    # Try old structure: extensions/{extension_id}/{version_dir}/'''
        
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Launcher for {extension_name} (Extension ID: {extension_id})

This is an auto-generated launcher for a marketplace extension.
The extension files are located in one of: {search_paths_str}

NOTE: Do not edit this file manually.
"""

import sys
import os
from pathlib import Path


def find_extension_base():
    """Find the extension base directory"""
    # Start from the script location
    here = Path(__file__).resolve().parent
    
{marketplace_code}
    candidate = here / "extensions" / "{extension_id}" / "{version_dir}"
    if candidate.exists() and candidate.is_dir():
        return candidate
    
    # Fallback: try from current working directory
    candidate = Path.cwd() / "extensions" / "{extension_id}" / "{version_dir}"
    if candidate.exists() and candidate.is_dir():
        return candidate
    
    raise FileNotFoundError(
        f"Extension directory not found. Tried: {search_paths_str}\\n"
        f"Please ensure the extension is properly installed."
    )


def main():
    """Main launcher function"""
    try:
        # Find extension base directory
        ext_base = find_extension_base()
        entry_file = ext_base / "{entry_rel_path}"
        
        if not entry_file.exists():
            print(f"Error: Entry point not found: {{entry_file}}", file=sys.stderr)
            return 1
        
        # Add extension directories to Python path
        for path_to_add in [ext_base, ext_base / "src", ext_base / "lib"]:
            if path_to_add.exists():
                sys.path.insert(0, str(path_to_add))
        
        # Execute the entry point
        print(f"Launching {extension_name}...")
        print(f"Extension directory: {{ext_base}}")
        print(f"Entry point: {{entry_file}}")
        print("-" * 60)
        
        # Execute the entry file in its own namespace
        namespace = {{
            "__file__": str(entry_file),
            "__name__": "__main__",
            "__extension_id__": "{extension_id}",
            "__extension_base__": str(ext_base),
        }}
        
        with open(entry_file, 'r', encoding='utf-8') as f:
            code = compile(f.read(), str(entry_file), 'exec')
            exec(code, namespace)
        
        return 0
        
    except FileNotFoundError as e:
        print(f"Error: {{e}}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error launching extension: {{e}}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
'''

