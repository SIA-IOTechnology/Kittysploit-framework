#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import importlib
import logging
from typing import List, Dict, Any, Optional
from core.framework.base_module import BaseModule

# Import du PolicyEngine pour la validation
try:
    from core.framework.utils.policy_engine import PolicyEngine, PolicyLevel
    from core.framework.utils.module_validator import ModuleValidator
    POLICY_ENGINE_AVAILABLE = True
except ImportError:
    POLICY_ENGINE_AVAILABLE = False

class ModuleLoader:
    
    def __init__(self, modules_path: str = "modules", sync_manager=None, enable_policy_validation: bool = True):
        self.modules_path = modules_path
        self.modules_cache = {}
        self.enable_policy_validation = enable_policy_validation and POLICY_ENGINE_AVAILABLE
        
        # Initialiser le validateur si disponible
        self.validator = None
        if self.enable_policy_validation:
            try:
                self.validator = ModuleValidator(use_policy_engine=True, policy_level="standard")
            except Exception as e:
                logging.warning(f"Impossible d'initialiser le PolicyEngine: {e}")
                self.enable_policy_validation = False
        self.sync_manager = sync_manager
    
    def discover_modules(self) -> Dict[str, str]:
        modules = {}
        
        # Recursively walk through the modules directory
        for root, dirs, files in os.walk(self.modules_path):
            for file in files:
                if file.endswith(".py") and not file.startswith("__"):
                    # Build the relative path of the module
                    rel_path = os.path.relpath(os.path.join(root, file), self.modules_path)
                    module_path = os.path.splitext(rel_path)[0].replace(os.path.sep, "/")
                    
                    # Add the module to the list
                    modules[module_path] = os.path.join(root, file)
        
        # Also discover modules from installed extensions (marketplace)
        extensions_modules = self._discover_extension_modules()
        modules.update(extensions_modules)
        
        return modules
    
    def _discover_extension_modules(self) -> Dict[str, str]:
        """Discover modules from installed marketplace modules in modules/marketplace/ directory"""
        modules = {}
        
        # Look in modules/marketplace/<type>/<module_id>/latest/
        marketplace_dir = os.path.join(self.modules_path, "marketplace")
        if not os.path.exists(marketplace_dir):
            return modules
        
        # Walk through marketplace directory organized by type
        for module_type in os.listdir(marketplace_dir):
            type_path = os.path.join(marketplace_dir, module_type)
            if not os.path.isdir(type_path):
                continue
            
            # Walk through each module in this type
            for module_id in os.listdir(type_path):
                module_path = os.path.join(type_path, module_id)
                if not os.path.isdir(module_path):
                    continue
                
                # Look for latest version or any version directory
                version_dirs = []
                for item in os.listdir(module_path):
                    item_path = os.path.join(module_path, item)
                    if os.path.isdir(item_path):
                        version_dirs.append(item_path)
                
                # If no version dirs, check root of module
                if not version_dirs:
                    version_dirs = [module_path]
                
                # Check each version directory for modules
                for version_dir in version_dirs:
                    # Look for extension.toml to get entry_point
                    manifest_path = os.path.join(version_dir, "extension.toml")
                    if os.path.exists(manifest_path):
                        try:
                            import toml
                            with open(manifest_path, 'r') as f:
                                manifest = toml.load(f)
                                entry_point = manifest.get('metadata', {}).get('entry_point', 'main.py')
                                
                                # Check if entry_point exists and is a Python file
                                entry_file = os.path.join(version_dir, entry_point)
                                if os.path.exists(entry_file) and entry_file.endswith('.py'):
                                    # Create module path: modules/marketplace/<type>/<module_id>
                                    module_path_str = f"modules/marketplace/{module_type}/{module_id}"
                                    modules[module_path_str] = entry_file
                                    break  # Only use first valid version
                        except Exception as e:
                            logging.debug(f"Could not parse manifest for {module_id}: {e}")
                            continue
                    
                    # Also check for any .py files in the root (fallback)
                    for file in os.listdir(version_dir):
                        if file.endswith(".py") and not file.startswith("__"):
                            module_path_str = f"modules/marketplace/{module_type}/{module_id}"
                            modules[module_path_str] = os.path.join(version_dir, file)
                            break
        
        return modules
    
    def load_module(self, module_path: str, load_only: bool = False, framework=None, silent: bool = False):
        """Load a module by its path
        
        Args:
            module_path: Path to the module
            load_only: If True, don't cache the module
            framework: Framework instance to pass to the module
            silent: If True, don't print error messages (useful for discovery)
        """
        try:
            # Check if this is a marketplace module (modules/marketplace/<type>/<module_id>)
            if module_path.startswith("modules/marketplace/"):
                return self._load_extension_module(module_path, load_only, framework, silent)
            
            # Lire le code source du module pour validation
            module_file_path = os.path.join(self.modules_path, module_path.replace("/", os.sep) + ".py")
            if not os.path.exists(module_file_path):
                # Essayer sans extension
                module_file_path = os.path.join(self.modules_path, module_path.replace("/", os.sep))
                if not os.path.exists(module_file_path):
                    if not silent:
                        logging.error(f"Module file not found: {module_path}")
                    return None
            
            # Valider le module avec PolicyEngine si activé
            if self.enable_policy_validation and self.validator:
                try:
                    with open(module_file_path, 'r', encoding='utf-8') as f:
                        module_code = f.read()
                    
                    validation_result = self.validator.validate(module_path, module_code)
                    
                    if not validation_result.get("valid", True):
                        errors = validation_result.get("errors", [])
                        if not silent:
                            logging.error(f"Module validation failed for {module_path}:")
                            for error in errors:
                                logging.error(f"  - {error}")
                        return None
                    
                    # Afficher les warnings si présents
                    warnings = validation_result.get("warnings", [])
                    if warnings and not silent:
                        for warning in warnings:
                            logging.warning(f"Module {module_path}: {warning}")
                    
                    # Vérifier l'approbation si requise
                    # Note: Par défaut, on ne bloque pas même si PENDING (mode permissif)
                    approval_status = validation_result.get("approval_status")
                    if approval_status and approval_status not in ["approved", "auto_approved", "pending"]:
                        # Seulement bloquer si explicitement REJECTED ou REVOKED
                        if approval_status in ["rejected", "revoked"]:
                            if not silent:
                                logging.error(f"Module {module_path} est {approval_status}")
                            return None
                        elif not silent:
                            logging.warning(f"Module {module_path} requires approval (status: {approval_status})")
                except Exception as e:
                    if not silent:
                        logging.warning(f"Erreur lors de la validation du module {module_path}: {e}")
                    # Continuer le chargement même si la validation échoue (mode permissif)
            
            # Build the import path
            import_path = module_path.replace("/", ".")
            if import_path.startswith("."):
                import_path = import_path[1:]
            
            # Import the module
            module = importlib.import_module(f"modules.{import_path}")
            
            # Instancier la classe Module with framework if it accepts it
            try:
                # Try to instantiate with framework if __init__ accepts it
                import inspect
                sig = inspect.signature(module.Module.__init__)
                if 'framework' in sig.parameters:
                    instance = module.Module(framework=framework)
                else:
                    instance = module.Module()
            except (TypeError, AttributeError):
                # Fallback to default instantiation
                instance = module.Module()
            
            # Set the reference to the framework (for modules that don't accept it in __init__)
            if framework:
                instance.framework = framework
            
            # Set the module name from the path if not defined
            if not instance.name:
                instance.name = module_path
            
            # Verify that the instance is a BaseModule
            if not isinstance(instance, BaseModule):
                raise TypeError(f"Le module {module_path} n'est pas une instance de BaseModule")
            
            # Cache the module if it's not a temporary load
            if not load_only:
                self.modules_cache[module_path] = instance
            
            return instance
            
        except ImportError as e:
            # Only log as error if it's not a missing dependency
            if "No module named" in str(e):
                logging.debug(f"Skipping module {module_path} due to missing dependency: {str(e)}")
                # Only print error if not in silent mode
                if not silent:
                    from core.output_handler import print_error
                    print_error(f"Failed to load module '{module_path}': Missing dependency - {str(e)}")
            else:
                logging.error(f"Error importing module {module_path}: {str(e)}")
                if not silent:
                    from core.output_handler import print_error
                    print_error(f"Failed to import module '{module_path}': {str(e)}")
        except AttributeError as e:
            logging.error(f"Module {module_path} does not have a Module class: {str(e)}")
            if not silent:
                from core.output_handler import print_error
                print_error(f"Module '{module_path}' does not have a Module class: {str(e)}")
        except TypeError as e:
            logging.error(f"Type error loading module {module_path}: {str(e)}")
            if not silent:
                from core.output_handler import print_error
                print_error(f"Type error loading module '{module_path}': {str(e)}")
        except Exception as e:
            logging.error(f"Error loading module {module_path}: {str(e)}")
            if not silent:
                from core.output_handler import print_error
                import traceback
                print_error(f"Failed to load module '{module_path}': {str(e)}")
                # Print full traceback for debugging
                print_error(f"Traceback: {traceback.format_exc()}")
        
        return None
    
    def _load_extension_module(self, module_path: str, load_only: bool = False, framework=None, silent: bool = False):
        """Load a module from an installed marketplace module"""
        try:
            # Extract module path components (modules/marketplace/<type>/<module_id>)
            # Remove "modules/marketplace/" prefix
            rel_path = module_path.replace("modules/marketplace/", "")
            parts = rel_path.split("/")
            
            if len(parts) < 2:
                if not silent:
                    logging.error(f"Invalid marketplace module path: {module_path}")
                return None
            
            module_type = parts[0]
            module_id = parts[1]
            
            # Build path to module directory
            module_dir = os.path.join(self.modules_path, "marketplace", module_type, module_id)
            if not os.path.exists(module_dir):
                if not silent:
                    logging.error(f"Marketplace module not found: {module_id}")
                return None
            
            # Find the latest version or any version
            version_dirs = []
            for item in os.listdir(module_dir):
                item_path = os.path.join(module_dir, item)
                if os.path.isdir(item_path):
                    version_dirs.append((item, item_path))
            
            # Sort to prefer "latest"
            version_dirs.sort(key=lambda x: (x[0] != "latest", x[0]))
            
            if not version_dirs:
                version_dirs = [("", module_dir)]
            
            # Try each version directory
            for version_name, version_dir in version_dirs:
                # Look for manifest to get entry_point
                manifest_path = os.path.join(version_dir, "extension.toml")
                entry_file = None
                
                if os.path.exists(manifest_path):
                    try:
                        from core.registry.manifest import ManifestParser
                        from core.registry.signature import RegistrySignatureManager
                        from core.output_handler import print_warning
                        
                        # Parse manifest
                        manifest_obj = ManifestParser.parse(manifest_path)
                        if manifest_obj:
                            # Verify signature if present
                            if manifest_obj.signature and manifest_obj.public_key:
                                signature_manager = RegistrySignatureManager()
                                # Create manifest content without signature/public_key for verification
                                # (signature is calculated on manifest without these fields)
                                manifest_dict = manifest_obj.to_dict()
                                # Remove signature and public_key for verification
                                manifest_dict.pop('signature', None)
                                manifest_dict.pop('public_key', None)
                                # Convert back to TOML
                                import toml
                                manifest_content_for_verification = toml.dumps(manifest_dict)
                                
                                is_valid = signature_manager.verify_signature(
                                    manifest_content_for_verification,
                                    manifest_obj.signature,
                                    manifest_obj.public_key
                                )
                                
                                if not is_valid:
                                    print_warning(f"Invalid signature for marketplace module '{module_id}' - module may have been tampered with")
                                # Note: We still load the module even if signature is invalid, but warn the user
                            elif not manifest_obj.signature:
                                # No signature present - warn if this is a marketplace module
                                print_warning(f"Marketplace module '{module_id}' is not signed - authenticity cannot be verified")
                            
                            # Get entry point from manifest
                            entry_point = manifest_obj.entry_point or 'main.py'
                            entry_file = os.path.join(version_dir, entry_point)
                        else:
                            # Fallback to TOML parsing
                            import toml
                            with open(manifest_path, 'r') as f:
                                manifest = toml.load(f)
                                entry_point = manifest.get('metadata', {}).get('entry_point', 'main.py')
                                entry_file = os.path.join(version_dir, entry_point)
                    except Exception as e:
                        logging.debug(f"Could not parse manifest: {e}")
                        # Fallback: look for main.py
                        entry_file = os.path.join(version_dir, 'main.py')
                
                # Fallback: look for main.py or any .py file
                if not entry_file or not os.path.exists(entry_file):
                    for file in os.listdir(version_dir):
                        if file.endswith(".py") and not file.startswith("__"):
                            entry_file = os.path.join(version_dir, file)
                            break
                
                if not entry_file or not os.path.exists(entry_file):
                    continue
                
                # Add extension directory to Python path
                if version_dir not in sys.path:
                    sys.path.insert(0, version_dir)
                
                # Import the module
                try:
                    # Get module name from file
                    module_name = os.path.splitext(os.path.basename(entry_file))[0]
                    spec = importlib.util.spec_from_file_location(f"extension_{module_id}", entry_file)
                    if spec is None or spec.loader is None:
                        continue
                    
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Look for Module class
                    ModuleClass = None
                    for name, obj in vars(module).items():
                        if (isinstance(obj, type) and 
                            issubclass(obj, BaseModule) and 
                            obj != BaseModule):
                            ModuleClass = obj
                            break
                    
                    if not ModuleClass:
                        if not silent:
                            logging.error(f"Marketplace module {module_id} does not have a Module class inheriting from BaseModule")
                        continue
                    
                    # Instantiate the module
                    import inspect
                    sig = inspect.signature(ModuleClass.__init__)
                    if 'framework' in sig.parameters:
                        instance = ModuleClass(framework=framework)
                    else:
                        instance = ModuleClass()
                    
                    if framework:
                        instance.framework = framework
                    
                    if not instance.name:
                        instance.name = module_path
                    
                    # Cache the module if not load_only
                    if not load_only:
                        self.modules_cache[module_path] = instance
                    
                    return instance
                    
                except Exception as e:
                    logging.debug(f"Error loading marketplace module {module_id}: {e}")
                    continue
            
            if not silent:
                logging.error(f"Could not load marketplace module: {module_path}")
            return None
            
        except Exception as e:
            logging.error(f"Error loading marketplace module {module_path}: {e}")
            if not silent:
                from core.output_handler import print_error
                print_error(f"Failed to load marketplace module '{module_path}': {str(e)}")
            return None
    
    def get_module_info(self, module_path: str, silent: bool = False) -> Optional[Dict[str, Any]]:
        """Get module information
        
        Args:
            module_path: Path to the module
            silent: If True, don't print error messages (useful for discovery)
        """
        module = self.load_module(module_path, load_only=True, silent=silent)
        if module:
            return module.get_info()
        return None
    
    def get_modules_by_type(self, module_type: str) -> Dict[str, Any]:
        """Get all modules of a specific type (exploit, payload, listener, etc.)"""
        modules = {}
        
        # Discover modules only in the specific type directory
        type_modules = self._discover_modules_by_type(module_type)
        
        for module_path, file_path in type_modules.items():
            try:
                # Load the module to get its info (silently to avoid error spam)
                module = self.load_module(module_path, load_only=True, silent=True)
                if module and hasattr(module, '__info__'):
                    # Double-check that the module is actually of the correct type
                    if hasattr(module, 'TYPE_MODULE') and module.TYPE_MODULE == module_type:
                        modules[module_path] = module
            except Exception as e:
                # Only log errors for the specific module type we're looking for
                # Skip modules with missing dependencies silently
                if "No module named" in str(e) or "ImportError" in str(e):
                    logging.debug(f"Skipping {module_type} module {module_path} due to missing dependencies: {e}")
                else:
                    logging.debug(f"Error loading {module_type} module {module_path}: {e}")
                continue
        
        return modules
    
    def _discover_modules_by_type(self, module_type: str) -> Dict[str, str]:
        """Discover modules only in the specific type directory"""
        modules = {}
        
        # Handle both singular and plural forms
        type_dirs = [module_type, f"{module_type}s"]
        
        for type_dir in type_dirs:
            type_path = os.path.join(self.modules_path, type_dir)
            if os.path.exists(type_path):
                # Recursively walk through the specific type directory
                for root, dirs, files in os.walk(type_path):
                    for file in files:
                        if file.endswith(".py") and not file.startswith("__"):
                            # Build the relative path of the module
                            rel_path = os.path.relpath(os.path.join(root, file), self.modules_path)
                            module_path = os.path.splitext(rel_path)[0].replace(os.path.sep, "/")
                            
                            # Add the module to the list
                            modules[module_path] = os.path.join(root, file)
        
        return modules
    
    def _is_module_type_path(self, module_path: str, module_type: str) -> bool:
        """Check if a module path corresponds to the specified type"""
        # Handle both singular and plural forms
        type_patterns = [
            f"/{module_type}/",
            f"/{module_type}s/",  # Handle plurals like payloads/
            module_path.startswith(f"{module_type}/"),
            module_path.startswith(f"{module_type}s/")
        ]
        return any(type_patterns)
    
    def search_modules_db(self, query: str = "", module_type: str = "", 
                         author: str = "", cve: str = "", tags: str = "", limit: int = 100) -> List[Dict]:
        """Search modules in database (faster than filesystem search)"""
        if not self.sync_manager:
            # Fallback to filesystem search
            return self._search_modules_filesystem(query, module_type, author, cve, tags, limit)
        
        return self.sync_manager.search_modules(query, module_type, author, cve, tags, limit)
    
    def get_module_by_path_db(self, path: str) -> Optional[Dict]:
        """Get module by path from database"""
        if not self.sync_manager:
            return None
        
        return self.sync_manager.get_module_by_path(path)
    
    def get_module_stats_db(self) -> Dict[str, int]:
        """Get module statistics from database"""
        if not self.sync_manager:
            return {}
        
        return self.sync_manager.get_module_stats()
    
    def _search_modules_filesystem(self, query: str = "", module_type: str = "", 
                                  author: str = "", cve: str = "", tags: str = "", limit: int = 100) -> List[Dict]:
        """Fallback filesystem search (slower)"""
        results = []
        discovered_modules = self.discover_modules()
        
        for module_path in discovered_modules:
            try:
                module_info = self.get_module_info(module_path)
                if not module_info:
                    continue
                
                # Apply filters
                if query and query.lower() not in module_info.get('name', '').lower():
                    if query.lower() not in module_info.get('description', '').lower():
                        continue
                
                if module_type and module_info.get('type', '') != module_type:
                    continue
                
                if author and author.lower() not in module_info.get('author', '').lower():
                    continue
                
                if cve and cve.lower() not in module_info.get('cve', '').lower():
                    continue
                
                if tags:
                    module_tags = module_info.get('tags', [])
                    if tags.lower() not in [t.lower() for t in module_tags]:
                        continue
                
                results.append({
                    'name': module_info.get('name', ''),
                    'description': module_info.get('description', ''),
                    'type': module_info.get('type', ''),
                    'path': module_path,
                    'author': module_info.get('author', ''),
                    'version': module_info.get('version', ''),
                    'cve': module_info.get('cve', ''),
                    'tags': module_info.get('tags', []),
                    'references': module_info.get('references', [])
                })
                
                if len(results) >= limit:
                    break
                    
            except Exception as e:
                logging.warning(f"Error processing module {module_path}: {e}")
                continue
        
        return results
