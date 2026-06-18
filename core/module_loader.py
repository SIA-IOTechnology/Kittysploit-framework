#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import difflib
import importlib
import importlib.util
import inspect
import json
import logging
import os
import re
import sys
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple

from core.framework.base_module import BaseModule
from core.utils.module_static_metadata import (
    extract_module_search_metadata,
    infer_module_type_from_path,
    search_text_matches_title_description,
    validate_static_module_contract,
)
from core.module_search import ModuleSearchFilters, apply_module_search_filters, extract_search_facets

# Import du PolicyEngine pour la validation
try:
    from core.framework.utils.policy_engine import PolicyEngine, PolicyLevel
    from core.framework.utils.module_validator import ModuleValidator
    POLICY_ENGINE_AVAILABLE = True
except ImportError:
    POLICY_ENGINE_AVAILABLE = False


class LoadFailureKind(str, Enum):
    NOT_FOUND = "not_found"
    CONTRACT = "contract"
    POLICY = "policy"
    POLICY_REJECTED = "policy_rejected"
    MISSING_DEPENDENCY = "missing_dependency"
    IMPORT_ERROR = "import_error"
    NO_MODULE_CLASS = "no_module_class"
    TYPE_ERROR = "type_error"
    UNKNOWN = "unknown"


@dataclass
class ModuleLoadFailure:
    module_path: str
    kind: LoadFailureKind
    detail: str
    cause: str = ""
    suggestions: List[str] = field(default_factory=list)
    contract_errors: List[str] = field(default_factory=list)
    missing_package: str = ""


def _default_modules_path() -> str:
    """Resolve modules directory: use installed package location if available, else 'modules' (cwd)."""
    try:
        import modules as mod
        return os.path.dirname(os.path.abspath(mod.__file__))
    except ImportError:
        return "modules"


class ModuleLoader:
    
    def __init__(
        self,
        modules_path: str = None,
        sync_manager=None,
        enable_policy_validation: bool = True,
        enable_contract_validation: bool = True,
        strict_contract_validation: bool = False,
    ):
        if modules_path is None:
            modules_path = _default_modules_path()
        self.modules_path = modules_path
        self.modules_cache = {}
        self.enable_policy_validation = enable_policy_validation and POLICY_ENGINE_AVAILABLE
        self.enable_contract_validation = enable_contract_validation
        self.strict_contract_validation = strict_contract_validation
        
        # Initialiser le validateur si disponible
        self.validator = None
        if self.enable_policy_validation:
            try:
                self.validator = ModuleValidator(use_policy_engine=True, policy_level="standard")
            except Exception as e:
                logging.warning(f"Impossible d'initialiser le PolicyEngine: {e}")
                self.enable_policy_validation = False
        self.sync_manager = sync_manager
        self.last_load_failure: Optional[ModuleLoadFailure] = None
        self._discovered_paths_cache: Optional[List[str]] = None

    def _import_module_name(self, module_path: str) -> str:
        import_path = module_path.replace("/", ".").lstrip(".")
        return f"modules.{import_path}"

    def _module_file_candidates(self, module_path: str) -> Tuple[str, str]:
        normalized = module_path.strip().strip("/")
        with_py = os.path.join(self.modules_path, normalized.replace("/", os.sep) + ".py")
        without_py = os.path.join(self.modules_path, normalized.replace("/", os.sep))
        return with_py, without_py

    def _discovered_paths_list(self) -> List[str]:
        if self._discovered_paths_cache is None:
            self._discovered_paths_cache = sorted(self.discover_modules().keys())
        return self._discovered_paths_cache

    def invalidate_discovery_cache(self) -> None:
        """Clear cached module paths (after sync, install, or reload)."""
        self._discovered_paths_cache = None

    def _suggest_module_paths(self, module_path: str, limit: int = 5) -> List[str]:
        query = module_path.strip().strip("/")
        if not query:
            return []

        candidates = self._discovered_paths_list()
        if not candidates:
            return []

        basename = query.rsplit("/", 1)[-1]
        suggestions: List[str] = []

        lower_query = query.lower()
        prefix_hits = [path for path in candidates if path.lower().startswith(lower_query)]
        suggestions.extend(prefix_hits[:limit])

        if len(suggestions) < limit:
            fuzzy = difflib.get_close_matches(query, candidates, n=limit, cutoff=0.55)
            suggestions.extend(path for path in fuzzy if path not in suggestions)

        if len(suggestions) < limit and basename:
            basename_hits = [
                path for path in candidates
                if path.rsplit("/", 1)[-1].lower() == basename.lower()
            ]
            suggestions.extend(path for path in basename_hits if path not in suggestions)

        return suggestions[:limit]

    def _missing_module_name(self, exc: BaseException) -> str:
        name = getattr(exc, "name", None)
        if name:
            return str(name)
        match = re.search(r"No module named '([^']+)'", str(exc))
        return match.group(1) if match else ""

    def _classify_import_error(self, module_path: str, exc: BaseException) -> Tuple[LoadFailureKind, str]:
        missing_name = self._missing_module_name(exc)
        if isinstance(exc, ModuleNotFoundError) and missing_name:
            root_name = self._import_module_name(module_path)
            if missing_name == root_name:
                return (
                    LoadFailureKind.IMPORT_ERROR,
                    f"Module package could not be imported ({missing_name})",
                )
            if missing_name.startswith(root_name + "."):
                return (
                    LoadFailureKind.IMPORT_ERROR,
                    f"Missing submodule inside module: {missing_name}",
                )
            if missing_name.startswith("modules."):
                return (
                    LoadFailureKind.IMPORT_ERROR,
                    f"Broken internal KittySploit import: {missing_name}",
                )
            return (
                LoadFailureKind.MISSING_DEPENDENCY,
                f"Missing Python dependency: {missing_name}",
            )
        return LoadFailureKind.IMPORT_ERROR, str(exc)

    def _pypi_name_hint(self, package_name: str) -> str:
        mapping = {
            "pil": "Pillow",
            "cv2": "opencv-python",
            "yaml": "PyYAML",
            "dotenv": "python-dotenv",
            "flask_cors": "flask-cors",
            "flask_socketio": "flask-socketio",
            "bs4": "beautifulsoup4",
            "Crypto": "pycryptodome",
        }
        return mapping.get(package_name, package_name.replace("_", "-"))

    def _report_failure(self, failure: ModuleLoadFailure, silent: bool = False) -> None:
        self.last_load_failure = failure
        if silent:
            logging.debug(
                "Module load failed (%s) for %s: %s",
                failure.kind.value,
                failure.module_path,
                failure.detail,
            )
            return

        from core.output_handler import print_error, print_info, print_warning

        titles = {
            LoadFailureKind.NOT_FOUND: f"Module path not found: '{failure.module_path}'",
            LoadFailureKind.CONTRACT: f"Module contract invalid: '{failure.module_path}'",
            LoadFailureKind.POLICY: f"Module policy validation failed: '{failure.module_path}'",
            LoadFailureKind.POLICY_REJECTED: f"Module rejected by policy: '{failure.module_path}'",
            LoadFailureKind.MISSING_DEPENDENCY: f"Missing dependency for '{failure.module_path}'",
            LoadFailureKind.IMPORT_ERROR: f"Module import failed: '{failure.module_path}'",
            LoadFailureKind.NO_MODULE_CLASS: f"Invalid module structure: '{failure.module_path}'",
            LoadFailureKind.TYPE_ERROR: f"Module type error: '{failure.module_path}'",
            LoadFailureKind.UNKNOWN: f"Failed to load module: '{failure.module_path}'",
        }
        print_error(titles.get(failure.kind, titles[LoadFailureKind.UNKNOWN]))

        if failure.cause:
            print_info(f"Cause: {failure.cause}")

        if failure.contract_errors:
            for error in failure.contract_errors:
                print_info(f"  - {error}")

        if failure.kind == LoadFailureKind.MISSING_DEPENDENCY:
            package = failure.missing_package
            if not package and failure.cause.startswith("Missing Python dependency: "):
                package = failure.cause.split(": ", 1)[-1]
            if package:
                print_info(f"Install with: pip install {self._pypi_name_hint(package)}")

        if failure.suggestions:
            print_info("Did you mean:")
            for suggestion in failure.suggestions:
                print_info(f"  use {suggestion}")

        if failure.kind == LoadFailureKind.NOT_FOUND:
            print_info("Tip: run 'search <keyword>' to browse the module index")

    def _fail(
        self,
        module_path: str,
        kind: LoadFailureKind,
        detail: str,
        *,
        cause: str = "",
        suggestions: Optional[List[str]] = None,
        contract_errors: Optional[List[str]] = None,
        missing_package: str = "",
        silent: bool = False,
    ) -> None:
        failure = ModuleLoadFailure(
            module_path=module_path,
            kind=kind,
            detail=detail,
            cause=cause or detail,
            suggestions=suggestions or [],
            contract_errors=contract_errors or [],
            missing_package=missing_package,
        )
        if kind == LoadFailureKind.NOT_FOUND and not failure.suggestions:
            failure.suggestions = self._suggest_module_paths(module_path)
        self._report_failure(failure, silent=silent)

    def _validate_module_contract(self, module_path: str, module_file_path: str, silent: bool = False) -> bool:
        """Validate KittySploit module metadata/options before importing code."""
        if not self.enable_contract_validation:
            return True

        result = validate_static_module_contract(module_path, module_file_path)
        errors = result.get("errors") or []
        warnings = result.get("warnings") or []

        if errors:
            if silent:
                for error in errors:
                    logging.debug("Module contract validation failed for %s: %s", module_path, error)
            else:
                self._fail(
                    module_path,
                    LoadFailureKind.CONTRACT,
                    "Static module contract validation failed",
                    cause=f"File: {module_file_path}",
                    contract_errors=list(errors),
                    silent=silent,
                )
        if warnings and not silent:
            for warning in warnings:
                logging.warning("Module %s: %s", module_path, warning)

        return not errors or not self.strict_contract_validation
    
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

        self._discovered_paths_cache = sorted(modules.keys())
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
        self.last_load_failure = None
        try:
            if module_path.startswith("modules/marketplace/"):
                return self._load_extension_module(module_path, load_only, framework, silent)

            module_file_path, module_file_alt = self._module_file_candidates(module_path)
            if os.path.isfile(module_file_path):
                resolved_file = module_file_path
            elif os.path.isfile(module_file_alt):
                resolved_file = module_file_alt
            else:
                self._fail(
                    module_path,
                    LoadFailureKind.NOT_FOUND,
                    "No module file exists for this path",
                    cause=f"Checked: {module_file_path} and {module_file_alt}",
                    silent=silent,
                )
                return None

            if not self._validate_module_contract(module_path, resolved_file, silent=silent):
                return None

            if self.enable_policy_validation and self.validator:
                try:
                    with open(resolved_file, "r", encoding="utf-8") as f:
                        module_code = f.read()

                    validation_result = self.validator.validate(module_path, module_code)

                    if not validation_result.get("valid", True):
                        errors = validation_result.get("errors", [])
                        self._fail(
                            module_path,
                            LoadFailureKind.POLICY,
                            "Policy validation failed",
                            contract_errors=list(errors),
                            silent=silent,
                        )
                        return None

                    warnings = validation_result.get("warnings", [])
                    if warnings and not silent:
                        for warning in warnings:
                            logging.warning("Module %s: %s", module_path, warning)

                    approval_status = validation_result.get("approval_status")
                    if approval_status and approval_status not in ["approved", "auto_approved", "pending"]:
                        if approval_status in ["rejected", "revoked"]:
                            self._fail(
                                module_path,
                                LoadFailureKind.POLICY_REJECTED,
                                f"Module approval status is {approval_status}",
                                silent=silent,
                            )
                            return None
                        if not silent:
                            logging.warning(
                                "Module %s requires approval (status: %s)",
                                module_path,
                                approval_status,
                            )
                except Exception as e:
                    if not silent:
                        logging.warning("Policy validation error for %s: %s", module_path, e)

            import_path = module_path.replace("/", ".").lstrip(".")
            module = importlib.import_module(f"modules.{import_path}")

            if not hasattr(module, "Module"):
                self._fail(
                    module_path,
                    LoadFailureKind.NO_MODULE_CLASS,
                    "Python file loaded but no Module class was found",
                    cause="Expected a class named Module inheriting from BaseModule",
                    silent=silent,
                )
                return None

            try:
                sig = inspect.signature(module.Module.__init__)
                if "framework" in sig.parameters:
                    instance = module.Module(framework=framework)
                else:
                    instance = module.Module()
            except (TypeError, AttributeError) as exc:
                try:
                    instance = module.Module()
                except Exception as inner_exc:
                    self._fail(
                        module_path,
                        LoadFailureKind.IMPORT_ERROR,
                        "Failed to instantiate Module class",
                        cause=f"{type(inner_exc).__name__}: {inner_exc}",
                        silent=silent,
                    )
                    return None
                if not silent:
                    logging.debug("Module %s init fallback after: %s", module_path, exc)

            if framework:
                instance.framework = framework

            if not instance.name:
                instance.name = module_path

            if not isinstance(instance, BaseModule):
                self._fail(
                    module_path,
                    LoadFailureKind.TYPE_ERROR,
                    "Module class is not a BaseModule subclass",
                    cause=f"Got {type(instance).__name__}",
                    silent=silent,
                )
                return None

            if not load_only:
                self.modules_cache[module_path] = instance

            return instance

        except ModuleNotFoundError as e:
            kind, cause = self._classify_import_error(module_path, e)
            missing_package = self._missing_module_name(e)
            if kind == LoadFailureKind.MISSING_DEPENDENCY:
                logging.debug("Skipping module %s due to missing dependency: %s", module_path, e)
            else:
                logging.error("Import error in module %s: %s", module_path, e)
            self._fail(
                module_path,
                kind,
                cause,
                cause=cause,
                missing_package=missing_package if kind == LoadFailureKind.MISSING_DEPENDENCY else "",
                silent=silent,
            )
        except ImportError as e:
            kind, cause = self._classify_import_error(module_path, e)
            missing_package = self._missing_module_name(e)
            logging.error("Import error in module %s: %s", module_path, e)
            self._fail(
                module_path,
                kind,
                cause,
                cause=cause,
                missing_package=missing_package if kind == LoadFailureKind.MISSING_DEPENDENCY else "",
                silent=silent,
            )
        except AttributeError as e:
            logging.error("Module %s does not have a Module class: %s", module_path, e)
            self._fail(
                module_path,
                LoadFailureKind.NO_MODULE_CLASS,
                "Module class is missing or invalid",
                cause=f"{type(e).__name__}: {e}",
                silent=silent,
            )
        except TypeError as e:
            logging.error("Type error loading module %s: %s", module_path, e)
            self._fail(
                module_path,
                LoadFailureKind.TYPE_ERROR,
                "Module type error during load",
                cause=f"{type(e).__name__}: {e}",
                silent=silent,
            )
        except Exception as e:
            logging.error("Error loading module %s: %s", module_path, e)
            self._fail(
                module_path,
                LoadFailureKind.UNKNOWN,
                "Unexpected error while loading module",
                cause=f"{type(e).__name__}: {e}",
                silent=silent,
            )
            if not silent:
                logging.debug("Traceback for %s:\n%s", module_path, traceback.format_exc())

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
                    self._fail(
                        module_path,
                        LoadFailureKind.NOT_FOUND,
                        "Invalid marketplace module path",
                        cause="Expected modules/marketplace/<type>/<module_id>",
                        silent=silent,
                    )
                return None
            
            module_type = parts[0]
            module_id = parts[1]
            
            # Build path to module directory
            module_dir = os.path.join(self.modules_path, "marketplace", module_type, module_id)
            if not os.path.exists(module_dir):
                if not silent:
                    self._fail(
                        module_path,
                        LoadFailureKind.NOT_FOUND,
                        f"Marketplace module not installed: {module_id}",
                        cause=f"Directory not found: {module_dir}",
                        suggestions=self._suggest_module_paths(module_path),
                        silent=silent,
                    )
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

                if not self._validate_module_contract(module_path, entry_file, silent=silent):
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
    
    def search_modules_db(
        self,
        filters: ModuleSearchFilters = None,
        query: str = "",
        module_type: str = "",
        author: str = "",
        cve: str = "",
        tags: str = "",
        limit: int = 100,
        platform: str = "",
        protocol: str = "",
        reliability: str = "",
        since=None,
        until=None,
    ) -> List[Dict]:
        """Search modules: use the workspace DB when configured, else static filesystem scan."""
        if filters is None:
            filters = ModuleSearchFilters(
                query=query,
                module_type=module_type,
                author=author,
                cve=cve,
                tag=tags,
                platform=platform,
                protocol=protocol,
                reliability=reliability,
                since=since,
                until=until,
                limit=limit,
            )
        if not self.sync_manager:
            return self._search_modules_filesystem(filters)

        try:
            return self.sync_manager.search_modules(filters=filters)
        except Exception as e:
            logging.debug(f"search_modules_db: database search failed: {e}")
            return []
    
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
    
    def _search_modules_filesystem(self, filters: ModuleSearchFilters) -> List[Dict]:
        """Filesystem search: parse __info__ from source only (no import / no payload init)."""
        results = []
        discovered_modules = self.discover_modules()

        for module_path, file_path in discovered_modules.items():
            try:
                meta = extract_module_search_metadata(file_path)
                facets = extract_search_facets(meta, module_path)
                tags_list = meta.get("tags") or []
                opts = {"_search": {key: value for key, value in facets.items() if value}}

                results.append({
                    'name': str(meta.get("name") or ""),
                    'description': str(meta.get("description") or ""),
                    'type': infer_module_type_from_path(module_path),
                    'path': module_path,
                    'author': str(meta.get("author") or ""),
                    'version': '',
                    'cve': str(meta.get("cve") or ""),
                    'tags': tags_list if isinstance(tags_list, list) else [],
                    'references': [],
                    'options': json.dumps(opts),
                    'platform': facets.get('platform') or '',
                    'protocol': facets.get('protocol') or '',
                    'reliability': facets.get('reliability') or '',
                })

            except Exception as e:
                logging.debug(f"Static search skip {module_path}: {e}")
                continue

        return apply_module_search_filters(results, filters)
