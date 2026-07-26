#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from itertools import chain
from six import iteritems, with_metaclass
from core.framework.option.base_option import Option as BaseOption, OptionValidationError
from core.framework.utils.dependencies import DependencyManager
from core.framework.failure import ProcedureError
import os
import shutil
from core.output_handler import print_success, print_error, print_status
import random
import string


@dataclass
class ModuleResult:
    """Normalized return value for module ``run()`` / ``_exploit()``."""

    success: bool = True
    finding: Any = None
    evidence: Any = None
    error: Optional[str] = None
    session_id: Optional[str] = None
    data: Any = None

    def __bool__(self) -> bool:
        return self.success

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"success": self.success}
        if self.finding is not None:
            payload["finding"] = self.finding
        if self.evidence is not None:
            payload["evidence"] = self.evidence
        if self.error:
            payload["error"] = self.error
        if self.session_id:
            payload["session_id"] = self.session_id
        if self.data is not None:
            payload["data"] = self.data
        return payload


def normalize_module_result(value: Any) -> ModuleResult:
    """Coerce legacy module return values into a ``ModuleResult``."""
    if value is None:
        return ModuleResult(success=True)
    if isinstance(value, ModuleResult):
        return value
    if isinstance(value, bool):
        return ModuleResult(success=value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ModuleResult(success=False, error="Empty result")
        lowered = text.lower()
        if lowered in {"false", "failed", "failure", "error", "no"}:
            return ModuleResult(success=False, error=text)
        return ModuleResult(success=True, session_id=text, data=text)
    if isinstance(value, dict):
        success = value.get("success")
        if success is None:
            success = value.get("ok")
        if success is None and "status" in value:
            success = str(value.get("status")).lower() in {
                "success",
                "ok",
                "completed",
                "vulnerable",
            }
        if success is None:
            success = not bool(value.get("error") or value.get("failed"))
        finding = value.get("finding", value.get("findings"))
        evidence = value.get("evidence")
        session_id = value.get("session_id", value.get("session"))
        error = value.get("error") or value.get("message")
        if isinstance(error, str) and error.lower() in {"scan_error"}:
            return ModuleResult(
                success=False,
                finding=finding,
                evidence=evidence,
                error=error,
                session_id=session_id,
                data=value,
            )
        return ModuleResult(
            success=bool(success),
            finding=finding,
            evidence=evidence,
            error=str(error) if error else None,
            session_id=str(session_id) if session_id else None,
            data=value.get("data", value.get("result", value)),
        )
    if isinstance(value, tuple):
        if not value:
            return ModuleResult(success=False, error="Empty tuple result")
        if len(value) >= 3 and not isinstance(value[0], bool):
            return ModuleResult(success=True, data=value)
        if len(value) == 1:
            return normalize_module_result(value[0])
        if isinstance(value[0], bool):
            result = ModuleResult(success=bool(value[0]), data=value)
            if len(value) > 1:
                second = value[1]
                if isinstance(second, str) and result.success and not result.session_id:
                    result.session_id = second.strip() or None
                elif isinstance(second, str) and not result.success and not result.error:
                    result.error = second
                elif second is not None and result.finding is None:
                    result.finding = second
            if len(value) > 2 and result.evidence is None:
                result.evidence = value[2]
            return result
        return ModuleResult(success=bool(value[0]), data=value)
    return ModuleResult(success=bool(value), data=value)


class ModuleOptionsAggregator(type):
    """Metaclass that dynamically aggregates the options of modules."""

    def __new__(cls, name, bases, attrs):
        # Aggregate the exploit attributes of base classes
        # Only collect from bases that have exploit_attributes (skip mixins that don't)
        base_exploit_attributes = []
        for base in bases:
            if hasattr(base, 'exploit_attributes'):
                base_exploit_attributes.append(base.exploit_attributes)
        
        if base_exploit_attributes:
            attrs["exploit_attributes"] = {
                k: v for d in base_exploit_attributes for k, v in iteritems(d)
            }
        else:
            attrs["exploit_attributes"] = {}
        
        # Process the current attributes
        for key, value in list(iteritems(attrs)):
            if isinstance(value, BaseOption):
                value.label = key
                # Use _default_display_value or fallback to str of default value
                display_value = getattr(value, '_default_display_value', str(getattr(value, '_default_value', '')))
                attrs["exploit_attributes"].update(
                    {
                        key: [
                            display_value,
                            value.required,
                            value.description,
                            value.advanced,
                        ]
                    }
                )
            elif key == "__info__":
                attrs["__info__"] = value
            elif key in attrs["exploit_attributes"]:
                del attrs["exploit_attributes"][key]
        
        return super(ModuleOptionsAggregator, cls).__new__(cls, name, bases, attrs)

class BaseModule(with_metaclass(ModuleOptionsAggregator, object)):
    """Base class for all KittySploit modules."""

    def __init__(self, framework=None):
        """
        Initialise un nouveau module.
        
        Args:
            framework: Reference to the main framework
        """
        self._options = {}
        self.name = ""
        self.description = ""
        self.author = ""
        self.references = []
        self.requires_root = False
        self.cve = None
        self.framework = framework
        self.dependency_manager = DependencyManager()
        self._check_module_dependencies()
        # Extract the information from the __info__ dictionary if present
        if hasattr(self.__class__, '__info__'):
            info = self.__class__.__info__
            if 'name' in info:
                self.name = info['name']
            if 'description' in info:
                self.description = info['description']
            if 'author' in info:
                self.author = info['author']
            if 'references' in info:
                self.references = info['references']
            if 'requires_root' in info:
                self.requires_root = info['requires_root']
            if 'cve' in info:
                self.cve = info['cve']
            if 'tags' in info:
                self.tags = info['tags']
            else:
                self.tags = []

    def _check_module_dependencies(self):
        if hasattr(self.__class__, '__info__'):
            deps = self.__class__.__info__.get('dependencies', [])
            optional_deps = self.__class__.__info__.get('optional_dependencies', [])
            self.dependency_manager.check_dependencies(deps, optional=False)
            if optional_deps:
                self.dependency_manager.check_dependencies(optional_deps, optional=True)

    def check_options(self) -> bool:
        """
        Check if all required options are defined.
        
        Returns:
            bool: True if all required options are defined, False otherwise
        """
        missing_options = self.get_missing_options()
        return len(missing_options) == 0
    
    def get_missing_options(self) -> List[str]:
        """
        Get a list of missing required options.
        
        Returns:
            List[str]: List of option names that are required but not set
        """
        missing = []
        exploit_attributes = getattr(self, 'exploit_attributes', {})
        for name, option_data in exploit_attributes.items():
            if len(option_data) >= 2 and option_data[1]:  # required flag
                if not hasattr(self, name):
                    missing.append(name)
                    continue
                
                # Get the option descriptor from the class
                option_descriptor = getattr(type(self), name, None)
                
                # For OptFile and similar descriptors, check display_value instead of calling __get__
                # which would try to read the file
                if option_descriptor and hasattr(option_descriptor, '_default_display_value'):
                    # Check if display_value is set
                    display_value = getattr(option_descriptor, '_default_display_value', '')
                    instance_id = id(self)
                    if hasattr(option_descriptor, '_instance_values') and instance_id in option_descriptor._instance_values:
                        display_value = option_descriptor._instance_values[instance_id].get('display_value', '')
                    
                    if not display_value or display_value == "":
                        missing.append(name)
                else:
                    # For other options, try to get the value normally
                    try:
                        value = getattr(self, name)
                        # Check if value is empty/None
                        if value is None or value == "" or (isinstance(value, list) and len(value) == 0):
                            missing.append(name)
                    except Exception:
                        # If getting the value raises an exception, consider the option as not set
                        missing.append(name)
        return missing

    def get_options(self) -> dict:
        """
        Return the options of the module.
        
        Returns:
            dict: Dictionary of options
        """
        return getattr(self, 'exploit_attributes', {})

    def set_option(self, name: str, value: Any) -> bool:
        """
        Set the value of an option.
        
        Args:
            name: Name of the option
            value: Value to set
            
        Returns:
            bool: True if the option has been defined with success, False otherwise
        """
        if hasattr(self, name):
            # Get the attribute - if it's a descriptor (Option), use __set__
            # Otherwise, use setattr normally
            attr = getattr(type(self), name, None)
            if attr is not None and hasattr(attr, '__set__'):
                # It's a descriptor, use __set__ to properly store the value
                attr.__set__(self, value)
            else:
                # Not a descriptor, use setattr normally
                setattr(self, name, value)
            return True
        return False

    def check(self) -> bool:
        """
        Check if the module can be executed in the current environment.
        
        Returns:
            bool: True if the module can be executed, False otherwise
        """
        return True
    
    def run(self):
        """
        Execute the module. Must be implemented by derived classes.

        Returns:
            ModuleResult | bool | str | dict | tuple | None: Execution outcome.
            Prefer returning ``ModuleResult`` or ``self.module_result(...)``.

        Raises:
            NotImplementedError: If the method is not implemented
        """
        raise NotImplementedError("Modules must implement the run() method")

    @staticmethod
    def module_result(
        *,
        success: bool = True,
        finding: Any = None,
        evidence: Any = None,
        error: Optional[str] = None,
        session_id: Optional[str] = None,
        data: Any = None,
    ) -> ModuleResult:
        return ModuleResult(
            success=success,
            finding=finding,
            evidence=evidence,
            error=error,
            session_id=session_id,
            data=data,
        )

    def vulnerable(self):
        """Hook when a module confirms the target is vulnerable (same messaging as ExploitBase)."""
        print_success("The target is vulnerable")

    def not_vulnerable(self):
        """Hook when the target is not vulnerable; prints the standard failure line."""
        from core.framework.failure import fail

        fail.NotVulnerable()

    def _exploit(self):
        try:
            return normalize_module_result(self.run())
        except ProcedureError:
            return ModuleResult(success=False)
        except Exception:
            return ModuleResult(success=False)
    
    def get_info(self) -> Dict[str, Any]:
        """
        Return the information about the module.
        
        Returns:
            Dict[str, Any]: Informations sur le module
        """
        return {
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "references": self.references,
            "requires_root": self.requires_root,
            "tags": getattr(self, 'tags', []),
            "options": getattr(self, 'exploit_attributes', {})
        }
    
    def __str__(self) -> str:
        """Representation of the module as a string."""
        return self.name
    

    def create_file(self, path: str, content: str) -> bool:
        """
        Create a file with the given content.
        
        Args:
            path: Path to the file
            content: Content of the file
            
        Returns:
            bool: True if the file has been created with success, False otherwise
        """
        try:
            full_path = os.path.normpath(path)
            parent_dir = os.path.dirname(full_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            if os.path.exists(full_path):
                print_status(f"File {full_path} already exists")
                print_status("Overwriting file...")
                os.remove(full_path)
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
            print_success(f"File {full_path} created successfully")
            return True
        except Exception as e:
            print_error(f"Error creating file {path}: {e}")
            return False
    
    def random_text(self, length: int) -> str:
        """
        Generate a random text of the given length.
        
        Args:
            length: Length of the random text
            
        Returns:
            str: Random text
        """
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    
    def create_dir(self, dir_path: str) -> bool:
        """
        Create a directory. If the directory already exists, it will be removed and recreated.
        
        Args:
            dir_path: Path to the directory
            
        Returns:
            bool: True if the directory has been created with success, False otherwise
        """
        # Use output directory relative to current working directory (same as write_out_dir)
        output_dir = os.path.join(os.getcwd(), "output")
        full_dir_path = os.path.join(output_dir, dir_path)
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Remove directory if it exists
        if os.path.exists(full_dir_path):
            try:
                shutil.rmtree(full_dir_path)
            except Exception as e:
                print_error(f"Error removing existing directory: {e}")
                return False
        
        # create directory
        try:
            os.makedirs(full_dir_path)
            return True
        except Exception as e:
            print_error(f"Error creating directory: {e}")
            return False
    

    def write_out_dir(self, file_path: str, content: str, *, quiet: bool = False) -> bool:
        """
        Write a file to the output directory.
        
        Args:
            file_path: Relative path to the file (e.g., "filename.php" or "subdir/filename.php")
            content: Content to write to the file
            quiet: Skip the success message when True
            
        Returns:
            bool: True if the file has been written successfully, False otherwise
        """
        try:
            # Use output directory relative to current working directory
            output_dir = os.path.join(os.getcwd(), "output")
            
            # Create output directory if it doesn't exist
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Build full file path
            full_path = os.path.join(output_dir, file_path)
            
            # Create parent directories if needed
            parent_dir = os.path.dirname(full_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)
            
            # Write file
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            if not quiet:
                print_success(f"File written: {full_path}")
            return True
        except Exception as e:
            print_error(f"Error writing file to output directory: {e}")
            return False

    def output_dir_path(self, file_path: str = "") -> str:
        output_dir = os.path.join(os.getcwd(), "output")
        rel = str(file_path or "").strip().replace("\\", "/").lstrip("/")
        if rel.startswith("output/"):
            rel = rel[len("output/") :]
        if not rel:
            return output_dir
        return os.path.join(output_dir, rel)