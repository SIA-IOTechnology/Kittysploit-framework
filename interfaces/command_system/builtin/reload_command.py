#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reload command implementation
Reloads the current module to pick up code changes
"""

import importlib
import sys
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class ReloadCommand(BaseCommand):
    """Command to reload the current module"""
    
    @property
    def name(self) -> str:
        return "reload"
    
    @property
    def description(self) -> str:
        return "Reload the current module to pick up code changes"
    
    @property
    def usage(self) -> str:
        return "reload"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command reloads the currently selected module, allowing you to pick up
any code changes you've made to the module file without restarting KittySploit.

Note: This will reset all module options to their default values.

Examples:
    reload                    # Reload the current module
        """
    
    def _get_module_path(self, module):
        """Get the module path from the module instance"""
        module_path = None
        
        # Try from __module__ attribute
        if hasattr(module, '__module__'):
            module_path = module.__module__
            if module_path.startswith('modules.'):
                module_path = module_path.replace('modules.', '')
        
        # Try from module loader cache
        if not module_path and hasattr(self.framework, 'module_loader'):
            for path, loaded_module in self.framework.module_loader.modules_cache.items():
                if loaded_module == module:
                    module_path = path
                    break
        
        # Try from discovered modules by matching name
        if not module_path and hasattr(self.framework, 'module_loader'):
            try:
                discovered_modules = self.framework.module_loader.discover_modules()
                for path, file_path in discovered_modules.items():
                    try:
                        # Try to match by module name
                        if hasattr(module, 'name') and module.name:
                            # Load module temporarily to check name
                            temp_module = self.framework.module_loader.load_module(path, load_only=True, silent=True)
                            if temp_module and hasattr(temp_module, 'name') and temp_module.name == module.name:
                                module_path = path
                                break
                    except:
                        continue
            except Exception as e:
                pass
        
        return module_path
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the reload command"""
        try:
            # Check if a module is selected
            if not hasattr(self.framework, 'current_module') or not self.framework.current_module:
                print_error("No module selected. Use 'use <module>' first.")
                return False
            
            current_module = self.framework.current_module
            
            # Get the module path
            module_path = self._get_module_path(current_module)
            
            if not module_path:
                print_error("Could not determine module path. Cannot reload.")
                print_info("Try using 'use <module_path>' again to reload the module.")
                return False
            
            print_info(f"Reloading module: {module_path}")
            
            # Build the import path
            import_path = module_path.replace("/", ".")
            if import_path.startswith("."):
                import_path = import_path[1:]
            
            full_import_path = f"modules.{import_path}"
            
            # Check if module is already imported
            if full_import_path not in sys.modules:
                print_warning(f"Module {full_import_path} is not in sys.modules. Loading it first...")
                # Load it first
                try:
                    importlib.import_module(full_import_path)
                except Exception as e:
                    print_error(f"Failed to import module: {e}")
                    return False
            
            # Reload the module
            try:
                module = sys.modules[full_import_path]
                importlib.reload(module)
                print_success("Module code reloaded from disk")
            except Exception as e:
                print_error(f"Failed to reload module: {e}")
                import traceback
                print_error(f"Traceback: {traceback.format_exc()}")
                return False
            
            # Create a new instance of the Module class
            try:
                import inspect
                sig = inspect.signature(module.Module.__init__)
                if 'framework' in sig.parameters:
                    new_instance = module.Module(framework=self.framework)
                else:
                    new_instance = module.Module()
            except (TypeError, AttributeError):
                # Fallback to default instantiation
                new_instance = module.Module()
            
            # Set framework reference
            if self.framework:
                new_instance.framework = self.framework
            
            # Set module name if not defined
            if not hasattr(new_instance, 'name') or not new_instance.name:
                new_instance.name = module_path
            
            # Update the cache
            if hasattr(self.framework, 'module_loader'):
                self.framework.module_loader.modules_cache[module_path] = new_instance
            
            # Replace current module
            self.framework.current_module = new_instance
            
            print_success(f"Module '{new_instance.name}' reloaded successfully")
            print_info("Note: All module options have been reset to their default values")
            
            return True
            
        except Exception as e:
            print_error(f"Error reloading module: {e}")
            import traceback
            print_error(f"Traceback: {traceback.format_exc()}")
            return False

