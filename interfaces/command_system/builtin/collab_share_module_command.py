#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Command to share the current module with other collaboration users
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import json
import os
from datetime import datetime

class CollabShareModuleCommand(BaseCommand):
    """Command to share the current module with collaboration users"""
    
    @property
    def name(self) -> str:
        return "collab_share_module"
    
    @property
    def description(self) -> str:
        return "Share the current module (path, options, and source code) with other users in the collaboration workspace"
    
    @property
    def usage(self) -> str:
        return "collab_share_module"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command shares the currently loaded module with all users in the same
collaboration workspace. It sends:
- Module path and file path
- Module source code (if file exists)
- Module options and their current values
- Module information (name, description, etc.)
- Timestamp for conflict resolution

Other users can then use 'collab_sync_module' to load the same module with
the same options and source code. The system will automatically handle:
- Creating new module files if they don't exist
- Comparing file hashes to detect changes
- Timestamp-based conflict resolution

Examples:
    use payloads/singles/cmd/unix/zig_reverse_tcp
    set lhost 192.168.1.100
    set lport 4444
    collab_share_module  # Share the module with other users
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the collab_share_module command"""
        # Check if connected to collaboration server
        if not hasattr(self.framework, 'collab_client') or not self.framework.collab_client:
            print_error("Not connected to collaboration server")
            print_info("Use 'collab_connect' to connect first")
            return False
        
        client = self.framework.collab_client
        
        if not client.is_connected:
            print_error("Not connected to collaboration server")
            return False
        
        # Check if a module is loaded
        if not self.framework.current_module:
            print_error("No module is currently loaded")
            print_info("Use 'use <module_path>' to load a module first")
            return False
        
        try:
            # Get module information
            module = self.framework.current_module
            
            # Get module path using the same method as collab_edit_module
            module_path = self._get_module_path(module)
            
            if not module_path:
                print_warning("Could not determine module path, using module name")
                module_path = getattr(module, 'name', 'unknown')
            
            # Try to find the actual file path using discover_modules
            module_file_path = None
            if hasattr(self.framework, 'module_loader'):
                discovered_modules = self.framework.module_loader.discover_modules()
                # module_path might be in Python format (with dots) or file format (with slashes)
                # Try both formats
                if module_path in discovered_modules:
                    module_file_path = discovered_modules[module_path]
                else:
                    # Convert Python format (dots) to file format (slashes)
                    file_format_path = module_path.replace('.', '/')
                    if file_format_path in discovered_modules:
                        module_file_path = discovered_modules[file_format_path]
            
            # If not found via discover_modules, construct the path manually
            if not module_file_path:
                # Convert Python format (dots) to file format (slashes)
                file_format_path = module_path.replace('.', '/')
                module_file_path = f"modules/{file_format_path}.py"
            
            # Read source code if file exists
            source_code = None
            file_exists = os.path.exists(module_file_path)
            
            if file_exists:
                try:
                    with open(module_file_path, 'r', encoding='utf-8') as f:
                        source_code = f.read()
                except Exception as e:
                    print_warning(f"Could not read module file: {e}")
                    source_code = None
            else:
                print_warning(f"Module file not found: {module_file_path}")
                print_info("Sharing module without source code (file does not exist)")
            
            # Get module options
            module_options = {}
            if hasattr(module, 'get_options'):
                options = module.get_options()
                for opt_name, opt_data in options.items():
                    if hasattr(module, opt_name):
                        opt_value = getattr(module, opt_name)
                        # Get option info
                        opt_info = {
                            'value': opt_value,
                            'description': opt_data[1] if len(opt_data) > 1 else '',
                            'required': opt_data[2] if len(opt_data) > 2 else False,
                            'advanced': opt_data[3] if len(opt_data) > 3 else False
                        }
                        module_options[opt_name] = opt_info
            
            # Get module info
            module_info = {}
            if hasattr(module, 'get_info'):
                module_info = module.get_info()
            else:
                module_info = {
                    'name': getattr(module, 'name', 'Unknown'),
                    'description': getattr(module, 'description', ''),
                    'author': getattr(module, 'author', '')
                }
            
            # Ensure file_path uses forward slashes for cross-platform compatibility
            # and is relative to modules/ directory
            if module_file_path.startswith('modules/'):
                relative_file_path = module_file_path.replace('\\', '/')
            else:
                # If absolute path, make it relative
                relative_file_path = module_file_path.replace('\\', '/')
                if os.path.isabs(relative_file_path):
                    # Try to make it relative to modules directory
                    modules_dir = os.path.join(os.getcwd(), 'modules')
                    try:
                        relative_file_path = os.path.relpath(relative_file_path, modules_dir).replace('\\', '/')
                        if not relative_file_path.startswith('..'):
                            relative_file_path = f"modules/{relative_file_path}"
                        else:
                            relative_file_path = module_file_path.replace('\\', '/')
                    except:
                        relative_file_path = module_file_path.replace('\\', '/')
            
            # Prepare module data to share
            module_data = {
                'module_path': module_path,
                'file_path': relative_file_path,
                'module_info': module_info,
                'module_options': module_options,
                'shared_by': client.username,
                'timestamp': datetime.utcnow().isoformat(),
                'is_new': not file_exists,
                'source_code': source_code  # Include source code if available
            }
            
            # Send via workspace sync
            workspace_data = {
                'shared_module': module_data
            }
            
            if client.sync_workspace(workspace_data):
                print_success(f"Module '{module_path}' shared with collaboration workspace")
                if source_code:
                    print_info(f"Source code included ({len(source_code)} bytes)")
                else:
                    print_warning("Source code not included (file not found)")
                print_info(f"Other users can use 'collab_sync_module' to load this module")
                return True
            else:
                print_error("Failed to share module")
                return False
                
        except Exception as e:
            print_error(f"Error sharing module: {e}")
            return False
    
    def _get_module_path(self, module):
        """Get the module path from the module instance (reused from collab_edit_module)"""
        # Try to find the module path
        module_path = None
        
        # Try from __module__ attribute
        if hasattr(module, '__module__'):
            module_path = module.__module__
            if module_path.startswith('modules.'):
                module_path = module_path.replace('modules.', '')
        
        # Try from module loader cache
        if not module_path and hasattr(self.framework, 'module_loader'):
            if hasattr(self.framework.module_loader, 'modules_cache'):
                for path, loaded_module in self.framework.module_loader.modules_cache.items():
                    if loaded_module == module:
                        module_path = path
                        break
        
        # Try from loaded_modules
        if not module_path and hasattr(self.framework, 'module_loader'):
            if hasattr(self.framework.module_loader, 'loaded_modules'):
                for path, loaded_module in self.framework.module_loader.loaded_modules.items():
                    if loaded_module == module:
                        module_path = path
                        break
        
        # Try from discovered modules
        if not module_path and hasattr(self.framework, 'module_loader'):
            try:
                discovered_modules = self.framework.module_loader.discover_modules()
                for path, file_path in discovered_modules.items():
                    try:
                        temp_module = self.framework.module_loader.load_module(path, load_only=True)
                        if temp_module and hasattr(temp_module, 'name') and hasattr(module, 'name'):
                            if temp_module.name == module.name:
                                module_path = path
                                break
                    except:
                        continue
            except:
                pass
        
        return module_path

