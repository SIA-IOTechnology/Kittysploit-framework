#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Command to enable collaborative editing of a module's source code
"""

import os
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class CollabEditModuleCommand(BaseCommand):
    """Command to enable collaborative editing of the current module"""
    
    @property
    def name(self) -> str:
        return "collab_edit_module"
    
    @property
    def description(self) -> str:
        return "Share the current module's source code for collaborative editing"
    
    @property
    def usage(self) -> str:
        return "collab_edit_module [start|stop|status]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command enables collaborative editing of a module's source code.
When enabled, changes to the module file are automatically shared with
other users in the collaboration workspace.

Commands:
    start   - Start sharing the current module for collaborative editing
    stop    - Stop sharing the module
    status  - Show current collaborative editing status

Note: This requires the module to be loaded and connected to a collaboration server.
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the collab_edit_module command"""
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
        
        # Parse command
        action = args[0].lower() if args else 'status'
        
        if action == 'start':
            return self._start_collaborative_editing(client)
        elif action == 'stop':
            return self._stop_collaborative_editing(client)
        elif action == 'status':
            return self._show_status(client)
        else:
            print_error(f"Unknown action: {action}")
            print_info(f"Usage: {self.usage}")
            return False
    
    def _start_collaborative_editing(self, client):
        """Start sharing module source code for collaborative editing"""
        try:
            # Get module file path
            module = self.framework.current_module
            module_path = self._get_module_path(module)
            
            if not module_path:
                print_error("Could not determine module file path")
                return False
            
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
            
            if not os.path.exists(module_file_path):
                print_error(f"Module file not found: {module_file_path}")
                print_info("Tip: Use 'collab_sync_module --apply-code' to create the file from shared module")
                return False
            
            # Read the current file content
            with open(module_file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
            
            # Share via workspace sync with source code
            workspace_data = {
                'editing_module': {
                    'module_path': module_path,
                    'file_path': module_file_path,
                    'source_code': file_content,
                    'edited_by': client.username,
                    'editing': True
                }
            }
            
            if client.sync_workspace(workspace_data):
                # Store editing state
                if not hasattr(client, '_editing_modules'):
                    client._editing_modules = {}
                client._editing_modules[module_path] = {
                    'file_path': module_file_path,
                    'editing': True
                }
                
                print_success(f"Module '{module_path}' is now being shared for collaborative editing")
                print_info("Other users can use 'collab_sync_edit' to receive updates")
                print_warning("Note: This is a basic implementation. For real-time sync, use 'edit' and manually share changes via 'collab_share_module_code'")
                return True
            else:
                print_error("Failed to start collaborative editing")
                return False
                
        except Exception as e:
            print_error(f"Error starting collaborative editing: {e}")
            return False
    
    def _stop_collaborative_editing(self, client):
        """Stop sharing module source code"""
        try:
            if not hasattr(client, '_editing_modules') or not client._editing_modules:
                print_warning("No module is currently being edited collaboratively")
                return True
            
            # Clear editing state
            workspace_data = {
                'editing_module': None
            }
            
            if client.sync_workspace(workspace_data):
                client._editing_modules = {}
                print_success("Stopped collaborative editing")
                return True
            else:
                print_error("Failed to stop collaborative editing")
                return False
                
        except Exception as e:
            print_error(f"Error stopping collaborative editing: {e}")
            return False
    
    def _show_status(self, client):
        """Show collaborative editing status"""
        if hasattr(client, '_editing_modules') and client._editing_modules:
            print_info("Collaborative editing is active for:")
            for module_path, info in client._editing_modules.items():
                print_info(f"  - {module_path}")
        else:
            print_info("No module is currently being edited collaboratively")
        
        # Check if someone else is editing
        workspace_data = client.get_workspace_data()
        if 'editing_module' in workspace_data and workspace_data['editing_module']:
            editing_info = workspace_data['editing_module']
            if editing_info.get('edited_by') != client.username:
                print_info(f"User '{editing_info.get('edited_by')}' is editing: {editing_info.get('module_path')}")
        
        return True
    
    def _get_module_path(self, module):
        """Get the module path from the module instance"""
        # Try to find the module path
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
        
        # Try from discovered modules
        if not module_path and hasattr(self.framework, 'module_loader'):
            discovered_modules = self.framework.module_loader.discover_modules()
            for path, file_path in discovered_modules.items():
                try:
                    temp_module = self.framework.module_loader.load_module(path, load_only=True)
                    if temp_module and temp_module.name == module.name:
                        module_path = path
                        break
                except:
                    continue
        
        return module_path

