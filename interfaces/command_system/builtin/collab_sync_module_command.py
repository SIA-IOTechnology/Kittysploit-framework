#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Command to sync/load a module shared by another collaboration user
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import os
import hashlib
from datetime import datetime

class CollabSyncModuleCommand(BaseCommand):
    """Command to sync/load a module shared by another user"""
    
    @property
    def name(self) -> str:
        return "collab_sync_module"
    
    @property
    def description(self) -> str:
        return "Load a module that was shared by another user in the collaboration workspace"
    
    @property
    def usage(self) -> str:
        return "collab_sync_module [--apply-code]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command loads the module that was most recently shared by another user
in the collaboration workspace. It will:
- Load the module using 'use'
- Set all the options to match the shared module
- Create or update the module file if source code is included
- Display information about who shared it

Options:
    --apply-code    Automatically apply code changes without prompting
                    (useful when shared code is newer than local file)

Examples:
    collab_sync_module              # Load the shared module (prompt for file changes)
    collab_sync_module --apply-code # Load and automatically apply code changes
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the collab_sync_module command"""
        # Parse arguments
        apply_code = '--apply-code' in args if args else False
        
        # Check if connected to collaboration server
        if not hasattr(self.framework, 'collab_client') or not self.framework.collab_client:
            print_error("Not connected to collaboration server")
            print_info("Use 'collab_connect' to connect first")
            return False
        
        client = self.framework.collab_client
        
        if not client.is_connected:
            print_error("Not connected to collaboration server")
            return False
        
        try:
            # Get shared module from workspace data
            shared_module = client.get_shared_module()
            
            if not shared_module:
                print_error("No module has been shared in this workspace")
                print_info("Ask another user to use 'collab_share_module' to share a module")
                return False
            
            module_path = shared_module.get('module_path')
            file_path = shared_module.get('file_path')
            module_info = shared_module.get('module_info', {})
            module_options = shared_module.get('module_options', {})
            shared_by = shared_module.get('shared_by', 'Unknown')
            source_code = shared_module.get('source_code')
            is_new = shared_module.get('is_new', False)
            shared_timestamp = shared_module.get('timestamp')
            
            if not module_path:
                print_error("Invalid shared module data: missing module path")
                return False
            
            # Normalize file_path: convert dots to slashes if needed
            if file_path and '.' in file_path and '/' not in file_path:
                # Likely in Python format, convert to file format
                file_path = file_path.replace('.', '/').replace('\\', '/')
                if not file_path.startswith('modules/'):
                    file_path = f"modules/{file_path}"
                if not file_path.endswith('.py'):
                    file_path = f"{file_path}.py"
            
            print_info(f"Loading module shared by {shared_by}: {module_path}")
            
            # Handle source code if available
            if source_code and file_path:
                should_write_file = False
                
                # Check if file exists locally
                if os.path.exists(file_path):
                    if is_new:
                        print_warning(f"File exists locally but was marked as new by {shared_by}")
                        print_info("This might be a different module with the same path")
                    
                    # Compare file content hash
                    local_hash = self._calculate_file_hash(file_path)
                    shared_hash = hashlib.md5(source_code.encode('utf-8')).hexdigest()
                    
                    if local_hash == shared_hash:
                        print_info("Local file matches shared code (no changes needed)")
                    else:
                        print_warning("Local file differs from shared code")
                        
                        # Compare timestamps if available
                        if shared_timestamp:
                            try:
                                shared_time = datetime.fromisoformat(shared_timestamp)
                                local_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                                
                                if shared_time > local_mtime:
                                    print_info(f"Shared code is newer (shared: {shared_time}, local: {local_mtime})")
                                    if apply_code:
                                        should_write_file = True
                                    else:
                                        print_warning("Use --apply-code to overwrite with shared code")
                                        print_info("Or use 'collab_sync_edit' for collaborative editing")
                                else:
                                    print_info(f"Local file is newer (local: {local_mtime}, shared: {shared_time})")
                                    print_warning("Skipping file write to preserve local changes")
                            except Exception as e:
                                print_warning(f"Could not compare timestamps: {e}")
                                if apply_code:
                                    should_write_file = True
                                else:
                                    response = input(f"Overwrite local file {file_path}? [y/N]: ").strip().lower()
                                    should_write_file = (response == 'y')
                        else:
                            if apply_code:
                                should_write_file = True
                            else:
                                response = input(f"Overwrite local file {file_path}? [y/N]: ").strip().lower()
                                should_write_file = (response == 'y')
                else:
                    # File doesn't exist - create it
                    print_info(f"Creating new module file: {file_path}")
                    should_write_file = True
                
                # Write file if needed
                if should_write_file:
                    try:
                        # Create directory if needed
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        
                        # Write file
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(source_code)
                        
                        print_success(f"File written: {file_path}")
                    except Exception as e:
                        print_error(f"Failed to write file: {e}")
                        return False
            elif is_new and not source_code:
                print_warning("Module marked as new but no source code provided")
                print_info("You may need to create the module file manually")
            
            # Load the module using the framework's load_module
            if not self.framework.load_module(module_path):
                print_error(f"Failed to load module: {module_path}")
                return False
            
            print_success(f"Module '{module_path}' loaded")
            
            # Set module options
            if module_options:
                print_info("Setting module options...")
                options_set = 0
                for opt_name, opt_data in module_options.items():
                    opt_value = opt_data.get('value')
                    if opt_value is not None:
                        if self.framework.set_module_option(opt_name, opt_value):
                            options_set += 1
                
                if options_set > 0:
                    print_success(f"Set {options_set} option(s)")
            
            # Display module info
            if module_info:
                print_info(f"Module: {module_info.get('name', module_path)}")
                if module_info.get('description'):
                    print_info(f"Description: {module_info.get('description')}")
            
            print_success("Module synchronized successfully")
            if source_code and not apply_code and os.path.exists(file_path):
                print_info("Tip: Use 'collab_sync_module --apply-code' to automatically apply code changes")
            return True
                
        except Exception as e:
            print_error(f"Error syncing module: {e}")
            return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5()
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception as e:
            print_warning(f"Could not calculate file hash: {e}")
            return ""

