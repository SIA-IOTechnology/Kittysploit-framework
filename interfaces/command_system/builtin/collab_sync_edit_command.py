#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Command to sync/receive module source code being edited collaboratively
"""

import os
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class CollabSyncEditCommand(BaseCommand):
    """Command to sync/receive module source code from collaborative editing"""
    
    @property
    def name(self) -> str:
        return "collab_sync_edit"
    
    @property
    def description(self) -> str:
        return "Receive and apply source code changes from collaborative editing"
    
    @property
    def usage(self) -> str:
        return "collab_sync_edit [--apply]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command receives the source code of a module that is being edited
collaboratively by another user and optionally applies it to your local file.

Options:
    --apply  - Apply the received source code to the local file (creates backup)

Examples:
    collab_sync_edit        # Show the shared source code
    collab_sync_edit --apply # Apply the shared source code to local file
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the collab_sync_edit command"""
        # Check if connected to collaboration server
        if not hasattr(self.framework, 'collab_client') or not self.framework.collab_client:
            print_error("Not connected to collaboration server")
            print_info("Use 'collab_connect' to connect first")
            return False
        
        client = self.framework.collab_client
        
        if not client.is_connected:
            print_error("Not connected to collaboration server")
            return False
        
        # Check for --apply flag
        apply_changes = '--apply' in args
        
        try:
            # Get workspace data
            workspace_data = client.get_workspace_data()
            
            if 'editing_module' not in workspace_data or not workspace_data['editing_module']:
                print_error("No module is currently being edited collaboratively")
                print_info("Ask another user to use 'collab_edit_module start' first")
                return False
            
            editing_info = workspace_data['editing_module']
            
            if not editing_info.get('editing'):
                print_error("Collaborative editing is not active")
                return False
            
            module_path = editing_info.get('module_path')
            file_path = editing_info.get('file_path')
            source_code = editing_info.get('source_code')
            edited_by = editing_info.get('edited_by', 'Unknown')
            
            if not source_code:
                print_error("No source code available in shared module")
                return False
            
            print_info(f"Module '{module_path}' is being edited by {edited_by}")
            
            if apply_changes:
                # Apply the changes
                if not file_path or not os.path.exists(file_path):
                    print_error(f"Module file not found: {file_path}")
                    return False
                
                # Create backup
                backup_path = f"{file_path}.backup"
                with open(file_path, 'r', encoding='utf-8') as f:
                    original_content = f.read()
                
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(original_content)
                
                print_info(f"Backup created: {backup_path}")
                
                # Apply new content
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(source_code)
                
                print_success(f"Source code applied to {file_path}")
                print_warning("Note: You may need to reload the module to see changes:")
                print_info(f"  use {module_path}")
                
                return True
            else:
                # Just show the source code
                print_info(f"Source code from {edited_by}:")
                print_info("-" * 60)
                print(source_code)
                print_info("-" * 60)
                print_info("Use 'collab_sync_edit --apply' to apply these changes")
                
                return True
                
        except Exception as e:
            print_error(f"Error syncing edit: {e}")
            return False

