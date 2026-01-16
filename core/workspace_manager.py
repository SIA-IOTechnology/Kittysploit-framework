#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Workspace Manager - Manages workspaces entirely in database
"""

from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from core.models.models import Workspace, Host, Task, Note, Loot
from core.db_manager import DatabaseManager
from core.output_handler import print_info, print_success, print_error, print_warning
from datetime import datetime

class WorkspaceManager:
    """Manages workspaces entirely in database"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.current_workspace: Optional[Workspace] = None
    
    def create_workspace(self, name: str, description: str = None) -> bool:
        """
        Create a new workspace
        
        Args:
            name: Name of the workspace
            description: Description of the workspace
            
        Returns:
            bool: True if workspace was created successfully, False otherwise
        """
        try:
            session = self.db_manager.get_session("default")
            if not session:
                print_error("Failed to get database session")
                return False
            
            # Check if workspace already exists
            existing = session.query(Workspace).filter(Workspace.name == name).first()
            if existing:
                print_error(f"Workspace '{name}' already exists")
                return False
            
            # Create new workspace
            workspace = Workspace(
                name=name,
                description=description or f"Workspace {name}",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            session.add(workspace)
            session.commit()
            
            print_success(f"Workspace '{name}' created successfully")
            return True
            
        except Exception as e:
            print_error(f"Error creating workspace '{name}': {str(e)}")
            return False
    
    def delete_workspace(self, name: str, force: bool = False) -> bool:
        """
        Delete a workspace
        
        Args:
            name: Name of the workspace to delete
            force: Force deletion without confirmation
            
        Returns:
            bool: True if workspace was deleted successfully, False otherwise
        """
        try:
            session = self.db_manager.get_session("default")
            if not session:
                print_error("Failed to get database session")
                return False
            
            workspace = session.query(Workspace).filter(Workspace.name == name).first()
            if not workspace:
                print_error(f"Workspace '{name}' not found")
                return False
            
            # Check if it's the current workspace
            if self.current_workspace and self.current_workspace.name == name:
                print_warning(f"Cannot delete current workspace '{name}'. Switch to another workspace first.")
                return False
            
            # Check if workspace has data
            host_count = session.query(Host).filter(Host.workspace_id == workspace.id).count()
            task_count = session.query(Task).filter(Task.workspace_id == workspace.id).count()
            note_count = session.query(Note).filter(Note.workspace_id == workspace.id).count()
            loot_count = session.query(Loot).filter(Loot.workspace_id == workspace.id).count()
            
            total_items = host_count + task_count + note_count + loot_count
            
            if total_items > 0 and not force:
                print_warning(f"Workspace '{name}' contains {total_items} items. Use --force to delete anyway.")
                return False
            
            # Delete workspace (cascade will handle related data)
            session.delete(workspace)
            session.commit()
            
            print_success(f"Workspace '{name}' deleted successfully")
            return True
            
        except Exception as e:
            print_error(f"Error deleting workspace '{name}': {str(e)}")
            return False
    
    def list_workspaces(self) -> List[Workspace]:
        """
        List all workspaces
        
        Returns:
            List[Workspace]: List of all workspaces
        """
        try:
            session = self.db_manager.get_session("default")
            if not session:
                print_error("Failed to get database session")
                return []
            
            workspaces = session.query(Workspace).filter(Workspace.is_active == True).all()
            return workspaces
            
        except Exception as e:
            print_error(f"Error listing workspaces: {str(e)}")
            return []
    
    def switch_workspace(self, name: str) -> bool:
        """
        Switch to a workspace
        
        Args:
            name: Name of the workspace to switch to
            
        Returns:
            bool: True if workspace was switched successfully, False otherwise
        """
        try:
            session = self.db_manager.get_session("default")
            if not session:
                print_error("Failed to get database session")
                return False
            
            workspace = session.query(Workspace).filter(Workspace.name == name).first()
            if not workspace:
                print_error(f"Workspace '{name}' not found")
                return False

            # Detach the instance from the session so it won't get expired/invalidated
            # when the scoped session is later removed (prevents "Instance is not bound
            # to a Session" errors when reading attributes like workspace.name).
            try:
                session.expunge(workspace)
            except Exception:
                pass

            self.current_workspace = workspace
            print_success(f"Switched to workspace '{name}'")
            return True
            
        except Exception as e:
            print_error(f"Error switching to workspace '{name}': {str(e)}")
            return False
    
    def get_current_workspace(self) -> Optional[Workspace]:
        """
        Get the current workspace
        
        Returns:
            Optional[Workspace]: Current workspace or None
        """
        return self.current_workspace
    
    def get_workspace_stats(self, name: str = None) -> Dict[str, int]:
        """
        Get statistics for a workspace
        
        Args:
            name: Name of the workspace (uses current if None)
            
        Returns:
            Dict[str, int]: Statistics dictionary
        """
        try:
            if name is None:
                if not self.current_workspace:
                    return {}
                workspace = self.current_workspace
            else:
                session = self.db_manager.get_session("default")
                if not session:
                    return {}
                workspace = session.query(Workspace).filter(Workspace.name == name).first()
                if not workspace:
                    return {}
            
            session = self.db_manager.get_session("default")
            if not session:
                return {}
            
            stats = {
                'hosts': session.query(Host).filter(Host.workspace_id == workspace.id).count(),
                'tasks': session.query(Task).filter(Task.workspace_id == workspace.id).count(),
                'notes': session.query(Note).filter(Note.workspace_id == workspace.id).count(),
                'loot': session.query(Loot).filter(Loot.workspace_id == workspace.id).count()
            }
            
            return stats
            
        except Exception as e:
            print_error(f"Error getting workspace stats: {str(e)}")
            return {}
    
    def init_default_workspace(self) -> bool:
        """
        Initialize the default workspace if it doesn't exist
        
        Returns:
            bool: True if default workspace was initialized successfully, False otherwise
        """
        try:
            session = self.db_manager.get_session("default")
            if not session:
                print_error("Failed to get database session")
                return False
            
            # Check if default workspace exists
            default_workspace = session.query(Workspace).filter(Workspace.name == "default").first()
            if not default_workspace:
                # Create default workspace
                default_workspace = Workspace(
                    name="default",
                    description="Default workspace",
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                
                session.add(default_workspace)
                session.commit()
                
                print_success("Default workspace created")
            
            # Set as current workspace
            try:
                session.expunge(default_workspace)
            except Exception:
                pass
            self.current_workspace = default_workspace
            return True
            
        except Exception as e:
            print_error(f"Error initializing default workspace: {str(e)}")
            return False
