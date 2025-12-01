#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from core.models.models import Base
from typing import Dict, Optional

class DatabaseManager:
    """Manages database connections and sessions for workspaces"""
    
    def __init__(self, workspaces_dir: str, encryption_manager=None):
        self.workspaces_dir = workspaces_dir
        self.engines: Dict[str, object] = {}
        self.sessions: Dict[str, object] = {}
        self.encryption_manager = encryption_manager
        
    def init_workspace_db(self, workspace: str) -> bool:
        """Initialize database for a workspace
        
        Args:
            workspace: Name of the workspace
            
        Returns:
            bool: True if database was initialized successfully, False otherwise
        """
        try:
            db_path = os.path.join("database", "database.db")
            
            # Create database directory if it doesn't exist
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            # Create SQLite database engine with larger pool size
            engine = create_engine(
                f'sqlite:///{db_path}',
                echo=False,
                pool_size=20,
                max_overflow=40,
                pool_pre_ping=True,  # Vérifie les connexions avant utilisation
                pool_recycle=3600  # Recycle les connexions après 1 heure
            )
            
            # Import registry models to ensure they're registered with Base
            try:
                import core.registry  # noqa: F401
            except ImportError:
                pass  # Registry not available, continue without it
            
            # Create all tables
            Base.metadata.create_all(engine)
            
            # Set encryption manager for encrypted fields
            if self.encryption_manager:
                self._setup_encryption_for_models()
            
            # Create session factory
            session_factory = sessionmaker(bind=engine, expire_on_commit=False)
            session = scoped_session(session_factory)
            
            # Store engine and session
            self.engines[workspace] = engine
            self.sessions[workspace] = session
            
            return True
        except Exception as e:
            print(f"Error initializing database for workspace {workspace}: {str(e)}")
            return False
    
    def _setup_encryption_for_models(self):
        """Setup encryption manager for all encrypted fields in models"""
        if not self.encryption_manager:
            return
        
        # Import models that use encryption
        from core.models.models import Credential, Loot, Session, CommandHistory
        
        # Set encryption manager for each model
        for model_class in [Credential, Loot, Session, CommandHistory]:
            if hasattr(model_class, 'set_encryption_manager'):
                model_class.set_encryption_manager(self.encryption_manager)
    
    def set_encryption_manager(self, encryption_manager):
        """Set encryption manager and update existing models"""
        self.encryption_manager = encryption_manager
        self._setup_encryption_for_models()
    
    def get_session(self, workspace: str) -> Optional[object]:
        """Get database session for a workspace
        
        Args:
            workspace: Name of the workspace
            
        Returns:
            Optional[object]: Database session or None if workspace doesn't exist
        """
        if workspace not in self.sessions:
            if not self.init_workspace_db(workspace):
                return None
        return self.sessions[workspace]
    
    @contextmanager
    def session_scope(self, workspace: str):
        """Provide a transactional scope around a series of operations
        
        Args:
            workspace: Name of the workspace
            
        Yields:
            Session: Database session
        """
        session = self.get_session(workspace)
        if not session:
            raise Exception(f"Failed to get session for workspace {workspace}")
        
        try:
            yield session
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.remove()
    
    @contextmanager
    def get_db_session(self, workspace: str = None):
        """Get database session with context manager (alias for session_scope)
        
        Args:
            workspace: Name of the workspace (optional, uses default if not provided)
            
        Yields:
            Session: Database session
        """
        if workspace is None:
            workspace = "default"
        return self.session_scope(workspace)
    
    def close_workspace_db(self, workspace: str) -> bool:
        """Close database connection for a workspace
        
        Args:
            workspace: Name of the workspace
            
        Returns:
            bool: True if connection was closed successfully, False otherwise
        """
        try:
            if workspace in self.sessions:
                self.sessions[workspace].remove()
                del self.sessions[workspace]
            
            if workspace in self.engines:
                self.engines[workspace].dispose()
                del self.engines[workspace]
            
            return True
        except Exception as e:
            print(f"Error closing database for workspace {workspace}: {str(e)}")
            return False
    
    def close_all(self):
        """Close all database connections"""
        for workspace in list(self.sessions.keys()):
            self.close_workspace_db(workspace) 
