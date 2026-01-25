#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from contextlib import contextmanager
from sqlalchemy import create_engine, text, inspect
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
            
            # Store engine temporarily for migration
            self.engines[workspace] = engine
            
            # Migrate modules table constraint if needed (to include 'workflow')
            self.migrate_modules_table_constraint(workspace)
            
            # Set encryption manager for encrypted fields
            if self.encryption_manager:
                self._setup_encryption_for_models()
            
            # Create session factory
            session_factory = sessionmaker(bind=engine, expire_on_commit=False)
            session = scoped_session(session_factory)
            
            # Store session
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
    
    def migrate_modules_table_constraint(self, workspace: str = "default") -> bool:
        """Migrate the modules table to update the CHECK constraint to include 'workflow'
        
        This is needed because SQLite doesn't support modifying CHECK constraints.
        We recreate the table with the correct constraint.
        
        Args:
            workspace: Name of the workspace
            
        Returns:
            bool: True if migration was successful, False otherwise
        """
        try:
            engine = self.engines.get(workspace)
            if not engine:
                # Initialize workspace if not already done
                if not self.init_workspace_db(workspace):
                    return False
                engine = self.engines[workspace]
            
            # Check if modules table exists
            inspector = inspect(engine)
            if 'modules' not in inspector.get_table_names():
                # Table doesn't exist, create it with correct constraint
                Base.metadata.create_all(engine)
                return True
            
            # Check if constraint already includes 'workflow'
            with engine.connect() as conn:
                # Get the CREATE TABLE statement
                result = conn.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name='modules'"))
                create_sql = result.fetchone()
                if create_sql and create_sql[0]:
                    sql_str = create_sql[0]
                    # Check if workflow is already in the constraint
                    if "'workflow'" in sql_str or '"workflow"' in sql_str:
                        # Constraint already updated
                        return True
            
            # Need to migrate: recreate table with correct constraint
            with engine.begin() as conn:
                # Get column names from the existing table
                result = conn.execute(text("PRAGMA table_info(modules)"))
                columns_info = result.fetchall()
                column_names = [col[1] for col in columns_info]  # Column name is at index 1
                
                # Get all indexes associated with modules table BEFORE renaming
                result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='modules'"))
                module_indexes = [row[0] for row in result.fetchall() if row[0] and not row[0].startswith('sqlite_')]
                
                # Create backup table
                conn.execute(text("DROP TABLE IF EXISTS modules_backup"))
                conn.execute(text("ALTER TABLE modules RENAME TO modules_backup"))
                
                # Drop all indexes that were associated with modules table
                # These indexes still exist globally and will conflict when we create the new table
                for idx_name in module_indexes:
                    try:
                        conn.execute(text(f'DROP INDEX IF EXISTS "{idx_name}"'))
                    except:
                        pass  # Ignore errors - index might not exist
                
                # Also check for any indexes that might have been created with specific names
                # SQLAlchemy creates indexes like: ix_modules_cve, ix_modules_name, idx_module_type_active
                result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='index'"))
                all_indexes = [row[0] for row in result.fetchall() if row[0] and not row[0].startswith('sqlite_')]
                for idx_name in all_indexes:
                    # Drop indexes that match SQLAlchemy naming patterns for modules table
                    if any(pattern in idx_name for pattern in ['ix_modules_', 'idx_module_']):
                        try:
                            conn.execute(text(f'DROP INDEX IF EXISTS "{idx_name}"'))
                        except:
                            pass
                
                # Create new table with correct constraint
                from core.models.models import Module
                Module.__table__.create(engine)
                
                # Copy data back using INSERT INTO ... SELECT FROM
                if column_names:
                    col_names = ', '.join(f'"{col}"' for col in column_names)
                    copy_sql = f'INSERT INTO modules ({col_names}) SELECT {col_names} FROM modules_backup'
                    conn.execute(text(copy_sql))
                
                # Drop backup table (this will also drop any remaining indexes associated with it)
                conn.execute(text("DROP TABLE modules_backup"))
            
            return True
            
        except Exception as e:
            print(f"Error migrating modules table constraint: {str(e)}")
            # Try to restore from backup if migration failed
            try:
                engine = self.engines.get(workspace)
                if engine:
                    with engine.begin() as conn:
                        # Check if backup exists
                        inspector = inspect(engine)
                        if 'modules_backup' in inspector.get_table_names():
                            # Restore from backup
                            conn.execute(text("DROP TABLE IF EXISTS modules"))
                            conn.execute(text("ALTER TABLE modules_backup RENAME TO modules"))
            except:
                pass
            return False 
