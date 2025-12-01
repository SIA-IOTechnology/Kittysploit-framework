#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Sync Manager - Handles synchronization of modules between filesystem and database
"""

import os
import json
import hashlib
import threading
import time
from datetime import datetime
from typing import List, Dict, Optional, Set
from pathlib import Path

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from core.db_manager import DatabaseManager
from core.models.models import Module
from core.output_handler import print_info, print_success, print_error, print_warning
from core.utils.exceptions import KittyException


class ModuleSyncManager:
    """Manages synchronization of modules between filesystem and database"""
    
    def __init__(self, db_manager: DatabaseManager, workspace: str = "default"):
        self.db_manager = db_manager
        self.workspace = workspace
        self.module_loader = None  # Lazy import to avoid circular dependency
        self.sync_thread = None
        self.is_syncing = False
        self.sync_interval = 300  # 5 minutes
        self.last_sync = None
        self._lock = threading.Lock()
    
    def _get_module_loader(self):
        """Get ModuleLoader instance with lazy import"""
        if self.module_loader is None:
            from core.module_loader import ModuleLoader
            self.module_loader = ModuleLoader()
        return self.module_loader
        
    def start_background_sync(self, interval: int = 300):
        """Start background synchronization thread"""
        if self.sync_thread and self.sync_thread.is_alive():
            print_warning("Background sync is already running")
            return
            
        self.sync_interval = interval
        self.sync_thread = threading.Thread(target=self._background_sync_loop, daemon=True)
        self.sync_thread.start()
        print_success(f"Background module sync started (interval: {interval}s)")
    
    def stop_background_sync(self):
        """Stop background synchronization thread"""
        self.is_syncing = False
        if self.sync_thread and self.sync_thread.is_alive():
            self.sync_thread.join(timeout=10)
        print_info("Background module sync stopped")
    
    def _background_sync_loop(self):
        """Background synchronization loop"""
        print_info("Module sync background thread started")
        
        while self.is_syncing:
            try:
                self.sync_modules()
                time.sleep(self.sync_interval)
            except Exception as e:
                print_error(f"Error in background sync: {e}")
                time.sleep(60)  # Wait 1 minute before retry
    
    def sync_modules(self, force: bool = False) -> Dict[str, int]:
        """Synchronize modules between filesystem and database"""
        with self._lock:
            if self.is_syncing and not force:
                print_warning("Sync already in progress")
                return {}
                
            self.is_syncing = True
            start_time = time.time()
            
            try:
                print_info("Starting module synchronization...")
                
                # Get modules from filesystem
                fs_modules = self._get_filesystem_modules()
                print_info(f"Found {len(fs_modules)} modules in filesystem")
                
                # Get modules from database
                db_modules = self._get_database_modules()
                print_info(f"Found {len(db_modules)} modules in database")
                
                # Calculate differences
                stats = self._calculate_sync_stats(fs_modules, db_modules)
                
                # Perform synchronization
                if stats['to_add'] or stats['to_update'] or stats['to_remove']:
                    self._perform_sync(fs_modules, db_modules, stats)
                else:
                    print_info("No changes detected")
                
                self.last_sync = datetime.utcnow()
                elapsed = time.time() - start_time
                
                print_success(f"Module sync completed in {elapsed:.2f}s")
                print_info(f"Added: {stats['added']}, Updated: {stats['updated']}, Removed: {stats['removed']}")
                
                return stats
                
            except Exception as e:
                print_error(f"Error during module sync: {e}")
                raise
            finally:
                self.is_syncing = False
    
    def _get_filesystem_modules(self) -> Dict[str, Dict]:
        """Get all modules from filesystem"""
        modules = {}
        
        try:
            # Discover modules using ModuleLoader
            discovered_modules = self._get_module_loader().discover_modules()
            
            for module_path, file_path in discovered_modules.items():
                try:
                    # Debug: print paths
                    print_info(f"Processing module: {module_path} -> {file_path}")
                    
                    # Get detailed module information
                    detailed_info = self._get_module_loader().get_module_info(module_path)
                    
                    # Calculate file hash for change detection
                    file_hash = self._calculate_file_hash(file_path)
                    
                    modules[module_path] = {
                        'path': module_path,
                        'name': detailed_info.get('name', ''),
                        'description': detailed_info.get('description', ''),
                        'type': detailed_info.get('type', ''),
                        'author': detailed_info.get('author', ''),
                        'version': detailed_info.get('version', ''),
                        'cve': detailed_info.get('cve', ''),
                        'tags': json.dumps(detailed_info.get('tags', [])),
                        'references': json.dumps(detailed_info.get('references', [])),
                        'options': json.dumps(detailed_info.get('options', {})),
                        'file_hash': file_hash,
                        'file_mtime': os.path.getmtime(file_path)
                    }
                    
                except Exception as e:
                    print_warning(f"Error processing module {module_path}: {e}")
                    continue
                    
        except Exception as e:
            print_error(f"Error discovering filesystem modules: {e}")
            
        return modules
    
    def _get_database_modules(self) -> Dict[str, Dict]:
        """Get all modules from database"""
        modules = {}
        
        try:
            with self.db_manager.session_scope(self.workspace) as session:
                db_modules = session.query(Module).all()
                
                for module in db_modules:
                    modules[module.path] = {
                        'id': module.id,
                        'path': module.path,
                        'name': module.name,
                        'description': module.description,
                        'type': module.type,
                        'author': module.author,
                        'version': module.version,
                        'cve': module.cve,
                        'references': module.references,
                        'options': module.options,
                        'file_hash': getattr(module, 'file_hash', None),
                        'file_mtime': getattr(module, 'file_mtime', None),
                        'updated_at': module.updated_at
                    }
                    
        except Exception as e:
            print_error(f"Error getting database modules: {e}")
            
        return modules
    
    def _calculate_sync_stats(self, fs_modules: Dict, db_modules: Dict) -> Dict[str, int]:
        """Calculate synchronization statistics"""
        fs_paths = set(fs_modules.keys())
        db_paths = set(db_modules.keys())
        
        # Modules to add (in filesystem but not in database)
        to_add = fs_paths - db_paths
        
        # Modules to remove (in database but not in filesystem)
        to_remove = db_paths - fs_paths
        
        # Modules to update (in both but different)
        to_update = set()
        for path in fs_paths & db_paths:
            fs_module = fs_modules[path]
            db_module = db_modules[path]
            
            # Check if module needs update
            if (fs_module['file_hash'] != db_module.get('file_hash') or
                fs_module['file_mtime'] != db_module.get('file_mtime')):
                to_update.add(path)
        
        return {
            'to_add': len(to_add),
            'to_update': len(to_update),
            'to_remove': len(to_remove),
            'added': 0,
            'updated': 0,
            'removed': 0
        }
    
    def _perform_sync(self, fs_modules: Dict, db_modules: Dict, stats: Dict):
        """Perform the actual synchronization"""
        try:
            with self.db_manager.session_scope(self.workspace) as session:
                # Add new modules
                for path in set(fs_modules.keys()) - set(db_modules.keys()):
                    self._add_module_to_db(session, fs_modules[path])
                    stats['added'] += 1
                
                # Update existing modules
                for path in set(fs_modules.keys()) & set(db_modules.keys()):
                    fs_module = fs_modules[path]
                    db_module = db_modules[path]
                    
                    if (fs_module['file_hash'] != db_module.get('file_hash') or
                        fs_module['file_mtime'] != db_module.get('file_mtime')):
                        self._update_module_in_db(session, db_module['id'], fs_module)
                        stats['updated'] += 1
                
                # Remove deleted modules
                for path in set(db_modules.keys()) - set(fs_modules.keys()):
                    self._remove_module_from_db(session, db_modules[path]['id'])
                    stats['removed'] += 1
                
                session.commit()
                
        except Exception as e:
            print_error(f"Error performing sync: {e}")
            raise
    
    def _add_module_to_db(self, session: Session, module_data: Dict):
        """Add a new module to the database"""
        try:
            module = Module(
                name=module_data['name'],
                description=module_data['description'],
                type=module_data['type'],
                path=module_data['path'],
                author=module_data['author'],
                version=module_data['version'],
                cve=module_data['cve'],
                tags=module_data['tags'],
                references=module_data['references'],
                options=module_data['options'],
                file_hash=module_data['file_hash'],
                file_mtime=module_data['file_mtime']
            )
            
            session.add(module)
            print_info(f"Added module: {module_data['name']} ({module_data['type']})")
            
        except Exception as e:
            print_error(f"Error adding module {module_data['name']}: {e}")
            raise
    
    def _update_module_in_db(self, session: Session, module_id: int, module_data: Dict):
        """Update an existing module in the database"""
        try:
            module = session.query(Module).filter(Module.id == module_id).first()
            if module:
                module.name = module_data['name']
                module.description = module_data['description']
                module.type = module_data['type']
                module.author = module_data['author']
                module.version = module_data['version']
                module.cve = module_data['cve']
                module.tags = module_data['tags']
                module.references = module_data['references']
                module.options = module_data['options']
                module.file_hash = module_data['file_hash']
                module.file_mtime = module_data['file_mtime']
                module.updated_at = datetime.utcnow()
                
                print_info(f"Updated module: {module_data['name']} ({module_data['type']})")
                
        except Exception as e:
            print_error(f"Error updating module {module_data['name']}: {e}")
            raise
    
    def _remove_module_from_db(self, session: Session, module_id: int):
        """Remove a module from the database"""
        try:
            module = session.query(Module).filter(Module.id == module_id).first()
            if module:
                print_info(f"Removed module: {module.name} ({module.type})")
                session.delete(module)
                
        except Exception as e:
            print_error(f"Error removing module {module_id}: {e}")
            raise
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""
    
    def search_modules(self, query: str = "", module_type: str = "", 
                      author: str = "", cve: str = "", tags: str = "", limit: int = 100) -> List[Dict]:
        """Search modules in database"""
        try:
            with self.db_manager.session_scope(self.workspace) as session:
                query_obj = session.query(Module).filter(Module.is_active == True)
                
                # Apply filters
                if query:
                    query_obj = query_obj.filter(
                        or_(
                            Module.name.ilike(f"%{query}%"),
                            Module.description.ilike(f"%{query}%")
                        )
                    )
                
                if module_type:
                    query_obj = query_obj.filter(Module.type == module_type)
                
                if author:
                    query_obj = query_obj.filter(Module.author.ilike(f"%{author}%"))
                
                if cve:
                    query_obj = query_obj.filter(Module.cve.ilike(f"%{cve}%"))
                
                if tags:
                    query_obj = query_obj.filter(Module.tags.ilike(f"%{tags}%"))
                
                # Apply limit and order
                modules = query_obj.order_by(Module.name).limit(limit).all()
                
                return [module.to_dict() for module in modules]
                
        except Exception as e:
            print_error(f"Error searching modules: {e}")
            return []
    
    def get_module_by_path(self, path: str) -> Optional[Dict]:
        """Get module by path from database"""
        try:
            with self.db_manager.session_scope(self.workspace) as session:
                module = session.query(Module).filter(
                    and_(Module.path == path, Module.is_active == True)
                ).first()
                
                return module.to_dict() if module else None
                
        except Exception as e:
            print_error(f"Error getting module by path {path}: {e}")
            return None
    
    def get_module_stats(self) -> Dict[str, int]:
        """Get module statistics"""
        try:
            with self.db_manager.session_scope(self.workspace) as session:
                total = session.query(Module).filter(Module.is_active == True).count()
                
                stats = {'total': total}
                
                # Count by type
                for module_type in ['exploits', 'auxiliary', 'payloads', 'listeners', 'post', 'scanner', 'encoder']:
                    count = session.query(Module).filter(
                        and_(Module.type == module_type, Module.is_active == True)
                    ).count()
                    stats[module_type] = count
                
                return stats
                
        except Exception as e:
            print_error(f"Error getting module stats: {e}")
            return {}
    
    def get_sync_status(self) -> Dict:
        """Get synchronization status"""
        return {
            'is_syncing': self.is_syncing,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'sync_interval': self.sync_interval,
            'background_sync_active': self.sync_thread and self.sync_thread.is_alive()
        }
