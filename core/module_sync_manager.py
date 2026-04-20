#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Sync Manager - Handles synchronization of modules between filesystem and database
"""

import os
import re
import json
import hashlib
import threading
import time
import logging
from datetime import datetime
from typing import List, Dict, Optional, Set
from pathlib import Path

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from core.db_manager import DatabaseManager
from core.models.models import Module
from core.output_handler import print_info, print_success, print_error, print_warning
from core.utils.exceptions import KittyException
from core.utils.module_static_metadata import extract_module_sync_metadata


class ModuleSyncManager:
    """Manages synchronization of modules between filesystem and database"""
    
    def __init__(self, db_manager: DatabaseManager, workspace: str = "default"):
        self.db_manager = db_manager
        self.workspace = workspace
        self.module_loader = None  # Lazy import to avoid circular dependency
        self.sync_thread = None
        self.is_syncing = False  # Flag for ongoing sync operation
        self.background_sync_active = False  # Flag for background sync loop
        self.sync_interval = 300  # 5 minutes
        self.last_sync = None
        self._lock = threading.Lock()
    
    def _get_module_loader(self):
        """Get ModuleLoader instance with lazy import"""
        if self.module_loader is None:
            from core.module_loader import ModuleLoader
            self.module_loader = ModuleLoader()
        return self.module_loader
    
    def _normalize_to_string(self, value, default='', separator=', '):
        """Normalize a value to string, handling both list and string types
        
        Args:
            value: Value to normalize (can be list, string, None, etc.)
            default: Default value if value is None or empty
            separator: Separator to use when joining lists
        
        Returns:
            str: Normalized string value
        """
        if value is None:
            return default
        elif isinstance(value, list):
            return separator.join(str(v) for v in value if v) if value else default
        elif isinstance(value, (dict, tuple)):
            # Convert complex types to JSON string
            return json.dumps(value) if value else default
        else:
            return str(value) if value else default
        
    def start_background_sync(self, interval: int = 300):
        """Start background synchronization thread"""
        if self.sync_thread and self.sync_thread.is_alive():
            print_warning("Background sync is already running")
            return
            
        self.sync_interval = interval
        self.background_sync_active = True  # Set flag before starting thread
        self.sync_thread = threading.Thread(target=self._background_sync_loop, daemon=True)
        self.sync_thread.start()
        print_success(f"Background module sync started (interval: {interval}s)")
    
    def stop_background_sync(self):
        """Stop background synchronization thread"""
        self.background_sync_active = False  # Stop the background loop
        if self.sync_thread and self.sync_thread.is_alive():
            self.sync_thread.join(timeout=10)
        print_info("Background module sync stopped")
    
    def _background_sync_loop(self):
        """Background synchronization loop"""
        print_info("Module sync background thread started")
        
        while self.background_sync_active:
            try:
                # Call sync_modules with force=True to allow it to run even if is_syncing is True
                # (which shouldn't happen, but we use force to be safe)
                self.sync_modules(force=True)
                # Sleep in small intervals to allow quick stop
                for _ in range(self.sync_interval):
                    if not self.background_sync_active:
                        break
                    time.sleep(1)
            except Exception as e:
                print_error(f"Error in background sync: {e}")
                # Sleep in small intervals to allow quick stop
                for _ in range(60):
                    if not self.background_sync_active:
                        break
                    time.sleep(1)
    
    def sync_modules(self, force: bool = False) -> Dict[str, int]:
        """Synchronize modules between filesystem and database"""
        with self._lock:
            if self.is_syncing and not force:
                print_warning("Sync already in progress")
                return {}
                
            self.is_syncing = True
            start_time = time.time()
            
            # Ensure database constraint is up to date (includes 'workflow' type)
            try:
                self.db_manager.migrate_modules_table_constraint(self.workspace)
            except Exception as e:
                print_warning(f"Could not migrate database constraint: {e}")
            
            # Temporarily suppress logging errors during sync to avoid cluttering the prompt
            root_logger = logging.getLogger()
            original_level = root_logger.level
            original_handlers_levels = {}
            for handler in root_logger.handlers:
                original_handlers_levels[handler] = handler.level
                handler.setLevel(logging.CRITICAL)  # Only show critical errors
            
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
                # Restore original logging levels
                root_logger.setLevel(original_level)
                for handler, level in original_handlers_levels.items():
                    handler.setLevel(level)
                self.is_syncing = False
    
    def _get_filesystem_modules(self) -> Dict[str, Dict]:
        """Build module list from disk via static __info__ parsing (no Python imports)."""
        modules = {}
        
        try:
            # Discover modules using ModuleLoader
            discovered_modules = self._get_module_loader().discover_modules()
            
            for module_path, file_path in discovered_modules.items():
                try:
                    # Static parse __info__ only — no import (avoids payload / dependency init spam)
                    meta = extract_module_sync_metadata(file_path)
                    default_name = module_path.split("/")[-1].replace("_", " ")
                    name = self._normalize_to_string(meta.get("name") or "") or default_name
                    if not name.strip():
                        name = default_name

                    # Calculate file hash for change detection
                    file_hash = self._calculate_file_hash(file_path)

                    # Convert file modification time to datetime
                    file_mtime_timestamp = os.path.getmtime(file_path)
                    file_mtime = datetime.fromtimestamp(file_mtime_timestamp)

                    module_type = self._detect_module_type_from_path(module_path)

                    cve_raw = self._normalize_to_string(meta.get("cve", ""))
                    cve_val = cve_raw if (cve_raw and re.match(r"^CVE-\d{4}-\d{4,}$", cve_raw)) else ""

                    tags_list = meta.get("tags") or []
                    if not isinstance(tags_list, list):
                        tags_list = []
                    refs_list = meta.get("references") or []
                    if not isinstance(refs_list, list):
                        refs_list = []
                    opts_dict = meta.get("options") or {}
                    if not isinstance(opts_dict, dict):
                        opts_dict = {}
                    try:
                        opts_json = json.dumps(opts_dict)
                    except (TypeError, ValueError):
                        opts_json = "{}"

                    modules[module_path] = {
                        "path": module_path,
                        "name": name,
                        "description": self._normalize_to_string(meta.get("description", "")),
                        "type": module_type,
                        "author": self._normalize_to_string(meta.get("author", "")),
                        "version": self._normalize_to_string(meta.get("version", "")),
                        "cve": cve_val,
                        "tags": json.dumps(tags_list),
                        "references": json.dumps(refs_list),
                        "options": opts_json,
                        "file_hash": file_hash,
                        "file_mtime": file_mtime,
                    }
                    
                except Exception as e:
                    # Silently skip modules that can't be processed (errors are logged but not displayed)
                    logging.debug(f"Error processing module {module_path} during sync: {e}")
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
            # Compare file_mtime properly (both should be datetime objects)
            fs_mtime = fs_module['file_mtime']
            db_mtime = db_module.get('file_mtime')
            
            # Convert db_mtime to datetime if it's a string or other type
            if db_mtime and not isinstance(db_mtime, datetime):
                if isinstance(db_mtime, str):
                    try:
                        db_mtime = datetime.fromisoformat(db_mtime.replace('Z', '+00:00'))
                    except:
                        db_mtime = None
                elif isinstance(db_mtime, (int, float)):
                    db_mtime = datetime.fromtimestamp(db_mtime)
            
            if (fs_module['file_hash'] != db_module.get('file_hash') or
                (fs_mtime and db_mtime and fs_mtime != db_mtime) or
                (fs_mtime and not db_mtime) or
                (not fs_mtime and db_mtime)):
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
                    
                    # Compare file_mtime properly (both should be datetime objects)
                    fs_mtime = fs_module['file_mtime']
                    db_mtime = db_module.get('file_mtime')
                    
                    # Convert db_mtime to datetime if it's a string or other type
                    if db_mtime and not isinstance(db_mtime, datetime):
                        if isinstance(db_mtime, str):
                            try:
                                db_mtime = datetime.fromisoformat(db_mtime.replace('Z', '+00:00'))
                            except:
                                db_mtime = None
                        elif isinstance(db_mtime, (int, float)):
                            db_mtime = datetime.fromtimestamp(db_mtime)
                    
                    if (fs_module['file_hash'] != db_module.get('file_hash') or
                        (fs_mtime and db_mtime and fs_mtime != db_mtime) or
                        (fs_mtime and not db_mtime) or
                        (not fs_mtime and db_mtime)):
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
            # Removed verbose logging - summary is shown at the end
            
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
                # Removed verbose logging - summary is shown at the end
                
        except Exception as e:
            print_error(f"Error updating module {module_data['name']}: {e}")
            raise
    
    def _remove_module_from_db(self, session: Session, module_id: int):
        """Remove a module from the database"""
        try:
            module = session.query(Module).filter(Module.id == module_id).first()
            if module:
                # Removed verbose logging - summary is shown at the end
                session.delete(module)
                
        except Exception as e:
            print_error(f"Error removing module {module_id}: {e}")
            raise
    
    def _detect_module_type_from_path(self, module_path: str) -> str:
        """Detect module type from module path
        Returns a type that matches the CHECK constraint: 'exploits', 'auxiliary', 'scanner', 'post', 'payloads', 'workflow'
        """
        path = (module_path or "").lower()
        
        # Valid types according to CHECK constraint in models.py
        valid_types = ['exploits', 'auxiliary', 'scanner', 'post', 'payloads', 'workflow', 'listeners', 'encoders', 'obfuscator']
        
        # Module path prefixes mapping (must match valid types in CHECK constraint)
        type_mapping = {
            'analysis/': 'auxiliary',
            'exploits/': 'exploits',
            'auxiliary/': 'auxiliary',
            'scanner/': 'scanner',  # Some scanners are in auxiliary/scanner/ but standalone scanner/ exists
            'post/': 'post',
            'payloads/': 'payloads',
            'workflow/': 'workflow',
            'scanner/': 'scanner',
            'browser_exploits/': 'exploits',  # Map to exploits
            'browser_auxiliary/': 'auxiliary',  # Map to auxiliary
            'listeners/': 'listeners',
            'encoders/': 'encoders',
            'obfuscators/': 'obfuscator',
        }
        
        # Check for type in path
        for prefix, module_type in type_mapping.items():
            if path.startswith(prefix):
                # Special case: auxiliary/scanner/ should be 'auxiliary' not 'scanner'
                if prefix == 'scanner/' and path.startswith('auxiliary/scanner/'):
                    return 'auxiliary'
                return module_type
        
        # Special case: auxiliary/scanner/ should be 'auxiliary' not 'scanner'
        if path.startswith('auxiliary/'):
            return 'auxiliary'
        
        # Default fallback - try to extract from first part of path
        parts = path.split('/')
        if len(parts) > 0:
            first_part = parts[0]
            # Normalize to match CHECK constraint values
            if first_part in valid_types:
                return first_part
            elif first_part == 'exploit':
                return 'exploits'
            elif first_part == 'payload':
                return 'payloads'
            elif first_part == 'scanner':
                return 'scanner'
            elif first_part == 'listener':
                return 'listeners'
            elif first_part == 'encoder':
                return 'encoders'
            elif first_part == 'obfuscator':
                return 'obfuscator'
        
        # Default to 'auxiliary' if we can't determine (safest fallback)
        return 'auxiliary'
    
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
                
                # Free-text: each token must match at least one of name, description, path, tags (SQL only).
                if query:
                    for raw_token in query.replace(",", " ").split():
                        token = raw_token.strip()
                        if not token:
                            continue
                        pattern = f"%{token}%"
                        query_obj = query_obj.filter(
                            or_(
                                Module.name.ilike(pattern),
                                Module.description.ilike(pattern),
                                Module.path.ilike(pattern),
                                Module.tags.ilike(pattern),
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
                for module_type in ['exploits', 'auxiliary', 'payloads', 'listeners', 'post', 'scanner', 'encoder', 'obfuscator']:
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
            'background_sync_active': self.background_sync_active and (self.sync_thread and self.sync_thread.is_alive()),
            'last_sync_datetime': self.last_sync  # Keep datetime object for formatting
        }
