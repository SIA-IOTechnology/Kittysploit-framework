#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
import uuid
from typing import Dict, List, Optional, Any
from core.session import Session, SessionData
from core.output_handler import print_error
from core.models.models import Session as DBSession
from datetime import datetime

class SessionManager:
    
    def __init__(self, sessions_dir: Optional[str] = None, clean_startup: bool = True, db_manager=None, framework=None):
        """
        Initialize SessionManager.
        
        Args:
            sessions_dir: Deprecated - no longer used (sessions are stored in database)
            clean_startup: If True, don't load old sessions from database on startup
            db_manager: Database manager instance
            framework: Framework instance
        """
        self.sessions: Dict[str, SessionData] = {}
        self.browser_sessions: Dict[str, Dict[str, Any]] = {}
        self.callbacks = []
        self._session_metadata: Dict[str, Dict[str, Any]] = {}
        self.db_manager = db_manager
        self.framework = framework
        self.clean_startup = clean_startup
        
        # Load sessions from database on startup (only if clean_startup is False)
        if not clean_startup:
            self._load_sessions_from_db()
    
    def _sync_session_to_db(self, session_id: str, session_data: SessionData) -> bool:
        """Sync a session to the database"""
        if not self.db_manager:
            return False
        
        try:
            db_session = self.db_manager.get_session("default")
            if not db_session:
                return False
                
            # Check if session already exists in DB
            existing_db_session = db_session.query(DBSession).filter_by(session_id=session_id).first()
            
            if existing_db_session:
                # Update existing session
                existing_db_session.session_type = session_data.session_type
                existing_db_session.target_host = session_data.host
                existing_db_session.target_port = session_data.port
                existing_db_session.session_data = json.dumps(session_data.data)
                existing_db_session.last_seen = datetime.utcnow()
                existing_db_session.is_active = True
            else:
                # Create new session in DB
                db_session_obj = DBSession(
                    session_id=session_id,
                    session_type=session_data.session_type,
                    target_host=session_data.host,
                    target_port=session_data.port,
                    session_data=json.dumps(session_data.data),
                    created_at=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    is_active=True
                )
                db_session.add(db_session_obj)
            
            db_session.commit()
            return True
        except Exception as e:
            print_error(f"Error syncing session {session_id} to database: {e}")
            return False
    
    def _sync_browser_session_to_db(self, session_id: str, browser_session: Dict[str, Any]) -> bool:
        """Sync a browser session to the database"""
        if not self.db_manager:
            return False
        
        try:
            db_session = self.db_manager.get_session("default")
            if not db_session:
                return False
                
            # Check if session already exists in DB
            existing_db_session = db_session.query(DBSession).filter_by(session_id=session_id).first()
            
            session_info = browser_session.get('info', {})
            session_data = {
                'commands_executed': browser_session.get('commands_executed', 0),
                'commands_sent': browser_session.get('commands_sent', 0),
                'first_seen': browser_session.get('first_seen'),
                'last_seen': browser_session.get('last_seen'),
                'active': browser_session.get('active', True)
            }
            
            if existing_db_session:
                # Update existing session
                existing_db_session.session_type = 'browser'
                existing_db_session.session_data = json.dumps(session_data)
                existing_db_session.session_info = json.dumps(session_info)
                existing_db_session.last_seen = datetime.utcnow()
                existing_db_session.is_active = browser_session.get('active', True)
            else:
                # Create new session in DB
                db_session_obj = DBSession(
                    session_id=session_id,
                    session_type='browser',
                    session_data=json.dumps(session_data),
                    session_info=json.dumps(session_info),
                    created_at=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    is_active=browser_session.get('active', True)
                )
                db_session.add(db_session_obj)
            
            db_session.commit()
            return True
        except Exception as e:
            print_error(f"Error syncing browser session {session_id} to database: {e}")
            return False
    
    def _load_sessions_from_db(self) -> None:
        """Load sessions from database on startup"""
        if not self.db_manager:
            return
        
        try:
            db_session = self.db_manager.get_session("default")
            if not db_session:
                return
            
            # If clean_startup is True, don't load old sessions
            if self.clean_startup:
                return
                
            # Only load sessions that are active and recent (created in last 7 days)
            from datetime import datetime, timedelta
            cutoff_date = datetime.utcnow() - timedelta(days=7)
            
            db_sessions = db_session.query(DBSession).filter(
                DBSession.is_active == True,
                DBSession.created_at >= cutoff_date
            ).all()
            
            for db_session_obj in db_sessions:
                session_id = db_session_obj.session_id
                
                # Store metadata for session
                self._session_metadata[session_id] = {
                    "created_at": db_session_obj.created_at.timestamp() if db_session_obj.created_at else time.time(),
                    "category": "browser" if db_session_obj.session_type == 'browser' else "standard"
                }
                
                if db_session_obj.session_type == 'browser':
                    # Load browser session
                    # Safely parse JSON, handling empty or invalid strings
                    session_data_str = (db_session_obj.session_data or '').strip()
                    session_info_str = (db_session_obj.session_info or '').strip()
                    
                    try:
                        session_data = json.loads(session_data_str) if session_data_str else {}
                    except (json.JSONDecodeError, ValueError):
                        session_data = {}
                    
                    try:
                        session_info = json.loads(session_info_str) if session_info_str else {}
                    except (json.JSONDecodeError, ValueError):
                        session_info = {}
                    
                    self.browser_sessions[session_id] = {
                        'id': session_id,
                        'type': 'browser',
                        'info': session_info,
                        'first_seen': session_data.get('first_seen', db_session_obj.created_at.timestamp() if db_session_obj.created_at else time.time()),
                        'last_seen': session_data.get('last_seen', db_session_obj.last_seen.timestamp() if db_session_obj.last_seen else time.time()),
                        'commands_sent': session_data.get('commands_sent', 0),
                        'commands_executed': session_data.get('commands_executed', 0),
                        'active': session_data.get('active', True)
                    }
                else:
                    # Load standard session
                    # Safely parse JSON, handling empty or invalid strings
                    session_data_str = (db_session_obj.session_data or '').strip()
                    
                    try:
                        session_data = json.loads(session_data_str) if session_data_str else {}
                    except (json.JSONDecodeError, ValueError):
                        session_data = {}
                    
                    # Get host - should be automatically decrypted by EncryptedString
                    host = db_session_obj.target_host or ''
                    
                    # If host looks encrypted (base64-like), try to decrypt manually
                    if host and (host.startswith('Z0FBQUFBQ') or len(host) > 50):
                        try:
                            if self.db_manager and hasattr(self.db_manager, 'encryption_manager'):
                                encryption_manager = self.db_manager.encryption_manager
                                if encryption_manager and encryption_manager._is_initialized:
                                    host = encryption_manager.decrypt_data(host)
                        except Exception:
                            # If decryption fails, keep the encrypted value
                            # This might be an old session with different encryption key
                            pass
                    
                    self.sessions[session_id] = SessionData(
                        id=session_id,
                        host=host,
                        port=db_session_obj.target_port or 0,
                        session_type=db_session_obj.session_type,
                        data=session_data
                    )
                        
        except Exception as e:
            print_error(f"Error loading sessions from database: {e}")
    
    def create_session(self, host: str, port: int, session_type: str, data=None) -> str:
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = SessionData(
            id=session_id,
            host=host,
            port=port,
            session_type=session_type,
            data=data or {}
        )
        self._session_metadata[session_id] = {
            "created_at": time.time(),
            "category": "standard"
        }
        
        # Sync to database
        self._sync_session_to_db(session_id, self.sessions[session_id])
        
        for callback in self.callbacks:
            try:
                callback('session_created', session_id, self.sessions[session_id])
            except Exception as e:
                print(f"Error in session callback: {e}")
        
        # Play sound notification if enabled
        self._play_session_sound()
        
        return session_id
    
    def _play_session_sound(self):
        """Play sound notification when a session is created"""
        try:
            # Check if sound is enabled in framework
            if self.framework and hasattr(self.framework, 'sound_enabled') and self.framework.sound_enabled:
                try:
                    from nava import play
                    import os
                    # Try to find the sound file
                    sound_file = None
                    # Get the framework root directory
                    # Try to get from framework if available, otherwise use current working directory
                    if hasattr(self.framework, '__file__'):
                        framework_root = os.path.abspath(os.path.join(os.path.dirname(self.framework.__file__), '..'))
                    else:
                        framework_root = os.getcwd()
                    
                    # Try multiple possible paths
                    possible_paths = [
                        os.path.join(framework_root, 'data/sound/notify.wav'),
                        os.path.join(os.getcwd(), 'data/sound/notify.wav'),
                        'data/sound/notify.wav',
                    ]
                    
                    for path in possible_paths:
                        abs_path = os.path.abspath(path)
                        if os.path.exists(abs_path):
                            sound_file = abs_path
                            break
                    
                    # Play notification sound
                    if sound_file:
                        play(sound_file)
                    # If file doesn't exist, we can't use nava without a file
                except ImportError:
                    # nava not installed, silently skip
                    pass
                except Exception as e:
                    # Error playing sound, silently skip
                    pass
        except Exception:
            # Framework not available or error, silently skip
            pass
    
    def register_browser_session(self, session_id, info):
        info = info or {}
        now = time.time()
        
        # Check if this is a new session
        is_new_session = session_id not in self.browser_sessions
        
        if session_id in self.browser_sessions:
            self.browser_sessions[session_id]['info'] = info
            self.browser_sessions[session_id]['last_seen'] = now
        else:
            self.browser_sessions[session_id] = {
                'id': session_id,
                'type': 'browser',
                'info': info,
                'first_seen': now,
                'last_seen': now,
                'commands_sent': 0,
                'commands_executed': info.get('commands_executed', 0),
                'active': True
            }
            self._session_metadata[session_id] = {
                "created_at": now,
                "category": "browser"
            }
        
        # Sync to database
        self._sync_browser_session_to_db(session_id, self.browser_sessions[session_id])
        
        # Play sound notification if enabled (only for new sessions)
        if is_new_session:
            self._play_session_sound()
        
        return self.browser_sessions[session_id]
    
    def update_browser_session(self, victim_id: str, info: Dict[str, Any]) -> bool:
        if victim_id not in self.browser_sessions:
            return False
        
        now = time.time()
        session = self.browser_sessions[victim_id]
        session['last_seen'] = now
        
        if not info:
            info = {}
        
        commands_executed = info.pop('commands_executed', None)
        if commands_executed is not None:
            session['commands_executed'] = commands_executed
        
        commands_sent = info.pop('commands_sent', None)
        if commands_sent is not None:
            session['commands_sent'] = commands_sent
        
        # Update nested info dictionary with remaining values
        session['info'].update(info)
        
        # Sync to database
        self._sync_browser_session_to_db(victim_id, session)
        
        for callback in self.callbacks:
            try:
                callback('browser_session_updated', victim_id, session)
            except Exception as e:
                print_error(f"Error in session callback: {e}")
        
        return True
    
    def handle_commands_sent(self, victim_id: str, commands: List[Dict[str, Any]]) -> None:
        """Gère l'envoi de commandes à une session de navigateur"""
        if victim_id in self.browser_sessions:
            session = self.browser_sessions[victim_id]
            session['commands_sent'] += len(commands)
            
            # Sync to database
            self._sync_browser_session_to_db(victim_id, session)
            
            # Notify the callbacks
            for callback in self.callbacks:
                try:
                    callback('commands_sent', victim_id, commands)
                except Exception as e:
                    print_error(f"Error in commands_sent callback: {e}")
    
    def get_session(self, session_id: str) -> Optional[SessionData]:
        """Get a session by its ID"""
        return self.sessions.get(session_id)
    
    def get_browser_session(self, session_id):
        """Get a browser session by its ID"""
        
        if session_id in self.browser_sessions:
            return self.browser_sessions[session_id]
        
        return None
    
    def get_sessions(self) -> List[SessionData]:
        """Get all standard sessions"""
        return list(self.sessions.values())
    
    def get_browser_sessions(self) -> List[Dict[str, Any]]:
        """Get all browser sessions"""
        return list(self.browser_sessions.values())
    
    def get_all_sessions(self) -> Dict[str, Any]:
        """Get all sessions (standard and browser)"""
        all_sessions = {
            'standard': self.get_sessions(),
            'browser': self.get_browser_sessions()
        }
        return all_sessions
    
    def cleanup_old_sessions(self, days: int = 7) -> int:
        """Clean up old sessions from database (mark as inactive)"""
        if not self.db_manager:
            return 0
        
        try:
            from datetime import datetime, timedelta
            db_session = self.db_manager.get_session("default")
            if not db_session:
                return 0
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Mark old sessions as inactive
            old_sessions = db_session.query(DBSession).filter(
                DBSession.is_active == True,
                DBSession.created_at < cutoff_date
            ).all()
            
            count = 0
            for session in old_sessions:
                session.is_active = False
                count += 1
            
            if count > 0:
                db_session.commit()
            
            return count
        except Exception as e:
            print_error(f"Error cleaning up old sessions: {e}")
            return 0
    
    def _remove_session_from_db(self, session_id: str) -> bool:
        """Remove a session from the database"""
        if not self.db_manager:
            return False
        
        try:
            db_session = self.db_manager.get_session("default")
            if not db_session:
                return False
                
            db_session_obj = db_session.query(DBSession).filter_by(session_id=session_id).first()
            if db_session_obj:
                db_session_obj.is_active = False
                db_session.commit()
                return True
        except Exception as e:
            print_error(f"Error removing session {session_id} from database: {e}")
        return False
    
    def remove_session(self, session_id: str) -> bool:
        """Remove a standard session"""
        if session_id in self.sessions:
            session = self.sessions.pop(session_id)
            
            # Remove from database
            self._remove_session_from_db(session_id)
            
            # Remove metadata
            self._session_metadata.pop(session_id, None)
            
            # Notify the callbacks
            for callback in self.callbacks:
                try:
                    callback('session_removed', session_id, session)
                except Exception as e:
                    print_error(f"Error in session callback: {e}")
            
            return True
        return False
    
    def remove_browser_session(self, victim_id: str) -> bool:
        """Remove a browser session"""
        if victim_id in self.browser_sessions:
            session = self.browser_sessions.pop(victim_id)
            
            # Remove from database
            self._remove_session_from_db(victim_id)
            
            # Remove metadata
            self._session_metadata.pop(victim_id, None)
            
            for callback in self.callbacks:
                try:
                    callback('browser_session_removed', victim_id, session)
                except Exception as e:
                    print_error(f"Error in session callback: {e}")
            
            return True
        return False
    
    def add_callback(self, callback):
        """Add a callback for session events"""
        self.callbacks.append(callback)
    
    def remove_callback(self, callback):
        """Remove a callback"""
        if callback in self.callbacks:
            self.callbacks.remove(callback) 
