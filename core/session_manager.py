#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
import uuid
from typing import Dict, List, Optional, Any
from core.session import Session, SessionData
from core.output_handler import print_error
from core.models.models import Session as DBSession
from core.utils.paths import sound_notify_path
from datetime import datetime

def _make_json_serializable(obj):
    """
    Recursively filter out non-JSON-serializable objects from a data structure.
    Replaces them with string representations or removes them.
    """
    if obj is None:
        return None
    elif isinstance(obj, (str, int, float, bool)):
        return obj
    elif isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            try:
                # Try to serialize the value to check if it's serializable
                json.dumps(value)
                result[key] = _make_json_serializable(value)
            except (TypeError, ValueError):
                # If not serializable, replace with string representation or skip
                # Skip connection objects and other non-serializable objects
                if hasattr(value, '__class__'):
                    class_name = value.__class__.__name__
                    # For connection objects, store metadata instead
                    if class_name in ['FTP', 'socket', 'SSHClient', 'paramiko.SSHClient']:
                        # Store connection metadata instead of the object
                        result[key] = {
                            '_type': 'connection',
                            '_class': class_name,
                            '_repr': str(value)
                        }
                    else:
                        # For other non-serializable objects, try to store a string representation
                        try:
                            result[key] = str(value)
                        except:
                            # If even str() fails, skip it
                            pass
                else:
                    # For other types, try string representation
                    try:
                        result[key] = str(value)
                    except:
                        pass
        return result
    elif isinstance(obj, (list, tuple)):
        result = []
        for item in obj:
            try:
                json.dumps(item)
                result.append(_make_json_serializable(item))
            except (TypeError, ValueError):
                # Skip non-serializable items in lists
                if hasattr(item, '__class__'):
                    class_name = item.__class__.__name__
                    if class_name in ['FTP', 'socket', 'SSHClient', 'paramiko.SSHClient']:
                        result.append({
                            '_type': 'connection',
                            '_class': class_name,
                            '_repr': str(item)
                        })
                    else:
                        try:
                            result.append(str(item))
                        except:
                            pass
                else:
                    try:
                        result.append(str(item))
                    except:
                        pass
        return result
    else:
        # For other types, try to convert to string
        try:
            return str(obj)
        except:
            return None

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
        # Defer durable session restore until master key is unlocked (hosts / session_data
        # may be Fernet-encrypted). Framework.complete_sensitive_startup() loads them.
        self._deferred_durable_load = not clean_startup
        self._durable_sessions_loaded = False
        # Session IDs explicitly killed this process — block DB re-activation races
        self._removed_session_ids: set = set()
        # Implant IDs retired via sessions kill / kill_agent (also persisted on disk)
        self._retired_implant_ids: set = set()
        self._load_retired_implants()
    
    def load_deferred_sessions(self, *, force: bool = False) -> int:
        """Load durable beacon sessions after encryption is ready.

        Returns the number of sessions currently in memory after load.
        """
        if self.clean_startup and not force:
            return 0
        if self._durable_sessions_loaded and not force:
            return len(self.sessions)
        if force:
            self.sessions.clear()
            self.browser_sessions.clear()
            self._session_metadata.clear()
        self._load_sessions_from_db()
        self._deferred_durable_load = False
        self._durable_sessions_loaded = True
        return len(self.sessions)

    def _get_workspace_id(self) -> Optional[int]:
        """Return the current workspace ID from the framework, if available."""
        if not self.framework:
            return None
        try:
            workspace_manager = getattr(self.framework, 'workspace_manager', None)
            if workspace_manager:
                current_workspace = workspace_manager.get_current_workspace()
                if current_workspace:
                    return current_workspace.id
        except Exception:
            pass
        return None

    def _get_db_session(self):
        if self.framework and hasattr(self.framework, 'get_db_session'):
            return self.framework.get_db_session()
        if self.db_manager:
            return self.db_manager.get_session("default")
        return None

    def _workspace_name(self) -> str:
        try:
            wm = getattr(self.framework, "workspace_manager", None) if self.framework else None
            if wm:
                current = wm.get_current_workspace()
                if current and getattr(current, "name", None):
                    return str(current.name)
        except Exception:
            pass
        return "default"

    def _retired_implants_path(self):
        from pathlib import Path

        return (
            Path.home()
            / ".kittysploit"
            / "workspaces"
            / self._workspace_name()
            / "retired_implants.json"
        )

    def _load_retired_implants(self) -> None:
        try:
            path = self._retired_implants_path()
            if not path.is_file():
                return
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                self._retired_implant_ids = {str(x).strip() for x in data if str(x).strip()}
            elif isinstance(data, dict):
                items = data.get("implants") or data.get("ids") or []
                self._retired_implant_ids = {str(x).strip() for x in items if str(x).strip()}
        except Exception:
            pass

    def _save_retired_implants(self) -> None:
        try:
            path = self._retired_implants_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(sorted(self._retired_implant_ids), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass

    def is_implant_retired(self, implant_id: str) -> bool:
        identity = str(implant_id or "").strip()
        return bool(identity) and identity in self._retired_implant_ids

    def retire_implant(self, implant_id: str) -> None:
        """Persistently refuse durable restore / recreate for this implant id."""
        identity = str(implant_id or "").strip()
        if not identity:
            return
        self._retired_implant_ids.add(identity)
        self._save_retired_implants()

    def unretire_implant(self, implant_id: str) -> bool:
        identity = str(implant_id or "").strip()
        if not identity or identity not in self._retired_implant_ids:
            return False
        self._retired_implant_ids.discard(identity)
        self._save_retired_implants()
        return True

    def reload_for_current_workspace(self) -> None:
        self.sessions.clear()
        self.browser_sessions.clear()
        self._session_metadata.clear()
        self._durable_sessions_loaded = False
        if not self.clean_startup:
            self.load_deferred_sessions(force=True)
        else:
            self._load_sessions_from_db()
            self._durable_sessions_loaded = True
    
    def _sync_session_to_db(self, session_id: str, session_data: SessionData) -> bool:
        """Sync a session to the database"""
        if not self.db_manager:
            return False
        # Never resurrect a session that was explicitly killed this process
        if session_id in self._removed_session_ids:
            return False
        try:
            implant = ""
            if isinstance(getattr(session_data, "data", None), dict):
                implant = str(
                    session_data.data.get("implant_id")
                    or session_data.data.get("client_id")
                    or ""
                ).strip()
            if implant and implant in self._retired_implant_ids:
                return False
        except Exception:
            pass
        
        try:
            db_session = self._get_db_session()
            if not db_session:
                return False

            workspace_id = self._get_workspace_id()
                
            # Use a transaction with retry logic for atomicity
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # Re-check tombstone inside the retry loop (kill may race)
                    if session_id in self._removed_session_ids:
                        return False
                    existing_db_session = db_session.query(DBSession).filter_by(session_id=session_id).first()
                    
                    # Filter out non-serializable objects from session data
                    serializable_data = _make_json_serializable(session_data.data)
                    
                    if existing_db_session:
                        # Update existing session
                        existing_db_session.session_type = session_data.session_type
                        existing_db_session.target_host = session_data.host
                        existing_db_session.target_port = session_data.port
                        existing_db_session.session_data = json.dumps(serializable_data)
                        existing_db_session.last_seen = datetime.utcnow()
                        existing_db_session.is_active = True
                        if workspace_id is not None:
                            existing_db_session.workspace_id = workspace_id
                    else:
                        # Create new session in DB
                        db_session_obj = DBSession(
                            session_id=session_id,
                            session_type=session_data.session_type,
                            target_host=session_data.host,
                            target_port=session_data.port,
                            session_data=json.dumps(serializable_data),
                            created_at=datetime.utcnow(),
                            last_seen=datetime.utcnow(),
                            is_active=True,
                            workspace_id=workspace_id,
                        )
                        db_session.add(db_session_obj)
                    
                    db_session.commit()
                    return True
                except Exception as inner_e:
                    db_session.rollback()
                    if attempt < max_retries - 1:
                        import time as _time
                        _time.sleep(0.1 * (attempt + 1))
                        continue
                    raise
        except Exception as e:
            print_error(f"Error syncing session {session_id} to database: {e}")
            return False
    
    def _sync_browser_session_to_db(self, session_id: str, browser_session: Dict[str, Any]) -> bool:
        """Sync a browser session to the database"""
        if not self.db_manager:
            return False
        
        try:
            db_session = self._get_db_session()
            if not db_session:
                return False

            workspace_id = self._get_workspace_id()
                
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
                if workspace_id is not None:
                    existing_db_session.workspace_id = workspace_id
            else:
                # Create new session in DB
                db_session_obj = DBSession(
                    session_id=session_id,
                    session_type='browser',
                    session_data=json.dumps(session_data),
                    session_info=json.dumps(session_info),
                    created_at=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    is_active=browser_session.get('active', True),
                    workspace_id=workspace_id,
                )
                db_session.add(db_session_obj)
            
            db_session.commit()
            return True
        except Exception as e:
            print_error(f"Error syncing browser session {session_id} to database: {e}")
            return False
    
    @staticmethod
    def _parse_session_data_field(raw: Any) -> Dict[str, Any]:
        """Normalize DB session_data which may be dict, JSON str, or encrypted text."""
        if raw is None:
            return {}
        if isinstance(raw, dict):
            return dict(raw)
        if isinstance(raw, (bytes, bytearray)):
            try:
                raw = raw.decode("utf-8", errors="replace")
            except Exception:
                return {}
        if not isinstance(raw, str):
            # Some encryptors return already-decoded objects
            try:
                if hasattr(raw, "items"):
                    return dict(raw)
            except Exception:
                pass
            return {}
        text = raw.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, ValueError, TypeError):
            return {}

    @staticmethod
    def _decrypt_host_value(host: str, db_manager=None) -> str:
        host = host or ""
        if not host:
            return host
        # EncryptedString leftover / Fernet-like blob
        if host.startswith("Z0FBQUFBQ") or (len(host) > 50 and "://" not in host and " " not in host):
            try:
                if db_manager and hasattr(db_manager, "encryption_manager"):
                    em = db_manager.encryption_manager
                    if em and getattr(em, "_is_initialized", False):
                        return em.decrypt_data(host)
            except Exception:
                pass
        return host

    @staticmethod
    def _is_durable_beacon_session(session_type: str, session_data: Optional[Dict[str, Any]]) -> bool:
        """True for HTTP-polling / beacon sessions that can rebind after restart."""
        st = str(session_type or "").lower()
        data = session_data or {}
        protocol = str(data.get("protocol") or "").lower()
        listener_type = str(data.get("listener_type") or data.get("listener_module") or "").lower()
        if st in ("polling", "http_polling", "beacon"):
            return True
        if protocol in ("http_polling", "polling"):
            return True
        if "reverse_http_polling" in listener_type or listener_type.endswith("http_polling"):
            return True
        if "poll" in listener_type.replace(" ", "_"):
            return True
        if data.get("implant_id") or data.get("client_id"):
            if "poll" in protocol or "poll" in listener_type:
                return True
        return False

    def _load_sessions_from_db(self, *, durable_beacons_only: bool = True) -> None:
        """Load sessions from database on startup.

        By default only durable beacon/polling sessions are restored (socket
        shells cannot be revived). Restored beacons are marked disconnected
        until the implant checks in again.
        """
        if not self.db_manager:
            return
        
        try:
            db_session = self._get_db_session()
            if not db_session:
                return
            
            # Prefer last_seen so long-lived implants still reload
            from datetime import datetime, timedelta
            cutoff_date = datetime.utcnow() - timedelta(days=7)

            workspace_id = self._get_workspace_id()
            query = db_session.query(DBSession).filter(
                DBSession.is_active == True,
            )
            # last_seen recent OR created recent (legacy rows)
            query = query.filter(
                (DBSession.last_seen >= cutoff_date) | (DBSession.created_at >= cutoff_date)
            )
            if workspace_id is not None:
                query = query.filter(DBSession.workspace_id == workspace_id)

            db_sessions = query.all()
            restored = 0
            
            for db_session_obj in db_sessions:
                session_id = db_session_obj.session_id
                if session_id in self._removed_session_ids:
                    continue
                
                # Store metadata for session
                self._session_metadata[session_id] = {
                    "created_at": db_session_obj.created_at.timestamp() if db_session_obj.created_at else time.time(),
                    "category": "browser" if db_session_obj.session_type == 'browser' else "standard"
                }
                
                if db_session_obj.session_type == 'browser':
                    if durable_beacons_only:
                        continue
                    session_data = self._parse_session_data_field(db_session_obj.session_data)
                    session_info = self._parse_session_data_field(db_session_obj.session_info)
                    
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
                    session_data = self._parse_session_data_field(db_session_obj.session_data)

                    if durable_beacons_only and not self._is_durable_beacon_session(
                        db_session_obj.session_type, session_data
                    ):
                        continue

                    implant = str(
                        (session_data or {}).get("implant_id")
                        or (session_data or {}).get("client_id")
                        or ""
                    ).strip()
                    if implant and implant in self._retired_implant_ids:
                        # Keep DB row inactive so it cannot bounce back
                        try:
                            db_session_obj.is_active = False
                            db_session.commit()
                        except Exception:
                            try:
                                db_session.rollback()
                            except Exception:
                                pass
                        continue
                    
                    host = self._decrypt_host_value(
                        db_session_obj.target_host or "",
                        self.db_manager,
                    )

                    # Beacons wait for check-in; sockets are not restored
                    if self._is_durable_beacon_session(db_session_obj.session_type, session_data):
                        session_data = dict(session_data)
                        session_data["transport_state"] = "disconnected"
                        session_data["pending_rebind"] = True
                        session_data["durable"] = True
                    
                    self.sessions[session_id] = SessionData(
                        id=session_id,
                        host=host,
                        port=db_session_obj.target_port or 0,
                        session_type=db_session_obj.session_type,
                        data=session_data
                    )
                    restored += 1

            if restored:
                from core.output_handler import print_info
                print_info(
                    f"Restored {restored} durable beacon session(s) "
                    f"(waiting for implant check-in)"
                )
                        
        except Exception as e:
            print_error(f"Error loading sessions from database: {e}")
    
    def create_session(self, host: str, port: int, session_type: str, data=None) -> str:
        session_id = str(uuid.uuid4())
        payload = data or {}
        # Fresh check-in after a kill: clear durable retirement for this implant
        try:
            implant = str(payload.get("implant_id") or payload.get("client_id") or "").strip()
            if implant and implant in self._retired_implant_ids:
                self.unretire_implant(implant)
        except Exception:
            pass
        self.sessions[session_id] = SessionData(
            id=session_id,
            host=host,
            port=port,
            session_type=session_type,
            data=payload
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
        self._maybe_show_assistant_for_session(session_id, session_type)

        return session_id

    def _maybe_show_assistant_for_session(self, session_id: str, session_type: str) -> None:
        """Show operator assistant suggestions when a new session is created."""
        try:
            if not self.framework or not getattr(self.framework, "assistant_enabled", False):
                return
            from interfaces.command_system.builtin.assistant import (
                AssistantContext,
                maybe_show_assistant,
            )

            maybe_show_assistant(
                self.framework,
                AssistantContext(
                    event="session_created",
                    session_id=str(session_id or ""),
                    session_type=str(session_type or ""),
                ),
            )
        except Exception:
            pass

    def update_session_data(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """Merge updates into an in-memory session and sync to the database."""
        session = self.sessions.get(session_id)
        if not session:
            return False
        if updates:
            session.data = {**(session.data or {}), **updates}
            if "address" in updates and isinstance(updates["address"], (list, tuple)) and len(updates["address"]) >= 2:
                session.host = str(updates["address"][0])
                try:
                    session.port = int(updates["address"][1])
                except (TypeError, ValueError):
                    pass
        self._sync_session_to_db(session_id, session)
        for callback in self.callbacks:
            try:
                callback("session_updated", session_id, session)
            except Exception as e:
                print_error(f"Error in session callback: {e}")
        return True

    def find_disconnected_session_by_identity(
        self,
        listener_id: str,
        *,
        implant_id: str = "",
        client_id: str = "",
    ) -> Optional[str]:
        identity = str(implant_id or client_id or "").strip()
        if not identity:
            return None
        for session_id, session in self.sessions.items():
            data = session.data or {}
            if data.get("listener_id") != listener_id:
                continue
            if data.get("transport_state") != "disconnected":
                continue
            existing = str(data.get("implant_id") or data.get("client_id") or "").strip()
            if existing == identity:
                return session_id
        return None

    def find_beacon_session_by_implant(
        self,
        implant_id: str,
        *,
        listener_module: str = "",
        prefer_disconnected: bool = True,
    ) -> Optional[str]:
        """Find an in-memory beacon/polling session by stable implant/client id.

        Unlike ``find_disconnected_session_by_identity``, this does **not** require
        the same ``listener_id`` (listener UUIDs change across restarts).
        """
        identity = str(implant_id or "").strip()
        if not identity:
            return None

        def _norm(s: str) -> str:
            return "".join(ch for ch in str(s or "").lower() if ch.isalnum())

        hint = _norm(listener_module)
        candidates: List[tuple] = []
        for session_id, session in self.sessions.items():
            data = session.data or {}
            if not isinstance(data, dict):
                data = self._parse_session_data_field(data)
            if not self._is_durable_beacon_session(session.session_type, data):
                continue
            existing = str(data.get("implant_id") or data.get("client_id") or "").strip()
            if existing != identity:
                continue
            # Optional soft filter: only skip when both sides look like polling
            # families but clearly differ (e.g. mqtt vs http). Matching human
            # names ("Reverse HTTP Polling Listener") vs paths is allowed.
            if hint:
                lm = _norm(
                    data.get("listener_module")
                    or data.get("listener_type")
                    or data.get("protocol")
                    or ""
                )
                if lm and hint:
                    related = (
                        hint in lm
                        or lm in hint
                        or ("poll" in hint and "poll" in lm)
                        or ("http" in hint and "http" in lm)
                    )
                    if not related and "poll" in lm:
                        # Different polling family — skip
                        if not ("poll" in hint):
                            continue
            disconnected = data.get("transport_state") == "disconnected" or data.get(
                "pending_rebind"
            )
            score = 0 if (prefer_disconnected and disconnected) else 1
            candidates.append((score, session_id))
        if not candidates:
            return None
        candidates.sort(key=lambda x: x[0])
        return candidates[0][1]

    def revive_beacon_session_from_db(
        self,
        implant_id: str,
        *,
        listener_module: str = "",
    ) -> Optional[str]:
        """Load a durable beacon session from DB into memory by implant id."""
        identity = str(implant_id or "").strip()
        if not identity or not self.db_manager:
            return None
        # Already in memory?
        existing = self.find_beacon_session_by_implant(
            identity, listener_module=listener_module
        )
        if existing:
            return existing
        try:
            db_session = self._get_db_session()
            if not db_session:
                return None
            from datetime import timedelta

            cutoff = datetime.utcnow() - timedelta(days=30)
            workspace_id = self._get_workspace_id()
            query = db_session.query(DBSession).filter(DBSession.is_active == True)
            if workspace_id is not None:
                query = query.filter(DBSession.workspace_id == workspace_id)
            rows = (
                query.order_by(DBSession.last_seen.desc())
                .limit(200)
                .all()
            )
            for row in rows:
                data = self._parse_session_data_field(row.session_data)
                if not self._is_durable_beacon_session(row.session_type, data):
                    continue
                existing_id = str(data.get("implant_id") or data.get("client_id") or "").strip()
                if existing_id != identity:
                    continue
                if existing_id in self._retired_implant_ids:
                    continue
                if row.session_id in self._removed_session_ids:
                    continue
                # Skip very old inactive beacons
                ls = row.last_seen or row.created_at
                if ls and ls < cutoff:
                    continue
                host = self._decrypt_host_value(row.target_host or "", self.db_manager)
                data = dict(data)
                data["transport_state"] = "disconnected"
                data["pending_rebind"] = True
                data["durable"] = True
                sid = row.session_id
                self.sessions[sid] = SessionData(
                    id=sid,
                    host=host,
                    port=row.target_port or 0,
                    session_type=row.session_type,
                    data=data,
                )
                self._session_metadata[sid] = {
                    "created_at": row.created_at.timestamp() if row.created_at else time.time(),
                    "category": "standard",
                }
                return sid
        except Exception as exc:
            print_error(f"Error reviving beacon session from DB: {exc}")
        return None
    
    def _play_session_sound(self):
        """Play sound notification when a session is created"""
        try:
            # Check if sound is enabled in framework
            if self.framework and hasattr(self.framework, 'sound_enabled') and self.framework.sound_enabled:
                try:
                    from nava import play
                    sound_file = sound_notify_path()
                    if sound_file:
                        play(str(sound_file))
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
            self._maybe_show_assistant_for_session(session_id, "browser")
        
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
        return self.sessions.get(session_id)
    
    def get_browser_session(self, session_id):
        
        if session_id in self.browser_sessions:
            return self.browser_sessions[session_id]
        
        return None
    
    def get_sessions(self) -> List[SessionData]:
        return list(self.sessions.values())
    
    def get_browser_sessions(self) -> List[Dict[str, Any]]:
        return list(self.browser_sessions.values())
    
    def get_all_sessions(self) -> Dict[str, Any]:
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
            db_session = self._get_db_session()
            if not db_session:
                return 0
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)

            workspace_id = self._get_workspace_id()
            query = db_session.query(DBSession).filter(
                DBSession.is_active == True,
                DBSession.created_at < cutoff_date
            )
            if workspace_id is not None:
                query = query.filter(DBSession.workspace_id == workspace_id)

            # Mark old sessions as inactive using a bulk UPDATE
            count = query.update({DBSession.is_active: False}, synchronize_session=False)

            if count > 0:
                db_session.commit()

            return count
        except Exception as e:
            print_error(f"Error cleaning up old sessions: {e}")
            return 0
    
    def _remove_session_from_db(self, session_id: str) -> bool:
        """Deactivate a session in the database (bulk UPDATE to avoid identity-map races)."""
        if not self.db_manager:
            return False
        
        try:
            db_session = self._get_db_session()
            if not db_session:
                return False

            # Bulk update bypasses stale ORM objects that concurrent poll threads
            # may still hold with is_active=True and later commit.
            updated = (
                db_session.query(DBSession)
                .filter_by(session_id=session_id)
                .update({"is_active": False}, synchronize_session=False)
            )
            db_session.commit()
            return updated > 0
        except Exception as e:
            try:
                db_session = self._get_db_session()
                if db_session:
                    db_session.rollback()
            except Exception:
                pass
            print_error(f"Error removing session {session_id} from database: {e}")
        return False
    
    def remove_session(self, session_id: str) -> bool:
        session = self.sessions.get(session_id)
        if session is None and session_id not in self.sessions:
            # Still try to deactivate DB row if present
            self._removed_session_ids.add(session_id)
            self._remove_session_from_db(session_id)
            return False

        # Tombstone first so concurrent poll/rehydrate cannot re-activate the row
        self._removed_session_ids.add(session_id)

        implant = ""
        try:
            data = session.data if session and isinstance(session.data, dict) else {}
            implant = str(data.get("implant_id") or data.get("client_id") or "").strip()
        except Exception:
            pass

        if session_id in self.sessions:
            session = self.sessions.pop(session_id)

            # Deactivate this row (bulk UPDATE — race-safe vs poll sync)
            self._remove_session_from_db(session_id)
            # Also deactivate any other active durable rows for the same implant
            if implant:
                self._deactivate_sessions_for_implant(implant, except_id=None)
                # Block durable restore of this implant until a fresh check-in
                if self._is_durable_beacon_session(
                    session.session_type if session else "",
                    session.data if session else {},
                ):
                    self.retire_implant(implant)

            # Remove metadata
            self._session_metadata.pop(session_id, None)

            # Notify the callbacks
            for callback in self.callbacks:
                try:
                    callback('session_removed', session_id, session)
                except Exception as e:
                    print_error(f"Error in session callback: {e}")

            return True

        self._remove_session_from_db(session_id)
        return False

    def _deactivate_sessions_for_implant(self, implant_id: str, *, except_id: Optional[str] = None) -> int:
        """Soft-delete all active DB sessions belonging to an implant id."""
        identity = str(implant_id or "").strip()
        if not identity or not self.db_manager:
            return 0
        try:
            db_session = self._get_db_session()
            if not db_session:
                return 0
            rows = (
                db_session.query(DBSession)
                .filter(DBSession.is_active == True)
                .all()
            )
            deactivated = 0
            for row in rows:
                if except_id and row.session_id == except_id:
                    continue
                data = self._parse_session_data_field(row.session_data)
                existing = str(
                    (data or {}).get("implant_id") or (data or {}).get("client_id") or ""
                ).strip()
                if existing == identity:
                    row.is_active = False
                    self._removed_session_ids.add(row.session_id)
                    deactivated += 1
                    # Drop from memory too
                    self.sessions.pop(row.session_id, None)
                    self._session_metadata.pop(row.session_id, None)
            if deactivated:
                db_session.commit()
            return deactivated
        except Exception as e:
            try:
                db_session = self._get_db_session()
                if db_session:
                    db_session.rollback()
            except Exception:
                pass
            print_error(f"Error deactivating sessions for implant {implant_id}: {e}")
            return 0
    
    def remove_browser_session(self, victim_id: str) -> bool:
        if victim_id in self.browser_sessions:
            session = self.browser_sessions.pop(victim_id)
            self._removed_session_ids.add(victim_id)
            
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
        self.callbacks.append(callback)
    
    def remove_callback(self, callback):
        if callback in self.callbacks:
            self.callbacks.remove(callback) 
