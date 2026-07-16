#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
History Manager for secure command history storage in database
"""

import json
import logging
import os
import re
import shlex
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from core.models.models import CommandHistory
from core.output_handler import print_info, print_success, print_error, print_warning


logger = logging.getLogger(__name__)

MAX_HISTORY_ENTRIES = 50

REDACTED_VALUE = "[REDACTED]"
SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "auth",
    "auth_token",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "credentials",
    "key",
    "pass",
    "passphrase",
    "passwd",
    "password",
    "private_key",
    "private-key",
    "proxy-authorization",
    "relay_token",
    "secret",
    "session_token",
    "token",
}
SENSITIVE_KEY_RE = re.compile(
    r"(?i)\b("
    r"api[_-]?key|auth(?:orization)?|auth[_-]?token|bearer|client[_-]?secret|"
    r"credential(?:s)?|pass(?:word|phrase|wd)?|private[_-]?key|proxy[_-]?authorization|"
    r"relay[_-]?token|secret|session[_-]?token|token"
    r")\b"
)
URL_CREDENTIAL_RE = re.compile(r"([a-z][a-z0-9+.-]*://[^:/\s@]+:)([^@\s/]+)(@)", re.IGNORECASE)


def _normalize_secret_key(value: str) -> str:
    return str(value or "").strip().lower().lstrip("-").replace("-", "_")


def _looks_sensitive_key(value: str) -> bool:
    normalized = _normalize_secret_key(value)
    return normalized in SENSITIVE_KEYS or bool(SENSITIVE_KEY_RE.search(normalized))


def _coerce_history_args(args: Any = None) -> List[Any]:
    if args is None:
        return []
    if isinstance(args, list):
        return args
    if isinstance(args, tuple):
        return list(args)
    if isinstance(args, dict):
        return [f"{key}={value}" for key, value in args.items()]
    return [args]


def _redact_token_value(token: str) -> str:
    token = URL_CREDENTIAL_RE.sub(rf"\1{REDACTED_VALUE}\3", str(token))
    if "=" in token:
        key, value = token.split("=", 1)
        if _looks_sensitive_key(key):
            return f"{key}={REDACTED_VALUE}"
        redacted_value = URL_CREDENTIAL_RE.sub(rf"\1{REDACTED_VALUE}\3", value)
        return f"{key}={redacted_value}"
    if ":" in token:
        key, value = token.split(":", 1)
        if _looks_sensitive_key(key):
            return f"{key}:{REDACTED_VALUE}"
    return token


def redact_history_args(args: List[str] = None) -> List[str]:
    redacted: List[str] = []
    redact_next = False
    for raw_arg in _coerce_history_args(args):
        arg = str(raw_arg)
        if redact_next:
            redacted.append(REDACTED_VALUE)
            redact_next = False
            continue

        redacted_arg = _redact_token_value(arg)
        redacted.append(redacted_arg)

        if redacted_arg == arg and "=" not in arg and ":" not in arg and _looks_sensitive_key(arg):
            redact_next = True
    return redacted


def redact_history_command(command: str) -> str:
    """Best-effort redaction for stored/displayed command strings."""
    text = URL_CREDENTIAL_RE.sub(rf"\1{REDACTED_VALUE}\3", str(command or ""))
    try:
        tokens = shlex.split(text, posix=False)
    except ValueError:
        tokens = text.split()
    if not tokens:
        return text
    return " ".join(redact_history_args(tokens))


class HistoryManager:
    """Manages encrypted command history in database"""
    
    def __init__(self, db_manager, workspace_id: Optional[int] = None, framework=None):
        self.db_manager = db_manager
        self.workspace_id = workspace_id
        self.user_id = None  # Will be set when user authenticates
        self.framework = framework  # Reference to framework for get_db_session
        # Trim any backlog left from older unlimited / higher-cap versions.
        try:
            self._limit_history(max_entries=MAX_HISTORY_ENTRIES)
        except Exception:
            logger.debug("Initial command-history prune failed", exc_info=True)
    
    def set_user_id(self, user_id: str):
        self.user_id = user_id

    def refresh_workspace(self) -> Optional[int]:
        current_id = self._resolve_workspace_id()
        previous_id = self.workspace_id
        self.workspace_id = current_id
        if current_id != previous_id:
            try:
                self._limit_history(max_entries=MAX_HISTORY_ENTRIES)
            except Exception:
                logger.debug("Workspace switch command-history prune failed", exc_info=True)
        return current_id

    def _resolve_workspace_id(self) -> Optional[int]:
        if self.framework:
            workspace_manager = getattr(self.framework, "workspace_manager", None)
            if workspace_manager:
                try:
                    current_workspace = workspace_manager.get_current_workspace()
                    if current_workspace and getattr(current_workspace, "id", None) is not None:
                        return current_workspace.id
                except Exception:
                    logger.debug("Unable to resolve current workspace for command history", exc_info=True)
        return self.workspace_id

    def _get_session(self):
        if self.framework:
            return self.framework.get_db_session()
        return self.db_manager.get_session("default")

    def _sanitize_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(entry)
        sanitized["command"] = redact_history_command(sanitized.get("command", ""))
        sanitized["args"] = redact_history_args(sanitized.get("args"))
        return sanitized

    def sanitize_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Public helper for callers that display or cache history entries."""
        return self._sanitize_entry(entry)

    def sanitize_command_parts(self, command_name: str, args: List[str] = None) -> Dict[str, Any]:
        safe_args = redact_history_args(args or [])
        safe_command = str(command_name or "")
        if safe_args:
            safe_command += " " + " ".join(safe_args)
        return {"command": redact_history_command(safe_command), "args": safe_args}
    
    def add_command(self, command: str, args: List[str] = None, success: bool = True, session_id: str = None) -> bool:
        try:
            session = self._get_session()
            workspace_id = self.refresh_workspace()
            safe_command = redact_history_command(command)
            safe_args = redact_history_args(args or [])
            
            # Prepare arguments as JSON string
            args_json = json.dumps(safe_args) if safe_args else None
            
            # Create new history entry
            history_entry = CommandHistory(
                command=safe_command,
                success=success,
                args=args_json,
                user_id=self.user_id,
                session_id=session_id,
                workspace_id=workspace_id
            )
            
            session.add(history_entry)
            session.commit()
            
            # Keep only the most recent entries in the database
            self._limit_history(max_entries=MAX_HISTORY_ENTRIES)
            
            return True
                
        except Exception as e:
            print_error(f"Error adding command to history: {e}")
            return False
    
    def get_history(self, limit: int = MAX_HISTORY_ENTRIES, offset: int = 0, user_id: str = None,
                   success_only: bool = False, search_term: str = None, redact: bool = True) -> List[Dict[str, Any]]:
        try:
            session = self._get_session()
            workspace_id = self.refresh_workspace()
            
            query = session.query(CommandHistory)
            
            # Filter by workspace
            if workspace_id:
                query = query.filter(CommandHistory.workspace_id == workspace_id)
            
            # Filter by user
            if user_id:
                query = query.filter(CommandHistory.user_id == user_id)
            elif self.user_id:
                query = query.filter(CommandHistory.user_id == self.user_id)
            
            # Filter by success status
            if success_only:
                query = query.filter(CommandHistory.success == True)
            
            # Search in command text
            if search_term:
                query = query.filter(CommandHistory.command.contains(search_term))
            
            # Order by timestamp (newest first)
            query = query.order_by(CommandHistory.timestamp.desc())
            
            # Apply pagination
            query = query.offset(offset).limit(limit)
            
            # Convert to dictionaries
            history = []
            for entry in query.all():
                # Safely parse args JSON
                args_list = []
                if entry.args:
                    try:
                        # Check if args is already a list or dict (already deserialized)
                        if isinstance(entry.args, (list, dict)):
                            args_list = entry.args
                        elif isinstance(entry.args, str):
                            # Try to parse as JSON string
                            args_list = json.loads(entry.args)
                        else:
                            # If it's another type, convert to list
                            args_list = [entry.args] if entry.args else []
                    except (json.JSONDecodeError, ValueError, TypeError):
                        # If JSON is invalid or type error, use empty list
                        args_list = []
                
                history_entry = {
                    'id': entry.id,
                    'timestamp': entry.timestamp.isoformat(),
                    'command': entry.command,
                    'success': entry.success,
                    'args': args_list,
                    'user_id': entry.user_id,
                    'session_id': entry.session_id
                }
                history.append(self._sanitize_entry(history_entry) if redact else history_entry)
            
            return history
                
        except Exception as e:
            print_error(f"Error retrieving history: {e}")
            return []
    
    def _limit_history(self, max_entries: int = MAX_HISTORY_ENTRIES) -> int:
        """Limit the history to a maximum number of entries, keeping the most recent ones."""
        try:
            max_entries = max(1, int(max_entries or MAX_HISTORY_ENTRIES))
            session = self._get_session()
            workspace_id = self._resolve_workspace_id()
            self.workspace_id = workspace_id

            base_query = session.query(CommandHistory)

            if workspace_id is not None:
                base_query = base_query.filter(CommandHistory.workspace_id == workspace_id)
            else:
                base_query = base_query.filter(CommandHistory.workspace_id.is_(None))

            if self.user_id:
                base_query = base_query.filter(CommandHistory.user_id == self.user_id)
            else:
                base_query = base_query.filter(CommandHistory.user_id.is_(None))

            total_count = base_query.count()
            if total_count <= max_entries:
                return 0

            keep_ids = [
                entry[0]
                for entry in base_query.order_by(CommandHistory.timestamp.desc())
                .limit(max_entries)
                .with_entities(CommandHistory.id)
                .all()
            ]
            if not keep_ids:
                return 0

            delete_query = session.query(CommandHistory)
            if workspace_id is not None:
                delete_query = delete_query.filter(CommandHistory.workspace_id == workspace_id)
            else:
                delete_query = delete_query.filter(CommandHistory.workspace_id.is_(None))
            if self.user_id:
                delete_query = delete_query.filter(CommandHistory.user_id == self.user_id)
            else:
                delete_query = delete_query.filter(CommandHistory.user_id.is_(None))

            deleted_count = delete_query.filter(
                ~CommandHistory.id.in_(keep_ids)
            ).delete(synchronize_session=False)
            session.commit()
            return int(deleted_count or 0)

        except Exception as e:
            print_error(f"Error limiting history: {e}")
            try:
                session = self._get_session()
                session.rollback()
            except Exception:
                logger.debug("History limit rollback failed", exc_info=True)
            return 0
    
    def clear_history(self, user_id: str = None, older_than_days: int = None) -> int:
        try:
            session = self._get_session()
            workspace_id = self.refresh_workspace()
            
            query = session.query(CommandHistory)
            
            # Filter by workspace
            if workspace_id:
                query = query.filter(CommandHistory.workspace_id == workspace_id)
            
            # Filter by user
            if user_id:
                query = query.filter(CommandHistory.user_id == user_id)
            elif self.user_id:
                query = query.filter(CommandHistory.user_id == self.user_id)
            
            # Filter by age
            if older_than_days:
                cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)
                query = query.filter(CommandHistory.timestamp < cutoff_date)
            
            # Count before deletion
            count = query.count()
            
            # Delete matching records
            query.delete(synchronize_session=False)
            session.commit()
            
            return count
                
        except Exception as e:
            print_error(f"Error clearing history: {e}")
            return 0
    
    def export_history(
        self,
        output_file: str,
        user_id: str = None,
        format: str = 'json',
        limit: int = MAX_HISTORY_ENTRIES,
        force: bool = False,
        success_only: bool = False,
        search_term: str = None,
    ) -> bool:
        try:
            export_format = (format or 'json').lower()
            if export_format not in {'json', 'csv'}:
                print_error(f"Unsupported export format: {format}")
                return False

            try:
                limit = max(1, min(int(limit), MAX_HISTORY_ENTRIES))
            except (TypeError, ValueError):
                limit = MAX_HISTORY_ENTRIES

            output_path = os.path.abspath(os.path.expanduser(str(output_file or "")))
            if not output_file or os.path.isdir(output_path):
                print_error("History export requires a file path")
                return False
            parent = os.path.dirname(output_path) or "."
            if parent and not os.path.isdir(parent):
                print_error(f"Export directory does not exist: {parent}")
                return False
            if os.path.exists(output_path) and not force:
                print_error(f"Refusing to overwrite existing file without force: {output_path}")
                return False

            history = self.get_history(
                limit=limit,
                user_id=user_id,
                success_only=success_only,
                search_term=search_term,
                redact=True,
            )
            
            if export_format == 'json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(history, f, indent=2, ensure_ascii=False)
            elif export_format == 'csv':
                import csv
                fieldnames = ['id', 'timestamp', 'command', 'success', 'args', 'user_id', 'session_id']
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    writer.writerows(history)
            
            print_success(f"History exported to {output_path} ({len(history)} redacted entries)")
            return True
            
        except Exception as e:
            print_error(f"Error exporting history: {e}")
            return False
    
    def get_stats(self, user_id: str = None) -> Dict[str, Any]:
        try:
            session = self._get_session()
            workspace_id = self.refresh_workspace()
            
            query = session.query(CommandHistory)
            
            # Filter by workspace
            if workspace_id:
                query = query.filter(CommandHistory.workspace_id == workspace_id)
            
            # Filter by user
            if user_id:
                query = query.filter(CommandHistory.user_id == user_id)
            elif self.user_id:
                query = query.filter(CommandHistory.user_id == self.user_id)
            
            total_commands = query.count()
            successful_commands = query.filter(CommandHistory.success == True).count()
            failed_commands = total_commands - successful_commands
            
            # Get most recent command
            most_recent = query.order_by(CommandHistory.timestamp.desc()).first()
            last_command_time = most_recent.timestamp.isoformat() if most_recent else None
            
            # Get most used commands
            from sqlalchemy import func
            command_counts = query.with_entities(
                CommandHistory.command,
                func.count(CommandHistory.command).label('count')
            ).group_by(CommandHistory.command).order_by(
                func.count(CommandHistory.command).desc()
            ).limit(10).all()
            
            most_used = [{'command': cmd, 'count': count} for cmd, count in command_counts]
            
            return {
                'total_commands': total_commands,
                'successful_commands': successful_commands,
                'failed_commands': failed_commands,
                'success_rate': (successful_commands / total_commands * 100) if total_commands > 0 else 0,
                'last_command_time': last_command_time,
                'most_used_commands': most_used
            }
                
        except Exception as e:
            print_error(f"Error getting history stats: {e}")
            return {}
