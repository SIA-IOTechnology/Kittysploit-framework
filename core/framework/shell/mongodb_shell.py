#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MongoDB shell implementation for MongoDB sessions.
"""

from pymongo import MongoClient
from pymongo.errors import PyMongoError
from typing import Dict, Any, List, Optional
import json
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning, print_success

class MongoDBShell(BaseShell):
    """MongoDB shell - interactive MongoDB commands"""

    def __init__(self, session_id: str, session_type: str = "mongodb", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None
        self.current_database = None
        self.host = "localhost"
        self.port = 27017
        self.database_name = "admin"

        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'show': self._cmd_show,
            'use': self._cmd_use,
            'db': self._cmd_db,
            'find': self._cmd_find,
            'count': self._cmd_count,
            'collections': self._cmd_collections,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'disconnect': self._cmd_exit,
        }

        self._initialize_mongodb_connection()

    def _initialize_mongodb_connection(self):
        try:
            if not self.framework:
                return
            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if session and session.data:
                    self.host = session.data.get('host', 'localhost')
                    self.port = session.data.get('port', 27017)
                    self.database_name = session.data.get('database', 'admin')
                    listener_id = session.data.get('listener_id')
                    if listener_id and hasattr(self.framework, 'active_listeners'):
                        listener = self.framework.active_listeners.get(listener_id)
                        if listener and hasattr(listener, '_session_connections'):
                            conn = listener._session_connections.get(self.session_id)
                            if conn and isinstance(conn, MongoClient):
                                self.connection = conn
                                self.current_database = conn[self.database_name]
                                return
                    if 'connection' in session.data:
                        conn = session.data['connection']
                        if isinstance(conn, MongoClient):
                            self.connection = conn
                            self.current_database = conn[self.database_name]
        except Exception as e:
            print_warning(f"Could not initialize MongoDB connection: {e}")

    @property
    def shell_name(self) -> str:
        return "mongodb"

    @property
    def prompt_template(self) -> str:
        db = self.current_database.name if self.current_database else "(none)"
        return f"mongodb [{db}]> "

    def get_prompt(self) -> str:
        return self.prompt_template

    def execute_command(self, command: str) -> Dict[str, Any]:
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        self.add_to_history(command)
        parts = command.strip().split(None, 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        if cmd in self.builtin_commands:
            try:
                return self.builtin_commands[cmd](args)
            except Exception as e:
                return {'output': '', 'status': 1, 'error': str(e)}
        return {'output': '', 'status': 1, 'error': f'Unknown command: {cmd}. Type help.'}

    def _cmd_help(self, args: str) -> Dict[str, Any]:
        help_text = """
MongoDB Shell Commands:
=======================
  show dbs           - List databases
  show collections   - List collections in current db
  use <db>           - Switch database
  db                 - Show current database
  find <coll> [query] - Find documents (e.g. find users {}, find users {"a":1})
  count <coll> [query]- Count documents
  collections        - Alias for show collections
  help               - This help
  exit, quit         - Exit shell
"""
        return {'output': help_text.strip(), 'status': 0, 'error': ''}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
        return {'output': '', 'status': 0, 'error': ''}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        history = self.get_history()
        if not history:
            return {'output': 'No history', 'status': 0, 'error': ''}
        return {'output': '\n'.join(f"{i+1:4d}  {c}" for i, c in enumerate(history)), 'status': 0, 'error': ''}

    def _cmd_show(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'MongoDB connection not available'}
        args_lower = (args or "").strip().lower()
        if args_lower == 'dbs' or args_lower == 'databases':
            try:
                dbs = self.connection.list_database_names()
                return {'output': '\n'.join(dbs), 'status': 0, 'error': ''}
            except PyMongoError as e:
                return {'output': '', 'status': 1, 'error': str(e)}
        if args_lower == 'collections':
            return self._cmd_collections("")
        return {'output': '', 'status': 1, 'error': 'Usage: show dbs | show collections'}

    def _cmd_use(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: use <database>'}
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'MongoDB connection not available'}
        db_name = args.strip()
        self.current_database = self.connection[db_name]
        self.database_name = db_name
        return {'output': f'switched to db {db_name}', 'status': 0, 'error': ''}

    def _cmd_db(self, args: str) -> Dict[str, Any]:
        db = self.current_database.name if self.current_database else "(none)"
        return {'output': db, 'status': 0, 'error': ''}

    def _cmd_collections(self, args: str) -> Dict[str, Any]:
        if not self.current_database:
            return {'output': '', 'status': 1, 'error': 'No database selected. Use: use <db>'}
        try:
            colls = self.current_database.list_collection_names()
            return {'output': '\n'.join(colls) if colls else '(none)', 'status': 0, 'error': ''}
        except PyMongoError as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_find(self, args: str) -> Dict[str, Any]:
        if not self.current_database:
            return {'output': '', 'status': 1, 'error': 'No database selected. Use: use <db>'}
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: find <collection> [query]'}
        parts = args.strip().split(None, 1)
        coll_name = parts[0]
        query_str = parts[1] if len(parts) > 1 else "{}"
        try:
            query = json.loads(query_str) if query_str.strip() else {}
        except json.JSONDecodeError:
            return {'output': '', 'status': 1, 'error': 'Invalid JSON query'}
        try:
            coll = self.current_database[coll_name]
            cursor = coll.find(query).limit(50)
            rows = list(cursor)
            if not rows:
                return {'output': '(0 documents)', 'status': 0, 'error': ''}
            lines = [json.dumps(r, default=str) for r in rows]
            return {'output': '\n'.join(lines), 'status': 0, 'error': ''}
        except PyMongoError as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_count(self, args: str) -> Dict[str, Any]:
        if not self.current_database:
            return {'output': '', 'status': 1, 'error': 'No database selected'}
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: count <collection> [query]'}
        parts = args.strip().split(None, 1)
        coll_name = parts[0]
        query_str = parts[1] if len(parts) > 1 else "{}"
        try:
            query = json.loads(query_str) if query_str.strip() else {}
        except json.JSONDecodeError:
            return {'output': '', 'status': 1, 'error': 'Invalid JSON query'}
        try:
            n = self.current_database[coll_name].count_documents(query)
            return {'output': str(n), 'status': 0, 'error': ''}
        except PyMongoError as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                pass
        self.is_active = False
        return {'output': 'Bye!', 'status': 0, 'error': ''}

    def get_available_commands(self) -> List[str]:
        return list(self.builtin_commands.keys())
