#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Redis shell implementation for Redis sessions.
"""

import redis
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning, print_success

class RedisShell(BaseShell):
    """Redis shell - execute Redis commands interactively"""

    def __init__(self, session_id: str, session_type: str = "redis", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None
        self.host = "localhost"
        self.port = 6379
        self.db = 0

        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'info': self._cmd_info,
            'keys': self._cmd_keys,
            'get': self._cmd_get,
            'set': self._cmd_set,
            'del': self._cmd_del,
            'type': self._cmd_type_cmd,
            'ttl': self._cmd_ttl,
            'dbsize': self._cmd_dbsize,
            'config': self._cmd_config,
            'select': self._cmd_select,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'disconnect': self._cmd_exit,
        }

        self._initialize_redis_connection()

    def _initialize_redis_connection(self):
        """Initialize Redis connection from session/listener"""
        try:
            if not self.framework:
                return
            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if session and session.data:
                    self.host = session.data.get('host', 'localhost')
                    self.port = session.data.get('port', 6379)
                    self.db = session.data.get('db', 0)
                    listener_id = session.data.get('listener_id')
                    if listener_id and hasattr(self.framework, 'active_listeners'):
                        listener = self.framework.active_listeners.get(listener_id)
                        if listener and hasattr(listener, '_session_connections'):
                            conn = listener._session_connections.get(self.session_id)
                            if conn and isinstance(conn, redis.Redis):
                                self.connection = conn
                                return
                    if 'connection' in session.data:
                        conn = session.data['connection']
                        if isinstance(conn, redis.Redis):
                            self.connection = conn
        except Exception as e:
            print_warning(f"Could not initialize Redis connection: {e}")

    @property
    def shell_name(self) -> str:
        return "redis"

    @property
    def prompt_template(self) -> str:
        return f"redis [{self.host}:{self.port} db{self.db}]> "

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
        return self._redis_execute(command)

    def _redis_execute(self, command: str) -> Dict[str, Any]:
        """Execute raw Redis command via execute_command"""
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'Redis connection not available'}
        try:
            parts = command.strip().split()
            if not parts:
                return {'output': '', 'status': 0, 'error': ''}
            result = self.connection.execute_command(*parts)
            if result is None:
                return {'output': '(nil)', 'status': 0, 'error': ''}
            if isinstance(result, list):
                lines = [str(item) for item in result]
                return {'output': '\n'.join(lines), 'status': 0, 'error': ''}
            return {'output': str(result), 'status': 0, 'error': ''}
        except redis.RedisError as e:
            return {'output': '', 'status': 1, 'error': str(e)}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_help(self, args: str) -> Dict[str, Any]:
        help_text = """
Redis Shell Commands:
====================
  keys [pattern]   - List keys (e.g. keys *)
  get <key>       - Get string value
  set <key> <val> - Set string value
  del <key> [...] - Delete key(s)
  type <key>      - Key type
  ttl <key>       - Time to live
  dbsize          - Number of keys in current db
  info [section]  - Server info (server, memory, stats, etc.)
  config get *    - Get config (e.g. config get dir)
  select <db>     - Switch database (0-15)
  <redis cmd>     - Any Redis command (e.g. HGETALL user:1)
  help            - This help
  exit, quit      - Exit shell
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

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'Redis connection not available'}
        try:
            section = args.strip() if args else None
            info = self.connection.info(section)
            if isinstance(info, dict):
                lines = []
                for k, v in info.items():
                    if isinstance(v, dict):
                        lines.append(f"# {k}")
                        for k2, v2 in v.items():
                            lines.append(f"{k2}:{v2}")
                    else:
                        lines.append(f"{k}:{v}")
                return {'output': '\n'.join(lines), 'status': 0, 'error': ''}
            return {'output': str(info), 'status': 0, 'error': ''}
        except redis.RedisError as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_keys(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'Redis connection not available'}
        try:
            pattern = args.strip() if args else '*'
            keys = self.connection.keys(pattern)
            if not keys:
                return {'output': '(empty list or set)', 'status': 0, 'error': ''}
            return {'output': '\n'.join(keys), 'status': 0, 'error': ''}
        except redis.RedisError as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_get(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: get <key>'}
        return self._redis_execute(f"GET {args}")

    def _cmd_set(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: set <key> <value>'}
        return self._redis_execute(f"SET {args}")

    def _cmd_del(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: del <key> [key ...]'}
        return self._redis_execute(f"DEL {args}")

    def _cmd_type_cmd(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: type <key>'}
        return self._redis_execute(f"TYPE {args}")

    def _cmd_ttl(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: ttl <key>'}
        return self._redis_execute(f"TTL {args}")

    def _cmd_dbsize(self, args: str) -> Dict[str, Any]:
        return self._redis_execute("DBSIZE")

    def _cmd_config(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: config get <param> or config set <param> <value>'}
        return self._redis_execute(f"CONFIG {args}")

    def _cmd_select(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: select <db 0-15>'}
        try:
            db = int(args.strip())
            self.connection.select(db)
            self.db = db
            return {'output': f'OK (db{db})', 'status': 0, 'error': ''}
        except ValueError:
            return {'output': '', 'status': 1, 'error': 'Invalid db number'}
        except redis.RedisError as e:
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
