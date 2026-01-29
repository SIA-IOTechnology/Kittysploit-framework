#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSSQL shell implementation for Microsoft SQL Server sessions.
"""

import pymssql
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning, print_success

class MSSQLShell(BaseShell):
    """MSSQL shell - execute T-SQL and browse database"""

    def __init__(self, session_id: str, session_type: str = "mssql", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None
        self.current_database = None
        self.host = "localhost"
        self.port = 1433
        self.username = "sa"

        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'use': self._cmd_use,
            'databases': self._cmd_databases,
            'tables': self._cmd_tables,
            'query': self._cmd_query,
            'select': self._cmd_select,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'disconnect': self._cmd_exit,
        }

        self._initialize_mssql_connection()

    def _initialize_mssql_connection(self):
        try:
            if not self.framework:
                return
            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if session and session.data:
                    self.host = session.data.get('host', 'localhost')
                    self.port = session.data.get('port', 1433)
                    self.username = session.data.get('username', 'sa')
                    self.current_database = session.data.get('database', 'master')
                    listener_id = session.data.get('listener_id')
                    if listener_id and hasattr(self.framework, 'active_listeners'):
                        listener = self.framework.active_listeners.get(listener_id)
                        if listener and hasattr(listener, '_session_connections'):
                            conn = listener._session_connections.get(self.session_id)
                            if conn and isinstance(conn, pymssql.Connection):
                                self.connection = conn
                                return
                    if 'connection' in session.data:
                        conn = session.data['connection']
                        if isinstance(conn, pymssql.Connection):
                            self.connection = conn
        except Exception as e:
            print_warning(f"Could not initialize MSSQL connection: {e}")

    @property
    def shell_name(self) -> str:
        return "mssql"

    @property
    def prompt_template(self) -> str:
        db = self.current_database if self.current_database else "(none)"
        return f"mssql [{db}]> "

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
        return self._execute_sql(command)

    def _execute_sql(self, sql: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'MSSQL connection not available'}
        try:
            cursor = self.connection.cursor(as_dict=True)
            cursor.execute(sql)
            if cursor.description:
                rows = cursor.fetchall()
                if not rows:
                    return {'output': '(0 rows)', 'status': 0, 'error': ''}
                headers = list(rows[0].keys())
                output_lines = [' | '.join(headers), '-' * 50]
                for row in rows:
                    values = [str(row[h]) if row.get(h) is not None else 'NULL' for h in headers]
                    output_lines.append(' | '.join(values))
                return {'output': '\n'.join(output_lines), 'status': 0, 'error': ''}
            self.connection.commit()
            return {'output': f'({cursor.rowcount} row(s) affected)', 'status': 0, 'error': ''}
        except pymssql.Error as e:
            return {'output': '', 'status': 1, 'error': f'MSSQL Error: {e}'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': str(e)}
        finally:
            try:
                cursor.close()
            except Exception:
                pass

    def _cmd_help(self, args: str) -> Dict[str, Any]:
        help_text = """
MSSQL Shell Commands:
=====================
  use <db>          - Set current database
  databases         - List databases
  tables            - List tables in current database
  query <sql>       - Execute SQL (e.g. query SELECT * FROM users)
  select ...       - Alias for query SELECT ...
  <sql>            - Execute any T-SQL
  help              - This help
  exit, quit        - Exit shell
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

    def _cmd_use(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: use <database>'}
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'MSSQL connection not available'}
        db = args.strip()
        try:
            cur = self.connection.cursor()
            cur.execute(f"USE [{db}]")
            cur.close()
            self.current_database = db
            return {'output': f'Using database {db}', 'status': 0, 'error': ''}
        except pymssql.Error as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_databases(self, args: str) -> Dict[str, Any]:
        return self._execute_sql(
            "SELECT name FROM sys.databases ORDER BY name"
        )

    def _cmd_tables(self, args: str) -> Dict[str, Any]:
        if not self.current_database:
            return {'output': '', 'status': 1, 'error': 'No database selected. Use: use <db>'}
        return self._execute_sql(
            f"SELECT TABLE_SCHEMA, TABLE_NAME FROM [{self.current_database}].INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME"
        )

    def _cmd_query(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: query <sql>'}
        return self._execute_sql(args)

    def _cmd_select(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: select ...'}
        return self._execute_sql(f"SELECT {args}")

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
