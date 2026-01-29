#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PostgreSQL shell implementation for PostgreSQL database sessions
"""

import psycopg2
import psycopg2.sql
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning, print_success

class PostgreSQLShell(BaseShell):
    """PostgreSQL shell implementation for database sessions"""

    def __init__(self, session_id: str, session_type: str = "postgresql", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None
        self.current_database = None
        self.host = "localhost"
        self.port = 5432
        self.username = "postgres"
        self.password = ""

        self.environment_vars = {
            'PGHOST': 'localhost',
            'PGUSER': 'postgres',
        }

        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            '\\c': self._cmd_connect,
            'connect': self._cmd_connect,
            '\\l': self._cmd_databases,
            '\\list': self._cmd_databases,
            '\\dt': self._cmd_tables,
            '\\d': self._cmd_describe,
            '\\du': self._cmd_roles,
            'dump': self._cmd_dump,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            '\\q': self._cmd_exit,
            'disconnect': self._cmd_exit,
        }

        self._initialize_postgresql_connection()

    def _initialize_postgresql_connection(self):
        """Initialize PostgreSQL connection from session/listener"""
        try:
            if not self.framework:
                return

            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if session and session.data:
                    self.host = session.data.get('host', 'localhost')
                    self.port = session.data.get('port', 5432)
                    self.username = session.data.get('username', 'postgres')
                    self.password = session.data.get('password', '')
                    self.current_database = session.data.get('database', 'postgres')

                    listener_id = session.data.get('listener_id')
                    if listener_id and hasattr(self.framework, 'active_listeners'):
                        listener = self.framework.active_listeners.get(listener_id)
                        if listener and hasattr(listener, '_session_connections'):
                            connection = listener._session_connections.get(self.session_id)
                            if connection and isinstance(connection, psycopg2.extensions.connection):
                                self.connection = connection
                                try:
                                    with self.connection.cursor() as cur:
                                        cur.execute("SELECT current_database()")
                                        row = cur.fetchone()
                                        if row:
                                            self.current_database = row[0]
                                except Exception:
                                    pass
                                return

                    if 'connection' in session.data:
                        conn = session.data['connection']
                        if isinstance(conn, psycopg2.extensions.connection):
                            self.connection = conn
                            try:
                                with self.connection.cursor() as cur:
                                    cur.execute("SELECT current_database()")
                                    row = cur.fetchone()
                                    if row:
                                        self.current_database = row[0]
                            except Exception:
                                pass
        except Exception as e:
            print_warning(f"Could not initialize PostgreSQL connection: {e}")

    @property
    def shell_name(self) -> str:
        return "postgresql"

    @property
    def prompt_template(self) -> str:
        db_name = self.current_database if self.current_database else "(none)"
        return f"postgresql [{db_name}]> "

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
                return {'output': '', 'status': 1, 'error': f'Built-in command error: {str(e)}'}

        if cmd.startswith('\\'):
            return {'output': '', 'status': 1, 'error': f'Unknown command: {cmd}'}

        try:
            return self._execute_sql(command)
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'SQL execution error: {str(e)}'}

    def _execute_sql(self, sql: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'PostgreSQL connection not available'}

        try:
            with self.connection.cursor() as cur:
                cur.execute(sql)

                if cur.description:
                    rows = cur.fetchall()
                    if not rows:
                        return {'output': ' (0 rows)', 'status': 0, 'error': ''}

                    headers = [desc[0] for desc in cur.description]
                    output_lines = [' | '.join(headers), '-' * (len(' | '.join(headers)))]

                    for row in rows:
                        values = [str(v) if v is not None else 'NULL' for v in row]
                        output_lines.append(' | '.join(values))

                    return {'output': '\n'.join(output_lines), 'status': 0, 'error': ''}
                else:
                    self.connection.commit()
                    return {'output': f' (command ok, {cur.rowcount} row(s))', 'status': 0, 'error': ''}

        except psycopg2.Error as e:
            if not self.connection.closed:
                self.connection.rollback()
            return {'output': '', 'status': 1, 'error': f'PostgreSQL Error: {e}'}
        except Exception as e:
            if self.connection and not self.connection.closed:
                self.connection.rollback()
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}

    def _cmd_help(self, args: str) -> Dict[str, Any]:
        help_text = """
PostgreSQL Shell Commands:
==========================

Database:
  \\l, \\list          - List databases
  \\c <db>            - Connect to database (reconnect)
  connect <db>       - Alias for \\c

Tables:
  \\dt                - List tables in current schema
  \\d <table>         - Describe table structure
  \\du                - List roles/users

Data:
  dump <table>       - Dump table (SELECT * FROM table)
  <SQL query>       - Execute any SQL

Utility:
  help               - This help
  clear              - Clear screen
  history            - Command history
  exit, quit, \\q     - Exit shell

Examples:
  \\l
  \\c mydb
  \\dt
  \\d users
  SELECT * FROM users LIMIT 10;
"""
        return {'output': help_text, 'status': 0, 'error': ''}

    def _cmd_connect(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: \\c <database> or connect <database>'}

        if not self.framework or not hasattr(self.framework, 'session_manager'):
            return {'output': '', 'status': 1, 'error': 'Cannot reconnect: session data unavailable'}

        session = self.framework.session_manager.get_session(self.session_id)
        if not session or not session.data:
            return {'output': '', 'status': 1, 'error': 'Cannot reconnect: session data unavailable'}

        host = session.data.get('host', self.host)
        port = session.data.get('port', self.port)
        user = session.data.get('username', self.username)
        password = session.data.get('password', self.password)

        try:
            if self.connection and not self.connection.closed:
                self.connection.close()
            self.connection = psycopg2.connect(
                host=host, port=port, user=user, password=password, dbname=args.strip()
            )
            self.current_database = args.strip()
            return {'output': f'Connected to database "{self.current_database}"', 'status': 0, 'error': ''}
        except psycopg2.Error as e:
            return {'output': '', 'status': 1, 'error': f'PostgreSQL Error: {e}'}

    def _cmd_databases(self, args: str) -> Dict[str, Any]:
        return self._execute_sql(
            "SELECT datname AS \"Name\" FROM pg_database WHERE datistemplate = false ORDER BY datname"
        )

    def _cmd_tables(self, args: str) -> Dict[str, Any]:
        return self._execute_sql(
            "SELECT tablename AS \"Name\" FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"
        )

    def _cmd_describe(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: \\d <table>'}

        table = args.strip().split()[0]
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'PostgreSQL connection not available'}
        try:
            with self.connection.cursor() as cur:
                cur.execute(
                    "SELECT column_name AS \"Column\", data_type AS \"Type\", "
                    "is_nullable AS \"Nullable\" FROM information_schema.columns "
                    "WHERE table_name = %s ORDER BY ordinal_position",
                    (table,)
                )
                rows = cur.fetchall()
                if not rows:
                    return {'output': f'Table "{table}" not found', 'status': 0, 'error': ''}
                headers = [desc[0] for desc in cur.description]
                output_lines = [' | '.join(headers), '-' * 50]
                for row in rows:
                    output_lines.append(' | '.join(str(v) if v else 'NULL' for v in row))
                return {'output': '\n'.join(output_lines), 'status': 0, 'error': ''}
        except psycopg2.Error as e:
            return {'output': '', 'status': 1, 'error': f'PostgreSQL Error: {e}'}

    def _cmd_roles(self, args: str) -> Dict[str, Any]:
        return self._execute_sql("SELECT rolname AS \"Role name\" FROM pg_roles ORDER BY rolname")

    def _cmd_dump(self, args: str) -> Dict[str, Any]:
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: dump <table>'}

        table = args.strip().split()[0]
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'PostgreSQL connection not available'}
        try:
            with self.connection.cursor() as cur:
                cur.execute(psycopg2.sql.SQL("SELECT * FROM {}").format(psycopg2.sql.Identifier(table)))
                rows = cur.fetchall()
                if not rows:
                    return {'output': ' (0 rows)', 'status': 0, 'error': ''}
                headers = [desc[0] for desc in cur.description]
                output_lines = [' | '.join(headers), '-' * 50]
                for row in rows:
                    output_lines.append(' | '.join(str(v) if v is not None else 'NULL' for v in row))
                return {'output': '\n'.join(output_lines), 'status': 0, 'error': ''}
        except psycopg2.Error as e:
            return {'output': '', 'status': 1, 'error': f'PostgreSQL Error: {e}'}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
        return {'output': '', 'status': 0, 'error': ''}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        history = self.get_history()
        if not history:
            return {'output': 'No commands in history', 'status': 0, 'error': ''}
        return {'output': '\n'.join(f"{i+1:4d}  {cmd}" for i, cmd in enumerate(history)), 'status': 0, 'error': ''}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        if self.connection and not self.connection.closed:
            try:
                self.connection.close()
            except Exception:
                pass
        self.is_active = False
        return {'output': 'Bye!', 'status': 0, 'error': ''}

    def get_available_commands(self) -> List[str]:
        return list(self.builtin_commands.keys())
