#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MySQL shell implementation for MySQL database sessions
"""

import pymysql
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning, print_success

class MySQLShell(BaseShell):
    """MySQL shell implementation for database sessions"""
    
    def __init__(self, session_id: str, session_type: str = "mysql", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None
        self.current_database = None
        self.host = "localhost"
        self.port = 3306
        self.username = "root"
        
        # Initialize MySQL environment
        self.environment_vars = {
            'MYSQL_HOST': 'localhost',
            'MYSQL_USER': 'root'
        }
        
        # Register built-in commands
        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'use': self._cmd_use,
            'show': self._cmd_show,
            'dump': self._cmd_dump,
            'tables': self._cmd_tables,
            'databases': self._cmd_databases,
            'describe': self._cmd_describe,
            'desc': self._cmd_describe,
            'select': self._cmd_select,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'disconnect': self._cmd_exit
        }
        
        # Initialize MySQL connection
        self._initialize_mysql_connection()
    
    def _initialize_mysql_connection(self):
        """Initialize MySQL connection from session/listener"""
        try:
            if not self.framework:
                return
            
            # Get session data
            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if session:
                    # Extract connection info from session data
                    if session.data:
                        self.host = session.data.get('host', 'localhost')
                        self.port = session.data.get('port', 3306)
                        self.username = session.data.get('username', 'root')
                        self.current_database = session.data.get('database', '')
                    
                    # Try to get MySQL connection from listener
                    listener_id = session.data.get('listener_id') if session.data else None
                    if listener_id and hasattr(self.framework, 'active_listeners'):
                        listener = self.framework.active_listeners.get(listener_id)
                        if listener and hasattr(listener, '_session_connections'):
                            connection = listener._session_connections.get(self.session_id)
                            if connection:
                                # Check if it's a pymysql connection
                                if isinstance(connection, pymysql.connections.Connection):
                                    self.connection = connection
                                    # Get current database
                                    if self.connection:
                                        self.connection.ping(reconnect=True)
                                        cursor = self.connection.cursor()
                                        cursor.execute("SELECT DATABASE()")
                                        result = cursor.fetchone()
                                        if result and result[0]:
                                            self.current_database = result[0]
                                        cursor.close()
                                    return
                    
                    # If connection found in additional_data
                    if session.data and 'connection' in session.data:
                        conn = session.data['connection']
                        if isinstance(conn, pymysql.connections.Connection):
                            self.connection = conn
                            self.connection.ping(reconnect=True)
                            cursor = self.connection.cursor()
                            cursor.execute("SELECT DATABASE()")
                            result = cursor.fetchone()
                            if result and result[0]:
                                self.current_database = result[0]
                            cursor.close()
                            return
                    
        except Exception as e:
            print_warning(f"Could not initialize MySQL connection: {e}")
    
    @property
    def shell_name(self) -> str:
        return "mysql"
    
    @property
    def prompt_template(self) -> str:
        db_name = self.current_database if self.current_database else "(none)"
        return f"mysql [{db_name}]> "
    
    def get_prompt(self) -> str:
        """Get the current shell prompt"""
        return self.prompt_template
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command in the MySQL shell"""
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        
        # Add to history
        self.add_to_history(command)
        
        # Parse command
        parts = command.strip().split(None, 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        # Check for built-in commands
        if cmd in self.builtin_commands:
            try:
                return self.builtin_commands[cmd](args)
            except Exception as e:
                return {'output': '', 'status': 1, 'error': f'Built-in command error: {str(e)}'}
        
        # Try to execute as SQL query
        try:
            return self._execute_sql(command)
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'SQL execution error: {str(e)}'}
    
    def _execute_sql(self, sql: str) -> Dict[str, Any]:
        """Execute SQL query"""
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'MySQL connection not available'}
        
        try:
            self.connection.ping(reconnect=True)
            cursor = self.connection.cursor(pymysql.cursors.DictCursor)
            cursor.execute(sql)
            
            # Check if query returns results
            if cursor.description:
                # SELECT query - fetch results
                rows = cursor.fetchall()
                if not rows:
                    return {'output': 'Empty set', 'status': 0, 'error': ''}
                
                # Format output
                headers = list(rows[0].keys())
                output_lines = []
                
                # Print headers
                header_line = ' | '.join(headers)
                output_lines.append(header_line)
                output_lines.append('-' * len(header_line))
                
                # Print rows
                for row in rows:
                    values = [str(row[h]) if row[h] is not None else 'NULL' for h in headers]
                    output_lines.append(' | '.join(values))
                
                return {'output': '\n'.join(output_lines), 'status': 0, 'error': ''}
            else:
                # Non-SELECT query (INSERT, UPDATE, DELETE, etc.)
                affected = cursor.rowcount
                self.connection.commit()
                return {'output': f'Query OK, {affected} row(s) affected', 'status': 0, 'error': ''}
                
        except pymysql.Error as e:
            return {'output': '', 'status': 1, 'error': f'MySQL Error: {e}'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
        finally:
            if 'cursor' in locals():
                cursor.close()
    
    def _cmd_help(self, args: str) -> Dict[str, Any]:
        """Show help"""
        help_text = """
MySQL Shell Commands:
=====================

Database Commands:
  use <database>          - Select a database
  show databases          - List all databases
  show tables             - List tables in current database
  show tables from <db>   - List tables in specific database
  
Table Commands:
  describe <table>        - Show table structure
  desc <table>            - Alias for describe
  dump <table>            - Dump table data (SELECT * FROM table)
  dump <database>         - Dump all tables in database
  
Query Commands:
  select ...              - Execute SELECT query
  <any SQL query>         - Execute any SQL query
  
Utility Commands:
  help                    - Show this help
  clear                   - Clear screen
  history                 - Show command history
  exit, quit, disconnect  - Exit MySQL shell

Examples:
  use mysql;
  show tables;
  describe users;
  dump users;
  select * from users limit 10;
"""
        return {'output': help_text, 'status': 0, 'error': ''}
    
    def _cmd_use(self, args: str) -> Dict[str, Any]:
        """Use a database"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: use <database>'}
        
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'MySQL connection not available'}
        
        try:
            self.connection.ping(reconnect=True)
            cursor = self.connection.cursor()
            cursor.execute(f"USE `{args}`")
            cursor.close()
            self.current_database = args
            return {'output': f'Database changed to {args}', 'status': 0, 'error': ''}
        except pymysql.Error as e:
            return {'output': '', 'status': 1, 'error': f'MySQL Error: {e}'}
    
    def _cmd_show(self, args: str) -> Dict[str, Any]:
        """Show databases or tables"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: show databases|tables'}
        
        args_lower = args.lower()
        if args_lower == 'databases':
            return self._cmd_databases("")
        elif args_lower == 'tables':
            return self._cmd_tables("")
        elif args_lower.startswith('tables from '):
            db = args_lower[13:].strip()
            return self._cmd_tables(f"from {db}")
        else:
            return self._execute_sql(f"SHOW {args}")
    
    def _cmd_databases(self, args: str) -> Dict[str, Any]:
        """List all databases"""
        return self._execute_sql("SHOW DATABASES")
    
    def _cmd_tables(self, args: str) -> Dict[str, Any]:
        """List tables"""
        if args.startswith("from "):
            db = args[5:].strip()
            return self._execute_sql(f"SHOW TABLES FROM `{db}`")
        else:
            if not self.current_database:
                return {'output': '', 'status': 1, 'error': 'No database selected'}
            return self._execute_sql("SHOW TABLES")
    
    def _cmd_describe(self, args: str) -> Dict[str, Any]:
        """Describe table structure"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: describe <table>'}
        return self._execute_sql(f"DESCRIBE `{args}`")
    
    def _cmd_dump(self, args: str) -> Dict[str, Any]:
        """Dump table or database"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: dump <table> or dump <database>'}
        
        # Check if it's a database or table
        # First, try as table in current database
        if self.current_database:
            try:
                result = self._execute_sql(f"SELECT * FROM `{args}`")
                if result['status'] == 0:
                    return result
            except:
                pass
        
        # If that failed, try as database name
        return self._dump_database(args)
    
    def _dump_database(self, db_name: str) -> Dict[str, Any]:
        """Dump all tables in a database"""
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'MySQL connection not available'}
        
        try:
            self.connection.ping(reconnect=True)
            cursor = self.connection.cursor()
            cursor.execute(f"SHOW TABLES FROM `{db_name}`")
            tables = [row[0] for row in cursor.fetchall()]
            cursor.close()
            
            if not tables:
                return {'output': f'No tables found in database {db_name}', 'status': 0, 'error': ''}
            
            output_lines = []
            for table in tables:
                output_lines.append(f"\n# Dumping table: {table}")
                result = self._execute_sql(f"SELECT * FROM `{db_name}`.`{table}`")
                if result['status'] == 0:
                    output_lines.append(result['output'])
                else:
                    output_lines.append(f"Error: {result['error']}")
            
            return {'output': '\n'.join(output_lines), 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_select(self, args: str) -> Dict[str, Any]:
        """Execute SELECT query"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: select ...'}
        return self._execute_sql(f"SELECT {args}")
    
    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        """Clear screen"""
        import os
        os.system('clear' if os.name != 'nt' else 'cls')
        return {'output': '', 'status': 0, 'error': ''}
    
    def _cmd_history(self, args: str) -> Dict[str, Any]:
        """Show command history"""
        history = self.get_history()
        if not history:
            return {'output': 'No commands in history', 'status': 0, 'error': ''}
        return {'output': '\n'.join(f"{i+1:4d}  {cmd}" for i, cmd in enumerate(history)), 'status': 0, 'error': ''}
    
    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        """Exit MySQL shell"""
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
        self.is_active = False
        return {'output': 'Bye!', 'status': 0, 'error': ''}
    
    def get_available_commands(self) -> List[str]:
        """Get list of available commands"""
        return list(self.builtin_commands.keys())

