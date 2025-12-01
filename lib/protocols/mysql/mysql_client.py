#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pymysql
import logging
from typing import Dict, List, Any, Optional, Union
from core.framework.base_module import BaseModule
from core.framework.failure import ProcedureError, FailureType

logger = logging.getLogger(__name__)

class MySQLClient(BaseModule):
    """MySQL client library for interacting with MySQL databases via sessions"""
    
    def __init__(self, framework=None):
        """
        Initialize MySQL client.
        """
        super().__init__(framework)
        self.logger = logger
        self._connection = None
        self._connection_info = None
    
    def get_mysql_connection(self) -> Optional[pymysql.connections.Connection]:
        """
        Get MySQL connection from the current session.
        
        Returns:
            pymysql.connections.Connection: MySQL connection object or None if not available
            
        Raises:
            ProcedureError: If connection cannot be established
        """
        # Return cached connection if available and still alive
        if self._connection:
            try:
                self._connection.ping(reconnect=True)
                return self._connection
            except:
                self._connection = None
        
        try:
            if not self.framework or not hasattr(self.framework, 'session_manager'):
                raise ProcedureError(FailureType.ConfigurationError, "Framework or session manager not available")
            
            # Get session_id from module options
            session_id_value = None
            if hasattr(self, 'session_id'):
                session_id_attr = getattr(self, 'session_id')
                if hasattr(session_id_attr, 'value'):
                    session_id_value = session_id_attr.value
                else:
                    session_id_value = str(session_id_attr)
            
            if not session_id_value:
                raise ProcedureError(FailureType.ConfigurationError, "Session ID not set. Use 'set session_id <id>' first.")
            
            session = self.framework.session_manager.get_session(session_id_value)
            if not session:
                raise ProcedureError(FailureType.NotFound, f"Session not found: {session_id_value}")
            
            if not session.data:
                raise ProcedureError(FailureType.NotAccess, "Session data not available")
            
            # Try to get connection from session data
            if 'connection' in session.data:
                conn = session.data['connection']
                if isinstance(conn, pymysql.connections.Connection):
                    conn.ping(reconnect=True)
                    self._connection = conn
                    self._connection_info = {
                        'host': session.data.get('host', 'localhost'),
                        'port': session.data.get('port', 3306),
                        'username': session.data.get('username', 'root'),
                        'database': session.data.get('database', '')
                    }
                    return self._connection
            
            # Try to get from listener
            listener_id = session.data.get('listener_id')
            if listener_id and hasattr(self.framework, 'active_listeners'):
                listener = self.framework.active_listeners.get(listener_id)
                if listener and hasattr(listener, '_session_connections'):
                    connection = listener._session_connections.get(session_id_value)
                    if isinstance(connection, pymysql.connections.Connection):
                        connection.ping(reconnect=True)
                        self._connection = connection
                        self._connection_info = {
                            'host': session.data.get('host', 'localhost'),
                            'port': session.data.get('port', 3306),
                            'username': session.data.get('username', 'root'),
                            'database': session.data.get('database', '')
                        }
                        return self._connection
            
            raise ProcedureError(FailureType.NotAccess, "MySQL connection not available in session")
            
        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Error getting MySQL connection: {e}")
    
    def execute_query(self, query: str, params: Optional[tuple] = None, fetch_all: bool = True) -> Union[List[Dict], Dict, bool]:
        """
        Execute a SQL query and return results.
        
        Args:
            query: SQL query to execute
            params: Parameters for parameterized query (optional)
            fetch_all: If True, fetch all results; if False, fetch one result
            
        Returns:
            List[Dict]: Query results (for SELECT queries)
            bool: True for successful execution (for INSERT/UPDATE/DELETE)
            Dict: Single row result if fetch_all=False
            
        Raises:
            ProcedureError: If query execution fails
        """
        connection = self.get_mysql_connection()
        if not connection:
            raise ProcedureError(FailureType.NotAccess, "MySQL connection not available")
        
        cursor = None
        try:
            cursor = connection.cursor(pymysql.cursors.DictCursor)
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            # Check if query returns results
            if cursor.description:
                # SELECT query - fetch results
                if fetch_all:
                    results = cursor.fetchall()
                    return results
                else:
                    result = cursor.fetchone()
                    return result if result else {}
            else:
                # Non-SELECT query (INSERT, UPDATE, DELETE, etc.)
                connection.commit()
                return True
                
        except pymysql.Error as e:
            connection.rollback()
            raise ProcedureError(FailureType.Unknown, f"MySQL Error: {e}")
        except Exception as e:
            if connection:
                connection.rollback()
            raise ProcedureError(FailureType.Unknown, f"Error executing query: {e}")
        finally:
            if cursor:
                cursor.close()
    
    def check_privilege(self, privilege: str) -> bool:
        """
        Check if current MySQL user has a specific privilege.
        
        Args:
            privilege: Privilege name (e.g., 'FILE', 'SUPER', 'PROCESS')
            
        Returns:
            bool: True if user has the privilege, False otherwise
        """
        try:
            query = """
                SELECT COUNT(*) as has_priv 
                FROM information_schema.user_privileges 
                WHERE grantee = CONCAT('\\'', REPLACE(CURRENT_USER(), '@', '\\'@\\''), '\\'') 
                AND privilege_type = %s
            """
            result = self.execute_query(query, (privilege,), fetch_all=False)
            return result.get('has_priv', 0) > 0
        except:
            return False
    
    def get_secure_file_priv(self) -> Optional[str]:
        """
        Get the secure_file_priv setting.
        
        Returns:
            str: secure_file_priv value or None
        """
        try:
            result = self.execute_query("SELECT @@secure_file_priv as value", fetch_all=False)
            return result.get('value') if result else None
        except:
            return None
    
    def get_plugin_dir(self) -> Optional[str]:
        """
        Get the plugin directory path.
        
        Returns:
            str: Plugin directory path or None
        """
        try:
            result = self.execute_query("SHOW VARIABLES LIKE 'plugin_dir'", fetch_all=False)
            if result:
                # Result is a dict with Variable_name and Value
                return list(result.values())[1] if len(result.values()) > 1 else None
            return None
        except:
            return None
    
    def get_current_user(self) -> Optional[str]:
        """
        Get current MySQL user.
        
        Returns:
            str: Current user or None
        """
        try:
            result = self.execute_query("SELECT USER() as user, CURRENT_USER() as current_user", fetch_all=False)
            if result:
                return result.get('user') or result.get('current_user')
            return None
        except:
            return None
    
    def use_database(self, database: str) -> bool:
        """
        Select a database.
        
        Args:
            database: Database name to use
            
        Returns:
            bool: True if successful
        """
        try:
            self.execute_query(f"USE `{database}`")
            return True
        except Exception as e:
            raise ProcedureError(FailureType.NotFound, f"Database not found: {database}")
    
    def list_databases(self) -> List[str]:
        """
        List all databases.
        
        Returns:
            List[str]: List of database names
        """
        try:
            results = self.execute_query("SHOW DATABASES")
            return [list(db.values())[0] for db in results]
        except:
            return []
    
    def list_tables(self, database: Optional[str] = None) -> List[str]:
        """
        List tables in a database.
        
        Args:
            database: Database name (uses current database if None)
            
        Returns:
            List[str]: List of table names
        """
        try:
            if database:
                query = f"SHOW TABLES FROM `{database}`"
            else:
                query = "SHOW TABLES"
            
            results = self.execute_query(query)
            return [list(table.values())[0] for table in results]
        except:
            return []
    
    def describe_table(self, table: str, database: Optional[str] = None) -> List[Dict]:
        """
        Get table structure.
        
        Args:
            table: Table name
            database: Database name (uses current database if None)
            
        Returns:
            List[Dict]: Table columns information
        """
        try:
            if database:
                query = f"DESCRIBE `{database}`.`{table}`"
            else:
                query = f"DESCRIBE `{table}`"
            
            return self.execute_query(query)
        except:
            return []
    
    def load_file(self, file_path: str) -> Optional[str]:
        """
        Read a file using LOAD_FILE() - requires FILE privilege.
        
        Args:
            file_path: Path to file to read
            
        Returns:
            str: File content or None if file cannot be read
            
        Raises:
            ProcedureError: If FILE privilege is not available
        """
        if not self.check_privilege('FILE'):
            raise ProcedureError(FailureType.NotAccess, "FILE privilege required for LOAD_FILE")
        
        try:
            result = self.execute_query("SELECT LOAD_FILE(%s) as content", (file_path,), fetch_all=False)
            return result.get('content') if result else None
        except Exception as e:
            raise ProcedureError(FailureType.NotAccess, f"Cannot read file: {e}")
    
    def write_file(self, file_path: str, content: str) -> bool:
        """
        Write a file using INTO OUTFILE - requires FILE privilege.
        
        Args:
            file_path: Path to file to write
            content: Content to write
            
        Returns:
            bool: True if successful
            
        Raises:
            ProcedureError: If FILE privilege is not available or write fails
        """
        if not self.check_privilege('FILE'):
            raise ProcedureError(FailureType.NotAccess, "FILE privilege required for INTO OUTFILE")
        
        try:
            # Escape content and file path
            escaped_content = content.replace('\\', '\\\\').replace("'", "\\'")
            escaped_path = file_path.replace('\\', '\\\\').replace("'", "\\'")
            query = f"SELECT '{escaped_content}' INTO OUTFILE '{escaped_path}'"
            self.execute_query(query)
            return True
        except Exception as e:
            raise ProcedureError(FailureType.NotAccess, f"Cannot write file: {e}")
    
    def close(self):
        """Close the MySQL connection"""
        if self._connection:
            try:
                self._connection.close()
            except:
                pass
            self._connection = None
            self._connection_info = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

