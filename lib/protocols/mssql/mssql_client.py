#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import Any, Dict, List, Optional, Union

import pymssql

from core.framework.base_module import BaseModule
from core.framework.failure import FailureType, ProcedureError

logger = logging.getLogger(__name__)

SYSTEM_DATABASES = frozenset({"master", "tempdb", "model", "msdb"})


class MSSQLClient(BaseModule):
    """MSSQL client for post modules using MSSQL sessions."""

    def __init__(self, framework=None):
        super().__init__(framework)
        self.logger = logger
        self._connection: Optional[pymssql.Connection] = None
        self._connection_info: Optional[Dict[str, Any]] = None

    def _session_id_value(self) -> str:
        if not hasattr(self, "session_id"):
            return ""
        session_id_attr = getattr(self, "session_id")
        if hasattr(session_id_attr, "value"):
            return str(session_id_attr.value or "").strip()
        return str(session_id_attr or "").strip()

    def get_mssql_connection(self) -> pymssql.Connection:
        if self._connection:
            try:
                cur = self._connection.cursor()
                cur.execute("SELECT 1")
                cur.close()
                return self._connection
            except Exception:
                self._connection = None

        if not self.framework or not hasattr(self.framework, "session_manager"):
            raise ProcedureError(
                FailureType.ConfigurationError,
                "Framework or session manager not available",
            )

        session_id_value = self._session_id_value()
        if not session_id_value:
            raise ProcedureError(
                FailureType.ConfigurationError,
                "Session ID not set. Use 'set session_id <id>' first.",
            )

        session = self.framework.session_manager.get_session(session_id_value)
        if not session:
            raise ProcedureError(
                FailureType.NotFound, f"Session not found: {session_id_value}"
            )
        if not session.data:
            raise ProcedureError(FailureType.NotAccess, "Session data not available")

        if "connection" in session.data:
            conn = session.data["connection"]
            if isinstance(conn, pymssql.Connection):
                self._connection = conn
                self._connection_info = {
                    "host": session.data.get("host", "localhost"),
                    "port": session.data.get("port", 1433),
                    "username": session.data.get("username", "sa"),
                    "database": session.data.get("database", "master"),
                }
                return self._connection

        listener_id = session.data.get("listener_id")
        if listener_id and hasattr(self.framework, "active_listeners"):
            listener = self.framework.active_listeners.get(listener_id)
            if listener and hasattr(listener, "_session_connections"):
                conn = listener._session_connections.get(session_id_value)
                if isinstance(conn, pymssql.Connection):
                    self._connection = conn
                    self._connection_info = {
                        "host": session.data.get("host", "localhost"),
                        "port": session.data.get("port", 1433),
                        "username": session.data.get("username", "sa"),
                        "database": session.data.get("database", "master"),
                    }
                    return self._connection

        raise ProcedureError(
            FailureType.NotAccess, "MSSQL connection not available in session"
        )

    def execute_query(
        self,
        query: str,
        params: Optional[tuple] = None,
        fetch_all: bool = True,
    ) -> Union[List[Dict[str, Any]], Dict[str, Any], bool]:
        connection = self.get_mssql_connection()
        cursor = None
        try:
            cursor = connection.cursor(as_dict=True)
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            if cursor.description:
                if fetch_all:
                    return cursor.fetchall() or []
                row = cursor.fetchone()
                return row if row else {}
            connection.commit()
            return True
        except pymssql.Error as exc:
            connection.rollback()
            raise ProcedureError(FailureType.Unknown, f"MSSQL Error: {exc}")
        except Exception as exc:
            connection.rollback()
            raise ProcedureError(FailureType.Unknown, f"Error executing query: {exc}")
        finally:
            if cursor:
                try:
                    cursor.close()
                except Exception:
                    pass

    def get_session_info(self) -> Dict[str, str]:
        info: Dict[str, str] = {}
        queries = {
            "current_user": "SELECT SYSTEM_USER AS value",
            "login_name": "SELECT SUSER_SNAME() AS value",
            "current_database": "SELECT DB_NAME() AS value",
            "server_name": "SELECT @@SERVERNAME AS value",
            "version": "SELECT @@VERSION AS value",
        }
        for key, query in queries.items():
            try:
                row = self.execute_query(query, fetch_all=False)
                if isinstance(row, dict) and row.get("value") is not None:
                    info[key] = str(row["value"])
            except ProcedureError:
                pass
        if self._connection_info:
            info.setdefault("host", str(self._connection_info.get("host", "")))
            info.setdefault("port", str(self._connection_info.get("port", "")))
        return info

    def get_version(self) -> Optional[str]:
        info = self.get_session_info()
        return info.get("version")

    def list_databases(self, include_system: bool = False) -> List[str]:
        rows = self.execute_query(
            "SELECT name FROM sys.databases ORDER BY name"
        )
        names = [str(row.get("name", "")) for row in rows if row.get("name")]
        if include_system:
            return names
        return [name for name in names if name not in SYSTEM_DATABASES]

    def use_database(self, database: str) -> bool:
        db = str(database or "").strip()
        if not db:
            raise ProcedureError(FailureType.NotFound, "Database name is empty")
        self.execute_query(f"USE [{db.replace(']', ']]')}]")
        if self._connection_info is not None:
            self._connection_info["database"] = db
        return True

    def list_tables(self, database: Optional[str] = None) -> List[tuple]:
        db = database or (self._connection_info or {}).get("database", "")
        if not db:
            row = self.execute_query("SELECT DB_NAME() AS db", fetch_all=False)
            db = str((row or {}).get("db") or "")
        if not db:
            return []
        rows = self.execute_query(
            "SELECT TABLE_SCHEMA, TABLE_NAME "
            f"FROM [{db.replace(']', ']]')}].INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_TYPE = 'BASE TABLE' "
            "ORDER BY TABLE_SCHEMA, TABLE_NAME"
        )
        return [
            (str(row.get("TABLE_SCHEMA", "dbo")), str(row.get("TABLE_NAME", "")))
            for row in rows
            if row.get("TABLE_NAME")
        ]

    def describe_table(
        self, table: str, schema: str = "dbo", database: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        db = database or (self._connection_info or {}).get("database", "")
        if not db:
            row = self.execute_query("SELECT DB_NAME() AS db", fetch_all=False)
            db = str((row or {}).get("db") or "")
        safe_schema = str(schema or "dbo").replace("'", "''")
        safe_table = str(table or "").replace("'", "''")
        rows = self.execute_query(
            "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH "
            f"FROM [{db.replace(']', ']]')}].INFORMATION_SCHEMA.COLUMNS "
            f"WHERE TABLE_SCHEMA = '{safe_schema}' AND TABLE_NAME = '{safe_table}' "
            "ORDER BY ORDINAL_POSITION"
        )
        return rows if isinstance(rows, list) else []

    def close(self):
        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None
            self._connection_info = None
