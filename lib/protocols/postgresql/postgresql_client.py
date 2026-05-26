#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import Any, Dict, List, Optional, Union

import psycopg2

from core.framework.base_module import BaseModule
from core.framework.failure import FailureType, ProcedureError

logger = logging.getLogger(__name__)


class PostgreSQLClient(BaseModule):
    """PostgreSQL client for post modules using PostgreSQL sessions."""

    def __init__(self, framework=None):
        super().__init__(framework)
        self.logger = logger
        self._connection = None
        self._connection_info = None

    def _session_id_value(self) -> str:
        if not hasattr(self, "session_id"):
            return ""
        session_id_attr = getattr(self, "session_id")
        if hasattr(session_id_attr, "value"):
            return str(session_id_attr.value or "").strip()
        return str(session_id_attr or "").strip()

    def get_postgresql_connection(self) -> psycopg2.extensions.connection:
        if self._connection and not self._connection.closed:
            return self._connection

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
            if isinstance(conn, psycopg2.extensions.connection) and not conn.closed:
                self._connection = conn
                self._connection_info = {
                    "host": session.data.get("host", "localhost"),
                    "port": session.data.get("port", 5432),
                    "username": session.data.get("username", "postgres"),
                    "database": session.data.get("database", "postgres"),
                }
                return self._connection

        listener_id = session.data.get("listener_id")
        if listener_id and hasattr(self.framework, "active_listeners"):
            listener = self.framework.active_listeners.get(listener_id)
            if listener and hasattr(listener, "_session_connections"):
                conn = listener._session_connections.get(session_id_value)
                if isinstance(conn, psycopg2.extensions.connection) and not conn.closed:
                    self._connection = conn
                    self._connection_info = {
                        "host": session.data.get("host", "localhost"),
                        "port": session.data.get("port", 5432),
                        "username": session.data.get("username", "postgres"),
                        "database": session.data.get("database", "postgres"),
                    }
                    return self._connection

        raise ProcedureError(
            FailureType.NotAccess, "PostgreSQL connection not available in session"
        )

    def _prepare_connection(self, connection, autocommit: bool = True) -> None:
        """Reset aborted transactions before running post-module queries."""
        if connection.closed:
            return
        try:
            connection.rollback()
        except Exception:
            pass
        if autocommit:
            connection.autocommit = True

    def execute_query(
        self,
        query: str,
        params: Optional[tuple] = None,
        fetch_all: bool = True,
        autocommit: bool = True,
    ) -> Union[List[tuple], tuple, bool, str]:
        connection = self.get_postgresql_connection()
        self._prepare_connection(connection, autocommit)

        try:
            with connection.cursor() as cur:
                if params:
                    cur.execute(query, params)
                else:
                    cur.execute(query)

                if cur.description:
                    if fetch_all:
                        return cur.fetchall()
                    row = cur.fetchone()
                    return row if row is not None else ()
                if not autocommit:
                    connection.commit()
                return True
        except psycopg2.Error as e:
            if not connection.closed and not autocommit:
                connection.rollback()
            raise ProcedureError(FailureType.Unknown, f"PostgreSQL Error: {e}")
        except Exception as e:
            if not connection.closed and not autocommit:
                connection.rollback()
            raise ProcedureError(FailureType.Unknown, f"Error executing query: {e}")

    def execute_query_raw(self, query: str) -> str:
        """Execute SQL and return stringified rows or error text (for exploit parsing)."""
        connection = self.get_postgresql_connection()
        self._prepare_connection(connection, autocommit=True)
        try:
            with connection.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()

                def to_hex(v):
                    if isinstance(v, memoryview):
                        return v.tobytes().hex()
                    return str(v)

                formatted = [[to_hex(v) for v in row] for row in rows]
                return str(formatted)
        except Exception as e:
            return str(e)

    def extension_installed(self, name: str) -> bool:
        try:
            rows = self.execute_query(
                "SELECT 1 FROM pg_extension WHERE extname = %s LIMIT 1",
                (name,),
                fetch_all=False,
            )
            return bool(rows)
        except Exception:
            return False

    def function_exists(self, name: str) -> bool:
        try:
            rows = self.execute_query(
                "SELECT 1 FROM pg_proc WHERE proname = %s LIMIT 1",
                (name,),
                fetch_all=False,
            )
            return bool(rows)
        except Exception:
            return False

    def get_version(self) -> Optional[str]:
        try:
            rows = self.execute_query("SELECT version();", fetch_all=False)
            return str(rows[0]) if rows else None
        except Exception:
            return None

    def get_session_info(self) -> Dict[str, str]:
        info: Dict[str, str] = {}
        queries = {
            "current_user": "SELECT current_user;",
            "session_user": "SELECT session_user;",
            "current_database": "SELECT current_database();",
            "server_addr": "SELECT inet_server_addr();",
            "server_port": "SELECT inet_server_port();",
            "is_superuser": "SELECT current_setting('is_superuser');",
        }
        for key, query in queries.items():
            try:
                rows = self.execute_query(query, fetch_all=False)
                if rows and rows[0] is not None:
                    info[key] = str(rows[0])
            except ProcedureError:
                pass
            except Exception:
                pass
        return info

    def is_superuser(self) -> bool:
        try:
            rows = self.execute_query(
                "SELECT current_setting('is_superuser');",
                fetch_all=False,
            )
            return str(rows[0]).lower() in ("on", "true", "1") if rows else False
        except Exception:
            return False

    def get_setting(self, name: str) -> Optional[str]:
        """Read a GUC via pg_settings (public) then current_setting(missing_ok)."""
        try:
            rows = self.execute_query(
                "SELECT setting FROM pg_settings WHERE name = %s;",
                (name,),
                fetch_all=False,
            )
            if rows and rows[0] is not None:
                return str(rows[0])
        except Exception:
            pass
        try:
            rows = self.execute_query(
                "SELECT current_setting(%s, true);",
                (name,),
                fetch_all=False,
            )
            if rows and rows[0] is not None:
                return str(rows[0])
        except Exception:
            pass
        return None

    def get_settings(self, names: List[str]) -> Dict[str, Optional[str]]:
        result: Dict[str, Optional[str]] = {n: None for n in names}
        if not names:
            return result
        try:
            rows = self.execute_query(
                "SELECT name, setting FROM pg_settings WHERE name = ANY(%s);",
                (list(names),),
            )
            for name, setting in rows:
                result[str(name)] = str(setting) if setting is not None else None
        except Exception:
            pass
        for name in names:
            if result[name] is None:
                result[name] = self.get_setting(name)
        return result

    def list_databases(self) -> List[str]:
        try:
            rows = self.execute_query(
                "SELECT datname FROM pg_database "
                "WHERE datistemplate = false ORDER BY datname;"
            )
            return [str(row[0]) for row in rows]
        except Exception:
            return []

    def list_schemas(self) -> List[str]:
        try:
            rows = self.execute_query(
                "SELECT nspname FROM pg_namespace "
                "WHERE nspname NOT LIKE 'pg\\_%' ESCAPE '\\' "
                "AND nspname <> 'information_schema' "
                "ORDER BY nspname;"
            )
            return [str(row[0]) for row in rows]
        except Exception:
            return []

    def list_tables(self, schema: str = "public") -> List[str]:
        try:
            rows = self.execute_query(
                "SELECT tablename FROM pg_tables "
                "WHERE schemaname = %s ORDER BY tablename;",
                (schema,),
            )
            return [str(row[0]) for row in rows]
        except Exception:
            return []

    def describe_table(self, table: str, schema: str = "public") -> List[tuple]:
        try:
            return self.execute_query(
                "SELECT column_name, data_type, is_nullable, column_default "
                "FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = %s "
                "ORDER BY ordinal_position;",
                (schema, table),
            )
        except Exception:
            return []

    def list_roles(self, include_system: bool = False) -> List[tuple]:
        query = (
            "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, "
            "rolreplication, rolbypassrls, rolcanlogin, rolvaliduntil "
            "FROM pg_roles "
        )
        if not include_system:
            query += "WHERE rolname NOT LIKE 'pg\\_%' ESCAPE '\\' "
        query += "ORDER BY rolname;"
        try:
            return self.execute_query(query)
        except Exception:
            return []

    def read_server_file(self, path: str, offset: int = 0, length: int = 8192) -> Optional[bytes]:
        """Read a server file via pg_read_file (superuser)."""
        if not self.is_superuser():
            raise ProcedureError(
                FailureType.NotAccess, "pg_read_file requires superuser"
            )
        rows = self.execute_query(
            "SELECT pg_read_file(%s, %s, %s);",
            (path, offset, length),
            fetch_all=False,
        )
        if not rows or rows[0] is None:
            return None
        data = rows[0]
        if isinstance(data, memoryview):
            return data.tobytes()
        if isinstance(data, bytes):
            return data
        return str(data).encode("utf-8", errors="replace")

    def write_server_file(self, path: str, content: str) -> bool:
        """Write a server file via COPY TO (superuser)."""
        if not self.is_superuser():
            raise ProcedureError(
                FailureType.NotAccess, "COPY TO server path requires superuser"
            )
        self.execute_query(
            "COPY (SELECT %s::text) TO %s;",
            (content, path),
        )
        return True

    def close(self):
        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None
            self._connection_info = None
