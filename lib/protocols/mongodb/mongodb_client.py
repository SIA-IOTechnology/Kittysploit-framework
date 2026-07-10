#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import Any, Dict, List, Optional

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from core.framework.base_module import BaseModule
from core.framework.failure import FailureType, ProcedureError

logger = logging.getLogger(__name__)


class MongoDBClient(BaseModule):
    """MongoDB client for post modules using MongoDB sessions."""

    def __init__(self, framework=None):
        super().__init__(framework)
        self.logger = logger
        self._connection: Optional[MongoClient] = None
        self._connection_info: Optional[Dict[str, Any]] = None

    def _session_id_value(self) -> str:
        if not hasattr(self, "session_id"):
            return ""
        session_id_attr = getattr(self, "session_id")
        if hasattr(session_id_attr, "value"):
            return str(session_id_attr.value or "").strip()
        return str(session_id_attr or "").strip()

    def get_mongodb_connection(self) -> MongoClient:
        if self._connection:
            try:
                self._connection.admin.command("ping")
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
            if isinstance(conn, MongoClient):
                conn.admin.command("ping")
                self._connection = conn
                self._connection_info = {
                    "host": session.data.get("host", "localhost"),
                    "port": session.data.get("port", 27017),
                    "username": session.data.get("username", ""),
                    "database": session.data.get("database", "admin"),
                }
                return self._connection

        listener_id = session.data.get("listener_id")
        if listener_id and hasattr(self.framework, "active_listeners"):
            listener = self.framework.active_listeners.get(listener_id)
            if listener and hasattr(listener, "_session_connections"):
                conn = listener._session_connections.get(session_id_value)
                if isinstance(conn, MongoClient):
                    conn.admin.command("ping")
                    self._connection = conn
                    self._connection_info = {
                        "host": session.data.get("host", "localhost"),
                        "port": session.data.get("port", 27017),
                        "username": session.data.get("username", ""),
                        "database": session.data.get("database", "admin"),
                    }
                    return self._connection

        raise ProcedureError(
            FailureType.NotAccess, "MongoDB connection not available in session"
        )

    def get_session_info(self) -> Dict[str, Any]:
        self.get_mongodb_connection()
        info = dict(self._connection_info or {})
        try:
            build = self._connection.admin.command("buildInfo")
            info["version"] = build.get("version", "")
        except PyMongoError:
            pass
        return info

    def list_databases(self) -> List[str]:
        conn = self.get_mongodb_connection()
        try:
            return conn.list_database_names()
        except PyMongoError as exc:
            raise ProcedureError(FailureType.Unknown, f"list_database_names failed: {exc}")

    def list_collections(self, database: str) -> List[str]:
        conn = self.get_mongodb_connection()
        db_name = str(database or "").strip()
        if not db_name:
            raise ProcedureError(FailureType.NotFound, "Database name is empty")
        try:
            return conn[db_name].list_collection_names()
        except PyMongoError as exc:
            raise ProcedureError(
                FailureType.Unknown, f"list_collection_names failed for {db_name}: {exc}"
            )

    def collection_stats(self, database: str, collection: str) -> Dict[str, Any]:
        conn = self.get_mongodb_connection()
        try:
            stats = conn[database].command("collStats", collection)
            return {
                "count": stats.get("count", 0),
                "size": stats.get("size", 0),
                "storageSize": stats.get("storageSize", 0),
                "avgObjSize": stats.get("avgObjSize", 0),
            }
        except PyMongoError:
            try:
                count = conn[database][collection].estimated_document_count()
                return {"count": count}
            except PyMongoError as exc:
                raise ProcedureError(FailureType.Unknown, f"collStats failed: {exc}")

    def sample_documents(
        self, database: str, collection: str, limit: int = 5
    ) -> List[Dict[str, Any]]:
        conn = self.get_mongodb_connection()
        try:
            cursor = conn[database][collection].find({}, limit=max(1, int(limit)))
            return list(cursor)
        except PyMongoError as exc:
            raise ProcedureError(FailureType.Unknown, f"find failed: {exc}")

    def close(self):
        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None
            self._connection_info = None
