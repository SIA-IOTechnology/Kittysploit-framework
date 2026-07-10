#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import Any, Dict, List, Optional

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, RequestError

from core.framework.base_module import BaseModule
from core.framework.failure import FailureType, ProcedureError

logger = logging.getLogger(__name__)


class ElasticsearchClient(BaseModule):
    """Elasticsearch client for post modules using Elasticsearch sessions."""

    def __init__(self, framework=None):
        super().__init__(framework)
        self.logger = logger
        self._connection: Optional[Elasticsearch] = None
        self._connection_info: Optional[Dict[str, Any]] = None

    def _session_id_value(self) -> str:
        if not hasattr(self, "session_id"):
            return ""
        session_id_attr = getattr(self, "session_id")
        if hasattr(session_id_attr, "value"):
            return str(session_id_attr.value or "").strip()
        return str(session_id_attr or "").strip()

    def get_elasticsearch_connection(self) -> Elasticsearch:
        if self._connection:
            try:
                if self._connection.ping():
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
            if isinstance(conn, Elasticsearch):
                self._connection = conn
                self._connection_info = {
                    "host": session.data.get("host", "localhost"),
                    "port": session.data.get("port", 9200),
                    "username": session.data.get("username", ""),
                    "use_ssl": session.data.get("use_ssl", False),
                }
                return self._connection

        listener_id = session.data.get("listener_id")
        if listener_id and hasattr(self.framework, "active_listeners"):
            listener = self.framework.active_listeners.get(listener_id)
            if listener and hasattr(listener, "_session_connections"):
                conn = listener._session_connections.get(session_id_value)
                if isinstance(conn, Elasticsearch):
                    self._connection = conn
                    self._connection_info = {
                        "host": session.data.get("host", "localhost"),
                        "port": session.data.get("port", 9200),
                        "username": session.data.get("username", ""),
                        "use_ssl": session.data.get("use_ssl", False),
                    }
                    return self._connection

        raise ProcedureError(
            FailureType.NotAccess, "Elasticsearch connection not available in session"
        )

    def get_session_info(self) -> Dict[str, Any]:
        self.get_elasticsearch_connection()
        info = dict(self._connection_info or {})
        try:
            cluster = self._connection.info()
            info["cluster_name"] = cluster.get("cluster_name", "")
            info["version"] = (cluster.get("version") or {}).get("number", "")
        except Exception:
            pass
        return info

    def list_indices(self, pattern: str = "*") -> str:
        conn = self.get_elasticsearch_connection()
        try:
            result = conn.cat.indices(index=pattern, format="text")
            return result if isinstance(result, str) else str(result)
        except Exception as exc:
            raise ProcedureError(FailureType.Unknown, f"cat.indices failed: {exc}")

    def search_index(
        self,
        index: str,
        query: Optional[Dict[str, Any]] = None,
        size: int = 10,
    ) -> List[Dict[str, Any]]:
        conn = self.get_elasticsearch_connection()
        body = query if query is not None else {"query": {"match_all": {}}}
        try:
            result = conn.search(index=index, body=body, size=max(1, int(size)))
            hits = (result.get("hits") or {}).get("hits") or []
            return [hit.get("_source", hit) for hit in hits]
        except RequestError as exc:
            raise ProcedureError(FailureType.Unknown, f"search failed: {exc}")
        except Exception as exc:
            raise ProcedureError(FailureType.Unknown, f"search failed: {exc}")

    def get_mapping(self, index: str) -> Dict[str, Any]:
        conn = self.get_elasticsearch_connection()
        try:
            return conn.indices.get_mapping(index=index)
        except NotFoundError:
            return {}
        except Exception as exc:
            raise ProcedureError(FailureType.Unknown, f"get_mapping failed: {exc}")

    def close(self):
        self._connection = None
        self._connection_info = None
