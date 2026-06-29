#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import Any, Dict, Iterator, List, Optional, Tuple

import redis

from core.framework.base_module import BaseModule
from core.framework.failure import FailureType, ProcedureError

logger = logging.getLogger(__name__)


class RedisClient(BaseModule):
    """Thin helper to reuse the Redis connection stored in an active session."""

    def __init__(self, framework=None):
        super().__init__(framework)
        self.logger = logger
        self._connection: Optional[redis.Redis] = None
        self._connection_info: Optional[Dict[str, Any]] = None

    def _session_id_value(self) -> str:
        if not hasattr(self, "session_id"):
            return ""
        session_id_attr = getattr(self, "session_id")
        if hasattr(session_id_attr, "value"):
            return str(session_id_attr.value or "").strip()
        return str(session_id_attr or "").strip()

    def get_redis_connection(self) -> redis.Redis:
        if self._connection:
            try:
                self._connection.ping()
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
            if isinstance(conn, redis.Redis):
                conn.ping()
                self._connection = conn
                self._connection_info = {
                    "host": session.data.get("host", "localhost"),
                    "port": session.data.get("port", 6379),
                    "db": session.data.get("db", 0),
                    "password": session.data.get("password", ""),
                }
                return self._connection

        listener_id = session.data.get("listener_id")
        if listener_id and hasattr(self.framework, "active_listeners"):
            listener = self.framework.active_listeners.get(listener_id)
            if listener and hasattr(listener, "_session_connections"):
                conn = listener._session_connections.get(session_id_value)
                if isinstance(conn, redis.Redis):
                    conn.ping()
                    self._connection = conn
                    self._connection_info = {
                        "host": session.data.get("host", "localhost"),
                        "port": session.data.get("port", 6379),
                        "db": session.data.get("db", 0),
                        "password": session.data.get("password", ""),
                    }
                    return self._connection

        raise ProcedureError(
            FailureType.NotAccess, "Redis connection not available in session"
        )

    def get_session_info(self) -> Dict[str, Any]:
        self.get_redis_connection()
        return dict(self._connection_info or {})

    def get_info(self, section: Optional[str] = None) -> Dict[str, Any]:
        conn = self.get_redis_connection()
        try:
            info = conn.info(section)
            return info if isinstance(info, dict) else {}
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"INFO failed: {exc}")

    def get_config(self, pattern: str = "*") -> Dict[str, str]:
        conn = self.get_redis_connection()
        try:
            result = conn.config_get(pattern)
            return result if isinstance(result, dict) else {}
        except redis.ResponseError as exc:
            raise ProcedureError(FailureType.NotAccess, f"CONFIG GET denied: {exc}")
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"CONFIG GET failed: {exc}")

    def config_get_allowed(self) -> bool:
        try:
            self.get_config("dir")
            return True
        except ProcedureError:
            return False

    def scan_keys(
        self,
        pattern: str = "*",
        count: int = 100,
        max_keys: int = 0,
    ) -> Iterator[str]:
        conn = self.get_redis_connection()
        seen = 0
        try:
            for key in conn.scan_iter(match=pattern, count=count):
                yield key
                seen += 1
                if max_keys and seen >= max_keys:
                    break
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"SCAN failed: {exc}")

    def count_keys(self, pattern: str = "*", count: int = 100) -> int:
        total = 0
        for _ in self.scan_keys(pattern=pattern, count=count):
            total += 1
        return total

    def enumerate_databases(self, max_db: int = 15) -> List[Tuple[int, int]]:
        conn = self.get_redis_connection()
        current_db = self._connection_info.get("db", 0) if self._connection_info else 0
        results: List[Tuple[int, int]] = []
        try:
            for db_index in range(max_db + 1):
                conn.select(db_index)
                size = int(conn.dbsize())
                if size > 0:
                    results.append((db_index, size))
        finally:
            try:
                conn.select(current_db)
            except Exception:
                pass
        return results

    def get_key_type(self, key: str) -> str:
        conn = self.get_redis_connection()
        try:
            return str(conn.type(key) or "none")
        except redis.RedisError:
            return "unknown"

    def get_string_value(self, key: str, max_length: int = 4096) -> Optional[str]:
        conn = self.get_redis_connection()
        try:
            if self.get_key_type(key) != "string":
                return None
            value = conn.get(key)
            if value is None:
                return None
            text = str(value)
            if len(text) > max_length:
                return text[: max_length - 3] + "..."
            return text
        except redis.RedisError:
            return None

    def select_db(self, db: int) -> None:
        conn = self.get_redis_connection()
        try:
            conn.select(int(db))
            if self._connection_info is not None:
                self._connection_info["db"] = int(db)
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"SELECT failed: {exc}")

    def set_string(
        self,
        key: str,
        value: str,
        ex: Optional[int] = None,
    ) -> bool:
        conn = self.get_redis_connection()
        try:
            result = conn.set(key, value, ex=ex)
            return bool(result)
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"SET failed: {exc}")

    def delete_keys(self, keys: List[str]) -> int:
        if not keys:
            return 0
        conn = self.get_redis_connection()
        try:
            return int(conn.delete(*keys))
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"DEL failed: {exc}")

    def get_ttl(self, key: str) -> int:
        conn = self.get_redis_connection()
        try:
            return int(conn.ttl(key))
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"TTL failed: {exc}")

    def set_expire(self, key: str, seconds: int) -> bool:
        conn = self.get_redis_connection()
        try:
            return bool(conn.expire(key, int(seconds)))
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"EXPIRE failed: {exc}")

    def persist_key(self, key: str) -> bool:
        conn = self.get_redis_connection()
        try:
            return bool(conn.persist(key))
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"PERSIST failed: {exc}")

    def flush_db(self) -> None:
        conn = self.get_redis_connection()
        try:
            conn.flushdb()
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"FLUSHDB failed: {exc}")

    def flush_all(self) -> None:
        conn = self.get_redis_connection()
        try:
            conn.flushall()
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"FLUSHALL failed: {exc}")

    def acl_list(self) -> List[str]:
        conn = self.get_redis_connection()
        try:
            result = conn.execute_command("ACL", "LIST")
            if isinstance(result, list):
                return [str(item) for item in result]
            return [str(result)] if result else []
        except redis.ResponseError as exc:
            raise ProcedureError(FailureType.NotAccess, f"ACL LIST denied: {exc}")
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"ACL LIST failed: {exc}")

    def acl_getuser(self, username: str) -> List[str]:
        conn = self.get_redis_connection()
        try:
            result = conn.execute_command("ACL", "GETUSER", username)
            if isinstance(result, list):
                return [str(item) for item in result]
            return [str(result)] if result else []
        except redis.ResponseError as exc:
            raise ProcedureError(FailureType.NotAccess, f"ACL GETUSER denied: {exc}")
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"ACL GETUSER failed: {exc}")

    def acl_setuser(self, username: str, *rules: str) -> bool:
        conn = self.get_redis_connection()
        try:
            result = conn.execute_command("ACL", "SETUSER", username, *rules)
            return bool(result) if result is not None else True
        except redis.ResponseError as exc:
            raise ProcedureError(FailureType.NotAccess, f"ACL SETUSER denied: {exc}")
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"ACL SETUSER failed: {exc}")

    def acl_deluser(self, username: str) -> int:
        conn = self.get_redis_connection()
        try:
            result = conn.execute_command("ACL", "DELUSER", username)
            return int(result or 0)
        except redis.ResponseError as exc:
            raise ProcedureError(FailureType.NotAccess, f"ACL DELUSER denied: {exc}")
        except redis.RedisError as exc:
            raise ProcedureError(FailureType.Unknown, f"ACL DELUSER failed: {exc}")
