#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LDAP session client for post modules (reuses ldap3 Connection from active sessions)."""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from core.framework.base_module import BaseModule
from core.framework.failure import FailureType, ProcedureError

try:
    from ldap3 import BASE, MODIFY_ADD, MODIFY_DELETE, SUBTREE, Connection
    from ldap3.core.exceptions import LDAPException
    LDAP3_AVAILABLE = True
except ImportError:
    BASE = MODIFY_ADD = MODIFY_DELETE = SUBTREE = Connection = LDAPException = None
    LDAP3_AVAILABLE = False

logger = logging.getLogger(__name__)


class LdapPostClient(BaseModule):
    """Reuse the ldap3 connection stored in an LDAP listener session."""

    def __init__(self, framework=None):
        super().__init__(framework)
        self.logger = logger
        self._connection: Optional[Connection] = None
        self._base_dn = ""
        self._config_dn = ""
        self._domain = ""

    def _session_id_value(self) -> str:
        if not hasattr(self, "session_id"):
            return ""
        session_id_attr = getattr(self, "session_id")
        if hasattr(session_id_attr, "value"):
            return str(session_id_attr.value or "").strip()
        return str(session_id_attr or "").strip()

    def get_ldap_connection(self) -> Connection:
        if self._connection and self._connection.bound:
            return self._connection

        if not LDAP3_AVAILABLE:
            raise ProcedureError(
                FailureType.ConfigurationError, "ldap3 is not installed"
            )
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

        conn = None
        if "connection" in session.data:
            candidate = session.data["connection"]
            if isinstance(candidate, Connection):
                conn = candidate

        if conn is None:
            listener_id = session.data.get("listener_id")
            if listener_id and hasattr(self.framework, "active_listeners"):
                listener = self.framework.active_listeners.get(listener_id)
                if listener and hasattr(listener, "_session_connections"):
                    candidate = listener._session_connections.get(session_id_value)
                    if isinstance(candidate, Connection):
                        conn = candidate

        if conn is None or not conn.bound:
            raise ProcedureError(
                FailureType.NotAccess, "LDAP connection not available in session"
            )

        self._connection = conn
        self._base_dn = str(session.data.get("base_dn") or "").strip()
        if not self._base_dn:
            try:
                conn.search("", "(objectClass=*)", BASE, attributes=["defaultNamingContext"])
                if conn.entries:
                    self._base_dn = self.attr_str(conn.entries[0], "defaultNamingContext")
            except Exception:
                pass
        if self._base_dn:
            self._config_dn = f"CN=Configuration,{self._base_dn}"
            parts = [
                p.replace("DC=", "").replace("dc=", "")
                for p in self._base_dn.split(",")
                if p.strip().upper().startswith("DC=")
            ]
            self._domain = ".".join(parts)
        return self._connection

    @property
    def base_dn(self) -> str:
        self.get_ldap_connection()
        return self._base_dn or ""

    @property
    def config_dn(self) -> str:
        self.get_ldap_connection()
        return self._config_dn or ""

    @property
    def domain(self) -> str:
        self.get_ldap_connection()
        return self._domain or ""

    def search(
        self,
        filter_str: str,
        attributes: List[str],
        base: Optional[str] = None,
        size_limit: int = 0,
    ) -> List[Any]:
        conn = self.get_ldap_connection()
        search_base = base or self._base_dn
        if not search_base:
            raise ProcedureError(FailureType.ConfigurationError, "Base DN is not set")
        try:
            conn.search(
                search_base,
                filter_str,
                SUBTREE,
                attributes=attributes,
                size_limit=size_limit or 0,
            )
            return list(conn.entries)
        except LDAPException as exc:
            raise ProcedureError(FailureType.Unknown, f"LDAP search failed: {exc}")

    def get_domain_object(self) -> Optional[Any]:
        conn = self.get_ldap_connection()
        if not self._base_dn:
            return None
        try:
            conn.search(self._base_dn, "(objectClass=domain)", BASE, attributes=["*"])
            return conn.entries[0] if conn.entries else None
        except LDAPException:
            return None

    def find_by_sam(self, sam_account: str, attributes: Optional[List[str]] = None) -> Optional[Any]:
        sam = str(sam_account or "").strip()
        if not sam:
            return None
        attrs = attributes or ["distinguishedName", "sAMAccountName", "servicePrincipalName"]
        rows = self.search(
            f"(&(objectClass=user)(sAMAccountName={self._ldap_escape(sam)}))",
            attrs,
            size_limit=1,
        )
        return rows[0] if rows else None

    def modify_entry(self, dn: str, changes: dict) -> bool:
        conn = self.get_ldap_connection()
        try:
            ok = conn.modify(dn, changes)
            if not ok:
                raise ProcedureError(
                    FailureType.Unknown,
                    f"LDAP modify failed: {conn.result.get('description', conn.result)}",
                )
            return True
        except LDAPException as exc:
            raise ProcedureError(FailureType.Unknown, f"LDAP modify failed: {exc}")

    def add_spn(self, target_dn: str, spn: str) -> bool:
        spn_value = str(spn or "").strip()
        if not spn_value:
            raise ProcedureError(FailureType.ConfigurationError, "SPN value is empty")
        return self.modify_entry(
            target_dn,
            {"servicePrincipalName": [(MODIFY_ADD, [spn_value])]},
        )

    def remove_spn(self, target_dn: str, spn: str) -> bool:
        spn_value = str(spn or "").strip()
        if not spn_value:
            raise ProcedureError(FailureType.ConfigurationError, "SPN value is empty")
        return self.modify_entry(
            target_dn,
            {"servicePrincipalName": [(MODIFY_DELETE, [spn_value])]},
        )

    @staticmethod
    def _ldap_escape(value: str) -> str:
        return (
            str(value or "")
            .replace("\\", "\\5c")
            .replace("*", "\\2a")
            .replace("(", "\\28")
            .replace(")", "\\29")
            .replace("\x00", "\\00")
        )

    def attr_str(self, entry: Any, name: str) -> str:
        value = getattr(entry, name, None)
        if value is None:
            return ""
        if hasattr(value, "value"):
            return str(value.value) if value.value is not None else ""
        if hasattr(value, "raw_values") and value.raw_values:
            return str(value.raw_values[0]) if value.raw_values[0] is not None else ""
        return str(value) if value is not None else ""

    def attr_int(self, entry: Any, name: str, default: int = 0) -> int:
        value = getattr(entry, name, None)
        if value is None:
            return default
        if hasattr(value, "value"):
            raw = value.value
        elif hasattr(value, "raw_values") and value.raw_values:
            raw = value.raw_values[0]
        else:
            raw = value
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default

    def attr_list(self, entry: Any, name: str) -> List[Any]:
        value = getattr(entry, name, None)
        if value is None:
            return []
        if hasattr(value, "values"):
            return list(value.values) if value.values else []
        if hasattr(value, "raw_values"):
            return list(value.raw_values) if value.raw_values else []
        if isinstance(value, (list, tuple)):
            return list(value)
        return [value]

    def resolve_sid(self, sid: str) -> str:
        sid_value = str(sid or "").strip()
        if not sid_value:
            return sid_value
        rows = self.search(
            f"(objectSid={sid_value})",
            ["sAMAccountName", "cn"],
            size_limit=1,
        )
        if rows:
            name = self.attr_str(rows[0], "sAMAccountName") or self.attr_str(rows[0], "cn")
            if name:
                return name
        return sid_value

    def close(self):
        self._connection = None
        self._base_dn = ""
        self._config_dn = ""
        self._domain = ""
