# -*- coding: utf-8 -*-
"""
Client AD/LDAP pour les modules scanner du framework.
Utilise ldap3 ; options compatibles BaseModule (target, port, ssl, username, password, base_dn).
"""

from typing import List, Any, Optional
from core.framework.option import OptString, OptPort, OptBool
from core.framework.base_module import BaseModule

try:
    from ldap3 import Server, Connection, SUBTREE, BASE, ALL
    from ldap3.core.exceptions import LDAPException
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False


def _get_opt(instance: Any, name: str) -> Any:
    v = getattr(instance, name, None)
    if hasattr(v, "value"):
        return v.value
    return v


class Ad_client(BaseModule):
    """Client LDAP/AD pour scanners : bind, search, get_domain_object, attr_*, resolve_sid."""

    target = OptString("", "Domain controller hostname or IP", True)
    port = OptPort(389, "LDAP port (389 or 636 for LDAPS)", True)
    ssl = OptBool(False, "Use LDAPS", True, advanced=True)
    username = OptString("", "Bind user (DOMAIN\\user or user@domain)", False)
    password = OptString("", "Bind password", False)
    base_dn = OptString("", "Base DN (leave empty to auto-detect)", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._conn: Optional[Connection] = None
        self._server = None
        self._base_dn = ""
        self._config_dn = ""
        self._schema_dn = ""
        self._domain = ""
        self._dc_ip = ""

    def _connect(self) -> bool:
        if self._conn is not None and self._conn.bound:
            return True
        if not LDAP3_AVAILABLE:
            return False
        host = _get_opt(self, "target") or ""
        port = int(_get_opt(self, "port") or 389)
        use_ssl = _get_opt(self, "ssl")
        if isinstance(use_ssl, str):
            use_ssl = use_ssl.lower() in ("true", "1", "yes")
        user = (_get_opt(self, "username") or "").strip()
        pwd = _get_opt(self, "password") or ""
        try:
            self._server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=10)
            self._conn = Connection(
                self._server,
                user=user if user else None,
                password=pwd if pwd else None,
                auto_bind=True,
            )
            if not self._conn.bound:
                return False
            self._base_dn = (_get_opt(self, "base_dn") or "").strip()
            if not self._base_dn and self._conn:
                try:
                    self._conn.search("", "(objectClass=*)", BASE, attributes=["defaultNamingContext"])
                    if self._conn.entries:
                        self._base_dn = self.attr_str(self._conn.entries[0], "defaultNamingContext") or ""
                except Exception:
                    pass
            if not self._base_dn and self._server.info:
                self._base_dn = (self._server.info.raw.get("defaultNamingContext") or [b""])[0]
                if isinstance(self._base_dn, bytes):
                    self._base_dn = self._base_dn.decode("utf-8", errors="ignore")
            if not self._base_dn:
                self._base_dn = ""
            self._config_dn = f"CN=Configuration,{self._base_dn}" if self._base_dn else ""
            if self._server.info and self._base_dn:
                schema = (self._server.info.raw.get("schemaNamingContext") or [b""])[0]
                if isinstance(schema, bytes):
                    schema = schema.decode("utf-8", errors="ignore")
                self._schema_dn = schema or ""
            else:
                self._schema_dn = ""
            # Domain name from base_dn (dc=foo,dc=bar -> foo.bar)
            if self._base_dn:
                parts = [p.replace("DC=", "").replace("dc=", "") for p in self._base_dn.split(",") if p.strip().upper().startswith("DC=")]
                self._domain = ".".join(parts) if parts else ""
            else:
                self._domain = ""
            # DC IP/hostname: first DC's dNSHostName
            self._dc_ip = host
            try:
                dcs = self.search("(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", ["dNSHostName"], base=self._base_dn, size_limit=1)
                if dcs and self.attr_str(dcs[0], "dNSHostName"):
                    self._dc_ip = self.attr_str(dcs[0], "dNSHostName").strip()
            except Exception:
                pass
            return True
        except LDAPException:
            return False
        except Exception:
            return False

    @property
    def conn(self) -> Optional[Any]:
        if self._connect():
            return self._conn
        return None

    @property
    def base_dn(self) -> str:
        if not self._base_dn and self._connect():
            pass
        return self._base_dn or ""

    @property
    def config_dn(self) -> str:
        if not self._config_dn and self._connect():
            pass
        return self._config_dn or ""

    @property
    def schema_dn(self) -> str:
        if not self._schema_dn and self._connect():
            pass
        return self._schema_dn or ""

    @property
    def domain(self) -> str:
        if not self._domain and self._connect():
            pass
        return self._domain or ""

    @property
    def dc_ip(self) -> str:
        if not self._dc_ip and self._connect():
            pass
        return self._dc_ip or _get_opt(self, "target") or ""

    def search(
        self,
        filter_str: str,
        attributes: List[str],
        base: Optional[str] = None,
        size_limit: int = 0,
    ) -> List[Any]:
        """Recherche LDAP ; retourne une liste d'entrées ldap3."""
        if not self._connect() or not self._conn:
            return []
        base = base or self._base_dn
        if not base:
            return []
        try:
            self._conn.search(base, filter_str, SUBTREE, attributes=attributes, size_limit=size_limit or 0)
            return list(self._conn.entries)
        except LDAPException:
            return []

    def get_domain_object(self) -> Optional[Any]:
        """Retourne l'entrée de l'objet domaine (default naming context)."""
        if not self._connect() or not self._base_dn or not self._conn:
            return None
        try:
            self._conn.search(self._base_dn, "(objectClass=domain)", BASE, attributes=["*"])
            return self._conn.entries[0] if self._conn.entries else None
        except LDAPException:
            return None

    def attr_str(self, entry: Any, name: str) -> str:
        """Valeur string d'un attribut (première valeur)."""
        v = getattr(entry, name, None)
        if v is None:
            return ""
        if hasattr(v, "value"):
            return str(v.value) if v.value is not None else ""
        if hasattr(v, "raw_values") and v.raw_values:
            return str(v.raw_values[0]) if v.raw_values[0] is not None else ""
        if isinstance(entry, dict):
            return str(entry.get(name, ""))
        return str(v) if v is not None else ""

    def attr_int(self, entry: Any, name: str, default: int = 0) -> int:
        """Valeur entière d'un attribut."""
        v = getattr(entry, name, None)
        if v is None:
            return default
        if hasattr(v, "value"):
            val = v.value
        elif hasattr(v, "raw_values") and v.raw_values:
            val = v.raw_values[0]
        else:
            val = v
        try:
            return int(val)
        except (TypeError, ValueError):
            return default

    def attr_list(self, entry: Any, name: str) -> List[Any]:
        """Liste des valeurs d'un attribut."""
        v = getattr(entry, name, None)
        if v is None:
            return []
        if hasattr(v, "values"):
            return list(v.values) if v.values else []
        if hasattr(v, "raw_values"):
            return list(v.raw_values) if v.raw_values else []
        if isinstance(v, (list, tuple)):
            return list(v)
        return [v]

    def resolve_sid(self, sid: str) -> str:
        """Résout un SID en nom (sAMAccountName ou CN) ; fallback sur le SID."""
        if not self._connect() or not self._conn:
            return sid
        try:
            # objectSid en LDAP est binaire ; on peut chercher par sid en format string selon le schéma
            res = self.search(f"(objectSid={sid})", ["sAMAccountName", "cn"], base=self._base_dn, size_limit=1)
            if res:
                n = self.attr_str(res[0], "sAMAccountName") or self.attr_str(res[0], "cn")
                if n:
                    return n
        except Exception:
            pass
        return sid
