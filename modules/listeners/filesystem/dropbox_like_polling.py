#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import uuid
from pathlib import Path

from kittysploit import *


class Module(Listener):
    __info__ = {
        "name": "Filesystem Dropbox-like Polling C2",
        "description": "Uses a shared directory as a dead-drop C2: agents read commands and write results.",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.REVERSE,
        "session_type": "polling",
        "protocol": "filesystem_polling",
    }

    root_dir = OptString("/tmp/ks-dropbox-c2", "Shared directory used by controller and agents", True)
    auto_client_id = OptString("agent1", "Client ID to create immediately (empty waits for register files)", False)
    poll_interval = OptInteger(2, "Directory poll interval in seconds", False)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.running = False
        self._pending_commands = {}
        self._received_output = {}
        self._client_id_to_session = {}
        self._session_to_client_id = {}
        self._seen_result_files = set()

    def _root(self) -> Path:
        return Path(str(self.root_dir)).expanduser().resolve()

    def _ensure_dirs(self):
        root = self._root()
        for name in ("register", "commands", "results"):
            (root / name).mkdir(parents=True, exist_ok=True)

    def _create_polling_session(self, client_id: str, client_ip: str = "filesystem"):
        if client_id in self._client_id_to_session:
            return self._client_id_to_session[client_id]
        data = {
            "protocol": "filesystem_polling",
            "client_id": client_id,
            "client_ip": client_ip,
            "root_dir": str(self._root()),
            "handler": "reverse",
            "session_type": "polling",
            "listener_type": "dropbox_like_polling",
        }
        session_id = self._create_session("reverse", client_ip, 0, data)
        if session_id:
            self._client_id_to_session[client_id] = session_id
            self._session_to_client_id[session_id] = client_id
            self._pending_commands[session_id] = []
            self._received_output[session_id] = []
            print_success(f"Filesystem polling agent {client_id} -> session {session_id}")
        return session_id

    def _poll_loop(self):
        root = self._root()
        while self.running:
            for marker in (root / "register").glob("*.agent"):
                self._create_polling_session(marker.stem, "filesystem")
            for result in (root / "results").glob("*.out"):
                key = str(result)
                if key in self._seen_result_files:
                    continue
                self._seen_result_files.add(key)
                client_id = result.name.split(".", 1)[0]
                session_id = self._create_polling_session(client_id, "filesystem")
                try:
                    text = result.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                self._append_output(session_id, text)
            time.sleep(max(int(self.poll_interval or 2), 1))

    def run(self, background=False):
        import threading

        self._ensure_dirs()
        if str(self.auto_client_id or "").strip():
            self._create_polling_session(str(self.auto_client_id).strip(), "filesystem")
        self.running = True
        self.listener_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.listener_thread.start()
        print_success(f"Filesystem polling listener started at {self._root()}")
        print_info("Agent convention: register/<client>.agent, commands/<client>.cmd, results/<client>.<nonce>.out")
        if background:
            return True
        try:
            while self.running:
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.running = False
        return True

    def set_pending_command(self, session_id: str, cmd: str):
        client_id = self._session_to_client_id.get(session_id)
        if not client_id:
            return
        path = self._root() / "commands" / f"{client_id}.cmd"
        path.write_text(cmd, encoding="utf-8")

    def _append_output(self, session_id: str, text: str):
        self._received_output.setdefault(session_id, []).append(text)
        self._received_output[session_id] = self._received_output[session_id][-500:]

    def get_output(self, session_id: str, clear=False) -> str:
        out = "\n".join(self._received_output.get(session_id, []))
        if clear:
            self._received_output[session_id] = []
        return out

    def get_output_lines(self, session_id: str, last_n=50):
        return self._received_output.get(session_id, [])[-last_n:]

    def shutdown(self):
        self.running = False

