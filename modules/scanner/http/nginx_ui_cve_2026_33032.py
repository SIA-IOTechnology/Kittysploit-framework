#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-33032 — nginx-ui MCPwn unauthenticated /mcp_message detection."""

import json
import re
import socket
import ssl
import time
import uuid
from typing import Optional, Tuple
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "nginx-ui CVE-2026-33032 MCPwn detection",
        "description": (
            "Non-destructive detector for CVE-2026-33032 (MCPwn): missing AuthRequired() "
            "on nginx-ui /mcp_message. Fingerprints nginx-ui, obtains an unauthenticated "
            "MCP sessionID via /mcp SSE, then sends benign tools/list JSON-RPC to "
            "/mcp_message. Never invokes destructive MCP tools. Affected builds prior to "
            "the AuthRequired fix (commonly cited < 2.3.4; upgrade to 2.3.6+ recommended)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-33032",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-33032",
            "https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/",
            "https://github.com/keraattin/CVE-2026-33032",
            "https://github.com/0xJacky/nginx-ui",
        ],
        "modules": [
            "auxiliary/admin/http/nginx_ui_cve_2026_33032_mcp_bypass",
        ],
        "tags": [
            "web",
            "scanner",
            "nginx-ui",
            "mcp",
            "auth-bypass",
            "cve-2026-33032",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
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
                "endpoint_pattern_any": ["/mcp", "/mcp_message"],
                "param_any": ["sessionID"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "mcp"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/admin/http/nginx_ui_cve_2026_33032_mcp_bypass",
                ],
            },
        },
    }

    port = OptPort(9000, "nginx-ui HTTP port (default 9000)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    sse_timeout = OptInteger(5, "Seconds to wait for MCP SSE sessionID", required=False, advanced=True)

    _SESSION_RE = re.compile(r"sessionI[Dd]=([A-Za-z0-9_\-]+)")
    _ENDPOINT_RE = re.compile(r"/mcp_message\?sessionI[Dd]=([A-Za-z0-9_\-]+)")
    _VERSION_RE = re.compile(r"(?:nginx[-_ ]?ui[^0-9]{0,16})?(\d+\.\d+\.\d+)", re.I)

    def _timeout(self) -> int:
        return max(int(self.timeout or 10), 5)

    def _host(self) -> str:
        if hasattr(self.target, "value"):
            return str(self.target.value or "").strip()
        return str(self.target or "").strip()

    def _extract_version(self, text: str, headers=None) -> str:
        headers = headers or {}
        for key in ("X-Version", "X-Nginx-UI-Version", "Server"):
            value = headers.get(key) or headers.get(key.lower())
            if value:
                match = self._VERSION_RE.search(str(value))
                if match:
                    return match.group(1)
        match = self._VERSION_RE.search(text or "")
        return match.group(1) if match else ""

    def _fingerprint(self) -> Tuple[bool, str]:
        for path in ("/api/settings", "/", "/api/system/info"):
            response = self.http_request(
                method="GET",
                path=path,
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if not response:
                continue
            text = response.text or ""
            lower = text.lower()
            headers = response.headers or {}
            if any(
                marker in lower
                for marker in ("nginx_ui", "nginx-ui", "node_secret", "nginx ui")
            ):
                return True, self._extract_version(text, headers)
            if "nginx" in lower and path.startswith("/api/"):
                return True, self._extract_version(text, headers)
        return False, ""

    def _find_session_id(self, text: str) -> Optional[str]:
        match = self._ENDPOINT_RE.search(text or "")
        if match:
            return match.group(1)
        match = self._SESSION_RE.search(text or "")
        return match.group(1) if match else None

    def _sse_session_via_http(self) -> Tuple[Optional[int], Optional[str]]:
        response = self.http_request(
            method="GET",
            path="/mcp",
            headers={
                "Accept": "text/event-stream",
                "Cache-Control": "no-cache",
            },
            timeout=max(int(self.sse_timeout or 5), 3),
            allow_redirects=False,
            stream=True,
        )
        if not response:
            return None, None
        status = response.status_code
        # Prefer raw stream chunks; fall back to .text
        buffered = ""
        try:
            if hasattr(response, "iter_content"):
                deadline = time.time() + max(int(self.sse_timeout or 5), 3)
                for chunk in response.iter_content(chunk_size=4096, decode_unicode=True):
                    if chunk:
                        buffered += chunk if isinstance(chunk, str) else chunk.decode(
                            "utf-8", errors="replace"
                        )
                        session_id = self._find_session_id(buffered)
                        if session_id:
                            return status, session_id
                    if time.time() >= deadline:
                        break
            else:
                buffered = response.text or ""
        except Exception:
            buffered = buffered or (getattr(response, "text", None) or "")
        return status, self._find_session_id(buffered)

    def _sse_session_via_socket(self) -> Tuple[Optional[int], Optional[str]]:
        host = self._host()
        port = int(self.port)
        use_ssl = bool(self.ssl) if not hasattr(self.ssl, "value") else bool(self.ssl.value)
        timeout = self._timeout()
        sse_wait = max(int(self.sse_timeout or 5), 3)

        try:
            raw = socket.create_connection((host, port), timeout=timeout)
        except Exception:
            return None, None

        sock = raw
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw, server_hostname=host)
            sock.settimeout(sse_wait)
            request = (
                f"GET /mcp HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Accept: text/event-stream\r\n"
                f"Cache-Control: no-cache\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            sock.sendall(request.encode("ascii"))
            buffered = b""
            status = None
            deadline = time.time() + sse_wait
            while time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buffered += chunk
                if status is None and b"\r\n" in buffered:
                    line = buffered.split(b"\r\n", 1)[0]
                    parts = line.split(b" ", 2)
                    if len(parts) >= 2 and parts[1].isdigit():
                        status = int(parts[1])
                session_id = self._find_session_id(
                    buffered.decode("utf-8", errors="replace")
                )
                if session_id:
                    return status, session_id
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return status, self._find_session_id(buffered.decode("utf-8", errors="replace"))

    def _probe_tools_list(self, session_id: str) -> Tuple[Optional[int], str, bool]:
        body = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/list",
            "params": {},
        }
        path = f"/mcp_message?sessionID={quote(session_id)}"
        response = self.http_request(
            method="POST",
            path=path,
            json=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            timeout=self._timeout(),
            allow_redirects=False,
        )
        if not response:
            return None, "", False
        text = response.text or ""
        lower = text.lower()
        indicates = (
            response.status_code == 200
            and ("tools" in lower or '"result"' in lower)
            and "unauthorized" not in lower
            and "auth" not in lower[:80]
        )
        # Stronger: auth errors often 401/403
        if response.status_code in (401, 403):
            indicates = False
        return response.status_code, text, indicates

    def run(self):
        print_status(f"Probing nginx-ui MCPwn (CVE-2026-33032) on port {self.port}...")

        is_nginx_ui, version = self._fingerprint()
        if not is_nginx_ui:
            print_info("nginx-ui fingerprint not found")
            return False
        print_success("nginx-ui fingerprint matched")
        if version:
            print_status(f"Version hint: {version}")

        status, session_id = self._sse_session_via_http()
        if not session_id:
            status, session_id = self._sse_session_via_socket()

        if not session_id:
            print_info(f"No unauthenticated MCP sessionID (SSE status={status})")
            self.set_info(
                severity="info",
                cve="CVE-2026-33032",
                reason=(
                    "nginx-ui detected but /mcp did not hand out a sessionID without auth "
                    f"(likely patched or MCP disabled; version={version or 'unknown'})"
                ),
                confidence="medium",
                version=version,
            )
            return False

        print_success(f"Unauthenticated MCP sessionID obtained (SSE HTTP {status})")
        print_info(f"sessionID={session_id[:12]}…")

        msg_status, body, vulnerable = self._probe_tools_list(session_id)
        preview = (body or "").replace("\n", " ")[:180]

        if vulnerable:
            reason = (
                f"CVE-2026-33032 confirmed: unauthenticated tools/list on /mcp_message "
                f"(HTTP {msg_status}; version={version or 'unknown'})"
            )
            print_success(reason)
            if preview:
                print_info(f"Evidence: {preview}")
            self.set_info(
                severity="critical",
                cve="CVE-2026-33032",
                reason=reason,
                confidence="high",
                version=version,
                endpoint="/mcp_message",
                session_id=session_id,
            )
            return True

        if msg_status in (401, 403):
            print_success(
                f"/mcp_message appears auth-gated (HTTP {msg_status}) — likely patched"
            )
            self.set_info(
                severity="info",
                cve="CVE-2026-33032",
                reason=f"sessionID issued but /mcp_message gated (HTTP {msg_status})",
                confidence="medium",
                version=version,
            )
            return False

        print_warning("Inconclusive — sessionID present but tools/list not confirmed")
        if preview:
            print_info(f"Response preview: {preview}")
        self.set_info(
            severity="medium",
            cve="CVE-2026-33032",
            reason=(
                f"MCP session without auth but tools/list inconclusive "
                f"(HTTP {msg_status}; version={version or 'unknown'})"
            ),
            confidence="low",
            version=version,
        )
        return True
