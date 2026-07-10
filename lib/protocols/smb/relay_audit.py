#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMB NTLM relay surface scoring helpers."""

from __future__ import annotations

from typing import Dict, List

from lib.protocols.smb.smb_probes import check_null_session, check_smb_signing, smb1_negotiate


def audit_smb_relay_surface(host: str, port: int = 445, timeout: float = 3.0) -> Dict[str, object]:
    signing_status, smb_version = check_smb_signing(host, port, timeout)
    null_session = check_null_session(host, port, timeout)
    smb1 = smb1_negotiate(host, port, timeout)

    findings: List[Dict[str, str]] = []
    score = 0

    if signing_status == "disabled":
        findings.append({
            "type": "signing_disabled",
            "severity": "high",
            "description": "SMB signing is disabled",
        })
        score += 4
    elif signing_status == "enabled_not_required":
        findings.append({
            "type": "signing_not_required",
            "severity": "medium",
            "description": "SMB signing is enabled but not required",
        })
        score += 3

    if null_session:
        findings.append({
            "type": "null_session",
            "severity": "high",
            "description": "Anonymous SMB null session accepted",
        })
        score += 3

    if smb1:
        findings.append({
            "type": "smbv1_enabled",
            "severity": "medium",
            "description": "SMBv1 negotiate response observed",
        })
        score += 2

    if signing_status in ("disabled", "enabled_not_required") and null_session:
        findings.append({
            "type": "relay_surface_high",
            "severity": "high",
            "description": "Weak signing posture combined with null session",
        })
        score += 2

    risk_level = "LOW" if score <= 2 else ("MEDIUM" if score <= 5 else "HIGH")
    return {
        "host": host,
        "port": port,
        "signing_status": signing_status,
        "smb_version": smb_version,
        "null_session": null_session,
        "smbv1_enabled": smb1,
        "findings": findings,
        "risk_score": min(10, score),
        "risk_level": risk_level,
    }
