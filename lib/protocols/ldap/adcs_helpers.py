#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AD CS / certificate template misconfiguration helpers."""

from __future__ import annotations

from typing import Any, Dict, List

# pKICertificateTemplate flags
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000040
CT_FLAG_AUTO_ENROLLMENT = 0x00000020

# Enrollment service CA flags (EDITF_ATTRIBUTESUBJECTALTNAME2)
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00010000

EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"


def _attr_int(entry: Any, name: str, getter) -> int:
    try:
        return int(getter(entry, name) or 0)
    except (TypeError, ValueError):
        return 0


def _attr_list(entry: Any, name: str, getter) -> List[str]:
    values = getter(entry, name) or []
    return [str(v) for v in values]


def analyze_certificate_template(entry: Any, attr_int, attr_list, attr_str) -> List[Dict[str, str]]:
    """Return ESC-style hints for one pKICertificateTemplate LDAP entry."""
    findings: List[Dict[str, str]] = []
    name = attr_str(entry, "cn") or attr_str(entry, "name")
    name_flags = _attr_int(entry, "msPKI-Certificate-Name-Flag", attr_int)
    enroll_flags = _attr_int(entry, "msPKI-Enrollment-Flag", attr_int)
    ekus = _attr_list(entry, "pKIExtendedKeyUsage", attr_list)
    ra_signature = _attr_int(entry, "msPKI-RA-Signature", attr_int)

    manager_approval = bool(enroll_flags & CT_FLAG_PEND_ALL_REQUESTS)
    enrollee_subject = bool(name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)

    if enrollee_subject and not manager_approval:
        findings.append({
            "esc": "ESC1",
            "template": name,
            "severity": "high",
            "description": "Enrollee supplies subject and manager approval is not required",
        })

    if not ekus:
        findings.append({
            "esc": "ESC2",
            "template": name,
            "severity": "high",
            "description": "Template has no extended key usage (any-purpose enrollment risk)",
        })
    elif EKU_ANY_PURPOSE in ekus:
        findings.append({
            "esc": "ESC2",
            "template": name,
            "severity": "high",
            "description": "Template allows Any Purpose EKU",
        })

    if EKU_CERT_REQUEST_AGENT in ekus and not ra_signature:
        findings.append({
            "esc": "ESC3",
            "template": name,
            "severity": "medium",
            "description": "Certificate Request Agent template without RA signature requirement",
        })

    return findings


def analyze_enrollment_service(entry: Any, attr_int, attr_str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    name = attr_str(entry, "cn") or attr_str(entry, "dNSHostName")
    flags = _attr_int(entry, "flags", attr_int)
    if flags & EDITF_ATTRIBUTESUBJECTALTNAME2:
        findings.append({
            "esc": "ESC6",
            "service": name,
            "severity": "high",
            "description": "CA allows requesters to specify Subject Alternative Names in CSR",
        })
    return findings
