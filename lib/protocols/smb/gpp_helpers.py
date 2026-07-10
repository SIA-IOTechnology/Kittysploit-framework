#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Group Policy Preferences password helpers."""

from __future__ import annotations

import base64
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

try:
    from Crypto.Cipher import AES

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

GPP_AES_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f1243016062fba4b")

GPP_FILENAMES = (
    "Groups.xml",
    "Services.xml",
    "ScheduledTasks.xml",
    "DataSources.xml",
    "Printers.xml",
    "Drives.xml",
    "Registry.xml",
)


def decrypt_cpassword(value: str) -> Optional[str]:
    if not value or not CRYPTO_AVAILABLE:
        return None
    try:
        raw = base64.b64decode(value)
        if len(raw) < 32:
            return None
        cipher = AES.new(GPP_AES_KEY, AES.MODE_CBC, raw[:16])
        plain = cipher.decrypt(raw[16:])
        return plain.decode("utf-16le").rstrip("\x00")
    except Exception:
        return None


def extract_gpp_secrets(xml_text: str, source: str = "") -> List[Dict[str, str]]:
    """Extract cpassword and credential hints from a GPP XML file."""
    findings: List[Dict[str, str]] = []
    if not xml_text:
        return findings
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for elem in root.iter():
        attrs = elem.attrib
        cpassword = attrs.get("cpassword") or attrs.get("CPassword") or ""
        if not cpassword:
            continue
        username = (
            attrs.get("userName")
            or attrs.get("username")
            or attrs.get("account")
            or attrs.get("newName")
            or attrs.get("defaultUsername")
            or attrs.get("DefaultUsername")
            or ""
        )
        password = decrypt_cpassword(cpassword) or "[encrypted]"
        findings.append({
            "source": source,
            "tag": elem.tag,
            "username": username,
            "password": password,
            "cpassword": cpassword[:12] + "..." if len(cpassword) > 12 else cpassword,
        })
    return findings
