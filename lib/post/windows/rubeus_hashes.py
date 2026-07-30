#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Parse Rubeus / hashcat Kerberos hash lines from tool output."""

from __future__ import annotations

import re
from typing import Dict, List

# hashcat modes: 13100 (TGS RC4), 18200 (AS-REP)
_KRB5TGS = re.compile(
    r"(\$krb5tgs\$\d+\$[^ \r\n\t]+)",
    re.IGNORECASE,
)
_KRB5ASREP = re.compile(
    r"(\$krb5asrep\$\d+\$[^ \r\n\t]+)",
    re.IGNORECASE,
)
# Rubeus sometimes prints SamAccountName nearby
_SAM = re.compile(r"(?:UserName|SamAccountName|Account)\s*[:=]\s*([^\s\\/]+)", re.IGNORECASE)


def extract_kerberos_hashes(text: str) -> List[Dict[str, str]]:
    """Return list of {kind, hash, username?} from Rubeus/raw output."""
    raw = str(text or "")
    found: List[Dict[str, str]] = []
    seen = set()

    for match in _KRB5TGS.finditer(raw):
        h = match.group(1).strip()
        if h in seen:
            continue
        seen.add(h)
        user = _guess_user_near(raw, match.start()) or _user_from_tgs(h)
        found.append({"kind": "krb5tgs", "hash": h, "username": user, "hashcat_mode": "13100"})

    for match in _KRB5ASREP.finditer(raw):
        h = match.group(1).strip()
        if h in seen:
            continue
        seen.add(h)
        user = _guess_user_near(raw, match.start()) or _user_from_asrep(h)
        found.append({"kind": "krb5asrep", "hash": h, "username": user, "hashcat_mode": "18200"})

    return found


def _guess_user_near(text: str, pos: int) -> str:
    window = text[max(0, pos - 400) : pos]
    matches = list(_SAM.finditer(window))
    if matches:
        return matches[-1].group(1).strip()
    return ""


def _user_from_tgs(h: str) -> str:
    # $krb5tgs$23$*user$DOMAIN$spn*$...
    parts = h.split("$")
    for part in parts:
        if part.startswith("*") and len(part) > 1:
            return part[1:]
    return ""


def _user_from_asrep(h: str) -> str:
    # $krb5asrep$23$user@DOMAIN:hex...
    parts = h.split("$")
    if len(parts) >= 4:
        ident = parts[3]
        return ident.split("@", 1)[0].split(":", 1)[0]
    return ""
