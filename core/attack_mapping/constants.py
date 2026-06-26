#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from typing import Dict, Tuple

MITRE_TECHNIQUE_RE = re.compile(
    r"attack\.mitre\.org/techniques/(T\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
TECHNIQUE_TOKEN_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
TACTIC_TOKEN_RE = re.compile(r"\bTA\d{4}\b", re.IGNORECASE)

PATH_TECHNIQUE_HINTS: Tuple[Tuple[str, str], ...] = (
    ("scanner/portscan", "T1046"),
    ("scanner/discovery", "T1046"),
    ("scanner/http", "T1595.002"),
    ("scanner/ssh", "T1046"),
    ("scanner/smb", "T1046"),
    ("exploits/", "T1190"),
    ("post/", "T1059"),
    ("payloads/", "T1059"),
    ("listeners/", "T1573"),
    ("auxiliary/scanner", "T1595"),
    ("auxiliary/osint", "T1590"),
    ("auxiliary/crawler", "T1594"),
)

TACTIC_ALIASES: Dict[str, str] = {
    "reconnaissance": "TA0043",
    "resource development": "TA0042",
    "resource-development": "TA0042",
    "initial access": "TA0001",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege escalation": "TA0004",
    "privilege-escalation": "TA0004",
    "defense evasion": "TA0005",
    "defense-evasion": "TA0005",
    "credential access": "TA0006",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral movement": "TA0008",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command and control": "TA0011",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}

OFFENSIVE_MODULE_TYPES = {
    "exploits",
    "browser_exploits",
    "payloads",
    "post",
    "listeners",
    "auxiliary",
    "scanner",
    "backdoors",
}
