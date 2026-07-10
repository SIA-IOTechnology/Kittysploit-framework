#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Privilege rights GPO analyser."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from lib.protocols.gpo.rules import load_privilege_rules

Resolver = Callable[[str, Optional[str]], Dict[str, Optional[str]]]


class GpoPrivilegeRightsAnalyser:
    """Detect dangerous User Rights Assignment via GPO."""

    def __init__(self, rules: Dict[str, Any] | None = None):
        self.rules = rules or load_privilege_rules()

    def analyse(self, privilege_rights: Dict[str, List[Dict[str, Optional[str]]]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for privilege, trustees in privilege_rights.items():
            rule = self.rules.get(privilege)
            if not rule:
                continue
            defaults = set(rule.get("default_trustees") or [])
            risky = []
            for trustee in trustees:
                sid = (trustee.get("sid") or "").upper()
                if not sid or sid in defaults or sid.startswith("S-1-5-8"):
                    continue
                risky.append(trustee)
            if risky:
                findings.append({
                    "privilege": privilege,
                    "analysis": rule.get("analysis"),
                    "edge": rule.get("edge"),
                    "references": rule.get("references"),
                    "trustees": risky,
                })
        return findings
