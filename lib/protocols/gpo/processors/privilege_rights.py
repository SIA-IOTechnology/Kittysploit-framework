#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Normalize privilege rights from GptTmpl.inf."""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

Resolver = Callable[[str, Optional[str]], Dict[str, Optional[str]]]


def _default_resolver(trustee: str, domain_sid: Optional[str] = None) -> Dict[str, Optional[str]]:
    trustee = (trustee or "").strip()
    if trustee.startswith("*S-") or trustee.startswith("S-"):
        sid = trustee.strip("*")
        return {"sid": sid, "name": trustee}
    return {"sid": None, "name": trustee}


def process_privilege_rights(
    settings: Dict[str, List[str]],
    domain_sid: Optional[str] = None,
    resolver: Optional[Resolver] = None,
) -> Dict[str, List[Dict[str, Optional[str]]]]:
    resolve = resolver or _default_resolver
    output: Dict[str, List[Dict[str, Optional[str]]]] = {}

    for privilege, trustees in settings.items():
        for trustee in trustees:
            if not trustee:
                continue
            if trustee.startswith("*"):
                sid = trustee.strip("*")
                info = resolve(sid, domain_sid)
                output.setdefault(privilege, []).append({
                    "sid": info.get("sid") or sid,
                    "name": info.get("name") or trustee,
                })
            else:
                info = resolve(trustee, domain_sid)
                output.setdefault(privilege, []).append({
                    "sid": info.get("sid"),
                    "name": info.get("name") or trustee,
                })
    return output
