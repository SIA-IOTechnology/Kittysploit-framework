#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""API BOLA/IDOR probing helpers."""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional


def _normalize_body(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


def _json_keys(payload: str) -> List[str]:
    try:
        data = json.loads(payload)
    except Exception:
        return []
    if isinstance(data, dict):
        return sorted(str(k) for k in data.keys())
    return []


def compare_idor_responses(
    baseline_status: Optional[int],
    baseline_body: str,
    candidate_status: Optional[int],
    candidate_body: str,
) -> Optional[Dict[str, str]]:
    if candidate_status not in (200, 201, 202, 204):
        return None
    if baseline_status not in (200, 201, 202, 204):
        return {
            "signal": "unauthenticated_access",
            "severity": "high",
            "description": "Alternate object ID returned success without baseline success",
        }

    base_norm = _normalize_body(baseline_body)
    cand_norm = _normalize_body(candidate_body)
    if not cand_norm or cand_norm == base_norm:
        return None

    base_keys = set(_json_keys(baseline_body))
    cand_keys = set(_json_keys(candidate_body))
    if base_keys and cand_keys and base_keys == cand_keys:
        return {
            "signal": "bola_idor",
            "severity": "high",
            "description": "Different object body with same JSON schema — possible BOLA/IDOR",
        }

    if len(cand_norm) > 20 and len(base_norm) > 20:
        return {
            "signal": "bola_idor",
            "severity": "medium",
            "description": "Alternate object ID returned distinct content",
        }
    return None
