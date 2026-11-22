#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OUI vendor lookup from KittySploit data/vendors/oui.json."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def _load_oui() -> dict[str, str]:
    root = Path(__file__).resolve().parents[3]
    path = root / "data" / "vendors" / "oui.json"
    if not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        return {str(k).upper().replace(":", ""): str(v) for k, v in data.items()}
    except Exception:
        return {}


def vendor_for_mac(mac: str) -> str:
    text = str(mac or "").replace(":", "").replace("-", "").upper()
    if len(text) < 6:
        return ""
    prefix = text[:6]
    return _load_oui().get(prefix, "")