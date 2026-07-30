#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Save Kerberos hashcat lines to loot files."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional


def default_loot_dir() -> Path:
    try:
        from core.utils.paths import framework_root

        root = framework_root()
    except Exception:
        root = None
    base = (root / "output" / "loot") if root else Path("output") / "loot"
    base.mkdir(parents=True, exist_ok=True)
    return base


def save_hash_loot(
    hashes: Iterable[Dict[str, str]],
    *,
    kind: str,
    session_id: str = "",
    loot_dir: Optional[Path] = None,
) -> Optional[Path]:
    rows = list(hashes)
    if not rows:
        return None
    out_dir = Path(loot_dir) if loot_dir else default_loot_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    sid = (session_id or "nosession")[:12]
    path = out_dir / f"{kind}_{sid}_{ts}.txt"
    lines = [r["hash"] for r in rows if r.get("hash")]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
