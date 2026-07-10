#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Deterministic refutation adjudication and guard cite-check.

Ported from T3MP3ST adjudicate.ts — strict-majority panel tally plus mandatory
cite-check before a REFUTED vote can stand.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

RefuterVerdict = str  # REFUTED | SURVIVED
PanelVerdict = str  # REFUTED | SURVIVED | INCONCLUSIVE

_COMPARISON_RE = re.compile(
    r"([\w.()\[\]>_$@-]+)\s*(>=|<=|==|!=|>|<)\s*([\w.()\[\]>_$@-]+)"
)
_GUARD_SHAPE_RE = re.compile(
    r"(?:>=|<=|==|!=)|\b(?:if|else|return|break|continue|throw|goto)\b|"
    r"\b(?:assert|clamp|min|max|bound|bounded|validate|sanitize|require|abort|"
    r"reject|checked?|verify|ensure|limit)\s*\(",
    re.I,
)
_MIRROR_OP = {">": "<", "<": ">", ">=": "<=", "<=": ">=", "==": "==", "!=": "!="}


def _normalize(text: str) -> str:
    return re.sub(r"\s+", "", str(text or "")).lower()


def _core_token(text: str) -> str:
    s = _normalize(text)
    s = re.sub(r"^[$@%(\s]+", "", s)
    s = re.sub(r"[)\s;,]+$", "", s)
    return s


def guard_exists_in_source(
    guard: Optional[Mapping[str, Any]],
    source: str,
) -> bool:
    """Return True if a cited killing guard is corroborated by source text."""
    if not guard or not str(guard.get("quote") or "").strip():
        return False
    src = str(source or "")
    if not src:
        return False

    raw_quote = str(guard.get("quote") or "")
    lines = src.splitlines()
    q_norm = _normalize(raw_quote)

    if len(q_norm) >= 6 and _GUARD_SHAPE_RE.search(raw_quote):
        for line in lines:
            if q_norm in _normalize(line):
                return True

    cited = _COMPARISON_RE.search(raw_quote)
    if not cited:
        return False

    a = _core_token(cited.group(1))
    b = _core_token(cited.group(3))
    op = cited.group(2)
    if not a or not b or a == b:
        return False

    for line in lines:
        for match in _COMPARISON_RE.finditer(line):
            la = _core_token(match.group(1))
            lb = _core_token(match.group(3))
            lop = match.group(2)
            if la == a and lb == b and lop == op:
                return True
            if la == b and lb == a and lop == _MIRROR_OP.get(op, op):
                return True
    return False


def adjudicate(verdicts: Sequence[Optional[Mapping[str, Any]]]) -> Dict[str, Any]:
    """
    Tally refuter votes with strict-majority rules.

    REFUTED requires refuted*2 > total (ties → SURVIVED).
    """
    valid = [
        v for v in verdicts
        if isinstance(v, Mapping) and str(v.get("verdict") or "") in {"REFUTED", "SURVIVED"}
    ]
    refuted = [v for v in valid if v.get("verdict") == "REFUTED"]
    total = len(valid)
    majority_refuted = total > 0 and len(refuted) * 2 > total
    verdict: PanelVerdict
    if total == 0:
        verdict = "INCONCLUSIVE"
    elif majority_refuted:
        verdict = "REFUTED"
    else:
        verdict = "SURVIVED"

    killing_guards = [
        v.get("killing_guard")
        for v in refuted
        if isinstance(v.get("killing_guard"), Mapping)
    ]
    return {
        "verdict": verdict,
        "refuted_count": len(refuted),
        "total": total,
        "killing_guards": killing_guards,
    }


def downgrade_unverified_refutes(
    verdicts: Sequence[Optional[Mapping[str, Any]]],
    resolve_source: Callable[[str], str],
) -> List[Optional[Dict[str, Any]]]:
    """Downgrade REFUTED votes whose killing_guard fails cite-check."""
    out: List[Optional[Dict[str, Any]]] = []
    for vote in verdicts:
        if vote is None:
            out.append(None)
            continue
        row = dict(vote)
        if row.get("verdict") != "REFUTED":
            out.append(row)
            continue
        guard = row.get("killing_guard")
        if not isinstance(guard, Mapping) or not guard.get("quote"):
            row["original_verdict"] = "REFUTED"
            row["verdict"] = "SURVIVED"
            row["guard_check"] = "unverified"
            out.append(row)
            continue
        file_name = str(guard.get("file") or "")
        source = str(resolve_source(file_name) or "")
        if guard_exists_in_source(guard, source):
            row["guard_check"] = "verified"
            out.append(row)
        else:
            row["original_verdict"] = "REFUTED"
            row["verdict"] = "SURVIVED"
            row["guard_check"] = "unverified"
            out.append(row)
    return out


def adjudicate_panel(
    verdicts: Sequence[Optional[Mapping[str, Any]]],
    *,
    resolve_source: Optional[Callable[[str], str]] = None,
) -> Dict[str, Any]:
    """Apply cite-check (when resolver provided) then adjudicate."""
    processed: List[Optional[Dict[str, Any]]]
    if resolve_source is not None:
        processed = downgrade_unverified_refutes(verdicts, resolve_source)
    else:
        processed = [dict(v) if isinstance(v, Mapping) else None for v in verdicts]
    result = adjudicate(processed)
    return {
        **result,
        "verdicts": [v for v in processed if v is not None],
    }
