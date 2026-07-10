#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""JSON body / REST API SQLi probes."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

from ..constants import DETECTION_CONFIDENCE
from ..fingerprint import evidence_snippet, fingerprint_dbms, match_sqli_error
from ..oracle import HttpParameterOracle
from ..techniques import TechniqueHit, boolean_evidence

_JSON_PATH_HINTS = ("/api/", "/wp-json/", "/graphql", "/rest/", "/v1/", "/v2/")


def is_json_api_entry(
    *,
    path: str = "",
    url: str = "",
    method: str = "GET",
    content_type: str = "",
) -> bool:
    p = (path or url or "").lower()
    if any(hint in p for hint in _JSON_PATH_HINTS):
        return True
    if method.upper() == "POST" and "json" in (content_type or "").lower():
        return True
    return False


def _json_error_probes(original: str) -> Tuple[Tuple[str, str], ...]:
    base = original if original else "1"
    return (
        (f"{base}'", "JSON single-quote"),
        (f'{base}"', "JSON double-quote"),
        (f"{base}' OR '1'='2", "JSON OR false"),
    )


def probe_json_body_sqli(
    send_json_payload: Callable[[Dict[str, Any]], Tuple[object, float]],
    params: Dict[str, Any],
    param: str,
    *,
    baseline_resp: Optional[Any] = None,
) -> Optional[TechniqueHit]:
    """
    Probe one JSON field for SQLi.

    ``send_json_payload(body_dict)`` performs the HTTP request with JSON body.
    """
    original = str((params or {}).get(param, "") or "1")

    def send_wrapped(payload: str, timeout=None):
        body = dict(params or {})
        body[param] = payload
        return send_json_payload(body)

    oracle = HttpParameterOracle(original_value=original, send_payload=send_wrapped)
    baseline = oracle.baseline()

    for payload, label in _json_error_probes(original):
        resp = oracle.send(payload)
        token = match_sqli_error(resp.text)
        if token:
            return TechniqueHit(
                technique="error",
                payload=payload,
                label=label,
                confidence=DETECTION_CONFIDENCE["error"],
                evidence=evidence_snippet(resp.text, token),
                dbms=fingerprint_dbms(resp.text),
                indicators=[f"JSON body SQL error: {label}"],
                status_code=resp.status_code,
                response_time=resp.elapsed,
                response_length=resp.length,
            )

    true_payload = f"{original} AND 1=1"
    false_payload = f"{original} AND 1=2"
    true_resp = oracle.send(true_payload)
    false_resp = oracle.send(false_payload)
    evidence = boolean_evidence(baseline, true_resp, false_resp)
    if evidence:
        return TechniqueHit(
            technique="boolean",
            payload=false_payload,
            label="JSON boolean",
            confidence=DETECTION_CONFIDENCE["boolean"],
            evidence=evidence,
            indicators=["JSON body boolean drift"],
            status_code=false_resp.status_code,
            response_time=false_resp.elapsed,
            response_length=false_resp.length,
        )
    return None
