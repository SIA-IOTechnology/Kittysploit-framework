#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SQLi detection techniques — minimal request budget, early exit."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .constants import DETECTION_CONFIDENCE, TECHNIQUE_LABELS
from .fingerprint import evidence_snippet, fingerprint_dbms, match_sqli_error
from .oracle import HttpParameterOracle, ProbeResponse
from .payloads import (
    boolean_numeric_probes,
    boolean_probes,
    error_probes,
    time_probe,
    union_probe,
)


@dataclass
class TechniqueHit:
    technique: str
    payload: str
    label: str
    confidence: int
    evidence: str
    dbms: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    status_code: int = 0
    response_time: float = 0.0
    response_length: int = 0


def boolean_evidence(baseline: ProbeResponse, true_resp: ProbeResponse, false_resp: ProbeResponse) -> str:
    if not baseline.text and baseline.status_code == 0:
        return ""
    if not true_resp.text and true_resp.status_code == 0:
        return ""
    if not false_resp.text and false_resp.status_code == 0:
        return ""

    baseline_len = baseline.length
    true_len = true_resp.length
    false_len = false_resp.length
    delta_true = abs(true_len - baseline_len)
    delta_false = abs(false_len - true_len)

    if (
        baseline.status_code == true_resp.status_code
        and abs(false_resp.status_code - baseline.status_code) <= 1
        and delta_true <= max(60, int(baseline_len * 0.08))
        and delta_false >= max(120, int(max(true_len, false_len) * 0.12))
    ):
        return (
            "Boolean response drift detected "
            f"(baseline={baseline_len}, true={true_len}, false={false_len})"
        )
    return ""


def probe_error(oracle: HttpParameterOracle) -> Optional[TechniqueHit]:
    original = oracle.original_value or "1"
    for payload, label in error_probes(original):
        resp = oracle.send(payload)
        token = match_sqli_error(resp.text)
        if not token:
            continue
        dbms = fingerprint_dbms(resp.text)
        return TechniqueHit(
            technique="error",
            payload=payload,
            label=label,
            confidence=DETECTION_CONFIDENCE["error"],
            evidence=evidence_snippet(resp.text, token),
            dbms=dbms,
            indicators=[f"SQL error after {label}", f"matched: {token}"],
            status_code=resp.status_code,
            response_time=resp.elapsed,
            response_length=resp.length,
        )
    return None


def probe_boolean(oracle: HttpParameterOracle, baseline: ProbeResponse) -> Optional[TechniqueHit]:
    original = oracle.original_value or "1"
    (true_payload, true_label), (false_payload, false_label) = boolean_probes(original)
    true_resp = oracle.send(true_payload)
    false_resp = oracle.send(false_payload)
    evidence = boolean_evidence(baseline, true_resp, false_resp)
    if not evidence:
        return None
    return TechniqueHit(
        technique="boolean",
        payload=false_payload,
        label=false_label,
        confidence=DETECTION_CONFIDENCE["boolean"],
        evidence=evidence,
        indicators=[f"Boolean drift: {true_label} vs {false_label}"],
        status_code=false_resp.status_code,
        response_time=false_resp.elapsed,
        response_length=false_resp.length,
    )


def probe_boolean_numeric(oracle: HttpParameterOracle, baseline: ProbeResponse) -> Optional[TechniqueHit]:
    original = oracle.original_value or "1"
    true_p, false_p, numeric_base = boolean_numeric_probes(original)
    true_payload, true_label = true_p
    false_payload, false_label = false_p

    if numeric_base != (original or "1").strip():
        base_resp = oracle.send(numeric_base)
    else:
        base_resp = baseline

    true_resp = oracle.send(true_payload)
    false_resp = oracle.send(false_payload)
    evidence = boolean_evidence(base_resp, true_resp, false_resp)
    if not evidence:
        return None
    return TechniqueHit(
        technique="boolean_numeric",
        payload=false_payload,
        label=false_label,
        confidence=DETECTION_CONFIDENCE["boolean_numeric"],
        evidence=evidence,
        indicators=[f"Numeric boolean: base={numeric_base}"],
        status_code=false_resp.status_code,
        response_time=false_resp.elapsed,
        response_length=false_resp.length,
    )


def probe_time(
    oracle: HttpParameterOracle,
    baseline: ProbeResponse,
    *,
    delay: float = 3.0,
    dbms: str = "",
    waf_detected: bool = False,
) -> Optional[TechniqueHit]:
    if waf_detected:
        return None

    original = oracle.original_value or "1"
    payload, label = time_probe(original, delay, dbms)
    timeout = max(delay + 6.0, 12.0)
    resp = oracle.send(payload, timeout=timeout)

    threshold = max(baseline.elapsed + 2.5, delay - 0.5)
    if resp.elapsed < threshold:
        return None

    return TechniqueHit(
        technique="time",
        payload=payload,
        label=label,
        confidence=DETECTION_CONFIDENCE["time"],
        evidence=f"Delayed response ({resp.elapsed:.2f}s vs baseline {baseline.elapsed:.2f}s)",
        dbms=dbms or None,
        indicators=[f"Time delay: {label}"],
        status_code=resp.status_code,
        response_time=resp.elapsed,
        response_length=resp.length,
    )


def probe_union(oracle: HttpParameterOracle, *, after_error: bool = False) -> Optional[TechniqueHit]:
    """Light UNION check — only meaningful when error-based already confirmed."""
    if not after_error:
        return None

    original = oracle.original_value or "1"
    payload, label = union_probe(original)
    resp = oracle.send(payload)
    if "kspi" not in resp.text.lower() and resp.length <= 50:
        return None

    return TechniqueHit(
        technique="union",
        payload=payload,
        label=label,
        confidence=DETECTION_CONFIDENCE["union"],
        evidence=f"UNION probe response len={resp.length}",
        indicators=["UNION SELECT probe"],
        status_code=resp.status_code,
        response_time=resp.elapsed,
        response_length=resp.length,
    )


def technique_label(technique: str) -> str:
    return TECHNIQUE_LABELS.get(technique, technique)
