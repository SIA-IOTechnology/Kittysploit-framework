#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SQLi detection techniques — context-aware, budget-aware."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .column_count import find_union_column_count
from .comparison import boolean_evidence, union_reflection_marker
from .constants import DETECTION_CONFIDENCE, TECHNIQUE_LABELS
from .fingerprint import evidence_snippet, fingerprint_dbms, match_sqli_error
from .injection_context import InjectionContext, infer_context_from_value, refine_context_with_oracle
from .oracle import HttpParameterOracle, ProbeResponse
from .payloads import boolean_probes, error_probes, time_probe, union_probe
from .tamper import expand_probe_list


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
    column_count: Optional[int] = None


def probe_error(
    oracle: HttpParameterOracle,
    ctx: Optional[InjectionContext] = None,
    *,
    waf_detected: bool = False,
) -> Optional[TechniqueHit]:
    context = ctx or infer_context_from_value(oracle.original_value or "1")
    payloads = expand_probe_list(
        [p for p, _ in error_probes(context)],
        waf=waf_detected,
    )
    labels = {p: lbl for p, lbl in error_probes(context)}
    for payload in payloads:
        resp = oracle.send(payload)
        token = match_sqli_error(resp.text)
        if not token:
            continue
        dbms = fingerprint_dbms(resp.text)
        label = labels.get(payload, "error probe")
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


def probe_boolean(
    oracle: HttpParameterOracle,
    baseline: ProbeResponse,
    ctx: Optional[InjectionContext] = None,
) -> Optional[TechniqueHit]:
    context = ctx or infer_context_from_value(oracle.original_value or "1")
    (true_payload, true_label), (false_payload, false_label) = boolean_probes(context)
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


def probe_boolean_numeric(
    oracle: HttpParameterOracle,
    baseline: ProbeResponse,
    ctx: Optional[InjectionContext] = None,
) -> Optional[TechniqueHit]:
    context = ctx or infer_context_from_value(oracle.original_value or "1")
    if not context.numeric:
        numeric_ctx = infer_context_from_value(
            context.original if context.original.strip().isdigit() else "1"
        )
        numeric_ctx.numeric = True
        context = numeric_ctx

    (true_payload, true_label), (false_payload, false_label) = boolean_probes(context)
    base_resp = baseline
    if (oracle.original_value or "").strip() != context.original:
        base_resp = oracle.send(context.original)

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
        indicators=[f"Numeric boolean: base={context.original}"],
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
    ctx: Optional[InjectionContext] = None,
) -> Optional[TechniqueHit]:
    if waf_detected:
        return None

    context = ctx or infer_context_from_value(oracle.original_value or "1")
    payload, label = time_probe(context, delay, dbms)
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


def probe_union(
    oracle: HttpParameterOracle,
    baseline: ProbeResponse,
    ctx: Optional[InjectionContext] = None,
    *,
    after_error: bool = False,
    after_boolean: bool = False,
) -> Optional[TechniqueHit]:
    """UNION with ORDER BY column enumeration when error or boolean already suggested SQLi."""
    if not after_error and not after_boolean:
        return None

    context = ctx or infer_context_from_value(oracle.original_value or "1")
    columns = find_union_column_count(oracle, context, baseline, max_columns=20)
    if columns is None:
        columns = 2

    payload, label = union_probe(context, columns)
    resp = oracle.send(payload)
    if not union_reflection_marker(resp.text):
        for fallback_cols in (columns + 1, columns - 1, 3, 2):
            if fallback_cols < 1 or fallback_cols > 24:
                continue
            payload, label = union_probe(context, fallback_cols)
            resp = oracle.send(payload)
            if union_reflection_marker(resp.text):
                columns = fallback_cols
                break
        else:
            if resp.length <= 40 and not match_sqli_error(resp.text):
                return None

    return TechniqueHit(
        technique="union",
        payload=payload,
        label=label,
        confidence=DETECTION_CONFIDENCE["union"],
        evidence=f"UNION reflected marker ({columns} columns)",
        indicators=["UNION SELECT column enumeration", f"columns={columns}"],
        status_code=resp.status_code,
        response_time=resp.elapsed,
        response_length=resp.length,
        column_count=columns,
    )


def prepare_context(oracle: HttpParameterOracle) -> InjectionContext:
    """Heuristic context + optional quote refinement (≤2 requests)."""
    ctx = infer_context_from_value(oracle.original_value or "1")
    if ctx.numeric:
        return ctx
    return refine_context_with_oracle(oracle, ctx, max_probes=2)


def technique_label(technique: str) -> str:
    return TECHNIQUE_LABELS.get(technique, technique)
