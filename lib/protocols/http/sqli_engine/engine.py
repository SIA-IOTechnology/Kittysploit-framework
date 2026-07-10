#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unified SQLi detection engine — low-noise, budget-aware."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .oracle import HttpParameterOracle, ProbeResponse
from .techniques import (
    TechniqueHit,
    probe_boolean,
    probe_boolean_numeric,
    probe_error,
    probe_time,
    probe_union,
    technique_label,
)


@dataclass
class SqliScanResult:
    vulnerable: bool = False
    technique: str = ""
    injection_type: str = ""
    payload: str = ""
    param: str = ""
    method: str = "GET"
    path: str = "/"
    original_value: str = "1"
    confidence: int = 0
    evidence: str = ""
    dbms: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    status_code: int = 0
    response_time: float = 0.0
    response_length: int = 0
    request_count: int = 0
    all_hits: List[TechniqueHit] = field(default_factory=list)

    def to_hit_dict(self, *, request_url: str = "") -> Dict[str, Any]:
        return {
            "vulnerable": self.vulnerable,
            "injection_type": self.injection_type or technique_label(self.technique),
            "technique": self.technique,
            "payload": self.payload,
            "param": self.param,
            "method": self.method,
            "path": self.path,
            "request_path": self.path,
            "request_url": request_url,
            "confidence": self.confidence,
            "evidence_snippet": self.evidence,
            "dbms": self.dbms,
            "indicators": list(self.indicators),
            "status_code": self.status_code,
            "response_time": self.response_time,
            "response_length": self.response_length,
            "request_count": self.request_count,
        }


class SqliEngine:
    """
    Scan one HTTP parameter with a minimal probe sequence:

    baseline → error (stop if hit) → boolean → boolean_numeric → time → union
    """

    def __init__(
        self,
        *,
        allow_time: bool = True,
        allow_union: bool = True,
        time_delay: float = 3.0,
        waf_detected: bool = False,
        max_requests: int = 16,
        stop_on_first: bool = True,
    ):
        self.allow_time = allow_time
        self.allow_union = allow_union
        self.time_delay = time_delay
        self.waf_detected = waf_detected
        self.max_requests = max(6, int(max_requests))
        self.stop_on_first = stop_on_first

    def _budget_left(self, oracle: HttpParameterOracle) -> bool:
        return oracle.request_count < self.max_requests

    def scan_parameter(
        self,
        oracle: HttpParameterOracle,
        *,
        param: str = "",
        method: str = "GET",
        path: str = "/",
    ) -> SqliScanResult:
        result = SqliScanResult(
            param=param,
            method=method,
            path=path,
            original_value=oracle.original_value or "1",
        )
        baseline: ProbeResponse = oracle.baseline()
        hits: List[TechniqueHit] = []
        dbms_hint = ""

        if self._budget_left(oracle):
            hit = probe_error(oracle)
            if hit:
                hits.append(hit)
                dbms_hint = hit.dbms or ""
                if self.stop_on_first:
                    return self._finalize(result, hits, oracle)

        if self._budget_left(oracle):
            hit = probe_boolean(oracle, baseline)
            if hit:
                hits.append(hit)
                if self.stop_on_first:
                    return self._finalize(result, hits, oracle)

        if self._budget_left(oracle):
            hit = probe_boolean_numeric(oracle, baseline)
            if hit:
                hits.append(hit)
                if self.stop_on_first:
                    return self._finalize(result, hits, oracle)

        if self.allow_time and self._budget_left(oracle):
            hit = probe_time(
                oracle,
                baseline,
                delay=self.time_delay,
                dbms=dbms_hint,
                waf_detected=self.waf_detected,
            )
            if hit:
                hits.append(hit)
                if self.stop_on_first:
                    return self._finalize(result, hits, oracle)

        if self.allow_union and self._budget_left(oracle) and any(h.technique == "error" for h in hits):
            hit = probe_union(oracle, after_error=True)
            if hit:
                hits.append(hit)

        return self._finalize(result, hits, oracle)

    @staticmethod
    def _finalize(result: SqliScanResult, hits: List[TechniqueHit], oracle: HttpParameterOracle) -> SqliScanResult:
        result.all_hits = hits
        result.request_count = oracle.request_count
        if not hits:
            return result

        primary = hits[0]
        for candidate in hits:
            if candidate.confidence > primary.confidence:
                primary = candidate

        result.vulnerable = True
        result.technique = primary.technique
        result.injection_type = technique_label(primary.technique)
        result.payload = primary.payload
        result.confidence = primary.confidence
        result.evidence = primary.evidence
        result.dbms = primary.dbms
        result.indicators = list(primary.indicators)
        result.status_code = primary.status_code
        result.response_time = primary.response_time
        result.response_length = primary.response_length
        return result

    def scan_many(
        self,
        targets: List[Dict[str, Any]],
        send_factory: Callable[[str, str, str, str], Callable[..., Any]],
    ) -> List[SqliScanResult]:
        """
        Scan multiple (path, param, method, original) targets.

        ``send_factory(path, param, method, original)`` returns ``send_payload``.
        """
        results: List[SqliScanResult] = []
        for target in targets:
            path = str(target.get("path") or "/")
            param = str(target.get("param") or "")
            method = str(target.get("method") or "GET").upper()
            original = str(target.get("original") or target.get("value") or "1")
            if not param:
                continue
            oracle = HttpParameterOracle(
                original_value=original,
                send_payload=send_factory(path, param, method, original),
            )
            results.append(
                self.scan_parameter(oracle, param=param, method=method, path=path)
            )
        return results

    def scan_extended(
        self,
        oracle: HttpParameterOracle,
        *,
        param: str = "",
        method: str = "GET",
        path: str = "",
        specialized: Optional[List[TechniqueHit]] = None,
    ) -> SqliScanResult:
        """Standard scan; if no hit, pick best specialized probe result."""
        result = self.scan_parameter(oracle, param=param, method=method, path=path)
        if result.vulnerable or not specialized:
            return result

        best = max(specialized, key=lambda h: h.confidence)
        result.vulnerable = True
        result.technique = best.technique
        result.injection_type = technique_label(best.technique)
        if best.label and "ORDER BY" in best.label:
            result.injection_type = f"{result.injection_type} (ORDER BY)"
        elif best.label and "JSON" in best.label:
            result.injection_type = f"{result.injection_type} (JSON body)"
        elif best.label and "Header" in best.label:
            result.injection_type = f"{result.injection_type} (header)"
        result.payload = best.payload
        result.confidence = best.confidence
        result.evidence = best.evidence
        result.dbms = best.dbms
        result.indicators = list(best.indicators)
        result.status_code = best.status_code
        result.response_time = best.response_time
        result.response_length = best.response_length
        result.all_hits = [best]
        return result
