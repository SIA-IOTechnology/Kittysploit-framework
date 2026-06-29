#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared WAF / blocking heuristics for the autonomous agent."""

from __future__ import annotations

import re
from typing import Any, Iterable, List, Sequence

from interfaces.command_system.builtin.agent.agent_constants import WAF_RISK_HTTP_STATUS_CODES

HTTP_STATUS_IN_TEXT_RE = re.compile(r"\b(\d{3})\b")

# Module/agent rows use ``status`` for outcomes like safe/vulnerable — not HTTP codes.
_MODULE_OUTCOME_STATUSES = frozenset({
    "safe",
    "vulnerable",
    "error",
    "skipped",
    "ok",
    "blocked",
})


def parse_http_status(*values: Any) -> int:
    """Return an HTTP status code from explicit numeric fields only."""
    for value in values:
        if value is None or value == "":
            continue
        if isinstance(value, int):
            if 100 <= value <= 599:
                return value
            continue
        text = str(value).strip().lower()
        if text in _MODULE_OUTCOME_STATUSES:
            continue
        if text.isdigit() and len(text) == 3:
            number = int(text)
            if 100 <= number <= 599:
                return number
        try:
            number = int(text)
        except (TypeError, ValueError):
            continue
        if 100 <= number <= 599:
            return number
    return 0

# Explicit block pages / challenge walls (not passive CDN assets).
WAF_BLOCKING_BODY_MARKERS: Sequence[str] = (
    "request blocked",
    "access denied",
    "not acceptable",
    "too many requests",
    "rate limit exceeded",
    "bot detection",
    "attention required",
    "challenge-platform",
    "cf-chl-bypass",
    "cf-chl-widget",
    "please enable cookies",
    "sorry, you have been blocked",
)

# Vendor hints: only actionable when paired with a block status or challenge page.
WAF_INFRA_BODY_MARKERS: Sequence[str] = (
    "cloudflare",
    "akamai",
    "imperva",
    "incapsula",
    "sucuri",
)

# Widgets often present on legitimate login pages — never pause on these alone.
WAF_BENIGN_WIDGET_MARKERS: Sequence[str] = (
    "recaptcha",
    "hcaptcha",
    "g-recaptcha",
    "captcha",
)


def _status_values(
    *,
    status_code: int = 0,
    body: str = "",
    message: str = "",
    details: Any = None,
) -> List[int]:
    values: List[int] = []
    if status_code:
        try:
            values.append(int(status_code))
        except (TypeError, ValueError):
            pass
    blob = " ".join([
        str(message or ""),
        str(body or "")[:4096],
        str(details or ""),
    ])
    for match in HTTP_STATUS_IN_TEXT_RE.findall(blob.lower()):
        try:
            values.append(int(match))
        except ValueError:
            continue
    return values


def is_actionable_waf_signal(
    result: Any = None,
    *,
    status_code: int = 0,
    body: str = "",
    message: str = "",
    details: Any = None,
) -> bool:
    """True when evidence suggests active blocking, not mere CDN/captcha presence."""
    if isinstance(result, dict):
        status_code = parse_http_status(
            result.get("status_code"),
            result.get("http_status"),
            result.get("code"),
        )
        if not status_code:
            status_code = parse_http_status(result.get("status"))
        body = str(result.get("body", "") or "")
        message = " ".join([
            str(result.get("message", "") or ""),
            str(result.get("details", "") or ""),
        ])
        details = result.get("headers", details)

    statuses = _status_values(
        status_code=status_code,
        body=body,
        message=message,
        details=details,
    )
    blob = " ".join([
        str(message or ""),
        str(body or "")[:4096],
        str(details or ""),
    ]).lower()

    if any(code in WAF_RISK_HTTP_STATUS_CODES for code in statuses):
        return True

    if any(marker in blob for marker in WAF_BLOCKING_BODY_MARKERS):
        return True

    if any(marker in blob for marker in WAF_INFRA_BODY_MARKERS):
        if any(marker in blob for marker in ("cf-chl", "challenge-platform", "cf-mitigated")):
            return True
        if any(code in WAF_RISK_HTTP_STATUS_CODES for code in statuses):
            return True
        return False

    if any(marker in blob for marker in WAF_BENIGN_WIDGET_MARKERS):
        return False

    return False


def approved_to_continue_through_waf(state: Any) -> bool:
    """Operator explicitly accepted intrusive/destructive engagement risk."""
    policy = getattr(state, "runtime_policy", None)
    if policy is None:
        return False
    approved = {str(v).strip().lower() for v in (getattr(policy, "approved_risks", None) or [])}
    return bool(approved & {"intrusive", "destructive"})
