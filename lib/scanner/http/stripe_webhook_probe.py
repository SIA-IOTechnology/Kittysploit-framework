#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stripe webhook secret abuse and endpoint misconfiguration probes."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from lib.scanner.http.vibe_secrets_probe import extract_vibe_secrets, mask_secret

_WEBHOOK_PATHS = (
    "/api/webhooks/stripe",
    "/api/stripe/webhook",
    "/webhooks/stripe",
    "/stripe/webhook",
    "/api/stripe-webhook",
    "/api/payments/stripe/webhook",
    "/api/billing/webhook",
)

_TEST_EVENT = {
    "id": "evt_kittysploit_probe",
    "object": "event",
    "type": "payment_intent.succeeded",
    "data": {"object": {"id": "pi_probe", "object": "payment_intent"}},
}


_WHSEC_RE = re.compile(r"\b(whsec_[A-Za-z0-9]{16,})\b")


def discover_stripe_webhook_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _WHSEC_RE.finditer(body):
        creds["whsec"] = match.group(1)
    for finding in extract_vibe_secrets(body, source="/"):
        if str(finding.get("service")) != "stripe":
            continue
        if finding.get("rule_id") == "stripe_whsec" or finding.get("kind") == "webhook_secret":
            masked = str(finding.get("value_masked") or "")
            if masked and "whsec" in body:
                for match in _WHSEC_RE.finditer(body):
                    creds.setdefault("whsec", match.group(1))
    for match in re.finditer(
        r"(?i)STRIPE_(?:WEBHOOK_)?SECRET\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        val = match.group(1).strip()
        if val.startswith("whsec_"):
            creds["whsec"] = val
    return creds


def _stripe_signature(payload: str, secret: str, timestamp: int | None = None) -> str:
    ts = timestamp or int(time.time())
    signed = f"{ts}.{payload}"
    digest = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
    return f"t={ts},v1={digest}"


def probe_webhook_unsigned(
    http_request: Callable[..., Any],
    path: str,
) -> Optional[Dict[str, Any]]:
    payload = json.dumps(_TEST_EVENT)
    response = http_request(
        method="POST",
        path=path,
        data=payload,
        headers={"Content-Type": "application/json"},
        allow_redirects=False,
        timeout=12,
    )
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    if status not in (200, 201, 204, 400):
        return None
    body = str(getattr(response, "text", "") or "")
    if status in (200, 201, 204) and "signature" not in body.lower():
        return {
            "path": path,
            "kind": "stripe_webhook_unsigned_accepted",
            "status_code": status,
            "severity": "critical",
            "preview": body[:200],
        }
    return None


def probe_webhook_signed(
    http_request: Callable[..., Any],
    path: str,
    whsec: str,
) -> Optional[Dict[str, Any]]:
    payload = json.dumps(_TEST_EVENT)
    sig = _stripe_signature(payload, whsec)
    response = http_request(
        method="POST",
        path=path,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Stripe-Signature": sig,
        },
        allow_redirects=False,
        timeout=12,
    )
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")
    if status in (200, 201, 204):
        return {
            "path": path,
            "kind": "stripe_webhook_signed_accepted",
            "status_code": status,
            "whsec_valid": True,
            "severity": "critical",
            "preview": body[:200],
        }
    if status == 400 and "signature" in body.lower():
        return {
            "path": path,
            "kind": "stripe_webhook_signature_required",
            "status_code": status,
            "severity": "info",
        }
    return None


def enumerate_stripe_webhooks(
    http_request: Callable[..., Any],
    homepage_html: str = "",
    *,
    whsec: str = "",
    extra_paths: Optional[List[str]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_stripe_webhook_credentials(homepage_html or "")
    if whsec:
        creds["whsec"] = whsec

    findings: List[Dict[str, Any]] = []
    paths = list(_WEBHOOK_PATHS)
    if extra_paths:
        paths.extend(extra_paths)
    for match in re.finditer(
        r"(?i)['\"](/api/[^'\"]*stripe[^'\"]*webhook[^'\"]*)['\"]",
        homepage_html or "",
    ):
        paths.append(match.group(1))

    seen = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)

        unsigned = probe_webhook_unsigned(http_request, path)
        if unsigned:
            findings.append(unsigned)
            continue

        secret = creds.get("whsec") or ""
        if secret:
            signed = probe_webhook_signed(http_request, path, secret)
            if signed:
                signed["whsec_masked"] = mask_secret(secret)
                findings.append(signed)
    if creds.get("whsec") and not findings:
        findings.append(
            {
                "kind": "stripe_whsec_discovered",
                "whsec_masked": mask_secret(creds["whsec"]),
                "severity": "critical",
                "detail": "webhook_secret_leaked_no_live_endpoint_confirmed",
            }
        )
    return findings, creds


__all__ = [
    "discover_stripe_webhook_credentials",
    "enumerate_stripe_webhooks",
    "probe_webhook_signed",
    "probe_webhook_unsigned",
]
