#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detect secrets commonly leaked in vibe-coded / no-code SPAs.

Covers Stripe, LLM providers, auth (Clerk), email/SMS, maps/CDN, BaaS DB URLs,
and related NEXT_PUBLIC_/VITE_/REACT_APP_ env assignments.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from lib.scanner.http.react_probe import extract_script_urls

# Shared fetch paths (aligned with supabase_probe)
_ENV_PATHS = (
    "/",
    "/env.js",
    "/config.js",
    "/config/env.js",
    "/config/runtime-env.js",
    "/runtime-env.js",
    "/env-config.js",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
)

# token_pattern, service, rule_id, kind, severity, note
_TOKEN_RULES: Tuple[Tuple[str, str, str, str, str, str], ...] = (
    # --- Stripe (payment) ---
    (r"\bsk_live_[A-Za-z0-9]{16,}\b", "stripe", "stripe_sk_live", "secret_key", "critical", "Stripe live secret key"),
    (r"\bsk_test_[A-Za-z0-9]{16,}\b", "stripe", "stripe_sk_test", "secret_key", "high", "Stripe test secret key"),
    (r"\bwhsec_[A-Za-z0-9]{16,}\b", "stripe", "stripe_whsec", "webhook_secret", "critical", "Stripe webhook signing secret"),
    (r"\brk_live_[A-Za-z0-9]{16,}\b", "stripe", "stripe_rk_live", "restricted_key", "high", "Stripe restricted live key"),
    (r"\bpk_live_[A-Za-z0-9]{16,}\b", "stripe", "stripe_pk_live", "publishable_key", "low", "Stripe publishable live key (expected client-side)"),
    # --- OpenAI / LLM ---
    (r"\bsk-proj-[A-Za-z0-9_-]{20,}\b", "openai", "openai_sk_proj", "secret_key", "critical", "OpenAI project API key"),
    (r"\bsk-ant-api03-[A-Za-z0-9_-]{20,}\b", "anthropic", "anthropic_sk", "secret_key", "critical", "Anthropic API key"),
    (r"\bgsk_[A-Za-z0-9]{20,}\b", "groq", "groq_gsk", "secret_key", "critical", "Groq API key"),
    (r"\bxai-[A-Za-z0-9_-]{20,}\b", "xai", "xai_key", "secret_key", "critical", "xAI API key"),
    (r"\bhf_[A-Za-z0-9]{20,}\b", "huggingface", "hf_token", "secret_key", "high", "Hugging Face token"),
    # sk- after stripe to avoid collision with sk_live/sk_test
    (r"\bsk-[A-Za-z0-9]{20,}\b", "openai", "openai_sk", "secret_key", "critical", "OpenAI-style API key"),
    # --- Email / SMS ---
    (r"\bre_[A-Za-z0-9_]{16,}\b", "resend", "resend_api_key", "secret_key", "critical", "Resend API key"),
    (r"\bSG\.[A-Za-z0-9._-]{20,}\b", "sendgrid", "sendgrid_api_key", "secret_key", "critical", "SendGrid API key"),
    (r"\bSK[a-f0-9]{32}\b", "twilio", "twilio_auth_token", "secret_key", "critical", "Twilio auth token"),
    # --- Maps / media ---
    (r"\bsk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "mapbox", "mapbox_sk", "secret_key", "critical", "Mapbox secret token"),
    (r"\bpk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "mapbox", "mapbox_pk", "publishable_key", "low", "Mapbox public token"),
    (r"\bcloudinary://[0-9]+:[A-Za-z0-9_-]+@[A-Za-z0-9_-]+\b", "cloudinary", "cloudinary_url", "connection_string", "critical", "Cloudinary URL with embedded secret"),
    # --- AWS / GitHub (common copy-paste leaks) ---
    (r"\bAKIA[0-9A-Z]{16}\b", "aws", "aws_access_key_id", "access_key_id", "high", "AWS access key id"),
    (r"\bghp_[A-Za-z0-9]{36,}\b", "github", "github_pat", "secret_key", "critical", "GitHub personal access token"),
    (r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "github", "github_fine_pat", "secret_key", "critical", "GitHub fine-grained PAT"),
)

# Named env: (regex with groups var_name, value), service, kind, severity, note
_NAMED_ENV_RULES: Tuple[Tuple[str, str, str, str, str], ...] = (
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)?STRIPE_(?:SECRET|API)_KEY)\s*[=:]\s*["']([^"']+)["']""",
        "stripe", "secret_key", "critical", "Stripe secret in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?STRIPE_WEBHOOK_SECRET)\s*[=:]\s*["']([^"']+)["']""",
        "stripe", "webhook_secret", "critical", "Stripe webhook secret in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)?OPENAI_API_KEY)\s*[=:]\s*["']([^"']+)["']""",
        "openai", "secret_key", "critical", "OpenAI key in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?ANTHROPIC_API_KEY)\s*[=:]\s*["']([^"']+)["']""",
        "anthropic", "secret_key", "critical", "Anthropic key in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?GROQ_API_KEY)\s*[=:]\s*["']([^"']+)["']""",
        "groq", "secret_key", "critical", "Groq key in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?CLERK_(?:SECRET_KEY|API_KEY))\s*[=:]\s*["']([^"']+)["']""",
        "clerk", "secret_key", "critical", "Clerk secret key in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)?CLERK_PUBLISHABLE_KEY)\s*[=:]\s*["']([^"']+)["']""",
        "clerk", "publishable_key", "low", "Clerk publishable key (expected client-side)",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?RESEND_API_KEY)\s*[=:]\s*["']([^"']+)["']""",
        "resend", "secret_key", "critical", "Resend key in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?SENDGRID_API_KEY)\s*[=:]\s*["']([^"']+)["']""",
        "sendgrid", "secret_key", "critical", "SendGrid key in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?TWILIO_(?:AUTH_TOKEN|API_KEY|API_SECRET))\s*[=:]\s*["']([^"']+)["']""",
        "twilio", "secret_key", "critical", "Twilio secret in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?MAPBOX_(?:SECRET|ACCESS)_TOKEN)\s*[=:]\s*["']([^"']+)["']""",
        "mapbox", "secret_key", "critical", "Mapbox secret token in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)?MAPBOX_(?:PUBLIC|PUBLISHABLE)_TOKEN)\s*[=:]\s*["']([^"']+)["']""",
        "mapbox", "publishable_key", "low", "Mapbox public token",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?CLOUDINARY_(?:URL|API_SECRET|SECRET))\s*[=:]\s*["']([^"']+)["']""",
        "cloudinary", "secret_key", "critical", "Cloudinary secret in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?UPLOADTHING_(?:SECRET|TOKEN|APP_ID))\s*[=:]\s*["']([^"']+)["']""",
        "uploadthing", "secret_key", "critical", "UploadThing secret in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?CONVEX_(?:DEPLOY_KEY|ADMIN_KEY|DEPLOYMENT))\s*[=:]\s*["']([^"']+)["']""",
        "convex", "secret_key", "critical", "Convex admin/deploy key in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?AUTH0_(?:CLIENT_SECRET|SECRET))\s*[=:]\s*["']([^"']+)["']""",
        "auth0", "secret_key", "critical", "Auth0 client secret in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?LIVEBLOCKS_(?:SECRET|API_KEY))\s*[=:]\s*["']([^"']+)["']""",
        "liveblocks", "secret_key", "critical", "Liveblocks secret in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?PUSHER_(?:SECRET|KEY))\s*[=:]\s*["']([^"']+)["']""",
        "pusher", "secret_key", "high", "Pusher secret in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?DATABASE_URL)\s*[=:]\s*["']([^"']+)["']""",
        "database", "connection_string", "critical", "Database URL in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?NEON_DATABASE_URL)\s*[=:]\s*["']([^"']+)["']""",
        "neon", "connection_string", "critical", "Neon database URL in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?PLANETSCALE_(?:DATABASE_URL|CONNECTION_STRING))\s*[=:]\s*["']([^"']+)["']""",
        "planetscale", "connection_string", "critical", "PlanetScale URL in client env",
    ),
    (
        r"""(?ix)\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)?TURSO_(?:DATABASE_URL|AUTH_TOKEN|DB_URL))\s*[=:]\s*["']([^"']+)["']""",
        "turso", "connection_string", "critical", "Turso credentials in client env",
    ),
)

_CONNECTION_RULES: Tuple[Tuple[str, str, str, str, str], ...] = (
    (
        r"""(?i)(postgres(?:ql)?://[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+)""",
        "postgres", "postgres_url", "connection_string", "critical", "PostgreSQL connection string with credentials",
    ),
    (
        r"""(?i)(mysql://[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+)""",
        "mysql", "mysql_url", "connection_string", "critical", "MySQL connection string with credentials",
    ),
    (
        r"""(?i)(libsql://[^\s"'<>]+)""",
        "turso", "libsql_url", "connection_string", "critical", "Turso/libSQL connection string",
    ),
    (
        r"""(?i)(mongodb(?:\+srv)?://[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+)""",
        "mongodb", "mongo_url", "connection_string", "critical", "MongoDB connection string with credentials",
    ),
    (
        r"""(?i)(redis://[^\s"'<>]*:[^\s"'<>@]+@[^\s"'<>]+)""",
        "redis", "redis_url", "connection_string", "critical", "Redis URL with credentials",
    ),
    (
        r"""(?i)([a-z][a-z0-9+.-]*://[^\s"'<>]+@(?:[a-z0-9.-]+\.)?neon\.tech[^\s"'<>]*)""",
        "neon", "neon_host_url", "connection_string", "critical", "Neon.tech database URL",
    ),
    (
        r"""(?i)([a-z][a-z0-9+.-]*://[^\s"'<>]+@[a-z0-9.-]+\.psdb\.cloud[^\s"'<>]*)""",
        "planetscale", "planetscale_url", "connection_string", "critical", "PlanetScale database URL",
    ),
    (
        r"""(?i)(https://[^\s"'<>]+@[a-z0-9.-]+\.convex\.cloud[^\s"'<>]*)""",
        "convex", "convex_url", "connection_string", "high", "Convex cloud URL with embedded credentials",
    ),
)

_COMPILED_TOKEN_RULES = [
    (re.compile(rx), service, rule_id, kind, severity, note)
    for rx, service, rule_id, kind, severity, note in _TOKEN_RULES
]

_COMPILED_NAMED = [
    (re.compile(rx), service, kind, severity, note)
    for rx, service, kind, severity, note in _NAMED_ENV_RULES
]

_COMPILED_CONN = [
    (re.compile(rx), service, rule_id, kind, severity, note)
    for rx, service, rule_id, kind, severity, note in _CONNECTION_RULES
]

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Placeholder / example values vibe templates ship with
_NOISE_VALUES = frozenset({
    "",
    "your-api-key",
    "your_api_key",
    "your-api-key-here",
    "sk_test_placeholder",
    "sk_live_placeholder",
    "changeme",
    "undefined",
    "null",
    "xxx",
    "todo",
    "replace-me",
    "insert-key-here",
})


def mask_secret(value: str) -> str:
    text = (value or "").strip()
    if len(text) <= 12:
        return text[:3] + "…" if text else ""
    if "://" in text and "@" in text:
        # Redact password segment in URLs
        try:
            scheme, rest = text.split("://", 1)
            if "@" in rest:
                creds, host = rest.rsplit("@", 1)
                if ":" in creds:
                    user = creds.split(":", 1)[0]
                    return f"{scheme}://{user}:****@{host[:40]}…"
        except Exception:
            pass
    return f"{text[:8]}…{text[-4:]}"


def _is_noise(value: str) -> bool:
    text = (value or "").strip()
    low = text.lower()
    if low in _NOISE_VALUES:
        return True
    if low.startswith("your-") or low.startswith("your_"):
        return True
    if low in ("pk_test_xxx", "sk_test_xxx", "sk_live_xxx"):
        return True
    if re.fullmatch(r"(?i)(changeme|replace-?me|insert-?key|todo|xxx|example|placeholder)", low):
        return True
    return False


def extract_vibe_secrets(text: str, *, source: str = "") -> List[Dict[str, Any]]:
    body = text or ""
    findings: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str]] = set()

    def add(
        *,
        service: str,
        rule_id: str,
        kind: str,
        severity: str,
        value: str,
        note: str,
        var_name: str = "",
    ) -> None:
        if _is_noise(value):
            return
        masked = mask_secret(value)
        dedup = (service, rule_id, masked)
        if dedup in seen:
            return
        seen.add(dedup)
        findings.append(
            {
                "service": service,
                "rule_id": rule_id,
                "kind": kind,
                "severity": severity,
                "value_masked": masked,
                "var_name": var_name,
                "source": source,
                "note": note,
            }
        )

    for regex, service, kind, severity, note in _COMPILED_NAMED:
        for match in regex.finditer(body):
            var_name = (match.group(1) or "").strip()
            value = (match.group(2) or "").strip()
            add(
                service=service,
                rule_id=f"env_{var_name.lower()}",
                kind=kind,
                severity=severity,
                value=value,
                note=note,
                var_name=var_name,
            )

    for regex, service, rule_id, kind, severity, note in _COMPILED_CONN:
        for match in regex.finditer(body):
            value = (match.group(1) or "").strip()
            add(
                service=service,
                rule_id=rule_id,
                kind=kind,
                severity=severity,
                value=value,
                note=note,
            )

    for regex, service, rule_id, kind, severity, note in _COMPILED_TOKEN_RULES:
        for match in regex.finditer(body):
            value = (match.group(0) or "").strip()
            if rule_id == "openai_sk" and (
                value.startswith("sk_live_")
                or value.startswith("sk_test_")
                or value.startswith("sk-proj-")
            ):
                continue
            add(
                service=service,
                rule_id=rule_id,
                kind=kind,
                severity=severity,
                value=value,
                note=note,
            )

    return findings


def worst_vibe_severity(findings: List[Dict[str, Any]], *, include_publishable: bool = False) -> str:
    if not findings:
        return "info"
    best = "info"
    for item in findings:
        sev = str(item.get("severity") or "info")
        kind = str(item.get("kind") or "")
        if not include_publishable and kind in ("publishable_key", "deploy_ref"):
            if sev in ("low", "info"):
                continue
        if _SEVERITY_RANK.get(sev, 99) < _SEVERITY_RANK.get(best, 99):
            best = sev
    return best


def summarize_by_service(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in findings:
        service = str(item.get("service") or "unknown")
        kind = str(item.get("kind") or "")
        if kind in ("publishable_key", "deploy_ref"):
            continue
        counts[service] = counts.get(service, 0) + 1
    return counts


def collect_vibe_http_bodies(http_request) -> List[Tuple[str, str]]:
    bodies: List[Tuple[str, str]] = []
    seen: Set[str] = set()

    def fetch(path: str) -> None:
        if path in seen:
            return
        seen.add(path)
        response = http_request(method="GET", path=path, allow_redirects=path == "/")
        if not response or response.status_code != 200:
            return
        text = response.text or ""
        if text.strip():
            bodies.append((path, text))

    for path in _ENV_PATHS:
        fetch(path)

    homepage = next((text for p, text in bodies if p == "/"), "")
    if homepage:
        for script_path in extract_script_urls(homepage, "/")[:12]:
            fetch(script_path)

    return bodies


__all__ = [
    "collect_vibe_http_bodies",
    "extract_vibe_secrets",
    "mask_secret",
    "summarize_by_service",
    "worst_vibe_severity",
]
