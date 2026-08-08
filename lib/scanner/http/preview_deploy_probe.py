#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Vercel/Netlify preview & staging deploys leaking production secrets."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlparse

from lib.scanner.http.react_probe import extract_script_urls

# ---------------------------------------------------------------------------
# Hostname heuristics
# ---------------------------------------------------------------------------

_VERCEL_PLATFORM_SUFFIXES = (".vercel.app", ".now.sh")
_NETLIFY_PLATFORM_SUFFIXES = (".netlify.app", ".netlify.com")

# project-git-branch-user.vercel.app or myapp-git-feature-foo.vercel.app
_VERCEL_PREVIEW_HOST_RX = re.compile(
    r"[a-z0-9-]+-git-[a-z0-9-]+-[a-z0-9-]+\.vercel\.app$|"
    r"-git-[a-z0-9-]+\.vercel\.app$",
    re.I,
)

# deploy-preview-42--mysite.netlify.app or feature--mysite.netlify.app
_NETLIFY_PREVIEW_HOST_RX = re.compile(
    r"^deploy-preview-\d+--[a-z0-9-]+\.netlify\.app$|"
    r"^[a-z0-9][a-z0-9-]*--[a-z0-9-]+\.netlify\.app$",
    re.I,
)

_STAGING_SUBDOMAIN_RX = re.compile(
    r"(?i)^(staging|stage|dev|develop|development|preview|preprod|test|testing|uat|qa|sandbox|canary|demo)\."
)

# ---------------------------------------------------------------------------
# Response / bundle env markers
# ---------------------------------------------------------------------------

_ENV_SIGNAL_RULES: Tuple[Tuple[str, str, str, str], ...] = (
    (r'(?i)"VERCEL_ENV"\s*:\s*"([^"]+)"', "vercel_env", "vercel", "VERCEL_ENV in client bundle"),
    (r"(?i)\bVERCEL_ENV\s*=\s*['\"]?(preview|production|development)['\"]?", "vercel_env", "vercel", "VERCEL_ENV assignment"),
    (r'(?i)"NEXT_PUBLIC_VERCEL_ENV"\s*:\s*"([^"]+)"', "next_public_vercel_env", "vercel", "NEXT_PUBLIC_VERCEL_ENV"),
    (r'(?i)"NETLIFY_CONTEXT"\s*:\s*"([^"]+)"', "netlify_context", "netlify", "NETLIFY_CONTEXT in client bundle"),
    (r"(?i)\bNETLIFY_CONTEXT\s*=\s*['\"]?(deploy-preview|branch-deploy|production|\w+)['\"]?", "netlify_context", "netlify", "NETLIFY_CONTEXT assignment"),
    (r'(?i)"CONTEXT"\s*:\s*"(deploy-preview|branch-deploy)"', "netlify_context_short", "netlify", "Netlify CONTEXT=deploy-preview"),
    (r'(?i)"DEPLOYMENT"\s*:\s*"preview"', "deployment_preview", "generic", "DEPLOYMENT=preview marker"),
    (r"(?i)deploy-preview-\d+", "netlify_preview_url", "netlify", "Netlify deploy-preview URL embedded"),
    (r"(?i)-git-[a-z0-9-]+\.vercel\.app", "vercel_preview_url", "vercel", "Vercel git preview URL embedded"),
)

_COMPILED_ENV_SIGNALS = [
    (re.compile(rx), key, platform, note) for rx, key, platform, note in _ENV_SIGNAL_RULES
]

_PREVIEW_ENV_VALUES = frozenset({
    "preview",
    "deploy-preview",
    "branch-deploy",
    "development",
    "dev",
})

_PRODUCTION_ENV_VALUES = frozenset({
    "production",
    "prod",
})

# Secret shapes that must not appear on preview/staging builds
_PROD_SECRET_RULE_IDS = frozenset({
    "stripe_sk_live",
    "stripe_whsec",
    "stripe_rk_live",
    "openai_sk_proj",
    "openai_sk",
    "anthropic_sk",
    "groq_gsk",
    "resend_api_key",
    "sendgrid_api_key",
    "twilio_auth_token",
    "mapbox_sk",
    "cloudinary_url",
    "github_pat",
    "github_fine_pat",
    "aws_access_key_id",
    "postgres_url",
    "mysql_url",
    "mongo_url",
    "redis_url",
    "neon_host_url",
    "planetscale_url",
    "libsql_url",
})

_PROD_SECRET_KINDS = frozenset({
    "secret_key",
    "webhook_secret",
    "connection_string",
    "restricted_key",
})

_PROD_ENV_NAME_HINTS = (
    "SECRET",
    "SERVICE_ROLE",
    "DATABASE_URL",
    "NEON_",
    "PLANETSCALE",
    "TURSO_",
    "CONVEX_DEPLOY",
    "WEBHOOK",
    "STRIPE_SECRET",
    "OPENAI_API",
    "ANTHROPIC_API",
)

_PREVIEW_FETCH_PATHS = (
    "/",
    "/env.js",
    "/config.js",
    "/config/runtime-env.js",
    "/runtime-env.js",
    "/_next/static/chunks/webpack.js",
)


def normalize_host(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        raw = urlparse(raw).hostname or raw
    return raw.split(":")[0].strip(".")


def classify_deployment(
    host: str,
    headers: Optional[Mapping[str, str]] = None,
    body: str = "",
) -> Dict[str, Any]:
    """Return platform, deploy_type (preview|staging|production|unknown), signals."""
    hostname = normalize_host(host)
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    signals: List[str] = []
    platform = "unknown"
    deploy_type = "unknown"
    confidence = "low"

    if hostname.endswith(_VERCEL_PLATFORM_SUFFIXES):
        platform = "vercel"
        signals.append("vercel_hostname")
        if _VERCEL_PREVIEW_HOST_RX.search(hostname) or "-git-" in hostname:
            deploy_type = "preview"
            confidence = "high"
            signals.append("vercel_git_preview_hostname")
        elif hostname.endswith(".vercel.app"):
            deploy_type = "production"
            confidence = "medium"
            signals.append("vercel_production_alias_candidate")

    if hostname.endswith(_NETLIFY_PLATFORM_SUFFIXES):
        platform = "netlify"
        signals.append("netlify_hostname")
        if _NETLIFY_PREVIEW_HOST_RX.match(hostname) or hostname.startswith("deploy-preview-"):
            deploy_type = "preview"
            confidence = "high"
            signals.append("netlify_deploy_preview_hostname")
        elif "--" in hostname.split(".")[0]:
            deploy_type = "preview"
            confidence = "high"
            signals.append("netlify_branch_subdomain")

    if _STAGING_SUBDOMAIN_RX.match(hostname):
        if deploy_type == "unknown":
            deploy_type = "staging"
        confidence = "medium" if confidence == "low" else confidence
        signals.append("staging_subdomain")

    deploy_ctx = hdrs.get("x-nf-deploy-context", "").lower()
    if deploy_ctx:
        platform = platform or "netlify"
        signals.append(f"header:x-nf-deploy-context={deploy_ctx}")
        if deploy_ctx in ("deploy-preview", "branch-deploy"):
            deploy_type = "preview"
            confidence = "high"

    vercel_deploy = hdrs.get("x-vercel-deployment-url", "")
    if vercel_deploy:
        platform = "vercel"
        signals.append("header:x-vercel-deployment-url")
        if "-git-" in vercel_deploy.lower():
            deploy_type = "preview"
            confidence = "high"

    for regex, key, plat, note in _COMPILED_ENV_SIGNALS:
        for match in regex.finditer(body or ""):
            value = ""
            if match.lastindex and match.lastindex >= 1:
                value = (match.group(1) or "").strip().lower()
            signals.append(f"bundle:{key}={value or 'matched'}")
            if plat != "generic":
                platform = platform or plat
            if value in _PREVIEW_ENV_VALUES or key in (
                "netlify_preview_url",
                "vercel_preview_url",
                "deployment_preview",
            ):
                deploy_type = "preview"
                confidence = "high"
            if value in _PRODUCTION_ENV_VALUES and deploy_type in ("preview", "staging"):
                signals.append("env_mismatch:production_env_on_non_prod_deploy")

    if deploy_type == "unknown" and platform in ("vercel", "netlify"):
        deploy_type = "production"
        confidence = "low"

    return {
        "platform": platform,
        "deploy_type": deploy_type,
        "confidence": confidence,
        "signals": signals,
        "hostname": hostname,
    }


def extract_deploy_env_signals(text: str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen = set()
    for regex, key, platform, note in _COMPILED_ENV_SIGNALS:
        for match in regex.finditer(text or ""):
            value = ""
            if match.lastindex and match.lastindex >= 1:
                value = (match.group(1) or "").strip()
            item = (key, value.lower())
            if item in seen:
                continue
            seen.add(item)
            findings.append(
                {
                    "key": key,
                    "value": value,
                    "platform": platform,
                    "note": note,
                }
            )
    return findings


def is_production_grade_secret(finding: Dict[str, Any]) -> bool:
    rule_id = str(finding.get("rule_id") or "")
    kind = str(finding.get("kind") or "")
    severity = str(finding.get("severity") or "")
    var_name = str(finding.get("var_name") or "").upper()
    service = str(finding.get("service") or "")

    if rule_id in _PROD_SECRET_RULE_IDS:
        return True
    if kind in _PROD_SECRET_KINDS and severity in ("critical", "high"):
        return True
    if any(hint in var_name for hint in _PROD_ENV_NAME_HINTS):
        return True
    if service == "stripe" and rule_id in ("stripe_sk_live", "stripe_whsec"):
        return True
    if service == "supabase" and str(finding.get("role") or "") == "service_role":
        return True
    return False


def has_env_mismatch(deploy_info: Dict[str, Any], env_signals: List[Dict[str, str]]) -> bool:
    if "env_mismatch:production_env_on_non_prod_deploy" in (deploy_info.get("signals") or []):
        return True
    if deploy_info.get("deploy_type") not in ("preview", "staging"):
        return False
    for signal in env_signals:
        value = str(signal.get("value") or "").lower()
        key = str(signal.get("key") or "")
        if value in _PRODUCTION_ENV_VALUES and key in (
            "vercel_env",
            "next_public_vercel_env",
            "netlify_context",
            "netlify_context_short",
        ):
            return True
    return False


def collect_preview_http_bodies(http_request, homepage_html: str = "") -> List[Tuple[str, str]]:
    bodies: List[Tuple[str, str]] = []
    seen = set()

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

    for path in _PREVIEW_FETCH_PATHS:
        fetch(path)

    homepage = homepage_html or next((text for p, text in bodies if p == "/"), "")
    if homepage:
        for script_path in extract_script_urls(homepage, "/")[:10]:
            fetch(script_path)

    return bodies


__all__ = [
    "classify_deployment",
    "collect_preview_http_bodies",
    "extract_deploy_env_signals",
    "has_env_mismatch",
    "is_production_grade_secret",
    "normalize_host",
]
