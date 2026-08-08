#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detect production secrets on Vercel/Netlify preview and staging deployments.

Vibe coders often wire production Supabase/Stripe/OpenAI/DB credentials into
preview builds (shared env vars, missing VERCEL_ENV guards, or branch deploys
with prod .env). This module classifies the deploy context and flags prod-grade
secrets or VERCEL_ENV / NETLIFY_CONTEXT mismatches.
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.preview_deploy_probe import (
    classify_deployment,
    collect_preview_http_bodies,
    extract_deploy_env_signals,
    has_env_mismatch,
    is_production_grade_secret,
    normalize_host,
)
from lib.scanner.http.supabase_probe import extract_supabase_findings
from lib.scanner.http.vibe_secrets_probe import extract_vibe_secrets


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Vercel / Netlify Preview Production Secrets Detection",
        "description": (
            "Detects Vercel git previews, Netlify deploy-preview URLs, and staging "
            "subdomains that embed production API keys, database URLs, or Supabase "
            "service_role tokens in client-side assets. Also flags "
            "VERCEL_ENV=production / NETLIFY_CONTEXT=production on non-production deploys."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": [
            "web",
            "scanner",
            "vercel",
            "netlify",
            "preview",
            "staging",
            "exposure",
            "secrets",
            "misconfig",
            "nocode",
            "vibe",
            "vuln",
        ],
        "references": [
            "https://vercel.com/docs/concepts/projects/environment-variables",
            "https://docs.netlify.com/site-deploys/overview/#deploy-previews",
        ],
        "modules": [
            "scanner/http/vibe_stack_secrets_detect",
            "scanner/http/supabase_key_exposure_detect",
            "scanner/http/vercel_detect",
            "scanner/http/netlify_detect",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 14,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "secret_exposure"],
            "cost": 1.0,
            "noise": 0.35,
            "value": 1.2,
            "requires": {
                "tech_hints_any": ["vercel", "netlify"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "secret_exposure", "from_detail": "preview_prod_secrets"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/http/vibe_stack_secrets_detect",
                    "scanner/http/supabase_key_exposure_detect",
                    "auxiliary/scanner/http/supabase_api_enum",
                    "scanner/http/vercel_source_detect",
                ],
            },
        },
    }

    require_preview_context = OptBool(
        True,
        "Only report when preview/staging deploy context is confirmed",
        False,
    )
    flag_env_mismatch = OptBool(
        True,
        "Report VERCEL_ENV / NETLIFY_CONTEXT production markers on preview builds",
        False,
    )
    include_staging_subdomains = OptBool(
        True,
        "Treat staging.* / dev.* / preview.* subdomains as non-production",
        False,
    )

    def _host(self) -> str:
        return normalize_host(str(getattr(self, "target", "") or ""))

    def _is_non_production_deploy(self, deploy_info: dict) -> bool:
        deploy_type = str(deploy_info.get("deploy_type") or "")
        if deploy_type in ("preview", "staging"):
            return True
        if not self._to_bool(self.include_staging_subdomains):
            return deploy_type == "preview"
        return deploy_type in ("preview", "staging")

    def run(self):
        response = self.http_request(method="GET", path="/", allow_redirects=True)
        if not response:
            return False

        headers = {k.lower(): v for k, v in (response.headers or {}).items()}
        homepage = response.text or ""
        host = self._host()

        deploy_info = classify_deployment(host, headers, homepage)
        if not self._is_non_production_deploy(deploy_info):
            if self._to_bool(self.require_preview_context):
                return False
            deploy_info["deploy_type"] = deploy_info.get("deploy_type") or "unknown"

        bodies = collect_preview_http_bodies(self.http_request, homepage_html=homepage)
        if not any(p == "/" for p, _ in bodies):
            bodies.insert(0, ("/", homepage))

        env_signals: list = []
        vibe_findings: list = []
        supabase_findings: list = []

        for path, text in bodies:
            chunk = text[:800_000]
            env_signals.extend(extract_deploy_env_signals(chunk))
            for finding in extract_vibe_secrets(chunk, source=path):
                if is_production_grade_secret(finding):
                    item = dict(finding)
                    item["on_preview"] = True
                    vibe_findings.append(item)
            for finding in extract_supabase_findings(chunk, source=path):
                role = str(finding.get("role") or "")
                if role == "service_role" or (
                    role in ("anon", "authenticated") and deploy_info.get("deploy_type") == "preview"
                ):
                    item = {k: v for k, v in finding.items() if k != "token"}
                    item["on_preview"] = True
                    if role == "service_role":
                        supabase_findings.append(item)

        # Re-classify with all body content for embedded preview URLs
        combined = "\n".join(text[:200_000] for _, text in bodies)
        deploy_info = classify_deployment(host, headers, combined)
        env_mismatch = self._to_bool(self.flag_env_mismatch) and has_env_mismatch(
            deploy_info, env_signals
        )

        prod_secrets = vibe_findings + [
            f for f in supabase_findings if f.get("role") == "service_role"
        ]

        if self._to_bool(self.require_preview_context) and not self._is_non_production_deploy(deploy_info):
            return False

        if not prod_secrets and not env_mismatch:
            return False

        platform = deploy_info.get("platform") or "unknown"
        deploy_type = deploy_info.get("deploy_type") or "unknown"

        reason_parts = []
        if prod_secrets:
            services = sorted({str(f.get("service") or "secret") for f in prod_secrets})
            reason_parts.append(
                f"{len(prod_secrets)} production-grade secret(s) on {platform} {deploy_type} ({', '.join(services)})"
            )
        if env_mismatch:
            reason_parts.append(
                f"production env marker on {deploy_type} deploy (VERCEL_ENV / NETLIFY_CONTEXT mismatch)"
            )

        evidence_parts = []
        for finding in prod_secrets[:10]:
            bits = [
                finding.get("source") or "?",
                str(finding.get("service") or "?"),
            ]
            if finding.get("var_name"):
                bits.append(str(finding["var_name"]))
            if finding.get("role"):
                bits.append(f"role={finding['role']}")
            if finding.get("value_masked"):
                bits.append(str(finding["value_masked"]))
            evidence_parts.append(" | ".join(bits))

        severity = "critical" if prod_secrets else "high"

        self.set_info(
            severity=severity,
            reason="; ".join(reason_parts),
            path="/",
            platform=platform,
            deploy_type=deploy_type,
            hostname=host,
            confidence=deploy_info.get("confidence"),
            deploy_signals=deploy_info.get("signals", [])[:15],
            env_signals=env_signals[:15],
            env_mismatch=env_mismatch,
            production_secrets=prod_secrets[:20],
            supabase_on_preview=supabase_findings[:10],
            evidence="; ".join(evidence_parts)[:1200],
        )
        return True
