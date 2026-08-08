#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scan vibe-coded SPAs for leaked secrets across the typical no-code stack.

Point-by-point coverage:
  1. Stripe (sk_live, whsec, env vars)
  2. LLM keys (OpenAI, Anthropic, Groq, Hugging Face)
  3. Auth (Clerk, Auth0 client secrets)
  4. Email/SMS (Resend, SendGrid, Twilio)
  5. Maps/media (Mapbox, Cloudinary)
  6. Upload/realtime (UploadThing, Liveblocks, Pusher)
  7. Database URLs (Neon, PlanetScale, Turso, generic Postgres/Mongo/Redis)
  8. Cloud tokens (AWS, GitHub)
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.vibe_secrets_probe import (
    collect_vibe_http_bodies,
    extract_vibe_secrets,
    summarize_by_service,
    worst_vibe_severity,
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Vibe Stack Client Secrets Detection",
        "description": (
            "Multi-service scanner for secrets commonly forgotten in vibe-coded apps: "
            "Stripe, OpenAI/Anthropic/Groq, Clerk, Resend/SendGrid/Twilio, Mapbox, "
            "Cloudinary, UploadThing, Convex/Neon/PlanetScale/Turso DB URLs, AWS, and GitHub tokens "
            "in HTML, env.js, .env leaks, and JS bundles."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": [
            "web",
            "scanner",
            "exposure",
            "secrets",
            "misconfig",
            "nocode",
            "vibe",
            "stripe",
            "openai",
            "clerk",
            "vuln",
        ],
        "references": [
            "https://stripe.com/docs/keys",
            "https://platform.openai.com/docs/guides/production-best-practices",
            "https://clerk.com/docs/deployments/overview",
        ],
        "modules": [
            "scanner/http/supabase_key_exposure_detect",
            "scanner/http/react_env_bundle_detect",
            "scanner/http/firebase_api_key_detect",
            "scanner/http/general_tokens_detect",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 14,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "secret_exposure"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.3,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "secret_exposure", "from_detail": "vibe_stack_secrets"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/http/preview_deploy_prod_secrets_detect",
                    "scanner/http/supabase_key_exposure_detect",
                    "auxiliary/scanner/http/supabase_api_enum",
                    "auxiliary/scanner/http/clerk_auth0_management_enum",
                    "auxiliary/scanner/http/turso_upstash_enum",
                    "scanner/http/drizzle_prisma_schema_exposure_detect",
                    "auxiliary/scanner/http/supabase_realtime_channel_abuse",
                    "auxiliary/scanner/http/trpc_openapi_procedure_enum",
                    "auxiliary/scanner/http/contentful_management_enum",
                    "auxiliary/scanner/http/posthog_analytics_pii_enum",
                    "auxiliary/scanner/http/langsmith_langfuse_key_abuse",
                    "scanner/http/saml_metadata_abuse_detect",
                    "scanner/http/trpc_batch_amplification_detect",
                    "scanner/http/firebase_rtdb_rules_audit_detect",
                    "auxiliary/scanner/http/strapi_users_enum",
                    "scanner/http/gitlab_ci_secrets_detect",
                    "scanner/http/terraform_state_secrets_detect",
                    "auxiliary/scanner/http/pusher_liveblocks_channel_enum",
                    "scanner/http/magic_link_surface_detect",
                    "auxiliary/scanner/http/grpc_web_method_enum",
                    "scanner/http/firestore_rules_audit_detect",
                    "auxiliary/scanner/http/strapi_graphql_abuse",
                    "auxiliary/scanner/http/supabase_otp_abuse",
                    "auxiliary/scanner/http/clerk_passwordless_enum",
                    "auxiliary/scanner/http/gitlab_api_token_abuse",
                    "auxiliary/scanner/http/convex_deploy_key_enum",
                    "auxiliary/scanner/http/appwrite_users_enum",
                    "auxiliary/scanner/http/pocketbase_admin_enum",
                    "auxiliary/scanner/http/sanity_directus_token_abuse",
                    "scanner/http/vercel_env_leak_detect",
                    "auxiliary/scanner/http/auth0_passwordless_enum",
                    "auxiliary/scanner/http/stripe_webhook_abuse",
                    "auxiliary/scanner/http/payloadcms_api_enum",
                    "auxiliary/scanner/http/uploadthing_abuse",
                    "auxiliary/scanner/http/resend_email_enum",
                    "auxiliary/scanner/http/neon_database_enum",
                    "auxiliary/scanner/http/planetscale_branch_enum",
                    "auxiliary/scanner/http/github_pat_repo_enum",
                    "scanner/http/firebase_api_key_detect",
                    "scanner/http/firestore_public_access_detect",
                    "scanner/http/react_sourcemap_detect",
                    "auxiliary/osint/js_sourcemap_analyzer",
                ],
            },
        },
    }

    include_publishable = OptBool(
        False,
        "Report publishable/client-safe keys (Mapbox pk, Stripe pk, Clerk publishable)",
        False,
        advanced=True,
    )
    min_severity = OptString(
        "high",
        "Minimum severity to report: critical, high, medium, low, info",
        False,
        advanced=True,
    )

    _SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

    def _passes_filter(self, finding: dict) -> bool:
        sev = str(finding.get("severity") or "info")
        kind = str(finding.get("kind") or "")
        if not self._to_bool(self.include_publishable) and kind in (
            "publishable_key",
            "deploy_ref",
        ):
            return False
        floor = str(self.min_severity or "high").strip().lower()
        if floor not in self._SEVERITY_ORDER:
            floor = "high"
        return self._SEVERITY_ORDER.index(sev) <= self._SEVERITY_ORDER.index(floor)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request)
        if not bodies:
            return False

        all_findings = []
        for path, text in bodies:
            all_findings.extend(extract_vibe_secrets(text[:800_000], source=path))

        findings = [f for f in all_findings if self._passes_filter(f)]
        if not findings:
            return False

        # Sort: critical first, then by service
        findings.sort(
            key=lambda f: (
                self._SEVERITY_ORDER.index(str(f.get("severity") or "info")),
                str(f.get("service") or ""),
            )
        )

        by_service = summarize_by_service(findings)
        severity = worst_vibe_severity(
            findings,
            include_publishable=self._to_bool(self.include_publishable),
        )

        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]

        reason_parts = []
        if critical:
            services = sorted({str(f.get("service")) for f in critical})
            reason_parts.append(
                f"{len(critical)} critical secret(s) ({', '.join(services)})"
            )
        if high:
            services = sorted({str(f.get("service")) for f in high})
            reason_parts.append(f"{len(high)} high-risk leak(s) ({', '.join(services)})")

        evidence_parts = []
        for finding in findings[:12]:
            bits = [
                finding.get("source") or "?",
                str(finding.get("service") or "?"),
                str(finding.get("kind") or "?"),
            ]
            if finding.get("var_name"):
                bits.append(str(finding["var_name"]))
            if finding.get("value_masked"):
                bits.append(str(finding["value_masked"]))
            evidence_parts.append(" | ".join(bits))

        self.set_info(
            severity=severity,
            reason="; ".join(reason_parts) or "Vibe stack secrets exposed in client assets",
            path=findings[0].get("source") or "/",
            services=sorted(by_service.keys()),
            service_counts=by_service,
            findings=findings[:25],
            evidence="; ".join(evidence_parts)[:1200],
        )
        return True
