#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detect Supabase API keys and service_role secrets leaked in SPAs.

Targets common vibe-coder mistakes: NEXT_PUBLIC_/VITE_/REACT_APP_ env vars,
hardcoded createClient(url, key) calls, exposed .env files, and JWT keys
embedded in JS bundles.
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.supabase_probe import (
    collect_http_bodies,
    extract_supabase_findings,
    mask_token,
    validate_supabase_key,
    worst_severity,
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Supabase Client Key Exposure Detection",
        "description": (
            "Scans HTML, runtime env JS, and SPA bundles for exposed Supabase project URLs "
            "and JWT API keys. Flags service_role / secret keys in client-side code "
            "(critical misconfiguration common in no-code / vibe-coded apps)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": [
            "web",
            "scanner",
            "supabase",
            "exposure",
            "secrets",
            "misconfig",
            "jwt",
            "vuln",
            "nocode",
        ],
        "references": [
            "https://supabase.com/docs/guides/api#api-keys",
            "https://supabase.com/docs/guides/database/postgres/row-level-security",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "secret_exposure"],
            "cost": 1.0,
            "noise": 0.35,
            "value": 1.2,
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
                    {"capability": "secret_exposure", "from_detail": "supabase_keys"},
                    {"capability": "cloud_backend", "from_detail": "supabase_project"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/http/supabase_api_enum",
                    "scanner/http/postrest_api_detect",
                    "scanner/http/supabase_studio_detect",
                    "scanner/http/react_env_bundle_detect",
                ],
            },
        },
    }

    validate_keys = OptBool(True, "Validate discovered JWT keys against Supabase REST API", False)
    max_validate = OptInteger(2, "Max keys to validate remotely", False, advanced=True)

    def _validate_findings(self, findings):
        if not self._to_bool(self.validate_keys):
            return []
        validated = []
        limit = int(getattr(self.max_validate, "value", None) or self.max_validate or 2)
        checked = 0
        self._configure_session()
        for item in findings:
            if checked >= max(1, limit):
                break
            role = str(item.get("role") or "")
            if role not in ("anon", "service_role", "authenticated", "unknown"):
                continue
            ref = str(item.get("project_ref") or "").strip()
            raw = str(item.get("token") or "").strip()
            if not ref or not raw:
                continue
            ok, detail = validate_supabase_key(
                ref,
                raw,
                self.session,
                verify_ssl=self._to_bool(self.verify_ssl),
            )
            validated.append(
                {
                    "project_ref": ref,
                    "role": role,
                    "live": ok,
                    "detail": detail,
                    "token_masked": mask_token(raw),
                }
            )
            checked += 1
        return validated

    def run(self):
        bodies = collect_http_bodies(self.http_request)
        if not bodies:
            return False

        all_findings = []
        for path, text in bodies:
            chunk = text[:750_000]
            all_findings.extend(extract_supabase_findings(chunk, source=path))

        if not all_findings:
            return False

        # De-duplicate while preserving highest-risk role per project/key
        dedup = {}
        for finding in all_findings:
            key = (
                finding.get("kind"),
                finding.get("project_ref"),
                finding.get("token_masked"),
                finding.get("var_name"),
            )
            existing = dedup.get(key)
            if not existing or finding.get("role") == "service_role":
                dedup[key] = finding
        findings = list(dedup.values())

        service_roles = [f for f in findings if f.get("role") == "service_role"]
        anon_keys = [f for f in findings if f.get("role") in ("anon", "authenticated")]
        urls_only = [f for f in findings if f.get("kind") == "url_only"]

        validated = self._validate_findings(findings)
        severity = worst_severity(findings)
        if validated and any(v.get("live") for v in validated):
            severity = "critical" if service_roles else severity

        projects = sorted({str(f.get("project_ref") or "") for f in findings if f.get("project_ref")})
        evidence_parts = []
        for finding in findings[:8]:
            bits = [finding.get("source") or "?"]
            if finding.get("var_name"):
                bits.append(str(finding["var_name"]))
            if finding.get("role"):
                bits.append(f"role={finding['role']}")
            if finding.get("project_ref"):
                bits.append(f"ref={finding['project_ref']}")
            if finding.get("token_masked"):
                bits.append(f"key={finding['token_masked']}")
            evidence_parts.append(" | ".join(bits))

        reason_bits = []
        if service_roles:
            reason_bits.append(
                f"{len(service_roles)} service_role/secret key(s) in client-side assets"
            )
        if anon_keys:
            reason_bits.append(f"{len(anon_keys)} anon JWT key(s) exposed")
        if urls_only and not (service_roles or anon_keys):
            reason_bits.append(f"{len(urls_only)} Supabase project URL(s) exposed")
        if validated:
            live_count = sum(1 for v in validated if v.get("live"))
            if live_count:
                reason_bits.append(f"{live_count} key(s) validated live against Supabase REST")

        self.set_info(
            severity=severity,
            reason="; ".join(reason_bits) or "Supabase credentials exposed in client-side code",
            path=findings[0].get("source") or "/",
            project_refs=projects[:10],
            service_role_exposed=bool(service_roles),
            anon_key_exposed=bool(anon_keys),
            findings=[
                {
                    k: v
                    for k, v in finding.items()
                    if k != "token"
                }
                for finding in findings[:15]
            ],
            validated_keys=validated,
            evidence="; ".join(evidence_parts)[:900],
        )
        return True
