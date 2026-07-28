#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect unauthenticated Firestore REST document listing."""

import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


_PROJECT_RE = re.compile(
    r"""(?:projectId|project_id)\s*[:=]\s*["']([a-z0-9\-]+)["']""",
    re.I,
)
_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Firestore Public REST Access",
        "description": (
            "Probe Cloud Firestore REST "
            "`/v1/projects/{project}/databases/(default)/documents` for anonymous list access. "
            "Project ID can be set explicitly or scraped from the target HTML/JS."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": [
            "web", "scanner", "firebase", "firestore", "misconfiguration", "cloud",
        ],
        "references": [
            "https://firebase.google.com/docs/firestore/use-rest-api",
            "https://cloud.google.com/firestore/docs/reference/rest",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
        },
    }

    project_id = OptString("", "Firestore project ID (optional if scrapeable)", False)
    api_key = OptString("", "Optional browser API key to append as ?key=", False, advanced=True)

    def _scrape_hints(self):
        projects = []
        keys = []
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if r and r.status_code == 200 and r.text:
            projects.extend(_PROJECT_RE.findall(r.text))
            keys.extend(_AIZA_RE.findall(r.text))
        # de-dupe
        return list(dict.fromkeys(projects)), list(dict.fromkeys(keys))

    def _probe(self, project: str, api_key: str = ""):
        path = f"/v1/projects/{quote(project)}/databases/(default)/documents"
        if api_key:
            path += f"?key={quote(api_key)}&pageSize=1"
        else:
            path += "?pageSize=1"
        url = f"https://firestore.googleapis.com{path}"
        try:
            self._configure_session()
            r = self.session.get(url, timeout=8, verify=self._to_bool(self.verify_ssl))
        except Exception as exc:
            return False, f"error:{exc}", -1, ""
        text = (r.text or "")[:1000]
        if r.status_code == 200 and (
            '"documents"' in text or text.strip() in ("{}", "") or '"nextPageToken"' in text
        ):
            return True, "anonymous document list allowed", r.status_code, text[:300]
        if r.status_code == 200:
            return True, "HTTP 200 from Firestore documents endpoint", r.status_code, text[:300]
        if r.status_code in (401, 403) or "PERMISSION_DENIED" in text:
            return False, "permission denied", r.status_code, text[:200]
        if r.status_code == 404:
            return False, "project/database not found", r.status_code, text[:200]
        return False, f"http_{r.status_code}", r.status_code, text[:200]

    def run(self):
        project = str(
            self.project_id.value if hasattr(self.project_id, "value") else self.project_id or ""
        ).strip()
        api_key = str(
            self.api_key.value if hasattr(self.api_key, "value") else self.api_key or ""
        ).strip()
        scraped_projects, scraped_keys = self._scrape_hints()
        if not project:
            if scraped_projects:
                project = scraped_projects[0]
            else:
                host = str(self.target.value if hasattr(self.target, "value") else self.target or "")
                # common firebase hosting: project.web.app / project.firebaseapp.com
                m = re.match(r"^([a-z0-9\-]+)\.(?:web\.app|firebaseapp\.com)$", host.split(":")[0], re.I)
                if m:
                    project = m.group(1)
        if not api_key and scraped_keys:
            api_key = scraped_keys[0]
        if not project:
            self.set_info(reason="No Firestore projectId found (set project_id or scan a Firebase SPA)")
            return False

        ok, msg, code, snippet = self._probe(project, api_key)
        self.set_info(
            severity="critical" if ok else "info",
            reason=f"project={project}; {msg}",
            project_id=project,
            http=code,
            evidence=snippet,
        )
        return bool(ok)
