#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extract Google/Firebase browser API keys (AIza...) and validate them."""

import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_PROJECT_RE = re.compile(
    r"""(?:projectId|project_id|authDomain)\s*[:=]\s*["']([a-z0-9\-]+)(?:\.firebaseapp\.com)?["']""",
    re.I,
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Firebase / Google Browser API Key Analysis",
        "description": (
            "Scrape exposed Google browser API keys (AIza...) from JS/HTML, then probe "
            "Identity Toolkit getProjectConfig to see if the key is live and which project "
            "it belongs to. Useful against SPAs that leak Firebase web configs."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": [
            "web", "scanner", "firebase", "google", "api-key", "exposure", "cloud",
        ],
        "references": [
            "https://firebase.google.com/docs/projects/api-keys",
            "https://cloud.google.com/docs/authentication/api-keys",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
        },
    }

    validate_keys = OptBool(True, "Validate discovered keys against Google APIs", False)
    max_keys = OptInteger(3, "Max keys to validate", False, advanced=True)

    def _collect_bodies(self):
        bodies = []
        for path in ("/", "/config.js", "/firebase-config.js", "/env.js", "/static/js/main.js"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if r and r.status_code == 200 and r.text:
                bodies.append((path, r.text))
        return bodies

    def _validate_key(self, api_key: str):
        """Return (valid, detail) using Identity Toolkit project config endpoint."""
        url = (
            "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig"
            f"?key={quote(api_key)}"
        )
        try:
            self._configure_session()
            r = self.session.get(url, timeout=8, verify=self._to_bool(self.verify_ssl))
        except Exception as exc:
            return False, f"probe_error:{exc}"
        text = (r.text or "")[:800]
        if r.status_code == 200 and ("projectId" in text or "authorizedDomains" in text):
            project = ""
            m = re.search(r'"projectId"\s*:\s*"([^"]+)"', text)
            if m:
                project = m.group(1)
            return True, f"live key; projectId={project or 'unknown'}"
        if r.status_code in (400, 403) and (
            "API_KEY_INVALID" in text
            or "API key not valid" in text
            or "API_KEY_SERVICE_BLOCKED" in text
        ):
            return False, "key rejected by Google"
        if r.status_code == 200:
            return True, "accepted (200)"
        return False, f"http_{r.status_code}"

    def run(self):
        bodies = self._collect_bodies()
        if not bodies:
            return False

        keys = []
        projects = []
        seen = set()
        for _path, body in bodies:
            for key in _AIZA_RE.findall(body):
                if key not in seen:
                    seen.add(key)
                    keys.append(key)
            for m in _PROJECT_RE.finditer(body):
                proj = m.group(1)
                if proj not in projects:
                    projects.append(proj)

        if not keys:
            return False

        details = []
        live = []
        limit = int(self.max_keys.value if hasattr(self.max_keys, "value") else self.max_keys or 3)
        if self._to_bool(self.validate_keys):
            for key in keys[: max(1, limit)]:
                ok, detail = self._validate_key(key)
                masked = f"{key[:8]}…{key[-4:]}"
                details.append(f"{masked}:{detail}")
                if ok:
                    live.append(key)
        else:
            details = [f"{k[:8]}…{k[-4:]}" for k in keys[:limit]]

        severity = "high" if live else "medium"
        self.set_info(
            severity=severity,
            reason=(
                f"Found {len(keys)} Google/Firebase API key(s)"
                + (f"; {len(live)} validated live" if live else "")
                + (f"; projects={','.join(projects[:5])}" if projects else "")
            ),
            api_keys_found=len(keys),
            api_keys_live=len(live),
            project_hints=projects[:5],
            evidence="; ".join(details)[:500],
        )
        return True
