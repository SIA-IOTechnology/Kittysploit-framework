#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect CVE-2026-58025 MediaWiki log-params unserialize (version + Import surface)."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.mediawiki import Mediawiki


def _cve_2026_58025_vulnerable(version: str) -> Optional[bool]:
    """Affected: < 1.43.9, < 1.44.6, < 1.45.4, < 1.46.0 (and older 1.x)."""
    parts = Mediawiki.mw_parse_version(version)
    if not parts or parts[0] != 1:
        return None
    minor = parts[1] if len(parts) > 1 else 0
    patch = parts[2] if len(parts) > 2 else 0
    if minor >= 46:
        return False
    if minor == 45:
        return patch < 4
    if minor == 44:
        return patch < 6
    if minor == 43:
        return patch < 9
    return True


class Module(Scanner, Http_client, Mediawiki):
    __info__ = {
        "name": "MediaWiki CVE-2026-58025 Detect",
        "description": (
            "Fingerprints MediaWiki and flags versions affected by CVE-2026-58025: "
            "LogEntryBase::extractParams() called unserialize() on user-controlled "
            "log_params from WikiImporter XML (<params>). Affected: < 1.43.9, "
            "< 1.44.6, < 1.45.4, < 1.46.0. Also probes Special:Import availability. "
            "Detection only — does not upload a payload."
        ),
        "author": ["shinthink", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-58025"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-58025",
            "https://www.cve.org/CVERecord?id=CVE-2026-58025",
            "https://phabricator.wikimedia.org/",
        ],
        "tags": [
            "mediawiki",
            "wiki",
            "deserialization",
            "unserialize",
            "rce",
            "cve",
            "cve-2026-58025",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints", "exploit_paths"],
            "chain": {
                "produces_capabilities": ["admin_surface"],
                "suggested_followups": [
                    "exploits/multi/http/mediawiki_cve_2026_58025_deser",
                ],
            },
        },
        "module": "exploits/multi/http/mediawiki_cve_2026_58025_deser",
        "modules": [
            "exploits/multi/http/mediawiki_cve_2026_58025_deser",
        ],
    }

    base_path = OptString(
        "",
        "MediaWiki base path (empty for web root; e.g. /w or /wiki)",
        False,
    )

    def _headers(self) -> Dict[str, str]:
        return {"User-Agent": str(self.user_agent or "KittySploit")}

    def _candidate_roots(self) -> List[str]:
        base = self.mw_normalize_base_path(str(self.base_path or ""))
        roots = [base]
        if not base:
            roots.extend(["", "/w", "/wiki", "/mediawiki"])
        seen = set()
        out: List[str] = []
        for root in roots:
            key = root or "/"
            if key in seen:
                continue
            seen.add(key)
            out.append(root)
        return out

    def _get(self, path: str):
        return self.http_request(
            method="GET",
            path=path,
            headers=self._headers(),
            allow_redirects=True,
            timeout=int(self.timeout or 15),
        )

    def _probe_root(self, root: str) -> Tuple[Dict, Optional[str]]:
        findings: Dict = {
            "detected": False,
            "version": "",
            "vulnerable": None,
            "root": root or "/",
            "import_available": False,
            "import_needs_auth": False,
            "api_generator": "",
        }

        for suffix in ("/", "/index.php", "/wiki/Main_Page", "/Main_Page"):
            if suffix == "/":
                path = root + "/" if root else "/"
            else:
                path = self.mw_join_path(root, suffix)
            try:
                resp = self._get(path)
            except Exception:
                continue
            if not resp or not getattr(resp, "text", None):
                continue
            html_info = self.mw_fingerprint_html(resp.text)
            if html_info.get("detected"):
                version = html_info.get("version") or ""
                findings.update(
                    {
                        "detected": True,
                        "version": version or findings["version"],
                        "vulnerable": _cve_2026_58025_vulnerable(version)
                        if version and version != "unknown"
                        else None,
                    }
                )
                break

        for api_suffix in ("/api.php", "/w/api.php"):
            if root.endswith("/w") and api_suffix.startswith("/w/"):
                api_path = self.mw_join_path(root, "/api.php")
            else:
                api_path = self.mw_join_path(root, api_suffix) if root else api_suffix
            try:
                resp = self._get(
                    f"{api_path}?action=query&meta=siteinfo&siprop=general&format=json"
                )
            except Exception:
                continue
            if not resp or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            api_info = self.mw_fingerprint_siteinfo(data)
            if api_info.get("detected"):
                findings["detected"] = True
                findings["api_generator"] = api_info.get("generator") or ""
                version = api_info.get("version") or ""
                if version:
                    findings["version"] = version
                    findings["vulnerable"] = (
                        _cve_2026_58025_vulnerable(version)
                        if version != "unknown"
                        else None
                    )
                break

        if not findings["detected"]:
            return findings, None

        import_paths = [
            self.mw_join_path(root, "/wiki/Special:Import"),
            self.mw_join_path(root, "/index.php?title=Special:Import"),
            self.mw_join_path(root, "/Special:Import"),
        ]
        if root.endswith("/w"):
            import_paths.insert(
                0, self.mw_join_path(root, "/index.php?title=Special:Import")
            )

        import_path = None
        for path in import_paths:
            try:
                resp = self._get(path)
            except Exception:
                continue
            if not resp:
                continue
            status = int(resp.status_code or 0)
            body = (resp.text or "").lower()
            loc = (resp.headers.get("Location") or getattr(resp, "url", "") or "").lower()
            if status in (301, 302, 303, 307, 308) and "login" in loc:
                findings["import_needs_auth"] = True
                import_path = path
                break
            if status == 200 and (
                "xmlimport" in body
                or "wpedittoken" in body
                or "special:import" in body
                or "import pages" in body
                or "upload file" in body
            ):
                findings["import_available"] = True
                if "login" in body and "xmlimport" not in body:
                    findings["import_needs_auth"] = True
                import_path = path
                break
            if status == 200 and "login" in body:
                findings["import_needs_auth"] = True
                import_path = path
                break

        return findings, import_path

    def run(self):
        best = None
        best_import = None
        for root in self._candidate_roots():
            findings, import_path = self._probe_root(root)
            if not findings.get("detected"):
                continue
            best = findings
            best_import = import_path
            if findings.get("vulnerable") is not None:
                break

        if not best:
            return False

        version = best.get("version") or "unknown"
        vulnerable = best.get("vulnerable")
        root = best.get("root") or "/"

        if vulnerable is True:
            severity = "critical"
            reason = (
                f"MediaWiki {version} appears vulnerable to CVE-2026-58025 "
                f"(log_params unserialize via import)"
            )
        elif vulnerable is False:
            severity = "info"
            reason = f"MediaWiki {version} appears patched for CVE-2026-58025"
        else:
            severity = "medium"
            reason = (
                f"MediaWiki detected (version={version}); "
                f"CVE-2026-58025 status unknown"
            )

        print_status(f"MediaWiki root={root} version={version} vulnerable={vulnerable}")
        if best.get("api_generator"):
            print_info(f"API generator: {best['api_generator']}")
        if best.get("import_available"):
            print_warning(f"Special:Import available at {best_import}")
        elif best.get("import_needs_auth"):
            print_info(f"Special:Import likely requires auth ({best_import})")

        self.set_info(
            severity=severity,
            reason=reason,
            version=version,
            vulnerable=vulnerable,
            root=root,
            import_path=best_import or "",
            import_available=bool(best.get("import_available")),
            import_needs_auth=bool(best.get("import_needs_auth")),
            cve="CVE-2026-58025",
        )
        return True
