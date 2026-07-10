#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import random
import string

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.joomla_probe import HELIX3_AJAX_PATH, HELIX3_PATCHED_VERSION, Joomla


class Module(Scanner, Http_client, Joomla):

    __info__ = {
        "name": "Joomla Helix3 CVE-2026-49049 (unauthenticated file write) detection",
        "description": (
            "Detects JoomShaper Helix3 <= 3.1.1 affected by CVE-2026-49049: "
            "unauthenticated arbitrary file write/delete and template parameter "
            "overwrite via the com_ajax helix3 plugin handler."
        ),
        "author": ["Phil Taylor", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-49049",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-49049",
            "https://mysites.guru/blog/helix3-security-update-changelog-failure/",
        ],
        "modules": [
            "auxiliary/admin/http/joomla_helix3_cve_2026_49049_file_write",
        ],
        "tags": [
            "web",
            "scanner",
            "joomla",
            "helix3",
            "joomshaper",
            "file-write",
            "path-traversal",
            "cve-2026-49049",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
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

    active_probe = OptBool(
        False,
        "Write and remove a harmless JSON probe via the unauthenticated save/remove actions",
        required=False,
    )

    def _random_probe_id(self) -> str:
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"_ks49049_{suffix}"

    def _probe_save_remove(self, probe_id: str) -> dict:
        result = {"save": False, "remove": False, "import": False}

        save = self.helix3_ajax_post(
            action="save",
            layout_name=probe_id,
            content=json.dumps({"probe": probe_id, "source": "kittysploit"}),
            timeout=12,
        )
        if self.helix3_ajax_success(save):
            result["save"] = True

        if result["save"]:
            remove = self.helix3_ajax_post(
                action="remove",
                layout_name=f"{probe_id}.json",
                timeout=12,
            )
            if remove and remove.status_code == 200:
                result["remove"] = True

        import_resp = self.helix3_ajax_post(
            action="import",
            template_id="1",
            settings="{}",
            timeout=12,
        )
        if self.helix3_ajax_success(import_resp):
            result["import"] = True

        return result

    def run(self):
        try:
            joomla = self.probe_joomla()
            if not joomla.get("found"):
                return False

            helix3 = self.probe_helix3()
            if not helix3.get("found"):
                return False

            joomla_version = joomla.get("version")
            helix3_version = helix3.get("version")

            if helix3_version and self.helix3_is_patched(helix3_version):
                self.set_info(
                    severity="info",
                    cve="CVE-2026-49049",
                    reason=(
                        f"Helix3 {helix3_version} >= {HELIX3_PATCHED_VERSION} "
                        "(patched against CVE-2026-49049)"
                    ),
                    joomla_version=joomla_version or "unknown",
                    helix3_version=helix3_version,
                )
                return False

            confidence = "high" if helix3_version else "medium"
            reason_parts = [
                f"JoomShaper Helix3 detected (version {helix3_version or 'unknown'})",
            ]
            if helix3_version:
                reason_parts.append(f"< {HELIX3_PATCHED_VERSION} threshold")

            probe_result = None
            if self.active_probe:
                probe_id = self._random_probe_id()
                probe_result = self._probe_save_remove(probe_id)
                if probe_result.get("save"):
                    confidence = "confirmed"
                    reason_parts.append(
                        f"unauthenticated save confirmed (probe {probe_id})"
                    )
                    if probe_result.get("remove"):
                        reason_parts.append("probe cleaned via remove")
                    else:
                        reason_parts.append(
                            f"remove cleanup failed — manual delete may be required: {probe_id}.json"
                        )
                elif helix3_version and not self.helix3_is_patched(helix3_version):
                    reason_parts.append("active probe inconclusive — endpoint may be blocked")
                    confidence = "medium"
                else:
                    return False

                if probe_result.get("import"):
                    reason_parts.append("import action reachable (v3.x template overwrite)")

            self.set_info(
                severity="high",
                cve="CVE-2026-49049",
                reason="; ".join(reason_parts),
                joomla_version=joomla_version or "unknown",
                helix3_version=helix3_version or "unknown",
                confidence=confidence,
                endpoint=HELIX3_AJAX_PATH,
                save_accessible=probe_result.get("save") if probe_result else None,
                remove_accessible=probe_result.get("remove") if probe_result else None,
                import_accessible=probe_result.get("import") if probe_result else None,
                active_probe=bool(self.active_probe),
            )
            return True

        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
