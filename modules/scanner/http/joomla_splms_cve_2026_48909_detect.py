#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.joomla_probe import Joomla


class Module(Scanner, Http_client, Joomla):

    __info__ = {
        "name": "Joomla SP LMS CVE-2026-48909 (PHP object injection) detection",
        "description": (
            "Detects JoomShaper SP LMS (com_splms) <= 4.1.3 affected by unauthenticated "
            "PHP object injection via the lmsOrders cookie (CVE-2026-48909). "
            "Full RCE requires Joomla < 5.2.2 (FormattedtextLogger gadget chain)."
        ),
        "author": ["Amin İsayev", "Proxima Cyber Security", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-48909",
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-48909",
        ],
        "modules": [
            "exploits/http/joomla_splms_cve_2026_48909_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "joomla",
            "splms",
            "joomshaper",
            "php-object-injection",
            "deserialization",
            "rce",
            "cve-2026-48909",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
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
                    {"capability": "deserialization", "from_detail": "lmsOrders"},
                    {"capability": "rce", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    _SPLMS_PATCHED = "4.1.4"
    _JOOMLA_RCE_PATCHED = "5.2.2"
    _CART_PATH = "/index.php?option=com_splms&view=cart"
    _XML_VERSION_RE = re.compile(r"<version>([^<]+)</version>", re.IGNORECASE)

    def _probe_splms(self) -> dict:
        result = {"found": False, "version": None, "cart_reachable": False}
        for manifest in (
            "/administrator/components/com_splms/splms.xml",
            "/components/com_splms/splms.xml",
        ):
            response = self.joomla_http_get(manifest, timeout=8)
            if not response or response.status_code != 200:
                continue
            body = response.text or ""
            match = self._XML_VERSION_RE.search(body)
            if match:
                result.update({"found": True, "version": match.group(1).strip()})
                break
            if "com_splms" in body.lower() or "sp lms" in body.lower():
                result["found"] = True
                break

        if not result["found"]:
            for asset in (
                "/components/com_splms/assets/css/splms.css",
                "/media/com_splms/css/splms.css",
            ):
                response = self.joomla_http_get(asset, timeout=6)
                if response and response.status_code == 200 and len(response.text or "") > 20:
                    result["found"] = True
                    break

        cart = self.joomla_http_get(self._CART_PATH, timeout=8)
        if cart and cart.status_code in (200, 500):
            body = (cart.text or "").lower()
            if "splms" in body or "com_splms" in body or cart.status_code == 200:
                result["cart_reachable"] = True
                if not result["found"] and ("splms" in body or "lms" in body):
                    result["found"] = True

        return result

    def run(self):
        try:
            joomla = self.probe_joomla()
            if not joomla.get("found"):
                return False

            splms = self._probe_splms()
            if not splms.get("found"):
                return False

            joomla_version = joomla.get("version")
            splms_version = splms.get("version")

            if splms_version and not self.version_less_than(splms_version, self._SPLMS_PATCHED):
                self.set_info(
                    severity="info",
                    cve="CVE-2026-48909",
                    reason=(
                        f"SP LMS {splms_version} >= {self._SPLMS_PATCHED} "
                        "(patched against CVE-2026-48909)"
                    ),
                    joomla_version=joomla_version or "unknown",
                    splms_version=splms_version,
                )
                return False

            rce_possible = (
                not joomla_version
                or self.version_less_than(joomla_version, self._JOOMLA_RCE_PATCHED)
            )
            confidence = "high" if splms_version else "medium"

            reason_parts = [
                f"JoomShaper SP LMS detected (version {splms_version or 'unknown'})",
            ]
            if splms_version:
                reason_parts.append(f"<= {self._SPLMS_PATCHED} threshold")
            if joomla_version:
                if rce_possible:
                    reason_parts.append(
                        f"Joomla {joomla_version} < {self._JOOMLA_RCE_PATCHED} — "
                        "RCE gadget chain likely available"
                    )
                else:
                    reason_parts.append(
                        f"Joomla {joomla_version} >= {self._JOOMLA_RCE_PATCHED} — "
                        "POI may exist but public RCE gadget chain blocked"
                    )
                    confidence = "medium"
            if splms.get("cart_reachable"):
                reason_parts.append("cart endpoint reachable")

            severity = "critical" if rce_possible else "high"
            self.set_info(
                severity=severity,
                cve="CVE-2026-48909",
                reason="; ".join(reason_parts),
                joomla_version=joomla_version or "unknown",
                splms_version=splms_version or "unknown",
                rce_gadget_available=rce_possible,
                confidence=confidence,
                endpoint=self._CART_PATH,
                cookie="lmsOrders",
            )
            return True

        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
