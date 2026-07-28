#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import re
import ssl
import time
import warnings
from typing import Optional, Tuple

from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Palo Alto GlobalProtect CVE-2026-0265 CAS auth bypass detection",
        "description": (
            "Detects whether a GlobalProtect portal is vulnerable to CVE-2026-0265 "
            "(CAS JWT signature bypass) via a single anonymous GET to "
            "/global-protect/prelogin.esp. Requires Cloud Authentication Service "
            "(CAS) attached and a PAN-OS build below the advisory hotfix cutoff. "
            "No authentication is attempted and no firewall state is modified."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-0265",
        "references": [
            "https://security.paloaltonetworks.com/CVE-2026-0265",
            "https://bishopfox.com/blog/detecting-cve-2026-0265-at-scale-pan-os-cas-authentication-bypass",
            "https://github.com/BishopFox/CVE-2026-0265-check",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-0265",
        ],
        "tags": [
            "web",
            "scanner",
            "paloalto",
            "pan-os",
            "globalprotect",
            "vpn",
            "cas",
            "auth-bypass",
            "jwt",
            "cve-2026-0265",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.1,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["globalprotect", "paloalto", "pan-os"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/global-protect/", "/ssl-vpn/"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "cas_jwt"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    _DEFAULT_UA = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    )
    _PRELOGIN_PATH = "/global-protect/prelogin.esp"

    # Per-base patched-hotfix cutoffs from the vendor advisory.
    _ADVISORY_PATCHED_HOTFIX = {
        (10, 2, 4): 44,
        (10, 2, 7): 34,
        (10, 2, 10): 36,
        (10, 2, 13): 21,
        (10, 2, 16): 7,
        (10, 2, 18): 6,
        (11, 1, 4): 33,
        (11, 1, 6): 32,
        (11, 1, 7): 6,
        (11, 1, 10): 25,
        (11, 1, 13): 5,
        (11, 2, 4): 17,
        (11, 2, 7): 13,
        (11, 2, 10): 6,
        (12, 1, 4): 5,
    }
    _ADVISORY_BASE_FLOOR = {(11, 1): 15, (11, 2): 12, (12, 1): 7}
    _UNAFFECTED_TRAINS = {(8, 1), (9, 1)}

    port = OptPort(443, "GlobalProtect HTTPS port", True)
    # Do not redefine `ssl` here: it would shadow the stdlib `ssl` import in
    # class scope (breaking `ssl.SSLContext` annotations) and Http_client already
    # provides the HTTPS OptBool.
    prelogin_path = OptString(
        _PRELOGIN_PATH,
        "GlobalProtect prelogin endpoint path",
        required=False,
    )
    user_agent = OptString(
        _DEFAULT_UA,
        "Probe User-Agent (browser-like UA bypasses gpsvc GP-client version gate)",
        required=False,
    )

    def _opt(self, option) -> str:
        if hasattr(option, "value"):
            return str(option.value or "").strip()
        return str(option or "").strip()

    def _configure_legacy_tls(self):
        """Relax TLS for older PAN-OS that still negotiate TLS 1.0/1.1 or weak ciphers."""

        class _LegacyTLSAdapter(HTTPAdapter):
            def __init__(self, *args, **kwargs):
                self._ssl_context = Module._build_legacy_ssl_context()
                super().__init__(*args, **kwargs)

            def init_poolmanager(self, *args, **kwargs):
                kwargs["ssl_context"] = self._ssl_context
                return super().init_poolmanager(*args, **kwargs)

            def proxy_manager_for(self, *args, **kwargs):
                kwargs["ssl_context"] = self._ssl_context
                return super().proxy_manager_for(*args, **kwargs)

        self.session.mount("https://", _LegacyTLSAdapter())

    @staticmethod
    def _build_legacy_ssl_context() -> ssl.SSLContext:
        ctx = create_urllib3_context()
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (AttributeError, ValueError):
            pass
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            try:
                ctx.set_ciphers("ALL")
            except ssl.SSLError:
                pass
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _b64url_decode(value: str) -> bytes:
        pad = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + pad)

    def _advisory_verdict(self, panos_version: str) -> str:
        if not panos_version:
            return "ERROR"
        if ".saas" in panos_version:
            return "NOT-AFFECTED-SAAS"
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?$", panos_version)
        if not match:
            return "ERROR"
        major, minor, patch, hotfix = (
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            int(match.group(4) or 0),
        )
        if (major, minor) in self._UNAFFECTED_TRAINS:
            return "PATCHED"
        floor = self._ADVISORY_BASE_FLOOR.get((major, minor))
        if floor is not None and patch >= floor:
            return "PATCHED"
        if (major, minor, patch) in self._ADVISORY_PATCHED_HOTFIX:
            cut = self._ADVISORY_PATCHED_HOTFIX[(major, minor, patch)]
            return "PATCHED" if hotfix >= cut else "VULNERABLE"
        if (major, minor) in {(10, 2), (11, 1), (11, 2), (12, 1)}:
            return "VULNERABLE"
        return "PATCHED"

    def _decode_token_from_prelogin(self, body: str) -> Optional[dict]:
        match = re.search(r"<saml-request>([^<]+)</saml-request>", body or "")
        if not match:
            return None
        try:
            html_form = base64.b64decode(match.group(1).strip()).decode(
                "utf-8", errors="replace"
            )
            token_match = re.search(r'name="Token"\s+value="([^"]+)"', html_form)
            if not token_match:
                return None
            parts = token_match.group(1).split(".")
            if len(parts) != 3:
                return None
            return json.loads(self._b64url_decode(parts[1]))
        except Exception:
            return None

    def _fetch_prelogin(self, path: str, user_agent: str, timeout: int):
        last_error = None
        for backoff in (0.0, 1.0, 2.0, 4.0):
            if backoff:
                time.sleep(backoff)
            response = self.http_request(
                method="GET",
                path=path,
                headers={"User-Agent": user_agent},
                allow_redirects=False,
                timeout=timeout,
            )
            if not response:
                last_error = "request failed"
                continue
            if response.status_code == 503:
                last_error = "HTTP 503 (gpsvc rate-limit)"
                continue
            return response, None
        return None, last_error or "all retries exhausted"

    def _scan(self) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
        """Return (verdict, panos_version, prelogin_msg, error)."""
        path = self._opt(self.prelogin_path) or self._PRELOGIN_PATH
        if not path.startswith("/"):
            path = "/" + path
        user_agent = self._opt(self.user_agent) or self._DEFAULT_UA
        timeout = max(int(self.timeout or 20), 10)

        response, error = self._fetch_prelogin(path, user_agent, timeout)
        if response is None:
            return "UNDETERMINED-ERROR", None, None, error

        body = response.text or ""
        pre_msg_match = re.search(r"<msg>([^<]*)</msg>", body)
        pre_msg = pre_msg_match.group(1) if pre_msg_match and pre_msg_match.group(1) else None

        if "GlobalProtect portal does not exist" in body:
            return "NOT-AFFECTED-NOT-GLOBALPROTECT", None, pre_msg, None
        if "Valid client certificate is required" in body:
            return "UNDETERMINED-MTLS-GATED", None, pre_msg, None
        if "CAS is not supported by the client" in body:
            return "UNDETERMINED-VERSION-GATED", None, pre_msg, None

        cas_match = re.search(r"<cas-auth>([^<]*)</cas-auth>", body)
        cas_auth = cas_match.group(1) if cas_match else None
        if cas_auth != "yes":
            return "NOT-AFFECTED-NO-CAS", None, pre_msg, None

        claims = self._decode_token_from_prelogin(body)
        if not claims:
            return (
                "UNDETERMINED-ERROR",
                None,
                pre_msg,
                "cas-auth=yes but Token decode from prelogin response failed",
            )

        panos_version = claims.get("PanOSversion") or None
        verdict = self._advisory_verdict(panos_version or "")
        if verdict == "ERROR":
            return (
                "UNDETERMINED-ERROR",
                panos_version,
                pre_msg,
                f"PanOSversion={panos_version!r} could not be parsed against the advisory matrix",
            )
        return verdict, panos_version, pre_msg, None

    def run(self):
        # Avoid mutating a shared scan session's TLS stack (bulk scanner pool).
        owns_session = bool(getattr(self, "_owns_session", True))
        previous_adapter = None
        try:
            if owns_session:
                self._configure_legacy_tls()
            else:
                # Private one-off session for legacy TLS probe
                import requests as _requests

                previous_adapter = self.session
                self.session = _requests.Session()
                self._owns_session = True
                self._configure_legacy_tls()

            verdict, panos_version, pre_msg, error = self._scan()
            version_label = panos_version or "-"

            if verdict == "VULNERABLE":
                self.set_info(
                    severity="high",
                    cve="CVE-2026-0265",
                    reason=(
                        f"CAS attached and PAN-OS {version_label} is below the "
                        "advisory patched hotfix cutoff"
                    ),
                )
                print_success(f"Verdict: {verdict} (PAN-OS {version_label})")
                return True

            if verdict == "PATCHED":
                self.set_info(
                    severity="info",
                    reason=f"CAS attached but PAN-OS {version_label} is patched for CVE-2026-0265",
                )
                print_info(f"Verdict: {verdict} (PAN-OS {version_label})")
                return False

            if verdict == "NOT-AFFECTED-SAAS":
                self.set_info(
                    severity="info",
                    reason=(
                        f"PAN-OS {version_label} is a .saas build; not affected per "
                        "Palo Alto (2026-05-21)"
                    ),
                )
                print_info(f"Verdict: {verdict} (PAN-OS {version_label})")
                return False

            if verdict == "NOT-AFFECTED-NO-CAS":
                self.set_info(
                    severity="info",
                    reason="prelogin succeeded but CAS is not attached (CVE does not apply)",
                )
                print_info(f"Verdict: {verdict}")
                return False

            if verdict == "NOT-AFFECTED-NOT-GLOBALPROTECT":
                # Soft miss on non-GP targets — not a scanner error
                return False

            if verdict == "UNDETERMINED-VERSION-GATED":
                print_warning(
                    "Verdict: UNDETERMINED-VERSION-GATED — CAS attached but User-Agent "
                    "was version-gated; retry with a real GP-client User-Agent"
                )
                if pre_msg:
                    print_info(f"prelogin msg: {pre_msg}")
                return False

            if verdict == "UNDETERMINED-MTLS-GATED":
                print_warning(
                    "Verdict: UNDETERMINED-MTLS-GATED — client certificate required; "
                    "verdict needs a cert-backed probe or inventory version"
                )
                return False

            # Undetermined / transport errors on random sites: silent miss
            if verdict.startswith("UNDETERMINED") or verdict.endswith("ERROR"):
                return False

            return False
        except Exception:
            # Never surface TLS/transport noise as a module failure during bulk scans
            return False
        finally:
            if previous_adapter is not None:
                try:
                    self.session.close()
                except Exception:
                    pass
                self.session = previous_adapter
                self._owns_session = False
