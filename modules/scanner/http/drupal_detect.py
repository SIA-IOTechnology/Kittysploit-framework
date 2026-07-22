#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Drupal detection',
        'description': 'Detects if Drupal is installed on the target.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': ['auxiliary/scanner/http/login/drupal_login_bruteforce'],
        'tags': ['web', 'scanner', 'drupal', 'cms'],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
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
         'suggested_followups': ['auxiliary/scanner/http/login/drupal_login_bruteforce']},
    },
    }

    path = OptString("/", "Drupal base path to test", required=False)

    def _candidate_paths(self):
        configured = str(self.path or "/").strip() or "/"
        if not configured.startswith("/"):
            configured = "/" + configured
        candidates = [configured.rstrip("/") or "/"]
        for candidate in ("/drupal", "/Drupal"):
            if candidate not in candidates:
                candidates.append(candidate)
        return candidates

    def _join(self, base_path, suffix):
        base = (base_path or "/").rstrip("/")
        if base == "":
            base = "/"
        suffix = "/" + str(suffix or "").lstrip("/")
        if base == "/":
            return suffix
        return base + suffix

    def _score_base_path(self, base_path):
        score = 0
        evidence = []
        r = self.http_request(method="GET", path=base_path, allow_redirects=True)
        if not r:
            return 0, evidence

        body = (r.text or "").lower()
        headers = str(r.headers).lower()

        if re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*drupal', body, re.IGNORECASE):
            score += 4
            evidence.append("generator")
        if "drupal.settings" in body or "drupalsettings" in body:
            score += 3
            evidence.append("drupal.settings")
        if "/sites/default/files/" in body or "/sites/all/" in body or f"{base_path.rstrip('/')}/sites/default" in body:
            score += 3
            evidence.append("sites/default")
        if "/core/assets/" in body:
            score += 2
            evidence.append("core/assets")
        if "drupal" in body or "drupal" in headers:
            score += 1
            evidence.append("drupal keyword")

        login_path = self._join(base_path, "/user/login")
        r2 = self.http_request(method="GET", path=login_path, allow_redirects=False)
        if r2 and r2.status_code in [200, 301, 302, 403]:
            login_body = (r2.text or "").lower()
            location = (r2.headers.get("Location", "") or "").lower()
            if (
                "form_id=\"user_login_form\"" in login_body
                or "name=\"form_id\" value=\"user_login_form\"" in login_body
                or "/user/login" in location
                or "drupal" in login_body
            ):
                score += 4
                evidence.append("user/login")

        return score, evidence

    def run(self):
        best = {"score": 0, "base_path": "/", "evidence": []}
        for base_path in self._candidate_paths():
            score, evidence = self._score_base_path(base_path)
            if score > best["score"]:
                best = {"score": score, "base_path": base_path, "evidence": evidence}

        if best["score"] >= 5:
            login_path = self._join(best["base_path"], "/user/login")
            self.set_info(
                severity="info",
                reason=f"Drupal detected at {best['base_path']}",
                base_path=best["base_path"],
                path=best["base_path"],
                login_path=login_path,
                evidence=", ".join(best["evidence"]),
            )
            return True

        self.set_info(reason="Drupal not detected")
        return False
