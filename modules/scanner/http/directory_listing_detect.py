#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS_TO_CHECK = ["/", "/images/", "/img/", "/assets/", "/static/", "/backup/", "/uploads/", "/files/", "/media/"]


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Directory listing detection',
        'description': 'Detects if directory listing is enabled on the server.',
        'author': 'KittySploit Team',
        'severity': 'low',
        'modules': [],
        'tags': ['web', 'scanner', 'directory', 'listing', 'disclosure'],
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
         'suggested_followups': []},
    },
    }

    def run(self):
        found = []
        for path in PATHS_TO_CHECK:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            t = r.text
            if "index of" in t.lower() or "directory listing" in t.lower() or ("<title>" in t.lower() and "index of" in t.lower()):
                found.append(path.rstrip("/") or "/")
        if found:
            self.set_info(severity="low", reason=f"Listing enabled: {', '.join(found)}")
            return True
        return False
