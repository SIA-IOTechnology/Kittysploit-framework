#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'robots.txt / sitemap detection',
        'description': 'Detects exposed robots.txt and sitemap references; reports interesting paths.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'robots', 'sitemap', 'disclosure', 'enumeration'],
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
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        r = self.http_request(method="GET", path="/robots.txt", allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        text = r.text
        if "user-agent" not in text.lower() and "disallow" not in text.lower() and "allow" not in text.lower():
            return False
        details = []
        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        disallow_paths = []
        sitemaps = []
        for line in lines:
            lower = line.lower()
            if lower.startswith("disallow:") and len(line) > 9:
                path = line[9:].strip()
                if path and path != "/":
                    disallow_paths.append(path)
            elif lower.startswith("sitemap:") and len(line) > 8:
                sitemaps.append(line[8:].strip())
        if disallow_paths:
            details.append("Disallow: " + ", ".join(disallow_paths[:10]))
        if sitemaps:
            details.append("Sitemap(s): " + ", ".join(sitemaps[:5]))
        reason = "robots.txt exposed" + ("; " + "; ".join(details) if details else "")
        self.set_info(severity="info", reason=reason)
        return True
