#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adobe AEM Installed OSGI Bundles leaked."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe AEM Installed OSGI Bundles Detection',
        'description': 'Adobe AEM Installed OSGI Bundles leaked.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'aem', 'adobe', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
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
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['https://www.slideshare.net/0ang3el/hacking-aem-sites'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/bin.tidy.infinity.json', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"jcr:primaryType":', '"jcr:uuid":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Adobe AEM Installed OSGI Bundles detected",
                path='/bin.tidy.infinity.json',
            )
            return True
        return False

