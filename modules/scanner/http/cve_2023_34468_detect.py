#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache NiFi H2 JDBC RCE surface detection (CVE-2023-34468)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache NiFi H2 JDBC RCE Detection (CVE-2023-34468)',
        'description': (
            'Detects Apache NiFi versions before 1.22.0 with API access to process groups. '
            'Such hosts may allow H2 JDBC URLs in DBCPConnectionPool (CVE-2023-34468).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'apache', 'nifi', 'h2', 'jdbc', 'rce', 'vuln',
        ],
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
                    {'capability': 'admin_surface', 'from_detail': 'NiFi API + old version'},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/multi/http/apache_nifi_cve_2023_34468_rce',
                    'exploits/multi/http/apache_nifi_executeprocess_rce',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-34468',
            'https://github.com/advisories/GHSA-xm2m-2q6h-22jw',
        ],
        'cve': 'CVE-2023-34468',
    }

    @staticmethod
    def _version_vulnerable(version: str) -> bool | None:
        parts = version.split('.')
        if len(parts) < 2:
            return None
        try:
            major, minor = int(parts[0]), int(parts[1])
        except ValueError:
            return None
        if major == 0:
            return True
        if major == 1 and minor < 22:
            return True
        return False

    def run(self):
        r = self.http_request(
            method='GET',
            path='/nifi-api/process-groups/root',
            allow_redirects=False,
        )
        if not r or int(r.status_code or 0) != 200:
            return False
        body = r.text or ''
        if not all(marker in body for marker in ('revision', 'canRead', 'permissions')):
            return False

        version = None
        about = self.http_request(method='GET', path='/nifi-api/flow/about', allow_redirects=False)
        if about and int(about.status_code or 0) == 200:
            data, _err = parse_json_response(about)
            if isinstance(data, dict):
                version = (data.get('about') or {}).get('version')

        if version:
            vuln = self._version_vulnerable(str(version))
            if vuln is False:
                return False
            if vuln is True:
                self.set_info(
                    severity='high',
                    reason=f'Apache NiFi {version} — CVE-2023-34468 H2 JDBC RCE surface',
                    path='/nifi-api/process-groups/root',
                    evidence=f'version={version}',
                )
                return True

        self.set_info(
            severity='medium',
            reason='Apache NiFi API exposed (H2 JDBC RCE possible on builds < 1.22.0)',
            path='/nifi-api/process-groups/root',
        )
        return True
