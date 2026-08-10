#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Security vulnerability known as Unauthenticated access to settings or Unauthenticated configuration download."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DAP-1325 - Information Disclosure Detection',
        'description': 'Security vulnerability known as Unauthenticated access to settings or Unauthenticated configuration download. This vulnerability occurs when a device, such as a repeater, allows the download of user settings without requiring proper authentication.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'config', 'dump', 'dlink', 'auth-bypass', 'disclosure', 'vuln'],
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
                'suggested_followups': [
                    'scanner/http/cve_2018_17786_detect',
                    'auxiliary/admin/http/dlink_exportsettings_config_dump',
                ],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/51556',
            'https://www.dropbox.com/s/eqz0ntlzqp5472l/DAP-1325.mp4?dl=0',
        ],
    }

    def run(self):
        # Prefer scanner/http/cve_2018_17786_detect (NASL-aligned header matchers).
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
        if not re.search(r'attachment;\s*filename="[^"]+\.(dat|bin)"', cdisp, re.I):
            return False
        self.set_info(
            severity='critical',
            reason='D-Link/TOTOLINK unauthenticated ExportSettings.sh config download',
            path=path,
        )
        return True

