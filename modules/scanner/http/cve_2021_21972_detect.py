#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VMware vCenter vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugi."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VMware vSphere Client (HTML5) - Remote Code Execution Detection',
        'description': 'VMware vCenter vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'vmware', 'rce', 'vcenter', 'kev', 'packetstorm', 'vkev', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://swarm.ptsecurity.com/unauth-rce-vmware/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21972',
            'https://www.vmware.com/security/advisories/VMSA-2021-0002.html',
            'http://packetstormsecurity.com/files/161590/VMware-vCenter-Server-7.0-Arbitrary-File-Upload.html',
            'https://github.com/NS-Sp4ce/CVE-2021-21972',
        ],
        'cve': 'CVE-2021-21972',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ui/vropspluginui/rest/services/getstatus', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('VSPHERE-UI-JSESSIONID',)
        body_regexes = ('(Install|Config) Final Progress',)
        if (all(m in headers for m in header_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="VMware vSphere Client (HTML5) - Remote Code Execution detected",
                path='/ui/vropspluginui/rest/services/getstatus',
            )
            return True
        return False

